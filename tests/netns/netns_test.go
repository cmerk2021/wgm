// Package netns contains end-to-end tests that run the real wgmd binary,
// wg-quick and nftables inside isolated network namespaces. They never
// touch the host's firewall or VPN configuration.
//
// Run as root:
//
//	sudo -E env "PATH=$PATH" GOTOOLCHAIN=local WGM_NETNS_TESTS=1 go test -v ./tests/netns/
package netns

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
)

const (
	nsA = "wgmtestA" // client: runs wgmd
	nsB = "wgmtestB" // server: WireGuard peer
)

func requireEnv(t *testing.T) {
	if os.Getenv("WGM_NETNS_TESTS") != "1" {
		t.Skip("set WGM_NETNS_TESTS=1 (and run as root) to run network namespace tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("network namespace tests require root")
	}
	for _, tool := range []string{"ip", "wg", "wg-quick", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func inNS(ns string, args ...string) error {
	return exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).Run()
}

func mustNS(t *testing.T, ns string, args ...string) {
	t.Helper()
	sh(t, append([]string{"ip", "netns", "exec", ns}, args...)...)
}

// The CI sandbox this was developed in filters egress from userspace
// sockets with a cgroup eBPF program, so leak tests must not rely on ping or
// ordinary sockets. Instead each probe is a throwaway kernel WireGuard
// interface in nsA whose handshake initiations are kernel-originated UDP
// packets; nftables counters in nsB observe whether they arrived. This also
// works unchanged on an unrestricted host.

// leak describes one kernel-generated traffic source.
type leak struct {
	name     string // interface name in nsA and counter name in nsB
	endpoint string // host:port
	fwmark   int    // 0 = unmarked (follows wg-quick policy routing)
	port     int    // local listen port
}

var (
	// Marked traffic bypasses wg-quick's policy routing and goes straight
	// out of the physical interface, so these exercise the firewall itself.
	leakMarkedPort = leak{"lkport", "10.99.0.2:51821", 51820, 41001}
	leakMarkedV6   = leak{"lkv6", "[fd99::2]:51820", 51820, 41002}
	leakMarkedDNS  = leak{"lkdns", "10.99.0.2:53", 51820, 41003}
	// Unmarked traffic: physical only when policy routing is missing.
	leakUnmarked4 = leak{"lkun4", "10.99.0.2:51821", 0, 41004}
	leakUnmarked6 = leak{"lkun6", "[fd99::2]:51822", 0, 41005}
	// Unmarked traffic aimed at the real endpoint address and port.
	leakUnmarkedEP = leak{"lkunep", "10.99.0.2:51820", 0, 41006}
)

func setupObserver(t *testing.T) {
	rules := `add table inet obs
add chain inet obs pre { type filter hook prerouting priority -400; policy accept; }
`
	for _, l := range []leak{leakMarkedPort, leakMarkedV6, leakMarkedDNS, leakUnmarked4, leakUnmarked6, leakUnmarkedEP} {
		rules += fmt.Sprintf("add counter inet obs %s\nadd rule inet obs pre iifname \"vB\" udp sport %d counter name %s\n", l.name, l.port, l.name)
	}
	cmd := exec.Command("ip", "netns", "exec", nsB, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("observer: %v\n%s", err, out)
	}
}

func observed(t *testing.T, name string) uint64 {
	out, err := exec.Command("ip", "netns", "exec", nsB, "nft", "-j", "list", "counter", "inet", "obs", name).Output()
	if err != nil {
		t.Fatalf("read counter %s: %v", name, err)
	}
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc.Nftables {
		if o.Counter != nil {
			return o.Counter.Packets
		}
	}
	t.Fatalf("counter %s not found", name)
	return 0
}

// emit brings up the given leak sources in nsA for a few seconds and
// returns how many packets nsB received from each.
func emit(t *testing.T, ls ...leak) map[string]uint64 {
	t.Helper()
	before := map[string]uint64{}
	for _, l := range ls {
		before[l.name] = observed(t, l.name)
		inNS(nsA, "ip", "link", "del", l.name)
		mustNS(t, nsA, "ip", "link", "add", l.name, "type", "wireguard")
		mustNS(t, nsA, "ip", "link", "set", l.name, "up")
		args := []string{"wg", "set", l.name, "listen-port", fmt.Sprint(l.port), "private-key", leakKeyFile,
			"peer", leakPeerPub, "endpoint", l.endpoint, "allowed-ips", "192.0.2.1/32", "persistent-keepalive", "1"}
		if l.fwmark != 0 {
			args = append(args[:3], append([]string{"fwmark", fmt.Sprint(l.fwmark)}, args[3:]...)...)
		}
		mustNS(t, nsA, args...)
	}
	time.Sleep(3 * time.Second)
	got := map[string]uint64{}
	for _, l := range ls {
		inNS(nsA, "ip", "link", "del", l.name)
		got[l.name] = observed(t, l.name) - before[l.name]
	}
	return got
}

var leakKeyFile, leakPeerPub string

type harness struct {
	t      *testing.T
	dir    string
	bin    string
	daemon *exec.Cmd
	client *ipc.Client
	sock   string
}

func setup(t *testing.T) *harness {
	requireEnv(t)
	h := &harness{t: t, dir: t.TempDir()}
	cleanup := func() {
		exec.Command("ip", "netns", "del", nsA).Run()
		exec.Command("ip", "netns", "del", nsB).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	h.bin = filepath.Join(h.dir, "wgmd")
	build := exec.Command("go", "build", "-o", h.bin, "github.com/cmerk2021/wgm/cmd/wgmd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	sh(t, "ip", "netns", "add", nsA)
	sh(t, "ip", "netns", "add", nsB)
	sh(t, "ip", "link", "add", "vA", "netns", nsA, "type", "veth", "peer", "name", "vB", "netns", nsB)
	mustNS(t, nsA, "ip", "link", "set", "lo", "up")
	mustNS(t, nsB, "ip", "link", "set", "lo", "up")
	mustNS(t, nsA, "ip", "addr", "add", "10.99.0.1/24", "dev", "vA")
	mustNS(t, nsB, "ip", "addr", "add", "10.99.0.2/24", "dev", "vB")
	mustNS(t, nsA, "ip", "-6", "addr", "add", "fd99::1/64", "dev", "vA", "nodad")
	mustNS(t, nsB, "ip", "-6", "addr", "add", "fd99::2/64", "dev", "vB", "nodad")
	mustNS(t, nsA, "ip", "link", "set", "vA", "up")
	mustNS(t, nsB, "ip", "link", "set", "vB", "up")
	mustNS(t, nsA, "ip", "route", "add", "default", "via", "10.99.0.2")
	mustNS(t, nsA, "ip", "-6", "route", "add", "default", "via", "fd99::2")
	// Static neighbours: the development sandbox filters the kernel's
	// neighbour-discovery socket, which would otherwise stall IPv6.
	macA := mac(t, nsA, "vA")
	macB := mac(t, nsB, "vB")
	mustNS(t, nsA, "ip", "-6", "neigh", "replace", "fd99::2", "lladdr", macB, "dev", "vA", "nud", "permanent")
	mustNS(t, nsB, "ip", "-6", "neigh", "replace", "fd99::1", "lladdr", macA, "dev", "vB", "nud", "permanent")

	privA := sh(t, "wg", "genkey")
	privB := sh(t, "wg", "genkey")
	pubA := pubkey(t, privA)
	pubB := pubkey(t, privB)
	keyB := filepath.Join(h.dir, "b.key")
	os.WriteFile(keyB, []byte(privB+"\n"), 0o600)
	mustNS(t, nsB, "ip", "link", "add", "wgs", "type", "wireguard")
	mustNS(t, nsB, "wg", "set", "wgs", "listen-port", "51820", "private-key", keyB, "peer", pubA, "allowed-ips", "10.8.0.2/32")
	mustNS(t, nsB, "ip", "addr", "add", "10.8.0.1/24", "dev", "wgs")
	mustNS(t, nsB, "ip", "link", "set", "wgs", "up")

	leakKeyFile = filepath.Join(h.dir, "leak.key")
	os.WriteFile(leakKeyFile, []byte(sh(t, "wg", "genkey")+"\n"), 0o600)
	leakPeerPub = pubkey(t, sh(t, "wg", "genkey"))
	setupObserver(t)

	wgDir := filepath.Join(h.dir, "wireguard")
	os.MkdirAll(wgDir, 0o700)
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = 10.99.0.2:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 5\n", privA, pubB)
	if err := os.WriteFile(filepath.Join(wgDir, "wg0.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	h.sock = filepath.Join(h.dir, "run", "control.sock")
	h.client = ipc.NewClient(h.sock)
	t.Cleanup(func() { h.stop(syscall.SIGKILL) })
	return h
}

func mac(t *testing.T, ns, dev string) string {
	out := sh(t, "ip", "-n", ns, "-j", "link", "show", dev)
	var links []struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil || len(links) != 1 {
		t.Fatalf("mac %s: %v %s", dev, err, out)
	}
	return links[0].Address
}

func pubkey(t *testing.T, priv string) string {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func (h *harness) args(sub ...string) []string {
	a := append([]string{"netns", "exec", nsA, h.bin}, sub...)
	return append(a, "--config-dir", filepath.Join(h.dir, "wireguard"), "--policy", filepath.Join(h.dir, "policy.json"),
		"--state-dir", filepath.Join(h.dir, "state"), "--socket", h.sock, "--group", "root", "--admin-group", "root")
}

func (h *harness) start() {
	h.t.Helper()
	h.daemon = exec.Command("ip", h.args()...)
	logf, _ := os.OpenFile(filepath.Join(h.dir, "wgmd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	h.daemon.Stdout, h.daemon.Stderr = logf, logf
	if err := h.daemon.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.waitFor("daemon ready", 15*time.Second, func() bool {
		return h.client.Call(context.Background(), api.OpPing, nil, nil) == nil
	})
}

func (h *harness) stop(sig syscall.Signal) {
	if h.daemon == nil || h.daemon.Process == nil {
		return
	}
	h.daemon.Process.Signal(sig)
	h.daemon.Wait()
	h.daemon = nil
	h.client.Close()
}

func (h *harness) call(op string, params, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return h.client.Call(ctx, op, params, out)
}

func (h *harness) waitFor(what string, timeout time.Duration, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	log, _ := os.ReadFile(filepath.Join(h.dir, "wgmd.log"))
	h.t.Fatalf("timed out waiting for %s\n--- wgmd log tail ---\n%s", what, tail(string(log), 40))
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (h *harness) tunnel() api.TunnelStatus {
	var st api.TunnelStatus
	if err := h.call(api.OpGetTunnel, api.NameParams{Name: "wg0"}, &st); err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *harness) waitState(want health.State, timeout time.Duration) {
	h.t.Helper()
	h.waitFor("state "+string(want), timeout, func() bool { return h.tunnel().Health.State == want })
}

func (h *harness) ks() api.KillSwitchStatus {
	var ks api.KillSwitchStatus
	if err := h.call(api.OpGetKillSwitch, nil, &ks); err != nil {
		h.t.Fatal(err)
	}
	return ks
}

func tableExists() bool {
	return inNS(nsA, "nft", "list", "table", "inet", firewall.TableName) == nil
}

// testPolicy uses handshake-based health only: active probes are userspace
// sockets, which the development sandbox blocks (see the leak comment).
// HandshakeStaleSec is short so outages are detected quickly; WireGuard
// re-handshakes roughly every two minutes, so the test keeps each phase
// short or tolerates a precautionary restart.
func testPolicy() config.TunnelPolicy {
	p := config.DefaultTunnelPolicy()
	p.Ownership = config.OwnershipManaged
	p.Health = config.HealthPolicy{IntervalSec: 2, HandshakeStaleSec: 30, FailureThreshold: 2, RecoveryThreshold: 1, ConnectGraceSec: 5}
	p.Recovery = config.RecoveryPolicy{Enabled: true, MaxAttempts: 10, InitialBackoffSec: 1, MaxBackoffSec: 4, Multiplier: 2,
		BudgetMax: 20, BudgetWindowSec: 120, VerifyTimeoutSec: 10}
	return p
}

func connected(s health.State) bool {
	return s == health.ConnectedUnverified || s == health.Healthy
}

func (h *harness) waitConnected(timeout time.Duration) {
	h.t.Helper()
	h.waitFor("tunnel connected", timeout, func() bool {
		s := h.tunnel()
		return connected(s.Health.State) && s.InterfaceExists && len(s.Peers) == 1 && s.Peers[0].HandshakeAgeSec >= 0 && s.Peers[0].HandshakeAgeSec < 30
	})
}

func TestEndToEnd(t *testing.T) {
	h := setup(t)
	h.start()

	// Discovery: present, not modified, not controlled.
	st := h.tunnel()
	if st.Ownership != config.OwnershipDiscovered || st.InterfaceExists {
		t.Fatalf("unexpected initial state %+v", st)
	}
	if err := h.call(api.OpConnect, api.NameParams{Name: "wg0"}, nil); err == nil {
		t.Fatal("discovered tunnel must not be connectable")
	}

	// Baseline: without a tunnel or kill switch every source reaches nsB,
	// which proves the detector works.
	all := []leak{leakMarkedPort, leakMarkedV6, leakMarkedDNS, leakUnmarked4, leakUnmarked6, leakUnmarkedEP}
	for name, n := range emit(t, all...) {
		if n == 0 {
			t.Fatalf("baseline: no packets observed from %s; detector is not working", name)
		}
	}

	if err := h.call(api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: testPolicy()}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.call(api.OpConnect, api.NameParams{Name: "wg0"}, nil); err != nil {
		t.Fatal(err)
	}
	h.waitConnected(30 * time.Second)
	st = h.tunnel()
	if st.RxBytes == 0 || st.TxBytes == 0 {
		t.Fatalf("runtime counters not reported: %+v", st)
	}
	t.Logf("connected: %s; rx=%d tx=%d", st.Health.Reason, st.RxBytes, st.TxBytes)

	// Throughput: keepalives (every 5 s) must yield valid, small rates.
	time.Sleep(7 * time.Second)
	var m api.MetricsResult
	if err := h.call(api.OpMetrics, api.MetricsParams{Name: "wg0", WindowSec: 30}, &m); err != nil {
		t.Fatal(err)
	}
	var peak float64
	valid := 0
	for _, p := range m.Live {
		if p.Valid {
			valid++
			if p.TxRate > peak {
				peak = p.TxRate
			}
		}
	}
	if valid < 3 || peak <= 0 || peak > 10000 {
		t.Fatalf("implausible live metrics: %d valid samples, peak tx %.1f B/s", valid, peak)
	}
	t.Logf("%d valid samples, peak tx rate %.1f B/s", valid, peak)

	t.Run("killswitch", func(t *testing.T) { killSwitchScenarios(t, h) })
}

func killSwitchScenarios(t *testing.T, h *harness) {
	var ks api.KillSwitchStatus
	pol := config.KillSwitchPolicy{Enabled: true, Tunnel: "wg0", Mode: config.KillSwitchFullTunnel, AllowDHCP: true}
	if err := h.call(api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: pol}, &ks); err != nil {
		t.Fatal(err)
	}
	if ks.Status.State != firewall.StateEnforced || !ks.Status.MarkRestricted {
		t.Fatalf("kill switch not enforced: %+v", ks.Status)
	}

	// assertBlocked checks traffic that routing would send out of the
	// physical interface. Marked sources bypass policy routing, so they
	// test the firewall directly, including that the endpoint exception is
	// restricted to the exact endpoint address, port and family.
	assertBlocked := func(stage string, ls ...leak) {
		t.Helper()
		ls = append([]leak{leakMarkedPort, leakMarkedV6, leakMarkedDNS}, ls...)
		for name, n := range emit(t, ls...) {
			if n != 0 {
				t.Fatalf("%s: %d packets from %s leaked via the physical interface", stage, n, name)
			}
		}
	}
	assertBlocked("enforced", leakUnmarkedEP)
	h.waitConnected(20 * time.Second)

	// Outage + automatic recovery while the kill switch stays enforced.
	mustNS(t, nsB, "ip", "link", "set", "wgs", "down")
	h.waitFor("recovery to start", 90*time.Second, func() bool {
		s := h.tunnel()
		return s.Recovery.Attempt > 0 || s.Health.State == health.Recovering
	})
	assertBlocked("during outage")
	mustNS(t, nsB, "ip", "link", "set", "wgs", "up")
	h.waitConnected(60 * time.Second)
	if h.ks().Status.State != firewall.StateEnforced {
		t.Fatal("kill switch not enforced after recovery")
	}

	// Interface removal: still blocked; the managed tunnel is brought back.
	mustNS(t, nsA, "ip", "link", "del", "wg0")
	assertBlocked("interface removed", leakUnmarked4, leakUnmarked6, leakUnmarkedEP)
	h.waitConnected(60 * time.Second)

	// Daemon crash: rules persist without the daemon.
	h.stop(syscall.SIGKILL)
	if !tableExists() {
		t.Fatal("kill switch removed by daemon crash")
	}
	assertBlocked("daemon killed")
	h.start()
	h.waitFor("kill switch re-verified", 20*time.Second, func() bool { return h.ks().Status.State == firewall.StateEnforced })
	h.waitConnected(30 * time.Second)

	// External tampering: a deleted table is reinstalled.
	mustNS(t, nsA, "nft", "delete", "table", "inet", firewall.TableName)
	h.waitFor("kill switch reinstalled", 20*time.Second, tableExists)
	assertBlocked("after reconcile")

	// A competing accept-all table does not override our drop.
	mustNS(t, nsA, "nft", "add table inet competitor; add chain inet competitor out { type filter hook output priority -400; policy accept; }; add rule inet competitor out accept")
	assertBlocked("competing accept table")
	mustNS(t, nsA, "nft", "delete", "table", "inet", "competitor")

	// Route change: without wg-quick's policy routing, unmarked traffic is
	// routed to the physical interface, where it must be dropped.
	inNS(nsA, "ip", "-4", "rule", "del", "not", "fwmark", "51820", "table", "51820")
	inNS(nsA, "ip", "-6", "rule", "del", "not", "fwmark", "51820", "table", "51820")
	assertBlocked("policy routing removed", leakUnmarked4, leakUnmarked6, leakUnmarkedEP)
	inNS(nsA, "ip", "-4", "rule", "add", "not", "fwmark", "51820", "table", "51820")
	inNS(nsA, "ip", "-6", "rule", "add", "not", "fwmark", "51820", "table", "51820")

	// Graceful stop keeps protection; boot restore re-applies it.
	h.stop(syscall.SIGTERM)
	if !tableExists() {
		t.Fatal("kill switch removed on daemon stop")
	}
	mustNS(t, nsA, "nft", "delete", "table", "inet", firewall.TableName) // simulate reboot
	sh(t, append([]string{"ip"}, h.args("killswitch-restore")...)...)
	if !tableExists() {
		t.Fatal("boot restore did not apply the kill switch")
	}
	assertBlocked("after boot restore")

	// Disabling through the API restores normal connectivity.
	h.start()
	pol.Enabled = false
	if err := h.call(api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: pol}, &ks); err != nil {
		t.Fatal(err)
	}
	if ks.Status.State != firewall.StateDisabled || tableExists() {
		t.Fatalf("disable failed: %+v", ks.Status)
	}
	for name, n := range emit(t, leakMarkedPort, leakMarkedV6) {
		if n == 0 {
			t.Fatalf("connectivity (%s) not restored after disabling the kill switch", name)
		}
	}

	// Manual disconnect: no automatic reconnect.
	if err := h.call(api.OpDisconnect, api.NameParams{Name: "wg0"}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Second)
	s := h.tunnel()
	if s.InterfaceExists || s.Health.State != health.Disconnected {
		t.Fatalf("tunnel came back after manual disconnect: %+v", s.Health)
	}

	// Emergency disable removes any leftover table (re-enable first).
	pol.Enabled = true
	if err := h.call(api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: pol}, nil); err != nil {
		t.Fatal(err)
	}
	h.stop(syscall.SIGTERM)
	if !tableExists() {
		t.Fatal("expected table before emergency disable")
	}
	assertBlocked("enabled while disconnected", leakUnmarked4, leakUnmarked6, leakUnmarkedEP)
	sh(t, append([]string{"ip"}, h.args("killswitch-disable")...)...)
	if tableExists() {
		t.Fatal("emergency disable left the table")
	}
}
