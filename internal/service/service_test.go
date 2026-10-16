package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/auth"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
	"github.com/cmerk2021/wgm/internal/tunnel"
)

const testConf = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32
DNS = 10.8.0.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 198.51.100.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

const peerKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeNet simulates kernel interfaces, peers and a remote network.
type fakeNet struct {
	mu        sync.Mutex
	clock     *fakeClock
	ifaces    map[string]*tunnel.Runtime
	reachable bool // peer answers handshakes and probes
	ups       int
	downs     int
	upErr     error
	owner     string
}

func (n *fakeNet) ListWireGuard(context.Context) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for k := range n.ifaces {
		out = append(out, k)
	}
	return out, nil
}

func (n *fakeNet) Read(_ context.Context, name string) (tunnel.Runtime, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	rt, ok := n.ifaces[name]
	if !ok {
		return tunnel.Runtime{Name: name}, nil
	}
	if n.reachable {
		// keepalives cause handshakes and traffic
		rt.Peers[0].LastHandshake = n.clock.Now().Add(-5 * time.Second)
		rt.Peers[0].RxBytes += 1000
		rt.Peers[0].TxBytes += 800
	} else {
		rt.Peers[0].TxBytes += 148
	}
	cp := *rt
	cp.Peers = append([]tunnel.PeerRuntime(nil), rt.Peers...)
	return cp, nil
}

func (n *fakeNet) Probe(_ context.Context, _ string, s config.ProbeSpec) health.ProbeResult {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.reachable {
		return health.ProbeResult{Probe: s.String(), OK: true, LatencyMs: 20, At: n.clock.Now()}
	}
	return health.ProbeResult{Probe: s.String(), OK: false, Detail: "timeout", At: n.clock.Now()}
}

func (n *fakeNet) Name() string { return "fake" }
func (n *fakeNet) Up(_ context.Context, name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ups++
	if n.upErr != nil {
		return n.upErr
	}
	n.ifaces[name] = &tunnel.Runtime{Name: name, Exists: true, Up: true, IsWireGuard: true, FwMark: 51820,
		Peers: []tunnel.PeerRuntime{{PublicKey: peerKey, Endpoint: "198.51.100.7:51820", PersistentKeepalive: 25 * time.Second}}}
	return nil
}
func (n *fakeNet) Down(_ context.Context, name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.downs++
	delete(n.ifaces, name)
	return nil
}
func (n *fakeNet) ExternalOwner(context.Context, string) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.owner, nil
}
func (n *fakeNet) UnderlayUp(context.Context, string) (bool, error) { return true, nil }

func (n *fakeNet) counts() (int, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ups, n.downs
}

type env struct {
	t      *testing.T
	dir    string
	clock  *fakeClock
	net    *fakeNet
	nft    *firewall.FakeNFT
	d      *Daemon
	admin  ipc.Caller
	oper   ipc.Caller
	store  *config.Store
	ctx    context.Context
	cancel context.CancelFunc
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	os.MkdirAll(wgDir, 0o700)
	if err := os.WriteFile(filepath.Join(wgDir, "wg0.conf"), []byte(testConf), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, clock: &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}}
	e.net = &fakeNet{clock: e.clock, ifaces: map[string]*tunnel.Runtime{}, reachable: true}
	e.nft = &firewall.FakeNFT{}
	e.admin = ipc.Caller{Peer: auth.Peer{UID: 0}, Role: api.RoleAdmin}
	e.oper = ipc.Caller{Peer: auth.Peer{UID: 1000}, Role: api.RoleOperator}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	t.Cleanup(e.cancel)
	e.start()
	return e
}

func (e *env) start() {
	store, _ := config.OpenStore(filepath.Join(e.dir, "etc-wgm", "policy.json"))
	e.store = store
	fw := firewall.NewManager(e.nft, filepath.Join(e.dir, "boot.nft"))
	fw.Now = e.clock.Now
	d, err := New(Options{
		ConfigDir: filepath.Join(e.dir, "wireguard"), Store: store, StatePath: filepath.Join(e.dir, "state.json"),
		Reader: e.net, Prober: e.net, Backend: e.net, Firewall: fw, Clock: e.clock, Synchronous: true,
		OperatorGroup: "wgm", AdminGroup: "wheel", Version: "test",
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.d = d
	d.Startup(e.ctx)
}

func (e *env) call(c ipc.Caller, op string, params any, out any) *api.Error {
	raw, _ := json.Marshal(params)
	res, aerr := e.d.Handle(e.ctx, c, op, raw)
	if aerr != nil {
		return aerr
	}
	if out != nil {
		b, _ := json.Marshal(res)
		json.Unmarshal(b, out)
	}
	return nil
}

// run advances the clock in 1s steps, ticking each time.
func (e *env) run(d time.Duration) {
	for i := 0; i < int(d/time.Second); i++ {
		e.clock.Add(time.Second)
		e.d.Tick(e.ctx)
	}
}

func (e *env) status() api.TunnelStatus {
	st, ok := e.d.Get("wg0")
	if !ok {
		e.t.Fatal("wg0 missing")
	}
	return st
}

func (e *env) manage(probes bool) {
	pol := config.DefaultTunnelPolicy()
	pol.Ownership = config.OwnershipManaged
	pol.Recovery.JitterFraction = 0
	if probes {
		pol.Health.Probes = []config.ProbeSpec{{Type: config.ProbeICMP, Target: "10.8.0.1"}}
	}
	if err := e.call(e.admin, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: pol}, nil); err != nil {
		e.t.Fatal(err)
	}
}

func TestDiscoveryIsNonDestructive(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.dir, "wireguard", "wg0.conf")
	before, _ := os.Stat(path)
	e.run(3 * time.Second)
	st := e.status()
	if st.Ownership != config.OwnershipDiscovered || st.InterfaceExists || !st.ConfigPresent || !st.FullTunnelV4 {
		t.Fatalf("%+v", st)
	}
	if st.Health.State != health.Disconnected {
		t.Fatalf("state %s", st.Health.State)
	}
	if ups, downs := e.net.counts(); ups+downs != 0 {
		t.Fatal("discovery must not touch tunnels")
	}
	after, _ := os.Stat(path)
	data, _ := os.ReadFile(path)
	if !after.ModTime().Equal(before.ModTime()) || string(data) != testConf {
		t.Fatal("configuration file was modified")
	}
	// No private key anywhere in the API output.
	b, _ := json.Marshal(e.d.List())
	d, _ := json.Marshal(e.d.Diagnostics(e.ctx))
	if strings.Contains(string(b)+string(d), "yAnz5TF") {
		t.Fatal("private key leaked")
	}
}

func TestDiscoveredTunnelCannotBeControlled(t *testing.T) {
	e := newEnv(t)
	if err := e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil); err == nil || err.Code != api.CodeForbidden {
		t.Fatalf("got %v", err)
	}
	pol := config.DefaultTunnelPolicy()
	pol.Ownership = config.OwnershipManaged
	if err := e.call(e.oper, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: pol}, nil); err == nil || err.Code != api.CodeForbidden {
		t.Fatalf("operator must not change ownership: %v", err)
	}
	// Operators may tune health settings without changing ownership.
	pol = config.DefaultTunnelPolicy()
	pol.Health.FailureThreshold = 5
	if err := e.call(e.oper, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: pol}, nil); err != nil {
		t.Fatal(err)
	}
	if ups, _ := e.net.counts(); ups != 0 {
		t.Fatal("unexpected activation")
	}
}

func TestConnectHealthyAndManualDisconnect(t *testing.T) {
	e := newEnv(t)
	e.manage(true)
	if err := e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil); err != nil {
		t.Fatal(err)
	}
	e.run(40 * time.Second)
	st := e.status()
	if st.Health.State != health.Healthy {
		t.Fatalf("want healthy, got %s (%s)", st.Health.State, st.Health.Reason)
	}
	if !st.RateValid || st.RxRate <= 0 || st.Peers[0].HandshakeAgeSec < 0 {
		t.Fatalf("metrics: %+v", st)
	}
	if err := e.call(e.oper, api.OpDisconnect, api.NameParams{Name: "wg0"}, nil); err != nil {
		t.Fatal(err)
	}
	e.run(30 * time.Minute)
	st = e.status()
	if st.Health.State != health.Disconnected || st.Intent != health.IntentDown {
		t.Fatalf("got %s intent %s", st.Health.State, st.Intent)
	}
	if ups, _ := e.net.counts(); ups != 1 {
		t.Fatalf("manual disconnect caused %d reconnects", ups-1)
	}
}

func TestRecoveryAfterSimulatedOutage(t *testing.T) {
	e := newEnv(t)
	e.manage(true)
	e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil)
	e.run(40 * time.Second)
	// Outage: peer stops answering; handshake goes stale.
	e.net.mu.Lock()
	e.net.reachable = false
	e.net.mu.Unlock()
	e.run(4 * time.Minute)
	ups, downs := e.net.counts()
	if downs == 0 || ups < 2 {
		t.Fatalf("expected a restart, ups=%d downs=%d", ups, downs)
	}
	st := e.status()
	if st.Health.State == health.Healthy {
		t.Fatal("must not be healthy during outage")
	}
	// Network returns: verify recovery by fresh checks.
	e.net.mu.Lock()
	e.net.reachable = true
	e.net.mu.Unlock()
	e.run(2 * time.Minute)
	st = e.status()
	if st.Health.State != health.Healthy || st.Recovery.Active {
		t.Fatalf("want healthy & idle recovery, got %s %+v", st.Health.State, st.Recovery)
	}
}

func TestRecoveryIsBounded(t *testing.T) {
	e := newEnv(t)
	e.manage(true)
	e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil)
	e.run(40 * time.Second)
	e.net.mu.Lock()
	e.net.reachable = false
	e.net.upErr = errors.New("endpoint unreachable")
	delete(e.net.ifaces, "wg0") // interface vanished
	e.net.mu.Unlock()
	e.run(3 * time.Hour)
	ups, _ := e.net.counts()
	max := config.DefaultRecoveryPolicy().MaxAttempts
	if ups-1 > max {
		t.Fatalf("recovery attempts %d exceed max %d", ups-1, max)
	}
	st := e.status()
	if st.Health.State != health.Error || !st.Recovery.Exhausted {
		t.Fatalf("want error/exhausted, got %s %+v", st.Health.State, st.Recovery)
	}
}

func TestMonitoredTunnelIsNeverRepaired(t *testing.T) {
	e := newEnv(t)
	e.net.Up(e.ctx, "wg0") // started externally
	e.net.mu.Lock()
	e.net.ups = 0
	e.net.mu.Unlock()
	pol := config.DefaultTunnelPolicy()
	pol.Ownership = config.OwnershipMonitored
	pol.Health.Probes = []config.ProbeSpec{{Type: config.ProbeICMP, Target: "10.8.0.1"}}
	if err := e.call(e.admin, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: pol}, nil); err != nil {
		t.Fatal(err)
	}
	e.net.mu.Lock()
	e.net.reachable = false
	e.net.mu.Unlock()
	e.run(30 * time.Minute)
	if ups, downs := e.net.counts(); ups+downs != 0 {
		t.Fatalf("monitored tunnel was modified: ups=%d downs=%d", ups, downs)
	}
	if st := e.status(); st.Health.State != health.Degraded {
		t.Fatalf("want degraded, got %s", st.Health.State)
	}
}

func TestExternalOwnerBlocksManagement(t *testing.T) {
	e := newEnv(t)
	e.net.owner = "systemd unit wg-quick@wg0.service"
	e.run(time.Second)
	e.d.mu.Lock()
	e.d.tunnels["wg0"].ownerAt = time.Time{}
	e.d.mu.Unlock()
	e.run(time.Second)
	pol := config.DefaultTunnelPolicy()
	pol.Ownership = config.OwnershipManaged
	if err := e.call(e.admin, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: pol}, nil); err == nil || err.Code != api.CodeConflict {
		t.Fatalf("got %v", err)
	}
}

func TestKillSwitchLifecycle(t *testing.T) {
	e := newEnv(t)
	e.manage(false)
	e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil)
	e.run(5 * time.Second)
	var ks api.KillSwitchStatus
	p := config.KillSwitchPolicy{Enabled: true, Tunnel: "wg0", Mode: config.KillSwitchFullTunnel, AllowDHCP: true}
	if err := e.call(e.admin, api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: p}, &ks); err != nil {
		t.Fatal(err)
	}
	if ks.Status.State != firewall.StateEnforced || !ks.Status.MarkRestricted || len(ks.Status.Endpoints) != 1 {
		t.Fatalf("%+v", ks)
	}
	if !strings.Contains(e.nft.Table, "198.51.100.7") || !strings.Contains(e.nft.Table, "0x0000ca6c") {
		t.Fatal(e.nft.Table)
	}
	// Disconnect keeps protection.
	e.call(e.oper, api.OpDisconnect, api.NameParams{Name: "wg0"}, nil)
	e.run(30 * time.Second)
	if !e.nft.Present() || e.d.KillSwitch().Status.State != firewall.StateEnforced {
		t.Fatal("kill switch must remain enforced after disconnect")
	}
	// External deletion is detected and repaired.
	e.nft.DeleteTable(e.ctx)
	e.run(6 * time.Second)
	if !e.nft.Present() {
		t.Fatal("kill switch not reinstalled after external removal")
	}
	// Daemon restart (crash) keeps the table; new daemon re-adopts it.
	e.start()
	e.run(6 * time.Second)
	if !e.nft.Present() || e.d.KillSwitch().Status.State != firewall.StateEnforced {
		t.Fatalf("after restart: %+v", e.d.KillSwitch().Status)
	}
	// Disable removes it.
	p.Enabled = false
	if err := e.call(e.admin, api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: p}, &ks); err != nil {
		t.Fatal(err)
	}
	if e.nft.Present() || ks.Status.State != firewall.StateDisabled {
		t.Fatalf("%+v", ks)
	}
}

func TestKillSwitchRejectsSplitTunnel(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(filepath.Join(e.dir, "wireguard", "split.conf"), []byte(strings.Replace(testConf, "0.0.0.0/0, ::/0", "10.8.0.0/24", 1)), 0o600)
	e.d.Rescan()
	err := e.call(e.admin, api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: config.KillSwitchPolicy{Enabled: true, Tunnel: "split", Mode: config.KillSwitchFullTunnel}}, nil)
	if err == nil || err.Code != api.CodeBadRequest {
		t.Fatalf("got %v", err)
	}
	if e.nft.Present() {
		t.Fatal("no rules expected")
	}
}

func TestCorruptPolicyNeverRemovesKillSwitch(t *testing.T) {
	e := newEnv(t)
	e.call(e.admin, api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: config.KillSwitchPolicy{Enabled: true, Tunnel: "wg0", Mode: config.KillSwitchFullTunnel}}, nil)
	if !e.nft.Present() {
		t.Fatal("not installed")
	}
	os.WriteFile(filepath.Join(e.dir, "etc-wgm", "policy.json"), []byte("{garbage"), 0o600)
	e.start()
	e.run(10 * time.Second)
	if !e.nft.Present() {
		t.Fatal("corrupt policy removed the kill switch")
	}
}

func TestIntentSurvivesRestartAndAutostart(t *testing.T) {
	e := newEnv(t)
	pol := config.DefaultTunnelPolicy()
	pol.Ownership = config.OwnershipManaged
	pol.Autostart = true
	if err := e.call(e.admin, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: "wg0", Policy: pol}, nil); err != nil {
		t.Fatal(err)
	}
	// Simulated boot: daemon starts, autostart connects.
	e.start()
	if ups, _ := e.net.counts(); ups != 1 {
		t.Fatalf("autostart ups=%d", ups)
	}
	e.call(e.oper, api.OpDisconnect, api.NameParams{Name: "wg0"}, nil)
	// Restart: manual disconnect is remembered, no autostart.
	e.start()
	e.run(time.Minute)
	if ups, _ := e.net.counts(); ups != 1 {
		t.Fatalf("autostart ignored manual disconnect: ups=%d", ups)
	}
}

func TestConfigChangeDetected(t *testing.T) {
	e := newEnv(t)
	e.manage(false)
	e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil)
	e.run(2 * time.Second)
	os.WriteFile(filepath.Join(e.dir, "wireguard", "wg0.conf"), []byte(strings.Replace(testConf, "198.51.100.7", "198.51.100.8", 1)), 0o600)
	e.run(6 * time.Second)
	if !e.status().ConfigChanged {
		t.Fatal("config change not reported")
	}
	evs := e.d.Events.Query("wg0", 0, 100)
	found := false
	for _, ev := range evs {
		if strings.Contains(ev.Message, "reconnect to apply") {
			found = true
		}
	}
	if !found {
		t.Fatal("no event")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	e := newEnv(t)
	e.manage(true)
	e.call(e.oper, api.OpConnect, api.NameParams{Name: "wg0"}, nil)
	e.run(30 * time.Second)
	var m api.MetricsResult
	if err := e.call(e.oper, api.OpMetrics, api.MetricsParams{Name: "wg0", WindowSec: 20}, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Live) < 19 || len(m.Latency) == 0 {
		t.Fatalf("live=%d latency=%d", len(m.Live), len(m.Latency))
	}
	if err := e.call(e.oper, api.OpMetrics, api.MetricsParams{Name: "wg0", WindowSec: 99999}, nil); err == nil {
		t.Fatal("window not validated")
	}
	if err := e.call(e.oper, api.OpGetTunnel, api.NameParams{Name: "../../etc/passwd"}, nil); err == nil || err.Code != api.CodeBadRequest {
		t.Fatal("name not validated")
	}
}
