package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
)

func sample(now time.Time) pollResult {
	managed := config.DefaultTunnelPolicy()
	managed.Ownership = config.OwnershipManaged
	up := now.Add(-time.Minute)
	return pollResult{
		at:   now,
		ping: &api.PingResult{Role: api.RoleOperator, DaemonVersion: "test", OperatorGroup: "wgm", Backend: "wg-quick"},
		list: &api.TunnelList{ConfigDir: "/etc/wireguard", Tunnels: []api.TunnelStatus{
			{Name: "wg0", Ownership: config.OwnershipManaged, Policy: managed, Manageable: true, ConfigPresent: true,
				InterfaceExists: true, InterfaceUp: true, IsWireGuard: true, Intent: health.IntentUp, UpSince: &up,
				RxBytes: 2048, TxBytes: 1024, RxRate: 512, TxRate: 256, RateValid: true, FullTunnelV4: true,
				Peers:  []api.PeerStatus{{PublicKey: "PUBKEY", HandshakeAgeSec: 12, AllowedIPs: []string{"0.0.0.0/0"}}},
				Health: health.Snapshot{State: health.Healthy, Reason: "connectivity probes succeeding", Since: now}},
			{Name: "home", Ownership: config.OwnershipDiscovered, Policy: config.DefaultTunnelPolicy(), Manageable: true,
				Health: health.Snapshot{State: health.Disconnected, Reason: "interface is not present", Since: now}},
		}},
		ks: &api.KillSwitchStatus{Policy: config.KillSwitchPolicy{Enabled: true, Tunnel: "wg0"}, Status: firewall.Status{State: firewall.StateDisabled, Reason: "nft failed"}},
	}
}

func TestDashboardRendersAndMarksStale(t *testing.T) {
	fa := test.NewTempApp(t)
	a := New(fa, "/nonexistent/control.sock")
	now := time.Now()
	a.apply(sample(now))

	if len(a.rows) != 2 {
		t.Fatalf("rows: %d", len(a.rows))
	}
	wg0 := a.rows["wg0"]
	if !strings.Contains(wg0.healthL.Text, "Healthy") || strings.Contains(wg0.healthL.Text, "stale") {
		t.Errorf("health label %q", wg0.healthL.Text)
	}
	for _, want := range []string{"512 B/s", "Handshake: 12s ago", "Total ↓ 2.0 KiB"} {
		if !strings.Contains(wg0.stats.Text, want) {
			t.Errorf("stats %q missing %q", wg0.stats.Text, want)
		}
	}
	if wg0.connectB.Disabled() == false || wg0.discoB.Disabled() {
		t.Error("running managed tunnel: connect should be disabled and disconnect enabled")
	}
	home := a.rows["home"]
	if !home.connectB.Disabled() || !home.discoB.Disabled() {
		t.Error("discovered tunnel must not be controllable")
	}
	if !strings.Contains(a.ksLabel.Text, "NOT enforced") {
		t.Errorf("kill switch label %q overstates protection", a.ksLabel.Text)
	}

	// Daemon goes away: data stays visible but is clearly stale, actions off.
	a.apply(pollResult{err: fmt.Errorf("%w: connect: connection refused", ipc.ErrUnavailable), at: now.Add(time.Second)})
	if !strings.Contains(a.banner.Text, "STALE") || !strings.Contains(a.banner.Text, "systemctl") {
		t.Errorf("banner %q", a.banner.Text)
	}
	if !strings.Contains(wg0.healthL.Text, "stale") || !wg0.discoB.Disabled() {
		t.Error("stale data must be marked and actions disabled")
	}
	if strings.Contains(wg0.stats.Text, "512 B/s") {
		t.Error("stale rates must not be shown as current")
	}

	// Reconnect restores normal display.
	a.apply(sample(time.Now()))
	if a.bannerBox.Visible() || strings.Contains(wg0.healthL.Text, "stale") {
		t.Error("banner should clear after reconnect")
	}

	// Removed tunnels disappear.
	r := sample(time.Now())
	r.list.Tunnels = r.list.Tunnels[:1]
	a.apply(r)
	if _, ok := a.rows["home"]; ok || len(a.list.Objects) != 1 {
		t.Error("removed tunnel still shown")
	}
}

func TestUnauthorisedUserGuidance(t *testing.T) {
	fa := test.NewTempApp(t)
	a := New(fa, "/nonexistent/control.sock")
	r := sample(time.Now())
	r.ping.Role = api.RoleNone
	a.apply(r)
	if !strings.Contains(a.banner.Text, "'wgm' group") {
		t.Errorf("banner %q", a.banner.Text)
	}
	if !a.rows["wg0"].discoB.Disabled() {
		t.Error("unauthorised user must not get enabled actions")
	}
}

func TestDetailWindowAndPolicyForm(t *testing.T) {
	fa := test.NewTempApp(t)
	a := New(fa, "/nonexistent/control.sock")
	r := sample(time.Now())
	a.apply(r)
	a.openDetails("wg0")
	d := a.details["wg0"]
	defer d.close()
	if !strings.Contains(d.peers.Text, "PUBKEY") || !strings.Contains(d.overview.Text, "Managed by WGM") {
		t.Errorf("detail text: %q / %q", d.peers.Text, d.overview.Text)
	}
	if strings.Contains(strings.ToLower(d.overview.Text+d.peers.Text), "private") {
		t.Error("detail view must not mention private keys")
	}
	p, err := d.form.read()
	if err != nil {
		t.Fatalf("loaded policy does not validate: %v", err)
	}
	if p.Ownership != config.OwnershipManaged || p.Health.IntervalSec != r.list.Tunnels[0].Policy.Health.IntervalSec {
		t.Errorf("form round trip: %+v", p)
	}
	d.form.interval.SetText("abc")
	if _, err := d.form.read(); err == nil {
		t.Error("non-numeric interval accepted")
	}
	d.form.interval.SetText("10")
	d.form.probes.SetText("icmp not-an-ip")
	if _, err := d.form.read(); err == nil {
		t.Error("bad probe accepted")
	}
	d.form.probes.SetText("icmp 10.8.0.1")
	d.form.ownership.SetSelected("Monitored (read-only)")
	d.form.autostart.SetChecked(true)
	if _, err := d.form.read(); err == nil {
		t.Error("autostart without management accepted")
	}

	// Graph data with an invalid sample renders without panicking.
	d.setMetrics(rangeLive, &api.MetricsResult{Interval: 1, Live: []api.MetricPoint{
		{RxRate: 10, Valid: true}, {Valid: false}, {RxRate: 30, TxRate: 5, Valid: true}, {RxRate: 20, Valid: true}}}, nil)
	if len(d.graph.series) != 2 || d.graph.Slots != liveWindow {
		t.Errorf("graph not populated: %+v", d.graph.series)
	}
	test.WidgetRenderer(d.graph).Refresh()
}

func TestKillSwitchWindowRequiresAdmin(t *testing.T) {
	fa := test.NewTempApp(t)
	a := New(fa, "/nonexistent/control.sock")
	r := sample(time.Now())
	a.apply(r)
	a.openKillSwitch()
	if !a.ksWin.apply.Disabled() {
		t.Error("operator must not be offered kill switch changes")
	}
	if len(a.ksWin.tunnel.Options) != 1 || a.ksWin.tunnel.Options[0] != "wg0" {
		t.Errorf("eligible tunnels %v", a.ksWin.tunnel.Options)
	}
	r.ping.Role = api.RoleAdmin
	a.apply(r)
	if a.ksWin.apply.Disabled() {
		t.Error("admin should be able to apply")
	}
	if !strings.Contains(a.ksWin.status.Text, "NOT enforced") {
		t.Errorf("status %q", a.ksWin.status.Text)
	}
}
