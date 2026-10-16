package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type fakeNFT = FakeNFT

func spec() Spec {
	return Spec{Interface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:51820")}, FwMark: 0xca6c, AllowDHCP: true}
}

func TestRenderValidation(t *testing.T) {
	bad := []Spec{
		{Interface: "wg0"},
		{Interface: "lo", Endpoints: spec().Endpoints},
		{Interface: `wg0" accept; flush ruleset; "`, Endpoints: spec().Endpoints},
		{Interface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:51820")}},
		{Interface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:0")}},
		{Interface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[ff02::1]:51820")}},
	}
	for _, s := range bad {
		if _, err := Render(s); err == nil {
			t.Errorf("expected error for %+v", s)
		}
	}
}

func TestRenderContent(t *testing.T) {
	rs, err := Render(spec())
	if err != nil {
		t.Fatal(err)
	}
	must := []string{
		"table inet wgm_killswitch\ndelete table inet wgm_killswitch\n",
		"type filter hook output priority filter; policy drop;",
		"type filter hook forward priority filter; policy drop;",
		`oifname "wg0" accept`,
		"meta mark 0x0000ca6c ip daddr 203.0.113.10 udp dport 51820 accept",
		"th dport { 53, 853 } counter drop",
		`comment "` + rs.Marker + `"`,
	}
	for _, m := range must {
		if !strings.Contains(rs.Text, m) {
			t.Errorf("ruleset missing %q:\n%s", m, rs.Text)
		}
	}
	for _, forbidden := range []string{"flush", "ruleset", "ip daddr { 10.0.0.0/8", "policy accept"} {
		if strings.Contains(rs.Text, forbidden) {
			t.Errorf("ruleset contains %q", forbidden)
		}
	}
	// Endpoint accept must be mark-restricted, never a bare address.
	if regexp.MustCompile(`(?m)^\s+ip daddr 203`).MatchString(rs.Text) {
		t.Error("endpoint exception without mark")
	}
	s := spec()
	s.FwMark = 0
	rs2, _ := Render(s)
	if !strings.Contains(rs2.Text, "\t\tip daddr 203.0.113.10 udp dport 51820 accept") || rs2.Hash == rs.Hash {
		t.Error("unmarked variant should differ and use address+port")
	}
	s = spec()
	s.AllowLAN = true
	rs3, _ := Render(s)
	dns := strings.Index(rs3.Text, "th dport { 53, 853 } counter drop")
	lan := strings.Index(rs3.Text, "ip daddr { 10.0.0.0/8")
	if dns < 0 || lan < 0 || dns > lan {
		t.Error("DNS drop must precede LAN accept")
	}
	// Deterministic.
	again, _ := Render(spec())
	if again.Text != rs.Text {
		t.Error("render not deterministic")
	}
}

func TestVerify(t *testing.T) {
	f := &fakeNFT{}
	rs, _ := Render(spec())
	f.Apply(context.Background(), rs.Text)
	data, _, _ := f.ListTable(context.Background())
	if ok, why := Verify(data, rs); !ok {
		t.Fatalf("verify failed: %s", why)
	}
	other, _ := Render(Spec{Interface: "wg1", Endpoints: spec().Endpoints})
	if ok, _ := Verify(data, other); ok {
		t.Fatal("verify must detect a different policy")
	}
	// Policy changed to accept.
	f.Table = strings.Replace(rs.Text, "hook output priority filter; policy drop;", "hook output priority filter; policy accept;", 1)
	data, _, _ = f.ListTable(context.Background())
	if ok, why := Verify(data, rs); ok || !strings.Contains(why, "policy=accept") {
		t.Fatalf("accept policy not detected: %v %s", ok, why)
	}
	// Extra rule inserted (e.g. someone added an accept).
	f.Table = strings.Replace(rs.Text, `oifname "lo" accept`, "oifname \"lo\" accept\n\t\taccept", 1)
	data, _, _ = f.ListTable(context.Background())
	if ok, _ := Verify(data, rs); ok {
		t.Fatal("extra rule not detected")
	}
}

func TestManagerLifecycle(t *testing.T) {
	ctx := context.Background()
	f := &fakeNFT{}
	boot := filepath.Join(t.TempDir(), "killswitch.nft")
	m := NewManager(f, boot)
	var transitions []State
	m.OnChange = func(_, n Status) { transitions = append(transitions, n.State) }
	if m.Status().State != StateDisabled {
		t.Fatal("initial state")
	}
	if err := m.Enable(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if st.State != StateEnforced || !st.MarkRestricted || st.LastVerified.IsZero() {
		t.Fatalf("%+v", st)
	}
	if len(transitions) < 2 || transitions[0] != StateInstalling || transitions[len(transitions)-1] != StateEnforced {
		t.Fatalf("transitions %v", transitions)
	}
	if data, err := os.ReadFile(boot); err != nil || !strings.Contains(string(data), TableName) {
		t.Fatal("boot file not written")
	}

	// Simulated daemon crash: a new manager instance must not remove rules
	// and must recognise them as enforced after reconciliation.
	m2 := NewManager(f, boot)
	sp := spec()
	if err := m2.Reconcile(ctx, &sp); err != nil {
		t.Fatal(err)
	}
	if m2.Status().State != StateEnforced || f.Table == "" {
		t.Fatalf("after restart: %+v", m2.Status())
	}

	// External removal (e.g. `nft flush ruleset`): reconcile reinstalls.
	f.Table = ""
	before := f.ApplyCount
	transitions = nil
	if err := m.Reconcile(ctx, &sp); err != nil {
		t.Fatal(err)
	}
	if f.ApplyCount != before+1 || m.Status().State != StateEnforced || transitions[0] != StateError {
		t.Fatalf("reinstall: %+v %v", m.Status(), transitions)
	}

	// Failed update keeps old rules and reports error.
	old := f.Table
	f.ApplyErr = errors.New("netlink: Error: Could not process rule")
	sp2 := spec()
	sp2.AllowLAN = true
	if err := m.Reconcile(ctx, &sp2); err == nil {
		t.Fatal("expected error")
	}
	if f.Table != old || m.Status().State != StateError {
		t.Fatalf("failed apply must leave rules: state %s", m.Status().State)
	}
	f.ApplyErr = nil

	// Invalid desired spec must not remove protection.
	bad := Spec{Interface: "wg0"}
	if err := m.Reconcile(ctx, &bad); err == nil || f.Table != old {
		t.Fatal("invalid spec must keep existing rules")
	}

	// Disable failure keeps reporting error.
	f.DeleteErr = errors.New("boom")
	if err := m.Disable(ctx); err == nil || m.Status().State != StateError {
		t.Fatal("disable failure must surface")
	}
	f.DeleteErr = nil
	if err := m.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if f.Table != "" || m.Status().State != StateDisabled {
		t.Fatalf("disable: %+v", m.Status())
	}
	if _, err := os.Stat(boot); !os.IsNotExist(err) {
		t.Fatal("boot file should be removed on disable")
	}
}

func TestManagerUnavailable(t *testing.T) {
	f := &fakeNFT{Unavail: errors.New("nft is not installed")}
	m := NewManager(f, "")
	m.Now = func() time.Time { return time.Unix(0, 0) }
	if err := m.Enable(context.Background(), spec()); err == nil {
		t.Fatal("expected error")
	}
	if m.Status().State != StateUnavailable {
		t.Fatalf("state = %s; must never claim enforcement", m.Status().State)
	}
}

func TestCheckOnlyWGMTable(t *testing.T) {
	rs, _ := Render(spec())
	if err := checkOnlyWGMTable(rs.Text); err != nil {
		t.Fatal(err)
	}
	for _, evil := range []string{"flush ruleset\n", "table inet firewalld {\n}\n", "delete table inet firewalld\n", "include \"/tmp/x\"\n"} {
		if err := checkOnlyWGMTable(rs.Text + evil); err == nil {
			t.Errorf("accepted %q", evil)
		}
	}
}
