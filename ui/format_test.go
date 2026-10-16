package ui

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
	"github.com/cmerk2021/wgm/internal/recovery"
)

func TestFormatBytesAndRate(t *testing.T) {
	cases := map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"}
	for in, want := range cases {
		if got := FormatBytes(in); got != want {
			t.Errorf("FormatBytes(%d)=%q want %q", in, got, want)
		}
	}
	if FormatRate(100, false) != "—" || FormatRate(-1, true) != "—" || FormatRate(math.NaN(), true) != "—" {
		t.Error("invalid rates must not render as numbers")
	}
	if got := FormatRate(0, true); got != "0 B/s" {
		t.Errorf("zero rate: %q", got)
	}
	if got := FormatRate(2.5*1024*1024, true); got != "2.5 MiB/s" {
		t.Errorf("got %q", got)
	}
}

func TestFormatAge(t *testing.T) {
	if FormatAge(-1) != "never" {
		t.Error("negative age must be never")
	}
	cases := map[float64]string{5: "5s ago", 125: "2m 05s ago", 7300: "2h 01m ago", 90000: "1d 01h ago"}
	for in, want := range cases {
		if got := FormatAge(in); got != want {
			t.Errorf("FormatAge(%v)=%q want %q", in, got, want)
		}
	}
}

func TestProbesRoundTrip(t *testing.T) {
	text := "icmp 10.8.0.1\ntcp [fd00::1]:443 timeout=1500\n# comment\n\ndns 10.8.0.1 example.com\n"
	ps, err := ParseProbes(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || ps[1].Port != 443 || ps[1].Target != "fd00::1" || ps[1].TimeoutMs != 1500 || ps[2].Query != "example.com" {
		t.Fatalf("parsed %+v", ps)
	}
	again, err := ParseProbes(FormatProbes(ps))
	if err != nil || fmt.Sprint(again) != fmt.Sprint(ps) {
		t.Fatalf("round trip: %v %+v", err, again)
	}
}

func TestProbesRejected(t *testing.T) {
	bad := []string{
		"ping 10.0.0.1",
		"icmp example.com",
		"tcp 10.0.0.1",
		"dns 10.0.0.1",
		"icmp 10.0.0.1; rm -rf /",
		"icmp 10.0.0.1 timeout=abc",
		"tcp 10.0.0.1:0",
	}
	for _, b := range bad {
		if _, err := ParseProbes(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
	many := strings.Repeat("icmp 10.0.0.1\n", config.MaxProbes+1)
	if _, err := ParseProbes(many); err == nil {
		t.Error("too many probes accepted")
	}
}

func TestKillSwitchLabelNeverOverstates(t *testing.T) {
	ks := api.KillSwitchStatus{Policy: config.KillSwitchPolicy{Enabled: true, Tunnel: "wg0"}, Status: firewall.Status{State: firewall.StateDisabled}}
	if l := KillSwitchLabel(ks); !strings.Contains(l, "NOT enforced") || KillSwitchSeverity(ks) != SevBad {
		t.Errorf("requested-but-not-enforced shown as %q", l)
	}
	ks.Status.State = firewall.StateError
	if KillSwitchSeverity(ks) != SevBad {
		t.Error("error must be bad")
	}
	ks.Status.State = firewall.StateUnavailable
	if KillSwitchSeverity(ks) != SevBad {
		t.Error("unavailable while requested must be bad")
	}
	ks.Status = firewall.Status{State: firewall.StateEnforced, Tunnel: "wg0"}
	if KillSwitchLabel(ks) != "Enforced for wg0" || KillSwitchSeverity(ks) != SevGood {
		t.Error("enforced")
	}
}

func TestHealthSeverity(t *testing.T) {
	if HealthSeverity(health.ConnectedUnverified) == SevGood {
		t.Error("unverified must not look healthy")
	}
	if HealthSeverity(health.Healthy) != SevGood || HealthSeverity(health.Degraded) != SevBad {
		t.Error("severity mapping")
	}
}

func TestRecoverySummary(t *testing.T) {
	now := time.Unix(1000, 0)
	if RecoverySummary(recovery.Status{}, now) != "" {
		t.Error("idle should be empty")
	}
	s := RecoverySummary(recovery.Status{Active: true, Attempt: 2, MaxAttempts: 5, Classification: recovery.ClassHandshake,
		LastAction: recovery.ActionRestart, NextAttemptAt: now.Add(30 * time.Second)}, now)
	for _, want := range []string{"attempt 2/5", "handshake failure", "restart", "next in 30s"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q missing %q", s, want)
		}
	}
	if s := RecoverySummary(recovery.Status{Exhausted: true, Attempt: 5, LastResult: "no handshake"}, now); !strings.Contains(s, "exhausted") {
		t.Error(s)
	}
}

func TestExplainError(t *testing.T) {
	sock := "/run/wgmd/control.sock"
	perm := fmt.Errorf("%w: dial unix %s: connect: permission denied", ipc.ErrUnavailable, sock)
	if !strings.Contains(ExplainError(perm, sock), "usermod -aG wgm") {
		t.Error("permission hint missing")
	}
	gone := fmt.Errorf("%w: dial unix %s: connect: no such file or directory", ipc.ErrUnavailable, sock)
	if !strings.Contains(ExplainError(gone, sock), "systemctl") {
		t.Error("start hint missing")
	}
	if !strings.Contains(ExplainError(api.Errf(api.CodeForbidden, "requires admin"), sock), "Not permitted") {
		t.Error("forbidden")
	}
	if ExplainError(errors.New("x"), sock) != "x" || ExplainError(nil, sock) != "" {
		t.Error("passthrough")
	}
}

func TestStaleness(t *testing.T) {
	now := time.Unix(100, 0)
	if !IsStale(time.Time{}, now, time.Second) || !IsStale(now.Add(-5*time.Second), now, 4*time.Second) || IsStale(now.Add(-time.Second), now, 4*time.Second) {
		t.Error("staleness")
	}
}

func TestNiceCeil(t *testing.T) {
	cases := map[float64]float64{0: 1, 0.5: 1, 3: 5, 10: 10, 11: 20, 150: 200, 999: 1000, 4500: 5000}
	for in, want := range cases {
		if got := NiceCeil(in); math.Abs(got-want) > 1e-9 {
			t.Errorf("NiceCeil(%v)=%v want %v", in, got, want)
		}
	}
}

func TestSegmentsGapsAndScaling(t *testing.T) {
	vals := []float64{0, 50, 100, 200, 25}
	ok := []bool{true, true, false, true, true}
	segs := Segments(vals, ok, 5, 100)
	// 0-1 drawn, 1-2 and 2-3 skipped (invalid), 3-4 drawn.
	if len(segs) != 2 {
		t.Fatalf("segments %+v", segs)
	}
	if segs[0].X1 != 0 || segs[0].Y2 != 0.5 {
		t.Errorf("first %+v", segs[0])
	}
	if segs[1].Y1 != 1 { // clamped to max
		t.Errorf("clamp %+v", segs[1])
	}
	// Fewer samples than slots are right-aligned.
	segs = Segments([]float64{1, 1}, []bool{true, true}, 11, 1)
	if len(segs) != 1 || segs[0].X2 != 1 || segs[0].X1 != 0.9 {
		t.Errorf("alignment %+v", segs)
	}
	if Segments(vals, ok, 1, 100) != nil || Segments(vals, ok, 5, 0) != nil {
		t.Error("degenerate input")
	}
	// More samples than slots keep the newest.
	segs = Segments([]float64{9, 9, 9, 1, 1}, []bool{true, true, true, true, true}, 2, 10)
	if len(segs) != 1 || segs[0].Y1 != 0.1 {
		t.Errorf("trim %+v", segs)
	}
}

func TestNewestHandshake(t *testing.T) {
	ts := api.TunnelStatus{Peers: []api.PeerStatus{{HandshakeAgeSec: -1}, {HandshakeAgeSec: 40}, {HandshakeAgeSec: 12}}}
	if NewestHandshake(ts) != 12 {
		t.Error("newest")
	}
	if NewestHandshake(api.TunnelStatus{}) != -1 {
		t.Error("none")
	}
}
