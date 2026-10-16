package health

import (
	"strings"
	"testing"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
)

var t0 = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

type harness struct {
	t   *testing.T
	m   *Machine
	now time.Time
	rx  uint64
	tx  uint64
	hs  time.Time
	ka  time.Duration
}

func newHarness(t *testing.T, mutate func(*config.HealthPolicy)) *harness {
	p := config.DefaultHealthPolicy()
	p.FailureThreshold = 3
	p.RecoveryThreshold = 2
	if mutate != nil {
		mutate(&p)
	}
	return &harness{t: t, m: NewMachine(p), now: t0}
}

func (h *harness) obs() Observation {
	return Observation{At: h.now, Exists: true, Up: true, IsWireGuard: true,
		Peers: []PeerObs{{LastHandshake: h.hs, Keepalive: h.ka, Rx: h.rx, Tx: h.tx}}}
}

func (h *harness) step(o Observation) State {
	h.m.Observe(o)
	h.now = h.now.Add(10 * time.Second)
	return h.m.State()
}

func probes(ok bool) []ProbeResult {
	return []ProbeResult{{Probe: "icmp 10.0.0.1", OK: ok, LatencyMs: 12}}
}

func TestDisconnectedWhenNoInterface(t *testing.T) {
	h := newHarness(t, nil)
	if s := h.step(Observation{At: h.now}); s != Disconnected {
		t.Fatalf("state = %s", s)
	}
	if !strings.Contains(h.m.Snapshot().Reason, "not present") {
		t.Fatal(h.m.Snapshot().Reason)
	}
}

func TestInterfaceUpIsNotHealthyWithoutProbes(t *testing.T) {
	h := newHarness(t, nil)
	h.hs = h.now.Add(-5 * time.Second)
	for i := 0; i < 5; i++ {
		h.rx += 100
		h.tx += 100
		if s := h.step(h.obs()); s != ConnectedUnverified {
			t.Fatalf("round %d: state = %s; an up interface with a handshake must not be reported healthy without probes", i, s)
		}
	}
}

func TestProbesMakeHealthyAndFailureThreshold(t *testing.T) {
	h := newHarness(t, nil)
	h.hs = h.now
	o := h.obs()
	o.ProbesConfigured = 1
	o.Probes = probes(true)
	if s := h.step(o); s != Healthy {
		t.Fatalf("state = %s (%s)", s, h.m.Snapshot().Reason)
	}
	// Two failed rounds: still healthy (threshold 3).
	for i := 1; i <= 2; i++ {
		h.hs = h.now
		o = h.obs()
		o.ProbesConfigured = 1
		o.Probes = probes(false)
		if s := h.step(o); s != Healthy {
			t.Fatalf("failure %d: state = %s; threshold not respected", i, s)
		}
		if !strings.Contains(h.m.Snapshot().Reason, "/3 failed rounds") {
			t.Fatalf("reason should report progress: %s", h.m.Snapshot().Reason)
		}
	}
	o = h.obs()
	o.ProbesConfigured = 1
	o.Probes = probes(false)
	if s := h.step(o); s != Degraded {
		t.Fatalf("third failure: state = %s", s)
	}
	// One success is not enough to clear (recovery threshold 2).
	o = h.obs()
	o.ProbesConfigured = 1
	o.Probes = probes(true)
	if s := h.step(o); s != Degraded {
		t.Fatalf("first success: state = %s", s)
	}
	o.At = h.now
	if s := h.step(o); s != Healthy {
		t.Fatalf("second success: state = %s", s)
	}
	hist := h.m.History()
	if len(hist) != 3 || hist[1].To != Degraded || hist[1].Reason == "" {
		t.Fatalf("history = %+v", hist)
	}
}

func TestProbeFailureWithFreshHandshakeMentionsBlocking(t *testing.T) {
	h := newHarness(t, func(p *config.HealthPolicy) { p.FailureThreshold = 1 })
	h.hs = h.now
	h.step(h.obs())
	h.rx += 1000
	o := h.obs()
	o.ProbesConfigured = 1
	o.Probes = probes(false)
	h.step(o)
	if h.m.State() != Degraded || !strings.Contains(h.m.Snapshot().Reason, "may be blocking") {
		t.Fatalf("%s: %s", h.m.State(), h.m.Snapshot().Reason)
	}
}

func TestQuietTunnelIsNotUnhealthy(t *testing.T) {
	h := newHarness(t, nil)
	h.hs = h.now.Add(-2 * time.Hour) // no keepalive, no traffic
	for i := 0; i < 10; i++ {
		if s := h.step(h.obs()); s != ConnectedUnverified {
			t.Fatalf("quiet tunnel became %s: %s", s, h.m.Snapshot().Reason)
		}
	}
	if !strings.Contains(h.m.Snapshot().Reason, "idle") {
		t.Fatal(h.m.Snapshot().Reason)
	}
}

func TestStaleHandshakeWithKeepaliveDegrades(t *testing.T) {
	h := newHarness(t, nil)
	h.ka = 25 * time.Second
	h.hs = h.now.Add(-10 * time.Minute)
	var s State
	for i := 0; i < 3; i++ {
		s = h.step(h.obs())
	}
	if s != Degraded || !strings.Contains(h.m.Snapshot().Reason, "keepalive") {
		t.Fatalf("%s: %s", s, h.m.Snapshot().Reason)
	}
}

func TestTxWithoutRxDegrades(t *testing.T) {
	h := newHarness(t, func(p *config.HealthPolicy) { p.FailureThreshold = 1 })
	h.hs = h.now.Add(-10 * time.Minute)
	h.step(h.obs())
	h.tx += 500
	h.step(h.obs())
	if h.m.State() == Degraded {
		t.Fatal("one round of tx-without-rx should not degrade")
	}
	h.tx += 500
	if s := h.step(h.obs()); s != Degraded {
		t.Fatalf("state = %s", s)
	}
}

func TestConnectingGraceAndNeverHandshake(t *testing.T) {
	h := newHarness(t, func(p *config.HealthPolicy) { p.ConnectGraceSec = 30; p.FailureThreshold = 1 })
	intentAt := h.now
	o := Observation{At: h.now, Intent: IntentUp, IntentAt: intentAt}
	if s := h.step(o); s != Connecting {
		t.Fatalf("state = %s", s)
	}
	o = h.obs()
	o.Intent, o.IntentAt = IntentUp, intentAt
	o.Peers[0].Keepalive = 25 * time.Second
	if s := h.step(o); s != Connecting {
		t.Fatalf("within grace: %s", s)
	}
	h.now = intentAt.Add(31 * time.Second)
	o = h.obs()
	o.Intent, o.IntentAt = IntentUp, intentAt
	o.Peers[0].Keepalive = 25 * time.Second
	if s := h.step(o); s != Degraded {
		t.Fatalf("after grace without handshake: %s (%s)", s, h.m.Snapshot().Reason)
	}
}

func TestIntentionalDisconnect(t *testing.T) {
	h := newHarness(t, nil)
	h.hs = h.now
	h.step(h.obs())
	if s := h.step(Observation{At: h.now, Intent: IntentDown, IntentAt: h.now}); s != Disconnected {
		t.Fatal(s)
	}
	if h.m.Snapshot().Reason != "disconnected by user" {
		t.Fatal(h.m.Snapshot().Reason)
	}
}

func TestUnexpectedDisappearance(t *testing.T) {
	h := newHarness(t, nil)
	h.hs = h.now
	h.step(h.obs())
	h.step(Observation{At: h.now, Intent: IntentUp, IntentAt: t0.Add(-time.Hour)})
	if h.m.State() != Disconnected || !strings.Contains(h.m.Snapshot().Reason, "unexpectedly") {
		t.Fatalf("%s %s", h.m.State(), h.m.Snapshot().Reason)
	}
}

func TestRecoveringAndVerification(t *testing.T) {
	h := newHarness(t, func(p *config.HealthPolicy) { p.FailureThreshold = 1 })
	h.hs = h.now
	o := h.obs()
	o.ProbesConfigured = 1
	o.Probes = probes(false)
	h.step(o)
	if h.m.State() != Degraded {
		t.Fatal(h.m.State())
	}
	o = h.obs()
	o.Recovering = true
	o.ProbesConfigured = 1
	o.Probes = probes(false)
	if s := h.step(o); s != Recovering {
		t.Fatal(s)
	}
	// After the recovery action, healthy requires fresh good rounds; the
	// visible state stays Recovering until the base state is verified.
	o = h.obs()
	o.Recovering = true
	o.ProbesConfigured = 1
	o.Probes = probes(true)
	if s := h.step(o); s != Recovering || h.m.Base() != Degraded {
		t.Fatalf("first verification round: %s base %s", s, h.m.Base())
	}
	o.At = h.now
	if s := h.step(o); s != Healthy {
		t.Fatalf("second verification round: %s", s)
	}
}

func TestRecoveryExhaustedIsError(t *testing.T) {
	h := newHarness(t, func(p *config.HealthPolicy) { p.FailureThreshold = 1 })
	h.hs = h.now
	o := h.obs()
	o.ProbesConfigured = 1
	o.Probes = probes(false)
	o.RecoveryExhausted = true
	o.RecoveryDetail = "5 attempts"
	if s := h.step(o); s != Error || !strings.Contains(h.m.Snapshot().Reason, "exhausted") {
		t.Fatalf("%s %s", s, h.m.Snapshot().Reason)
	}
}

func TestAdminDownAndNonWireGuard(t *testing.T) {
	h := newHarness(t, nil)
	o := h.obs()
	o.Up = false
	if s := h.step(o); s != Error {
		t.Fatal(s)
	}
	o = h.obs()
	o.IsWireGuard = false
	if s := h.step(o); s != Error {
		t.Fatal(s)
	}
}

func TestHandshakeFreshness(t *testing.T) {
	h := newHarness(t, func(p *config.HealthPolicy) { p.HandshakeStaleSec = 180 })
	for _, c := range []struct {
		age   time.Duration
		fresh bool
	}{{0, true}, {179 * time.Second, true}, {180 * time.Second, true}, {181 * time.Second, false}, {-5 * time.Second, true}} {
		h.hs = h.now.Add(-c.age)
		h.step(h.obs())
		if got := h.m.Snapshot().Signals.HandshakeFresh; got != c.fresh {
			t.Errorf("age %v: fresh=%v want %v", c.age, got, c.fresh)
		}
	}
	h.hs = time.Time{}
	h.step(h.obs())
	if sig := h.m.Snapshot().Signals; sig.EverHandshaked || sig.NewestHandshakeAgeSec != -1 {
		t.Fatalf("never: %+v", sig)
	}
}

func TestCounterResetDoesNotCountAsTraffic(t *testing.T) {
	h := newHarness(t, nil)
	h.rx, h.tx = 1000, 1000
	h.step(h.obs())
	h.rx, h.tx = 10, 2000 // rx reset
	h.step(h.obs())
	if sig := h.m.Snapshot().Signals; sig.RxAdvancing || sig.TxAdvancing {
		t.Fatalf("reset treated as traffic: %+v", sig)
	}
}
