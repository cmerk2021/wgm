package recovery

import (
	"errors"
	"testing"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/health"
)

var t0 = time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)

func policy() config.RecoveryPolicy {
	p := config.DefaultRecoveryPolicy()
	p.InitialBackoffSec = 5
	p.MaxBackoffSec = 60
	p.Multiplier = 2
	p.JitterFraction = 0
	p.MaxAttempts = 3
	p.BudgetMax = 10
	p.BudgetWindowSec = 3600
	p.VerifyTimeoutSec = 30
	return p
}

func degraded() health.Snapshot {
	return health.Snapshot{State: health.Degraded, Base: health.Degraded, Reason: "probes failing",
		Signals: health.Signals{ProbesConfigured: 1, ConsecutiveProbeFailures: 3, HandshakeFresh: false}}
}

func healthy() health.Snapshot {
	return health.Snapshot{State: health.Healthy, Base: health.Healthy}
}

func input(now time.Time, h health.Snapshot) Input {
	return Input{Now: now, Managed: true, Policy: policy(), Health: h, Intent: health.IntentUp,
		InterfaceExists: true, InterfaceUp: true, UnderlayUp: true}
}

func TestBackoff(t *testing.T) {
	p := policy()
	want := []time.Duration{5, 10, 20, 40, 60, 60}
	for i, w := range want {
		if got := Backoff(p, i, 0.5); got != w*time.Second {
			t.Errorf("attempt %d: %v want %v", i, got, w*time.Second)
		}
	}
	p.JitterFraction = 0.2
	if lo, hi := Backoff(p, 1, 0), Backoff(p, 1, 0.999999); lo != 8*time.Second || hi < 11900*time.Millisecond || hi > 12*time.Second {
		t.Errorf("jitter bounds: %v %v", lo, hi)
	}
	if got := Backoff(p, 10, 0.999); got > 60*time.Second {
		t.Errorf("jitter must not exceed max backoff: %v", got)
	}
}

func TestUnmanagedNeverActs(t *testing.T) {
	e := New()
	in := input(t0, degraded())
	in.Managed = false
	for i := 0; i < 100; i++ {
		in.Now = t0.Add(time.Duration(i) * time.Minute)
		if d := e.Evaluate(in); d.Action != ActionNone {
			t.Fatalf("unmanaged tunnel got action %s", d.Action)
		}
	}
	if e.Active() {
		t.Fatal("engine must stay idle for unmanaged tunnels")
	}
}

func TestIntentionalDisconnectNoReconnect(t *testing.T) {
	e := New()
	in := input(t0, health.Snapshot{State: health.Disconnected, Base: health.Disconnected})
	in.InterfaceExists = false
	in.Intent = health.IntentDown
	for i := 0; i < 50; i++ {
		in.Now = t0.Add(time.Duration(i) * time.Minute)
		if d := e.Evaluate(in); d.Action != ActionNone {
			t.Fatalf("manual disconnect triggered %s", d.Action)
		}
	}
	// Explicit opt-in allows it.
	in.Policy.ReconnectAfterManualDisconnect = true
	e.Evaluate(in)
	in.Now = in.Now.Add(time.Minute)
	if d := e.Evaluate(in); d.Action != ActionBringUp {
		t.Fatalf("opt-in reconnect: %+v", d)
	}
}

func TestNoIntentNoAction(t *testing.T) {
	e := New()
	in := input(t0, health.Snapshot{Base: health.Disconnected})
	in.InterfaceExists = false
	in.Intent = health.IntentNone
	for i := 0; i < 10; i++ {
		in.Now = t0.Add(time.Duration(i) * time.Minute)
		if d := e.Evaluate(in); d.Action != ActionNone {
			t.Fatal(d)
		}
	}
}

func TestBoundedRetriesAndExhaustion(t *testing.T) {
	e := New()
	now := t0
	var actions []Action
	var times []time.Time
	for i := 0; i < 2000 && !e.Exhausted(); i++ {
		d := e.Evaluate(input(now, degraded()))
		if d.Action != ActionNone {
			actions = append(actions, d.Action)
			times = append(times, now)
			if d.Action.Disruptive() || d.Action == ActionRecheck {
				e.Report(now, d.Action, nil)
			}
		}
		now = now.Add(time.Second)
	}
	if !e.Exhausted() {
		t.Fatal("never exhausted")
	}
	want := []Action{ActionRestart, ActionRestart, ActionRestart, ActionGiveUp}
	if len(actions) != len(want) {
		t.Fatalf("actions = %v", actions)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("actions = %v", actions)
		}
	}
	// First attempt after initial backoff; later attempts after verify
	// timeout (30s) plus growing backoff (10s, 20s).
	gaps := []time.Duration{times[1].Sub(times[0]), times[2].Sub(times[1])}
	if gaps[0] != 40*time.Second || gaps[1] != 50*time.Second {
		t.Fatalf("gaps = %v", gaps)
	}
	if times[0].Sub(t0) != 5*time.Second {
		t.Fatalf("first attempt at %v", times[0].Sub(t0))
	}
	// After exhaustion nothing more happens, however long it stays bad.
	for i := 0; i < 1000; i++ {
		now = now.Add(time.Minute)
		if d := e.Evaluate(input(now, degraded())); d.Action != ActionNone {
			t.Fatalf("action after exhaustion: %s", d.Action)
		}
	}
	// Healthy again clears exhaustion.
	e.Evaluate(input(now, healthy()))
	if e.Exhausted() || e.Active() {
		t.Fatal("healthy state should clear exhaustion")
	}
}

func TestSuccessfulRecoveryVerification(t *testing.T) {
	e := New()
	e.Evaluate(input(t0, degraded()))
	d := e.Evaluate(input(t0.Add(5*time.Second), degraded()))
	if d.Action != ActionRestart {
		t.Fatalf("%+v", d)
	}
	// While executing, nothing else happens.
	if d := e.Evaluate(input(t0.Add(6*time.Second), degraded())); d.Action != ActionNone {
		t.Fatal(d)
	}
	e.Report(t0.Add(7*time.Second), ActionRestart, nil)
	if !e.Active() || e.Status(t0).Phase != "verifying" {
		t.Fatal(e.Status(t0))
	}
	e.Evaluate(input(t0.Add(20*time.Second), healthy()))
	st := e.Status(t0.Add(20 * time.Second))
	if e.Active() || st.Attempt != 0 || st.LastResult == "" || st.BudgetUsed != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestFailedActionBacksOff(t *testing.T) {
	e := New()
	e.Evaluate(input(t0, degraded()))
	d := e.Evaluate(input(t0.Add(5*time.Second), degraded()))
	e.Report(t0.Add(5*time.Second), d.Action, errors.New("wg-quick failed"))
	st := e.Status(t0.Add(5 * time.Second))
	if st.Phase != "waiting" || !st.NextAttemptAt.Equal(t0.Add(15*time.Second)) {
		t.Fatalf("%+v", st)
	}
}

func TestRestartBudget(t *testing.T) {
	e := New()
	p := policy()
	p.MaxAttempts = 50
	p.BudgetMax = 2
	p.BudgetWindowSec = 600
	now := t0
	restarts := 0
	for i := 0; i < 600; i++ {
		in := input(now, degraded())
		in.Policy = p
		if d := e.Evaluate(in); d.Action.Disruptive() {
			restarts++
			e.Report(now, d.Action, errors.New("still broken"))
		}
		now = now.Add(time.Second)
	}
	if restarts != 2 {
		t.Fatalf("restarts in window = %d, want budget 2", restarts)
	}
	if st := e.Status(now); st.BudgetUsed != 2 || st.Exhausted {
		t.Fatalf("%+v", st)
	}
}

func TestClassification(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Input)
		want Action
	}{
		{"missing", func(in *Input) {
			in.InterfaceExists = false
			in.Health = health.Snapshot{Base: health.Disconnected}
		}, ActionBringUp},
		{"probe only", func(in *Input) {
			in.Health.Signals.HandshakeFresh = true
			in.Health.Signals.RxAdvancing = true
		}, ActionRecheck},
		{"handshake", func(in *Input) {}, ActionRestart},
		{"admin down", func(in *Input) {
			in.InterfaceUp = false
			in.Health = health.Snapshot{Base: health.Error}
		}, ActionRestart},
		{"not wireguard", func(in *Input) {
			in.Health = health.Snapshot{Base: health.Error}
		}, ActionGiveUp},
		{"outage", func(in *Input) { in.UnderlayUp = false }, ActionNone},
	}
	for _, c := range cases {
		e := New()
		in := input(t0, degraded())
		c.mod(&in)
		e.Evaluate(in)
		in.Now = t0.Add(10 * time.Second)
		if d := e.Evaluate(in); d.Action != c.want {
			t.Errorf("%s: got %+v want %s", c.name, d, c.want)
		}
	}
}

func TestOutageDoesNotConsumeAttempts(t *testing.T) {
	e := New()
	now := t0
	for i := 0; i < 3600; i++ {
		in := input(now, degraded())
		in.UnderlayUp = false
		if d := e.Evaluate(in); d.Action != ActionNone {
			t.Fatalf("outage produced %s", d.Action)
		}
		now = now.Add(time.Second)
	}
	if e.Exhausted() || e.Status(now).Attempt != 0 {
		t.Fatalf("%+v", e.Status(now))
	}
}

func TestDisconnectCancelsRecovery(t *testing.T) {
	e := New()
	e.Evaluate(input(t0, degraded()))
	if !e.Active() {
		t.Fatal("expected active")
	}
	in := input(t0.Add(time.Second), degraded())
	in.Intent = health.IntentDown
	e.Evaluate(in)
	if e.Active() {
		t.Fatal("manual disconnect must cancel recovery")
	}
}
