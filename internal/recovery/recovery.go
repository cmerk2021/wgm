// Package recovery decides when and how to repair a managed tunnel. It is
// driven by health evaluations rather than timers of its own, applies
// bounded exponential backoff with jitter and a restart budget, and never
// acts on tunnels WGM is not authorized to manage or that the user
// intentionally disconnected.
//
// The engine is pure decision logic; the daemon executes the returned
// actions and reports their outcome.
package recovery

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/health"
)

// Classification is the likely cause of a failure.
type Classification string

const (
	ClassNone             Classification = ""
	ClassInterfaceMissing Classification = "interface_missing"
	ClassInterfaceDown    Classification = "interface_down"
	ClassHandshake        Classification = "handshake_failure"
	ClassProbeOnly        Classification = "probe_failure_with_active_tunnel"
	ClassProbe            Classification = "probe_failure"
	ClassNetworkOutage    Classification = "underlying_network_outage"
	ClassUnrecoverable    Classification = "needs_user_attention"
)

// Action is something the daemon should do.
type Action string

const (
	ActionNone    Action = ""
	ActionBringUp Action = "bring_up" // interface missing: activate tunnel
	ActionRestart Action = "restart"  // deactivate and re-activate tunnel
	ActionRecheck Action = "recheck"  // refresh state only; no disruption
	ActionGiveUp  Action = "give_up"  // retry policy exhausted
)

// Disruptive reports whether the action changes tunnel state.
func (a Action) Disruptive() bool { return a == ActionBringUp || a == ActionRestart }

type phase int

const (
	phaseIdle phase = iota
	phaseWaiting
	phaseExecuting
	phaseVerifying
)

// Input is the information the engine needs for one decision.
type Input struct {
	Now             time.Time
	Managed         bool
	Policy          config.RecoveryPolicy
	Health          health.Snapshot
	Intent          health.Intent
	InterfaceExists bool
	InterfaceUp     bool
	// UnderlayUp reports whether the host has any usable non-tunnel
	// network path (e.g. a default route on a physical interface).
	UnderlayUp bool
}

// Decision is the engine's instruction for this round.
type Decision struct {
	Action Action
	Class  Classification
	Reason string
}

// Status is the externally visible recovery state.
type Status struct {
	Active         bool           `json:"active"`
	Phase          string         `json:"phase"`
	Attempt        int            `json:"attempt"`
	MaxAttempts    int            `json:"max_attempts"`
	NextAttemptAt  time.Time      `json:"next_attempt_at,omitempty"`
	Classification Classification `json:"classification,omitempty"`
	LastAction     Action         `json:"last_action,omitempty"`
	LastResult     string         `json:"last_result,omitempty"`
	LastResultAt   time.Time      `json:"last_result_at,omitempty"`
	Exhausted      bool           `json:"exhausted"`
	BudgetUsed     int            `json:"budget_used"`
	BudgetMax      int            `json:"budget_max"`
}

// Engine is the per-tunnel recovery state. Not safe for concurrent use.
type Engine struct {
	// Rand returns a value in [0,1); injectable for deterministic tests.
	Rand func() float64

	phase          phase
	attempt        int
	nextAt         time.Time
	verifyDeadline time.Time
	class          Classification
	lastAction     Action
	lastResult     string
	lastResultAt   time.Time
	exhausted      bool
	restarts       []time.Time
	policy         config.RecoveryPolicy
}

// New returns an idle engine.
func New() *Engine { return &Engine{Rand: rand.Float64} }

// Active reports whether recovery is in progress.
func (e *Engine) Active() bool { return e.phase != phaseIdle }

// Exhausted reports whether the retry policy has been used up.
func (e *Engine) Exhausted() bool { return e.exhausted }

// Detail is a short description for health reasons.
func (e *Engine) Detail() string {
	switch e.phase {
	case phaseWaiting:
		return fmt.Sprintf("attempt %d/%d pending (%s)", e.attempt+1, e.policy.MaxAttempts, e.class)
	case phaseExecuting:
		return fmt.Sprintf("attempt %d/%d: %s", e.attempt, e.policy.MaxAttempts, e.lastAction)
	case phaseVerifying:
		return fmt.Sprintf("verifying attempt %d/%d", e.attempt, e.policy.MaxAttempts)
	}
	if e.exhausted {
		return e.lastResult
	}
	return ""
}

// Status returns the current status.
func (e *Engine) Status(now time.Time) Status {
	names := map[phase]string{phaseIdle: "idle", phaseWaiting: "waiting", phaseExecuting: "executing", phaseVerifying: "verifying"}
	s := Status{
		Active: e.Active(), Phase: names[e.phase], Attempt: e.attempt, MaxAttempts: e.policy.MaxAttempts,
		Classification: e.class, LastAction: e.lastAction, LastResult: e.lastResult, LastResultAt: e.lastResultAt,
		Exhausted: e.exhausted, BudgetUsed: e.budgetUsed(now), BudgetMax: e.policy.BudgetMax,
	}
	if e.phase == phaseWaiting {
		s.NextAttemptAt = e.nextAt
	}
	return s
}

// Reset clears all recovery state except the restart budget (used when
// the user explicitly connects or disconnects).
func (e *Engine) Reset(reason string, now time.Time) {
	if e.phase != phaseIdle || e.exhausted {
		e.result(now, reason)
	}
	e.phase, e.attempt, e.exhausted, e.class = phaseIdle, 0, false, ClassNone
}

func (e *Engine) result(now time.Time, r string) {
	e.lastResult, e.lastResultAt = r, now
}

func (e *Engine) budgetUsed(now time.Time) int {
	window := time.Duration(e.policy.BudgetWindowSec) * time.Second
	n := 0
	for _, t := range e.restarts {
		if now.Sub(t) < window {
			n++
		}
	}
	return n
}

func (e *Engine) pruneBudget(now time.Time) {
	window := time.Duration(e.policy.BudgetWindowSec) * time.Second
	kept := e.restarts[:0]
	for _, t := range e.restarts {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	e.restarts = kept
}

// Backoff returns the delay before attempt n (0-based) including jitter.
func Backoff(p config.RecoveryPolicy, n int, r float64) time.Duration {
	base := float64(p.InitialBackoffSec) * math.Pow(p.Multiplier, float64(n))
	if base > float64(p.MaxBackoffSec) {
		base = float64(p.MaxBackoffSec)
	}
	d := base * (1 + p.JitterFraction*(2*r-1))
	if d > float64(p.MaxBackoffSec) {
		d = float64(p.MaxBackoffSec)
	}
	if d < 1 {
		d = 1
	}
	return time.Duration(d * float64(time.Second))
}

func (e *Engine) rnd() float64 {
	if e.Rand == nil {
		return 0.5
	}
	return e.Rand()
}

func good(s health.Snapshot) bool {
	return s.Base == health.Healthy || s.Base == health.ConnectedUnverified
}

func classify(in Input) Classification {
	sig := in.Health.Signals
	switch {
	case in.Health.Base == health.Error && in.InterfaceExists && !in.InterfaceUp:
		return ClassInterfaceDown
	case in.Health.Base == health.Error:
		return ClassUnrecoverable
	case !in.InterfaceExists:
		if !in.UnderlayUp {
			return ClassNetworkOutage
		}
		return ClassInterfaceMissing
	case !in.UnderlayUp:
		return ClassNetworkOutage
	case sig.ProbesConfigured > 0 && sig.ConsecutiveProbeFailures > 0 && sig.HandshakeFresh && sig.RxAdvancing:
		return ClassProbeOnly
	case !sig.HandshakeFresh:
		return ClassHandshake
	default:
		return ClassProbe
	}
}

func needsRecovery(in Input) bool {
	switch in.Health.Base {
	case health.Degraded:
		return true
	case health.Error:
		return in.InterfaceExists
	case health.Disconnected:
		return !in.InterfaceExists
	}
	return false
}

// Evaluate returns the decision for this round.
func (e *Engine) Evaluate(in Input) Decision {
	e.policy = in.Policy
	e.pruneBudget(in.Now)

	eligible := in.Managed && in.Policy.Enabled
	why := "tunnel is not managed by WGM"
	if in.Managed && !in.Policy.Enabled {
		why = "automatic recovery is disabled for this tunnel"
	}
	if eligible {
		switch in.Intent {
		case health.IntentUp:
		case health.IntentDown:
			if !in.Policy.ReconnectAfterManualDisconnect {
				eligible, why = false, "tunnel was intentionally disconnected"
			}
		default:
			eligible, why = false, "WGM has no request to keep this tunnel up"
		}
	}
	if !eligible {
		if e.phase != phaseIdle {
			e.Reset("recovery cancelled: "+why, in.Now)
		}
		return Decision{}
	}

	if e.phase == phaseExecuting {
		return Decision{}
	}
	if good(in.Health) {
		switch {
		case e.phase == phaseVerifying:
			e.result(in.Now, fmt.Sprintf("recovered after %d attempt(s) (%s)", e.attempt, e.lastAction))
		case e.phase == phaseWaiting:
			e.result(in.Now, "recovered without intervention")
		case e.exhausted:
			e.result(in.Now, "tunnel healthy again; recovery state cleared")
		default:
			return Decision{}
		}
		e.phase, e.attempt, e.exhausted, e.class = phaseIdle, 0, false, ClassNone
		return Decision{Reason: e.lastResult}
	}
	if !needsRecovery(in) || e.exhausted {
		return Decision{}
	}
	if e.phase == phaseVerifying {
		if in.Now.Before(e.verifyDeadline) {
			return Decision{}
		}
		e.result(in.Now, fmt.Sprintf("attempt %d (%s) did not restore health within %ds", e.attempt, e.lastAction, in.Policy.VerifyTimeoutSec))
		e.phase = phaseWaiting
		e.nextAt = in.Now.Add(Backoff(in.Policy, e.attempt, e.rnd()))
		return Decision{Reason: e.lastResult}
	}
	if e.phase == phaseIdle {
		e.phase = phaseWaiting
		e.attempt = 0
		e.class = classify(in)
		e.nextAt = in.Now.Add(Backoff(in.Policy, 0, e.rnd()))
		return Decision{Class: e.class, Reason: fmt.Sprintf("failure detected (%s); first attempt at %s", e.class, e.nextAt.Format(time.TimeOnly))}
	}
	// phaseWaiting
	if in.Now.Before(e.nextAt) {
		return Decision{}
	}
	e.class = classify(in)
	if e.attempt >= in.Policy.MaxAttempts {
		e.exhausted = true
		e.phase = phaseIdle
		e.result(in.Now, fmt.Sprintf("recovery exhausted after %d attempt(s); last classification %s", e.attempt, e.class))
		return Decision{Action: ActionGiveUp, Class: e.class, Reason: e.lastResult}
	}
	var act Action
	switch e.class {
	case ClassNetworkOutage:
		// Restarting cannot help while the underlying network is down.
		// Waiting does not consume an attempt, but is rate limited.
		e.nextAt = in.Now.Add(time.Duration(in.Policy.MaxBackoffSec) * time.Second)
		e.result(in.Now, "underlying network unavailable; waiting before retrying")
		return Decision{Action: ActionNone, Class: e.class, Reason: e.lastResult}
	case ClassUnrecoverable:
		e.exhausted = true
		e.phase = phaseIdle
		e.result(in.Now, "failure cannot be repaired automatically: "+in.Health.Reason)
		return Decision{Action: ActionGiveUp, Class: e.class, Reason: e.lastResult}
	case ClassProbeOnly:
		act = ActionRecheck
	case ClassInterfaceMissing:
		act = ActionBringUp
	default:
		act = ActionRestart
	}
	if act.Disruptive() {
		if used := e.budgetUsed(in.Now); used >= in.Policy.BudgetMax {
			oldest := e.restarts[0]
			e.nextAt = oldest.Add(time.Duration(in.Policy.BudgetWindowSec) * time.Second)
			e.result(in.Now, fmt.Sprintf("restart budget used (%d/%d); next attempt not before %s", used, in.Policy.BudgetMax, e.nextAt.Format(time.TimeOnly)))
			return Decision{Class: e.class, Reason: e.lastResult}
		}
	}
	e.attempt++
	e.lastAction = act
	e.phase = phaseExecuting
	return Decision{Action: act, Class: e.class, Reason: fmt.Sprintf("attempt %d/%d: %s (%s)", e.attempt, in.Policy.MaxAttempts, act, e.class)}
}

// Report records the outcome of executing a Decision's action.
func (e *Engine) Report(now time.Time, act Action, err error) {
	if e.phase != phaseExecuting {
		return
	}
	if act.Disruptive() {
		e.restarts = append(e.restarts, now)
	}
	if err != nil {
		e.result(now, fmt.Sprintf("attempt %d (%s) failed: %v", e.attempt, act, err))
		e.phase = phaseWaiting
		e.nextAt = now.Add(Backoff(e.policy, e.attempt, e.rnd()))
		return
	}
	e.result(now, fmt.Sprintf("attempt %d (%s) executed; verifying", e.attempt, act))
	e.phase = phaseVerifying
	e.verifyDeadline = now.Add(time.Duration(e.policy.VerifyTimeoutSec) * time.Second)
}
