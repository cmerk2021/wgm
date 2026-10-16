// Package health evaluates WireGuard tunnel health from multiple signals
// (interface state, handshakes, counters, active probes, intent and
// recovery state) using an explicit state machine with hysteresis.
//
// The package has no Linux or GUI dependencies; time is supplied by the
// caller so evaluation is deterministic in tests.
package health

import (
	"fmt"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
)

// State is a tunnel health state.
type State string

const (
	Unknown             State = "unknown"
	Connecting          State = "connecting"
	ConnectedUnverified State = "connected_unverified"
	Healthy             State = "healthy"
	Degraded            State = "degraded"
	Recovering          State = "recovering"
	Disconnected        State = "disconnected"
	Error               State = "error"
)

// Label returns a short human-readable label.
func (s State) Label() string {
	switch s {
	case Connecting:
		return "Connecting"
	case ConnectedUnverified:
		return "Connected (unverified)"
	case Healthy:
		return "Healthy"
	case Degraded:
		return "Degraded"
	case Recovering:
		return "Recovering"
	case Disconnected:
		return "Disconnected"
	case Error:
		return "Error"
	}
	return "Unknown"
}

// Connected reports whether the state implies the interface is up.
func (s State) Connected() bool {
	switch s {
	case ConnectedUnverified, Healthy, Degraded:
		return true
	}
	return false
}

// Intent is the most recent explicit desire for the tunnel's state.
type Intent string

const (
	IntentNone Intent = ""     // no explicit request (externally managed)
	IntentUp   Intent = "up"   // user or autostart asked for the tunnel
	IntentDown Intent = "down" // user explicitly disconnected
)

// Clock abstracts time for deterministic tests.
type Clock interface{ Now() time.Time }

// SystemClock is the wall/monotonic clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// ProbeResult is the outcome of one probe execution.
type ProbeResult struct {
	Probe     string    `json:"probe"`
	OK        bool      `json:"ok"`
	LatencyMs float64   `json:"latency_ms,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	At        time.Time `json:"at"`
}

// PeerObs is the subset of peer state used for health.
type PeerObs struct {
	LastHandshake time.Time
	Keepalive     time.Duration
	Rx, Tx        uint64
}

// Observation is one round of collected signals.
type Observation struct {
	At                time.Time
	Exists            bool
	Up                bool
	IsWireGuard       bool
	Peers             []PeerObs
	ProbesConfigured  int
	Probes            []ProbeResult // nil when no probe round ran this tick
	Intent            Intent
	IntentAt          time.Time
	Recovering        bool
	RecoveryExhausted bool
	RecoveryDetail    string
}

// Signals are the derived indicators exposed to clients.
type Signals struct {
	HandshakeFresh            bool    `json:"handshake_fresh"`
	EverHandshaked            bool    `json:"ever_handshaked"`
	NewestHandshakeAgeSec     float64 `json:"newest_handshake_age_sec"` // -1: never
	KeepaliveConfigured       bool    `json:"keepalive_configured"`
	RxAdvancing               bool    `json:"rx_advancing"`
	TxAdvancing               bool    `json:"tx_advancing"`
	TxWithoutRxRounds         int     `json:"tx_without_rx_rounds"`
	ProbesConfigured          int     `json:"probes_configured"`
	ConsecutiveProbeFailures  int     `json:"consecutive_probe_failures"`
	ConsecutiveProbeSuccesses int     `json:"consecutive_probe_successes"`
	LastProbeLatencyMs        float64 `json:"last_probe_latency_ms"`
	BadRounds                 int     `json:"bad_rounds"`
	GoodRounds                int     `json:"good_rounds"`
}

// Transition records a meaningful state change.
type Transition struct {
	At     time.Time `json:"at"`
	From   State     `json:"from"`
	To     State     `json:"to"`
	Reason string    `json:"reason"`
}

// Snapshot is the externally visible health of a tunnel.
type Snapshot struct {
	State      State         `json:"state"`
	Base       State         `json:"base_state"`
	Reason     string        `json:"reason"`
	Since      time.Time     `json:"since"`
	Signals    Signals       `json:"signals"`
	LastProbes []ProbeResult `json:"last_probes,omitempty"`
}

const maxHistory = 200

// Machine is the per-tunnel health state machine. It is not safe for
// concurrent use; the daemon serialises access per tunnel.
type Machine struct {
	policy config.HealthPolicy

	state  State // visible state (includes recovery overlay)
	base   State // signal-derived state with hysteresis
	reason string
	since  time.Time

	sig        Signals
	lastProbes []ProbeResult
	prevRx     uint64
	prevTx     uint64
	havePrev   bool
	history    []Transition
}

// NewMachine creates a machine in the Unknown state.
func NewMachine(p config.HealthPolicy) *Machine {
	return &Machine{policy: p, state: Unknown, base: Unknown, reason: "no observations yet"}
}

// SetPolicy updates thresholds; streaks are preserved.
func (m *Machine) SetPolicy(p config.HealthPolicy) { m.policy = p }

// Snapshot returns the current view.
func (m *Machine) Snapshot() Snapshot {
	return Snapshot{State: m.state, Base: m.base, Reason: m.reason, Since: m.since, Signals: m.sig,
		LastProbes: append([]ProbeResult(nil), m.lastProbes...)}
}

// History returns recorded transitions, oldest first.
func (m *Machine) History() []Transition { return append([]Transition(nil), m.history...) }

// State returns the current state.
func (m *Machine) State() State { return m.state }

// Base returns the signal-derived state before the recovery overlay.
func (m *Machine) Base() State { return m.base }

// Observe folds in one observation. It returns the transition if the
// visible state changed.
//
// Evaluation happens in two layers. The base layer derives a state from
// signals with hysteresis; it keeps running during recovery so that
// recovery can be verified with fresh checks. The visible layer overlays
// recovery: Recovering while recovery is active and the base state is not
// yet good, and Error when recovery has been exhausted.
func (m *Machine) Observe(o Observation) (Transition, bool) {
	raw, reason := m.classify(o)
	base, baseReason := m.applyHysteresis(raw, reason)
	m.base = base
	next, nextReason := base, baseReason
	good := base == Healthy || base == ConnectedUnverified
	switch {
	case o.Intent == IntentDown && base == Disconnected:
		// Intentional disconnect always wins.
	case o.Recovering && !good:
		next = Recovering
		nextReason = "automatic recovery in progress"
		if o.RecoveryDetail != "" {
			nextReason += ": " + o.RecoveryDetail
		}
		nextReason += " [" + baseReason + "]"
	case o.RecoveryExhausted && (base == Degraded || base == Disconnected):
		next = Error
		nextReason = baseReason + "; automatic recovery exhausted" + detail(o)
	}
	if next == m.state {
		m.reason = nextReason
		return Transition{}, false
	}
	t := Transition{At: o.At, From: m.state, To: next, Reason: nextReason}
	m.state, m.reason, m.since = next, nextReason, o.At
	m.history = append(m.history, t)
	if len(m.history) > maxHistory {
		m.history = m.history[len(m.history)-maxHistory:]
	}
	return t, true
}

func (m *Machine) grace() time.Duration { return time.Duration(m.policy.ConnectGraceSec) * time.Second }

func (m *Machine) stale() time.Duration { return time.Duration(m.policy.HandshakeStaleSec) * time.Second }

func (m *Machine) inGrace(o Observation) bool {
	return o.Intent == IntentUp && !o.IntentAt.IsZero() && o.At.Sub(o.IntentAt) < m.grace()
}

// classify computes the instantaneous ("raw") state for one observation
// and updates the derived signals.
func (m *Machine) classify(o Observation) (State, string) {
	m.updateSignals(o)
	if !o.Exists {
		m.resetStreaks()
		m.havePrev = false
		switch {
		case m.inGrace(o):
			return Connecting, "waiting for interface to appear"
		case o.Intent == IntentDown:
			return Disconnected, "disconnected by user"
		case m.base.Connected() || m.state == Recovering:
			return Disconnected, "interface disappeared unexpectedly"
		case o.Intent == IntentUp:
			return Disconnected, "interface is not present although a connection was requested"
		default:
			return Disconnected, "interface is not present"
		}
	}
	if !o.IsWireGuard {
		m.resetStreaks()
		return Error, "interface exists but is not a WireGuard device (or WireGuard state is unreadable)"
	}
	if !o.Up {
		m.resetStreaks()
		return Error, "interface exists but is administratively down"
	}

	raw, reason := m.classifyUp(o)
	switch raw {
	case Degraded:
		m.sig.BadRounds++
		m.sig.GoodRounds = 0
	case Healthy, ConnectedUnverified:
		m.sig.GoodRounds++
		m.sig.BadRounds = 0
	}
	return raw, reason
}

func detail(o Observation) string {
	if o.RecoveryDetail == "" {
		return ""
	}
	return " (" + o.RecoveryDetail + ")"
}

func (m *Machine) resetStreaks() {
	m.sig.BadRounds, m.sig.GoodRounds = 0, 0
	m.sig.TxWithoutRxRounds = 0
}

func (m *Machine) updateSignals(o Observation) {
	s := &m.sig
	s.ProbesConfigured = o.ProbesConfigured
	s.KeepaliveConfigured = false
	var newest time.Time
	var rx, tx uint64
	for _, p := range o.Peers {
		if p.Keepalive > 0 {
			s.KeepaliveConfigured = true
		}
		if p.LastHandshake.After(newest) {
			newest = p.LastHandshake
		}
		rx += p.Rx
		tx += p.Tx
	}
	s.EverHandshaked = !newest.IsZero()
	if newest.IsZero() {
		s.NewestHandshakeAgeSec = -1
		s.HandshakeFresh = false
	} else {
		age := o.At.Sub(newest)
		if age < 0 {
			age = 0 // peer clock skew / wall clock step; treat as just now
		}
		s.NewestHandshakeAgeSec = age.Seconds()
		s.HandshakeFresh = age <= m.stale()
	}
	if o.Exists && m.havePrev && rx >= m.prevRx && tx >= m.prevTx {
		s.RxAdvancing = rx > m.prevRx
		s.TxAdvancing = tx > m.prevTx
	} else {
		s.RxAdvancing, s.TxAdvancing = false, false
	}
	if s.TxAdvancing && !s.RxAdvancing {
		s.TxWithoutRxRounds++
	} else if s.RxAdvancing {
		s.TxWithoutRxRounds = 0
	}
	m.prevRx, m.prevTx, m.havePrev = rx, tx, o.Exists

	if o.Probes != nil {
		m.lastProbes = append(m.lastProbes[:0], o.Probes...)
		anyOK := false
		for _, p := range o.Probes {
			if p.OK {
				anyOK = true
				s.LastProbeLatencyMs = p.LatencyMs
			}
		}
		if anyOK {
			s.ConsecutiveProbeSuccesses++
			s.ConsecutiveProbeFailures = 0
		} else if len(o.Probes) > 0 {
			s.ConsecutiveProbeFailures++
			s.ConsecutiveProbeSuccesses = 0
		}
	}
	if o.ProbesConfigured == 0 {
		m.lastProbes = nil
		s.ConsecutiveProbeFailures, s.ConsecutiveProbeSuccesses = 0, 0
	}
}

// classifyUp evaluates an existing, up WireGuard interface.
func (m *Machine) classifyUp(o Observation) (State, string) {
	s := m.sig
	grace := m.inGrace(o)
	if grace && !s.EverHandshaked {
		return Connecting, "interface up, waiting for first handshake"
	}

	// Tunnel-level failure evidence.
	switch {
	case !s.EverHandshaked && (s.KeepaliveConfigured || s.TxAdvancing):
		return Degraded, "no handshake has completed with any peer although packets are being sent"
	case s.EverHandshaked && !s.HandshakeFresh && s.KeepaliveConfigured:
		return Degraded, fmt.Sprintf("latest handshake is %s old despite persistent keepalive", fmtAge(s.NewestHandshakeAgeSec))
	case s.EverHandshaked && !s.HandshakeFresh && s.TxWithoutRxRounds >= 2:
		return Degraded, fmt.Sprintf("sending traffic but nothing received and latest handshake is %s old", fmtAge(s.NewestHandshakeAgeSec))
	}

	if s.ProbesConfigured > 0 {
		switch {
		case s.ConsecutiveProbeFailures > 0:
			r := fmt.Sprintf("connectivity probes failing (%d consecutive rounds)", s.ConsecutiveProbeFailures)
			if s.HandshakeFresh && s.RxAdvancing {
				r += "; handshake is fresh and data is arriving, so the probe target may be blocking probes"
			}
			return Degraded, r
		case s.ConsecutiveProbeSuccesses > 0:
			r := "connectivity probes succeeding"
			if s.LastProbeLatencyMs > 0 {
				r += fmt.Sprintf(" (%.1f ms)", s.LastProbeLatencyMs)
			}
			return Healthy, r
		default:
			return ConnectedUnverified, "awaiting first connectivity probe"
		}
	}
	switch {
	case s.HandshakeFresh:
		return ConnectedUnverified, "handshake is recent but no connectivity probes are configured, so end-to-end reachability is not verified"
	case !s.EverHandshaked:
		return ConnectedUnverified, "interface up and idle; no handshake yet (no traffic and no keepalive)"
	default:
		return ConnectedUnverified, fmt.Sprintf("interface up and idle; latest handshake %s ago (normal for quiet tunnels without keepalive)", fmtAge(s.NewestHandshakeAgeSec))
	}
}

// applyHysteresis prevents flapping between connected states.
func (m *Machine) applyHysteresis(raw State, reason string) (State, string) {
	cur := m.base
	switch raw {
	case Degraded:
		if cur == Degraded {
			return Degraded, reason
		}
		if m.sig.BadRounds < m.policy.FailureThreshold && (cur == Healthy || cur == ConnectedUnverified || cur == Connecting || cur == Unknown) {
			hold := cur
			if cur == Connecting || cur == Unknown {
				hold = ConnectedUnverified
			}
			return hold, fmt.Sprintf("%s (%d/%d failed rounds before marking degraded)", reason, m.sig.BadRounds, m.policy.FailureThreshold)
		}
		return Degraded, reason
	case Healthy, ConnectedUnverified:
		if (cur == Degraded || cur == Error) && m.sig.GoodRounds < m.policy.RecoveryThreshold {
			return cur, fmt.Sprintf("%s (%d/%d good rounds before clearing)", reason, m.sig.GoodRounds, m.policy.RecoveryThreshold)
		}
		return raw, reason
	}
	return raw, reason
}

func fmtAge(sec float64) string {
	if sec < 0 {
		return "never"
	}
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}
