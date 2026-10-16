// Package config defines WGM's versioned policy model (tunnel ownership,
// health, recovery, kill switch and monitoring preferences) together with
// validation, defaults, persistence and schema migration.
//
// WireGuard's own configuration files remain the source of truth for keys and
// peers. Nothing in this package stores private or preshared keys.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// CurrentSchemaVersion is the policy file schema written by this build.
const CurrentSchemaVersion = 1

// Ownership describes how much authority WGM has over a tunnel.
type Ownership string

const (
	// OwnershipDiscovered tunnels are shown read-only; no probes, no changes.
	OwnershipDiscovered Ownership = "discovered"
	// OwnershipMonitored tunnels get active health probes but WGM never
	// changes their state.
	OwnershipMonitored Ownership = "monitored"
	// OwnershipManaged tunnels may be connected, disconnected and recovered
	// by WGM.
	OwnershipManaged Ownership = "managed"
)

// Valid reports whether o is a known ownership level.
func (o Ownership) Valid() bool {
	switch o {
	case OwnershipDiscovered, OwnershipMonitored, OwnershipManaged:
		return true
	}
	return false
}

// ProbeType selects a connectivity probe implementation.
type ProbeType string

const (
	ProbeICMP ProbeType = "icmp"
	ProbeTCP  ProbeType = "tcp"
	ProbeDNS  ProbeType = "dns"
)

// ProbeSpec is a single active connectivity check. Targets must be IP
// literals so that probes never trigger name resolution outside the tunnel.
type ProbeSpec struct {
	Type      ProbeType `json:"type"`
	Target    string    `json:"target"`
	Port      int       `json:"port,omitempty"`  // tcp only
	Query     string    `json:"query,omitempty"` // dns only: name to resolve
	TimeoutMs int       `json:"timeout_ms,omitempty"`
}

// String renders a short human-readable description of the probe.
func (p ProbeSpec) String() string {
	switch p.Type {
	case ProbeTCP:
		return fmt.Sprintf("tcp %s", netip.AddrPortFrom(mustAddr(p.Target), uint16(p.Port)))
	case ProbeDNS:
		return fmt.Sprintf("dns %s@%s", p.Query, p.Target)
	default:
		return fmt.Sprintf("%s %s", p.Type, p.Target)
	}
}

func mustAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

// HealthPolicy configures the health engine for one tunnel.
type HealthPolicy struct {
	IntervalSec       int         `json:"interval_sec"`
	HandshakeStaleSec int         `json:"handshake_stale_sec"`
	FailureThreshold  int         `json:"failure_threshold"`
	RecoveryThreshold int         `json:"recovery_threshold"`
	ConnectGraceSec   int         `json:"connect_grace_sec"`
	Probes            []ProbeSpec `json:"probes,omitempty"`
}

// RecoveryPolicy configures automatic recovery for a managed tunnel.
type RecoveryPolicy struct {
	Enabled           bool    `json:"enabled"`
	MaxAttempts       int     `json:"max_attempts"`
	InitialBackoffSec int     `json:"initial_backoff_sec"`
	MaxBackoffSec     int     `json:"max_backoff_sec"`
	Multiplier        float64 `json:"multiplier"`
	JitterFraction    float64 `json:"jitter_fraction"`
	BudgetMax         int     `json:"budget_max"`
	BudgetWindowSec   int     `json:"budget_window_sec"`
	VerifyTimeoutSec  int     `json:"verify_timeout_sec"`
	// ReconnectAfterManualDisconnect lets recovery bring a tunnel back up
	// after the user disconnected it. Off by default.
	ReconnectAfterManualDisconnect bool `json:"reconnect_after_manual_disconnect"`
}

// TunnelPolicy is WGM's per-tunnel policy, stored separately from the
// WireGuard configuration.
type TunnelPolicy struct {
	Ownership Ownership      `json:"ownership"`
	Autostart bool           `json:"autostart"`
	Health    HealthPolicy   `json:"health"`
	Recovery  RecoveryPolicy `json:"recovery"`
}

// KillSwitchMode selects the protection strategy.
type KillSwitchMode string

// KillSwitchFullTunnel blocks all egress except via the VPN interface and
// the minimum endpoint bootstrap traffic.
const KillSwitchFullTunnel KillSwitchMode = "full"

// KillSwitchPolicy is the desired kill-switch configuration.
type KillSwitchPolicy struct {
	Enabled   bool           `json:"enabled"`
	Tunnel    string         `json:"tunnel,omitempty"`
	Mode      KillSwitchMode `json:"mode"`
	AllowLAN  bool           `json:"allow_lan"`
	AllowDHCP bool           `json:"allow_dhcp"`
}

// MonitoringPrefs controls sampling and retention.
type MonitoringPrefs struct {
	SampleIntervalSec    int  `json:"sample_interval_sec"`
	PersistHistory       bool `json:"persist_history"`
	MetricsRetentionDays int  `json:"metrics_retention_days"`
	EventRetentionDays   int  `json:"event_retention_days"`
}

// File is the complete on-disk policy document (/etc/wgm/policy.json).
type File struct {
	SchemaVersion int                     `json:"schema_version"`
	Revision      uint64                  `json:"revision"`
	Tunnels       map[string]TunnelPolicy `json:"tunnels"`
	KillSwitch    KillSwitchPolicy        `json:"kill_switch"`
	Monitoring    MonitoringPrefs         `json:"monitoring"`
}

// DefaultHealthPolicy returns conservative defaults.
func DefaultHealthPolicy() HealthPolicy {
	return HealthPolicy{
		IntervalSec:       10,
		HandshakeStaleSec: 180,
		FailureThreshold:  3,
		RecoveryThreshold: 2,
		ConnectGraceSec:   30,
	}
}

// DefaultRecoveryPolicy returns bounded recovery defaults.
func DefaultRecoveryPolicy() RecoveryPolicy {
	return RecoveryPolicy{
		Enabled:           true,
		MaxAttempts:       5,
		InitialBackoffSec: 5,
		MaxBackoffSec:     300,
		Multiplier:        2,
		JitterFraction:    0.2,
		BudgetMax:         10,
		BudgetWindowSec:   3600,
		VerifyTimeoutSec:  45,
	}
}

// DefaultTunnelPolicy is applied to tunnels with no stored policy.
func DefaultTunnelPolicy() TunnelPolicy {
	return TunnelPolicy{
		Ownership: OwnershipDiscovered,
		Health:    DefaultHealthPolicy(),
		Recovery:  DefaultRecoveryPolicy(),
	}
}

// DefaultMonitoringPrefs returns sensible retention limits.
func DefaultMonitoringPrefs() MonitoringPrefs {
	return MonitoringPrefs{
		SampleIntervalSec:    1,
		PersistHistory:       true,
		MetricsRetentionDays: 7,
		EventRetentionDays:   30,
	}
}

// Default returns an empty policy file at the current schema.
func Default() *File {
	return &File{
		SchemaVersion: CurrentSchemaVersion,
		Tunnels:       map[string]TunnelPolicy{},
		KillSwitch:    KillSwitchPolicy{Mode: KillSwitchFullTunnel, AllowDHCP: true},
		Monitoring:    DefaultMonitoringPrefs(),
	}
}

// Clone returns a deep copy.
func (f *File) Clone() *File {
	c := *f
	c.Tunnels = make(map[string]TunnelPolicy, len(f.Tunnels))
	for k, v := range f.Tunnels {
		v.Health.Probes = append([]ProbeSpec(nil), v.Health.Probes...)
		c.Tunnels[k] = v
	}
	return &c
}

// TunnelPolicy returns the stored policy for name or the default.
func (f *File) TunnelPolicy(name string) TunnelPolicy {
	if p, ok := f.Tunnels[name]; ok {
		return p
	}
	return DefaultTunnelPolicy()
}

// TunnelNames returns the sorted names that have stored policies.
func (f *File) TunnelNames() []string {
	names := make([]string, 0, len(f.Tunnels))
	for n := range f.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Linux interface names: 1-15 chars; wg-quick additionally restricts the
// character set to [a-zA-Z0-9_=+.-].
var ifaceNameRE = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

// ValidInterfaceName reports whether name is an acceptable WireGuard
// interface/tunnel name.
func ValidInterfaceName(name string) bool {
	return ifaceNameRE.MatchString(name) && name != "." && name != ".."
}

var hostnameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

// ValidationError collects all problems found in a policy.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid policy: " + strings.Join(e.Problems, "; ")
}

type problems []string

func (p *problems) addf(format string, args ...any) { *p = append(*p, fmt.Sprintf(format, args...)) }

func (p problems) err() error {
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Problems: p}
}

func checkRange(p *problems, field string, v, lo, hi int) {
	if v < lo || v > hi {
		p.addf("%s must be between %d and %d (got %d)", field, lo, hi, v)
	}
}

// MaxProbes bounds the number of probes per tunnel.
const MaxProbes = 8

// ValidateProbe validates one probe specification.
func ValidateProbe(ps ProbeSpec) error {
	var p problems
	validateProbe(&p, "probe", ps)
	return p.err()
}

func validateProbe(p *problems, field string, ps ProbeSpec) {
	addr, err := netip.ParseAddr(ps.Target)
	if err != nil {
		p.addf("%s target %q must be an IP address literal", field, ps.Target)
	} else if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.Zone() != "" {
		p.addf("%s target %s is not a routable unicast address", field, ps.Target)
	}
	if ps.TimeoutMs != 0 {
		checkRange(p, field+" timeout_ms", ps.TimeoutMs, 100, 10000)
	}
	switch ps.Type {
	case ProbeICMP:
		if ps.Port != 0 || ps.Query != "" {
			p.addf("%s: icmp probes take no port or query", field)
		}
	case ProbeTCP:
		checkRange(p, field+" port", ps.Port, 1, 65535)
	case ProbeDNS:
		if ps.Port != 0 {
			p.addf("%s: dns probes always use port 53", field)
		}
		if len(ps.Query) == 0 || len(ps.Query) > 253 || !hostnameRE.MatchString(ps.Query) {
			p.addf("%s query %q is not a valid hostname", field, ps.Query)
		}
	default:
		p.addf("%s type %q is not supported (icmp, tcp, dns)", field, ps.Type)
	}
}

// Validate checks a health policy.
func (h HealthPolicy) Validate() error {
	var p problems
	h.validate(&p, "health")
	return p.err()
}

func (h HealthPolicy) validate(p *problems, prefix string) {
	checkRange(p, prefix+".interval_sec", h.IntervalSec, 2, 3600)
	checkRange(p, prefix+".handshake_stale_sec", h.HandshakeStaleSec, 30, 86400)
	checkRange(p, prefix+".failure_threshold", h.FailureThreshold, 1, 50)
	checkRange(p, prefix+".recovery_threshold", h.RecoveryThreshold, 1, 50)
	checkRange(p, prefix+".connect_grace_sec", h.ConnectGraceSec, 5, 600)
	if len(h.Probes) > MaxProbes {
		p.addf("%s: at most %d probes are allowed", prefix, MaxProbes)
	}
	for i, ps := range h.Probes {
		validateProbe(p, fmt.Sprintf("%s.probes[%d]", prefix, i), ps)
	}
}

// Validate checks a recovery policy.
func (r RecoveryPolicy) Validate() error {
	var p problems
	r.validate(&p, "recovery")
	return p.err()
}

func (r RecoveryPolicy) validate(p *problems, prefix string) {
	checkRange(p, prefix+".max_attempts", r.MaxAttempts, 1, 50)
	checkRange(p, prefix+".initial_backoff_sec", r.InitialBackoffSec, 1, 3600)
	checkRange(p, prefix+".max_backoff_sec", r.MaxBackoffSec, 1, 86400)
	if r.MaxBackoffSec < r.InitialBackoffSec {
		p.addf("%s.max_backoff_sec must be >= initial_backoff_sec", prefix)
	}
	if r.Multiplier < 1 || r.Multiplier > 10 {
		p.addf("%s.multiplier must be between 1 and 10", prefix)
	}
	if r.JitterFraction < 0 || r.JitterFraction > 0.5 {
		p.addf("%s.jitter_fraction must be between 0 and 0.5", prefix)
	}
	checkRange(p, prefix+".budget_max", r.BudgetMax, 1, 1000)
	checkRange(p, prefix+".budget_window_sec", r.BudgetWindowSec, 60, 7*86400)
	checkRange(p, prefix+".verify_timeout_sec", r.VerifyTimeoutSec, 5, 3600)
}

// Validate checks a tunnel policy.
func (t TunnelPolicy) Validate() error {
	var p problems
	t.validate(&p, "tunnel")
	return p.err()
}

func (t TunnelPolicy) validate(p *problems, prefix string) {
	if !t.Ownership.Valid() {
		p.addf("%s.ownership %q is invalid", prefix, t.Ownership)
	}
	if t.Autostart && t.Ownership != OwnershipManaged {
		p.addf("%s.autostart requires ownership %q", prefix, OwnershipManaged)
	}
	t.Health.validate(p, prefix+".health")
	t.Recovery.validate(p, prefix+".recovery")
}

// Validate checks a kill-switch policy (tunnel existence is checked by the
// daemon, which knows the discovered tunnels).
func (k KillSwitchPolicy) Validate() error {
	var p problems
	k.validate(&p)
	return p.err()
}

func (k KillSwitchPolicy) validate(p *problems) {
	if k.Mode != KillSwitchFullTunnel {
		p.addf("kill_switch.mode %q is not supported (only %q)", k.Mode, KillSwitchFullTunnel)
	}
	if (k.Enabled || k.Tunnel != "") && !ValidInterfaceName(k.Tunnel) {
		p.addf("kill_switch.tunnel %q is not a valid interface name", k.Tunnel)
	}
}

// Validate checks monitoring preferences.
func (m MonitoringPrefs) Validate() error {
	var p problems
	m.validate(&p)
	return p.err()
}

func (m MonitoringPrefs) validate(p *problems) {
	checkRange(p, "monitoring.sample_interval_sec", m.SampleIntervalSec, 1, 60)
	checkRange(p, "monitoring.metrics_retention_days", m.MetricsRetentionDays, 1, 365)
	checkRange(p, "monitoring.event_retention_days", m.EventRetentionDays, 1, 3650)
}

// Validate checks the whole document.
func (f *File) Validate() error {
	var p problems
	if f.SchemaVersion != CurrentSchemaVersion {
		p.addf("schema_version %d is not %d", f.SchemaVersion, CurrentSchemaVersion)
	}
	for _, name := range f.TunnelNames() {
		if !ValidInterfaceName(name) {
			p.addf("tunnel name %q is invalid", name)
			continue
		}
		f.Tunnels[name].validate(&p, "tunnels."+name)
	}
	f.KillSwitch.validate(&p)
	f.Monitoring.validate(&p)
	return p.err()
}

// ErrUnsupportedSchema is returned for policy files written by a newer WGM.
var ErrUnsupportedSchema = errors.New("policy schema is newer than this version of WGM")
