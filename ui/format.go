// Package ui implements the unprivileged Fyne desktop client for wgmd.
//
// Presentation helpers in this file are pure functions so they can be unit
// tested without a graphical session. Health evaluation and all policy
// decisions live in the daemon; the UI only renders what the daemon reports.
package ui

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
	"github.com/cmerk2021/wgm/internal/recovery"
)

// FormatBytes renders a cumulative byte count using binary units.
func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// FormatRate renders an instantaneous rate in bytes per second. Invalid
// rates (no baseline yet, counter reset) render as an em dash so they are
// never mistaken for zero traffic.
func FormatRate(bps float64, valid bool) string {
	if !valid || math.IsNaN(bps) || math.IsInf(bps, 0) || bps < 0 {
		return "—"
	}
	if bps < 1024 {
		return fmt.Sprintf("%.0f B/s", bps)
	}
	units := []string{"KiB/s", "MiB/s", "GiB/s"}
	v := bps / 1024
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// FormatAge renders a handshake age; negative means never/unknown.
func FormatAge(sec float64) string {
	if sec < 0 || math.IsNaN(sec) {
		return "never"
	}
	return FormatDuration(time.Duration(sec*float64(time.Second))) + " ago"
}

// FormatDuration renders a coarse human duration.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d.Round(time.Second) / time.Second)
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm %02ds", s/60, s%60)
	case s < 86400:
		return fmt.Sprintf("%dh %02dm", s/3600, (s%3600)/60)
	}
	return fmt.Sprintf("%dd %02dh", s/86400, (s%86400)/3600)
}

// Severity classifies a state for colouring and notifications.
type Severity int

const (
	SevNeutral Severity = iota
	SevGood
	SevWarn
	SevBad
)

// HealthSeverity maps a health state to a severity.
func HealthSeverity(s health.State) Severity {
	switch s {
	case health.Healthy:
		return SevGood
	case health.ConnectedUnverified, health.Connecting, health.Recovering:
		return SevWarn
	case health.Degraded, health.Error:
		return SevBad
	}
	return SevNeutral
}

// HealthIcon returns a short textual marker for a health state, so state is
// conveyed without relying on colour alone.
func HealthIcon(s health.State) string {
	switch HealthSeverity(s) {
	case SevGood:
		return "●"
	case SevWarn:
		return "◐"
	case SevBad:
		return "✖"
	}
	return "○"
}

// InterfaceSummary describes the interface state.
func InterfaceSummary(t api.TunnelStatus) string {
	switch {
	case t.RuntimeError != "":
		return "error"
	case !t.InterfaceExists:
		return "down (no interface)"
	case !t.IsWireGuard:
		return "not WireGuard"
	case !t.InterfaceUp:
		return "admin down"
	}
	return "up"
}

// OwnershipLabel describes how WGM relates to the tunnel.
func OwnershipLabel(t api.TunnelStatus) string {
	s := ""
	switch t.Ownership {
	case config.OwnershipManaged:
		s = "Managed by WGM"
	case config.OwnershipMonitored:
		s = "Monitored (read-only)"
	default:
		s = "Discovered (not monitored)"
	}
	if t.Autostart {
		s += ", autostart"
	}
	if t.KillSwitch {
		s += ", kill switch"
	}
	return s
}

// NewestHandshake returns the smallest non-negative peer handshake age, or
// -1 if no peer has completed a handshake.
func NewestHandshake(t api.TunnelStatus) float64 {
	best := -1.0
	for _, p := range t.Peers {
		if p.HandshakeAgeSec >= 0 && (best < 0 || p.HandshakeAgeSec < best) {
			best = p.HandshakeAgeSec
		}
	}
	return best
}

// KillSwitchLabel summarises the enforced (not requested) kill switch state.
func KillSwitchLabel(ks api.KillSwitchStatus) string {
	st := ks.Status
	switch st.State {
	case firewall.StateEnforced:
		return "Enforced for " + st.Tunnel
	case firewall.StateDisabled:
		if ks.Policy.Enabled {
			return "Requested but NOT enforced"
		}
		return "Disabled"
	case firewall.StateInstalling:
		return "Installing…"
	case firewall.StateRecovering:
		return "Recovering (re-applying rules)"
	case firewall.StateUnavailable:
		return "Unavailable on this system"
	case firewall.StateError:
		return "ERROR: protection state unknown"
	}
	return string(st.State)
}

// KillSwitchSeverity maps the kill switch state to a severity.
func KillSwitchSeverity(ks api.KillSwitchStatus) Severity {
	switch ks.Status.State {
	case firewall.StateEnforced:
		return SevGood
	case firewall.StateDisabled:
		if ks.Policy.Enabled {
			return SevBad
		}
		return SevNeutral
	case firewall.StateInstalling, firewall.StateRecovering:
		return SevWarn
	case firewall.StateUnavailable:
		if ks.Policy.Enabled {
			return SevBad
		}
		return SevNeutral
	}
	return SevBad
}

// RecoverySummary renders recovery progress, or "" when idle.
func RecoverySummary(r recovery.Status, now time.Time) string {
	switch {
	case r.Exhausted:
		s := fmt.Sprintf("Recovery exhausted after %d attempts", r.Attempt)
		if r.LastResult != "" {
			s += ": " + r.LastResult
		}
		return s
	case !r.Active:
		return ""
	}
	s := fmt.Sprintf("Recovering (%s)", strings.ReplaceAll(string(r.Classification), "_", " "))
	if r.Attempt > 0 {
		s += fmt.Sprintf(", attempt %d/%d", r.Attempt, r.MaxAttempts)
	}
	if r.LastAction != recovery.ActionNone {
		s += ", last action: " + strings.ReplaceAll(string(r.LastAction), "_", " ")
	}
	if !r.NextAttemptAt.IsZero() && r.NextAttemptAt.After(now) {
		s += ", next in " + FormatDuration(r.NextAttemptAt.Sub(now))
	}
	return s
}

// ParseProbes parses one probe per non-empty line:
//
//	icmp 10.0.0.1
//	tcp 10.0.0.1:443
//	dns 10.0.0.53 example.com
//
// An optional trailing "timeout=MS" applies to any probe. Results are
// validated with the same rules the daemon enforces.
func ParseProbes(text string) ([]config.ProbeSpec, error) {
	var out []config.ProbeSpec
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ps, err := parseProbe(line)
		if err == nil {
			err = config.ValidateProbe(ps)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d (%q): %w", i+1, line, err)
		}
		out = append(out, ps)
	}
	if len(out) > config.MaxProbes {
		return nil, fmt.Errorf("at most %d probes are allowed", config.MaxProbes)
	}
	return out, nil
}

func parseProbe(line string) (config.ProbeSpec, error) {
	f := strings.Fields(line)
	var ps config.ProbeSpec
	if n := len(f); n > 1 && strings.HasPrefix(f[n-1], "timeout=") {
		ms, err := strconv.Atoi(strings.TrimPrefix(f[n-1], "timeout="))
		if err != nil {
			return ps, errors.New("timeout must be a number of milliseconds")
		}
		ps.TimeoutMs = ms
		f = f[:n-1]
	}
	if len(f) < 2 {
		return ps, errors.New("expected: <icmp|tcp|dns> <target> [query]")
	}
	ps.Type = config.ProbeType(strings.ToLower(f[0]))
	switch ps.Type {
	case config.ProbeICMP:
		if len(f) != 2 {
			return ps, errors.New("expected: icmp <ip>")
		}
		ps.Target = f[1]
	case config.ProbeTCP:
		if len(f) != 2 {
			return ps, errors.New("expected: tcp <ip:port>")
		}
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return ps, errors.New("expected: tcp <ip:port> (use [v6]:port for IPv6)")
		}
		ps.Target, ps.Port = ap.Addr().String(), int(ap.Port())
	case config.ProbeDNS:
		if len(f) != 3 {
			return ps, errors.New("expected: dns <resolver-ip> <name>")
		}
		ps.Target, ps.Query = f[1], f[2]
	default:
		return ps, fmt.Errorf("unknown probe type %q (use icmp, tcp or dns)", f[0])
	}
	return ps, nil
}

// FormatProbes is the inverse of ParseProbes.
func FormatProbes(ps []config.ProbeSpec) string {
	var b strings.Builder
	for _, p := range ps {
		switch p.Type {
		case config.ProbeTCP:
			if a, err := netip.ParseAddr(p.Target); err == nil {
				b.WriteString("tcp " + netip.AddrPortFrom(a, uint16(p.Port)).String())
			} else {
				b.WriteString("tcp " + p.Target)
			}
		case config.ProbeDNS:
			b.WriteString("dns " + p.Target + " " + p.Query)
		default:
			b.WriteString(string(p.Type) + " " + p.Target)
		}
		if p.TimeoutMs > 0 {
			fmt.Fprintf(&b, " timeout=%d", p.TimeoutMs)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// ExplainError turns transport and daemon errors into actionable text.
func ExplainError(err error, socket string) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ipc.ErrUnavailable) {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "permission denied"):
			return "Permission denied on " + socket + ". Add your user to the 'wgm' group (sudo usermod -aG wgm $USER) and log out and back in."
		case strings.Contains(msg, "no such file"), strings.Contains(msg, "connection refused"):
			return "The WGM daemon is not running. Start it with: sudo systemctl enable --now wgmd"
		}
		return "Cannot reach the WGM daemon: " + msg
	}
	var ae *api.Error
	if errors.As(err, &ae) {
		switch ae.Code {
		case api.CodeForbidden:
			return "Not permitted: " + ae.Message
		case api.CodeConflict:
			return "Conflict: " + ae.Message + " (refresh and try again)"
		case api.CodeUnavailable:
			return "Unavailable: " + ae.Message
		case api.CodeTimeout:
			return "The daemon timed out: " + ae.Message
		}
		return ae.Message
	}
	return err.Error()
}

// IsStale reports whether data fetched at t should be presented as stale.
func IsStale(fetched, now time.Time, maxAge time.Duration) bool {
	return fetched.IsZero() || now.Sub(fetched) > maxAge
}

// NiceCeil rounds v up to 1, 2 or 5 times a power of ten (min 1), giving
// stable graph scales.
func NiceCeil(v float64) float64 {
	if v <= 1 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 1
	}
	exp := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*exp*(1+1e-9) {
			return m * exp
		}
	}
	return 10 * exp
}
