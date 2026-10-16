// Package api defines WGM's versioned local IPC protocol: newline-delimited
// JSON request/response messages over a Unix domain socket.
//
// See docs/IPC.md for the full specification.
package api

import (
	"encoding/json"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/recovery"
	"github.com/cmerk2021/wgm/internal/tunnel"
)

// ProtocolVersion is the wire protocol version. Requests carrying a
// different version are rejected with CodeUnsupportedVersion.
const ProtocolVersion = 1

// DefaultSocketPath is the daemon's control socket.
const DefaultSocketPath = "/run/wgmd/control.sock"

// Size limits.
const (
	MaxRequestSize  = 64 << 10
	MaxResponseSize = 16 << 20
)

// Operation names (the complete allowlist).
const (
	OpPing            = "ping"
	OpListTunnels     = "tunnels.list"
	OpGetTunnel       = "tunnels.get"
	OpConnect         = "tunnels.connect"
	OpDisconnect      = "tunnels.disconnect"
	OpSetTunnelPolicy = "tunnels.set_policy"
	OpRescan          = "tunnels.rescan"
	OpGetKillSwitch   = "killswitch.get"
	OpSetKillSwitch   = "killswitch.set"
	OpGetPolicy       = "policy.get"
	OpSetMonitoring   = "monitoring.set"
	OpEvents          = "events.list"
	OpMetrics         = "metrics.get"
	OpDiagnostics     = "diagnostics.get"
)

// Request is a client message.
type Request struct {
	Version int             `json:"version"`
	ID      uint64          `json:"id"`
	Op      string          `json:"op"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a daemon message.
type Response struct {
	Version int             `json:"version"`
	ID      uint64          `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error codes.
const (
	CodeBadRequest         = "bad_request"
	CodeUnsupportedVersion = "unsupported_version"
	CodeUnknownOp          = "unknown_op"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeConflict           = "conflict"
	CodeUnavailable        = "unavailable"
	CodeTimeout            = "timeout"
	CodeBusy               = "busy"
	CodeInternal           = "internal"
)

// Error is a structured error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errf builds an Error.
func Errf(code, msg string) *Error { return &Error{Code: code, Message: msg} }

// Role is a caller's authorization level.
type Role string

const (
	RoleNone     Role = "none"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// PingResult answers OpPing.
type PingResult struct {
	DaemonVersion   string    `json:"daemon_version"`
	ProtocolVersion int       `json:"protocol_version"`
	UID             uint32    `json:"uid"`
	Role            Role      `json:"role"`
	OperatorGroup   string    `json:"operator_group"`
	AdminGroup      string    `json:"admin_group"`
	StartedAt       time.Time `json:"started_at"`
	Backend         string    `json:"backend"`
	PolicyReadOnly  string    `json:"policy_read_only,omitempty"`
}

// NameParams selects a tunnel.
type NameParams struct {
	Name string `json:"name"`
}

// SetTunnelPolicyParams updates a tunnel policy.
type SetTunnelPolicyParams struct {
	Name             string              `json:"name"`
	Policy           config.TunnelPolicy `json:"policy"`
	ExpectedRevision uint64              `json:"expected_revision,omitempty"`
}

// SetKillSwitchParams updates the kill switch policy.
type SetKillSwitchParams struct {
	Policy           config.KillSwitchPolicy `json:"policy"`
	ExpectedRevision uint64                  `json:"expected_revision,omitempty"`
}

// SetMonitoringParams updates monitoring preferences.
type SetMonitoringParams struct {
	Monitoring       config.MonitoringPrefs `json:"monitoring"`
	ExpectedRevision uint64                 `json:"expected_revision,omitempty"`
}

// EventsParams queries the event log.
type EventsParams struct {
	Tunnel  string `json:"tunnel,omitempty"`
	SinceID int64  `json:"since_id,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// MetricsParams queries throughput history.
type MetricsParams struct {
	Name string `json:"name"`
	// WindowSec selects live (in-memory, per-sample) history; at most 3600.
	WindowSec int `json:"window_sec,omitempty"`
	// HistoryHours selects persisted per-minute aggregates; at most 24*365.
	HistoryHours int `json:"history_hours,omitempty"`
}

// PeerStatus is a peer's combined configuration and runtime view.
type PeerStatus struct {
	PublicKey           string    `json:"public_key"`
	Endpoint            string    `json:"endpoint,omitempty"`
	ConfiguredEndpoint  string    `json:"configured_endpoint,omitempty"`
	AllowedIPs          []string  `json:"allowed_ips,omitempty"`
	LastHandshake       time.Time `json:"last_handshake,omitempty"`
	HandshakeAgeSec     float64   `json:"handshake_age_sec"` // -1: never / unknown
	PersistentKeepalive int       `json:"persistent_keepalive_sec,omitempty"`
	HasPresharedKey     bool      `json:"has_preshared_key"`
	RxBytes             uint64    `json:"rx_bytes"`
	TxBytes             uint64    `json:"tx_bytes"`
	RxRate              float64   `json:"rx_rate"`
	TxRate              float64   `json:"tx_rate"`
	RateValid           bool      `json:"rate_valid"`
}

// TunnelStatus is the full view of one tunnel.
type TunnelStatus struct {
	Name           string   `json:"name"`
	ConfigPath     string   `json:"config_path,omitempty"`
	ConfigPresent  bool     `json:"config_present"`
	ConfigError    string   `json:"config_error,omitempty"`
	ConfigChanged  bool     `json:"config_changed"`
	ConfigWarnings []string `json:"config_warnings,omitempty"`
	Hooks          []string `json:"hooks,omitempty"`
	SaveConfig     bool     `json:"save_config"`
	FullTunnelV4   bool     `json:"full_tunnel_v4"`
	FullTunnelV6   bool     `json:"full_tunnel_v6"`

	Ownership     config.Ownership    `json:"ownership"`
	Autostart     bool                `json:"autostart"`
	Policy        config.TunnelPolicy `json:"policy"`
	Backend       string              `json:"backend"`
	ExternalOwner string              `json:"external_owner,omitempty"`
	Manageable    bool                `json:"manageable"`
	ManageBlocker string              `json:"manage_blocker,omitempty"`
	Intent        health.Intent       `json:"intent,omitempty"`
	KillSwitch    bool                `json:"kill_switch"`

	InterfaceExists bool       `json:"interface_exists"`
	InterfaceUp     bool       `json:"interface_up"`
	IsWireGuard     bool       `json:"is_wireguard"`
	RuntimeError    string     `json:"runtime_error,omitempty"`
	Addresses       []string   `json:"addresses,omitempty"`
	Routes          []string   `json:"routes,omitempty"`
	DNS             []string   `json:"dns,omitempty"`
	ListenPort      int        `json:"listen_port,omitempty"`
	FwMark          int        `json:"fwmark,omitempty"`
	UpSince         *time.Time `json:"up_since,omitempty"`

	Peers     []PeerStatus `json:"peers,omitempty"`
	RxBytes   uint64       `json:"rx_bytes"`
	TxBytes   uint64       `json:"tx_bytes"`
	RxRate    float64      `json:"rx_rate"`
	TxRate    float64      `json:"tx_rate"`
	RateValid bool         `json:"rate_valid"`

	Health        health.Snapshot     `json:"health"`
	HealthHistory []health.Transition `json:"health_history,omitempty"`
	Recovery      recovery.Status     `json:"recovery"`

	UpdatedAt time.Time `json:"updated_at"`
}

// TunnelList answers OpListTunnels.
type TunnelList struct {
	Tunnels      []TunnelStatus `json:"tunnels"`
	PolicyRev    uint64         `json:"policy_revision"`
	DiscoveryErr string         `json:"discovery_error,omitempty"`
	ConfigDir    string         `json:"config_dir"`
	GeneratedAt  time.Time      `json:"generated_at"`
}

// KillSwitchStatus answers OpGetKillSwitch.
type KillSwitchStatus struct {
	Policy    config.KillSwitchPolicy `json:"policy"`
	Status    firewall.Status         `json:"status"`
	Warnings  []string                `json:"warnings,omitempty"`
	PolicyRev uint64                  `json:"policy_revision"`
}

// MetricPoint is one live sample.
type MetricPoint struct {
	T         time.Time `json:"t"`
	RxRate    float64   `json:"rx"`
	TxRate    float64   `json:"tx"`
	Valid     bool      `json:"valid"`
	LatencyMs float64   `json:"latency_ms,omitempty"`
}

// MetricsResult answers OpMetrics.
type MetricsResult struct {
	Name     string        `json:"name"`
	Live     []MetricPoint `json:"live,omitempty"`
	Latency  []MetricPoint `json:"latency,omitempty"`
	History  []MetricPoint `json:"history,omitempty"`
	Interval int           `json:"interval_sec"`
}

// Diagnostics answers OpDiagnostics. It is safe to share: no private or
// preshared keys, no hook commands.
type Diagnostics struct {
	GeneratedAt   time.Time                 `json:"generated_at"`
	DaemonVersion string                    `json:"daemon_version"`
	Host          map[string]string         `json:"host"`
	Tools         map[string]bool           `json:"tools"`
	Tunnels       []TunnelStatus            `json:"tunnels"`
	Configs       map[string]*tunnel.Config `json:"configs"`
	KillSwitch    KillSwitchStatus          `json:"kill_switch"`
	Policy        *config.File              `json:"policy"`
	Events        []EventView               `json:"events"`
}

// EventView mirrors events.Event for the wire.
type EventView struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Tunnel   string    `json:"tunnel,omitempty"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
}
