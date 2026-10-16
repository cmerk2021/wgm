package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/auth"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/events"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
	"github.com/cmerk2021/wgm/internal/sysexec"
	"github.com/cmerk2021/wgm/internal/tunnel"
)

// Handle implements ipc.Handler. Authorization by operation has already
// been enforced by the transport; field-level rules are enforced here.
func (d *Daemon) Handle(ctx context.Context, c ipc.Caller, op string, params json.RawMessage) (any, *api.Error) {
	switch op {
	case api.OpPing:
		return d.ping(c), nil
	case api.OpListTunnels:
		return d.List(), nil
	case api.OpGetTunnel:
		var p api.NameParams
		if e := decodeName(params, &p); e != nil {
			return nil, e
		}
		st, ok := d.Get(p.Name)
		if !ok {
			return nil, api.Errf(api.CodeNotFound, "unknown tunnel "+p.Name)
		}
		return st, nil
	case api.OpConnect, api.OpDisconnect:
		var p api.NameParams
		if e := decodeName(params, &p); e != nil {
			return nil, e
		}
		var err error
		if op == api.OpConnect {
			err = d.Connect(ctx, p.Name)
		} else {
			err = d.Disconnect(ctx, p.Name)
		}
		if err != nil {
			return nil, toAPIError(err)
		}
		st, _ := d.Get(p.Name)
		return st, nil
	case api.OpSetTunnelPolicy:
		var p api.SetTunnelPolicyParams
		if e := ipc.DecodeParams(params, &p); e != nil {
			return nil, e
		}
		return d.setTunnelPolicy(c, p)
	case api.OpRescan:
		d.Rescan()
		return d.List(), nil
	case api.OpGetKillSwitch:
		return d.KillSwitch(), nil
	case api.OpSetKillSwitch:
		var p api.SetKillSwitchParams
		if e := ipc.DecodeParams(params, &p); e != nil {
			return nil, e
		}
		return d.setKillSwitch(ctx, p)
	case api.OpGetPolicy:
		return d.o.Store.Get(), nil
	case api.OpSetMonitoring:
		var p api.SetMonitoringParams
		if e := ipc.DecodeParams(params, &p); e != nil {
			return nil, e
		}
		if err := p.Monitoring.Validate(); err != nil {
			return nil, api.Errf(api.CodeBadRequest, err.Error())
		}
		f, err := d.o.Store.Update(p.ExpectedRevision, func(f *config.File) error {
			f.Monitoring = p.Monitoring
			return nil
		})
		if err != nil {
			return nil, toAPIError(err)
		}
		d.Events.Add("", events.KindConfig, events.Info, "monitoring preferences updated by uid "+uidStr(c))
		return f, nil
	case api.OpEvents:
		var p api.EventsParams
		if e := ipc.DecodeParams(params, &p); e != nil {
			return nil, e
		}
		if p.Tunnel != "" && !config.ValidInterfaceName(p.Tunnel) {
			return nil, api.Errf(api.CodeBadRequest, "invalid tunnel name")
		}
		if p.Limit <= 0 || p.Limit > 2000 {
			p.Limit = 500
		}
		return toViews(d.Events.Query(p.Tunnel, p.SinceID, p.Limit)), nil
	case api.OpMetrics:
		var p api.MetricsParams
		if e := ipc.DecodeParams(params, &p); e != nil {
			return nil, e
		}
		return d.metrics(ctx, p)
	case api.OpDiagnostics:
		return d.Diagnostics(ctx), nil
	}
	return nil, api.Errf(api.CodeUnknownOp, "unknown operation "+op)
}

func uidStr(c ipc.Caller) string { return strconv.FormatUint(uint64(c.Peer.UID), 10) }

func decodeName(params json.RawMessage, p *api.NameParams) *api.Error {
	if e := ipc.DecodeParams(params, p); e != nil {
		return e
	}
	if !config.ValidInterfaceName(p.Name) {
		return api.Errf(api.CodeBadRequest, "invalid tunnel name")
	}
	return nil
}

func toAPIError(err error) *api.Error {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae
	}
	var ve *config.ValidationError
	switch {
	case errors.As(err, &ve):
		return api.Errf(api.CodeBadRequest, err.Error())
	case errors.Is(err, config.ErrConflict):
		return api.Errf(api.CodeConflict, err.Error())
	}
	return api.Errf(api.CodeInternal, err.Error())
}

func toViews(evs []events.Event) []api.EventView {
	out := make([]api.EventView, 0, len(evs))
	for _, e := range evs {
		out = append(out, api.EventView{ID: e.ID, Time: e.Time, Tunnel: e.Tunnel, Kind: string(e.Kind), Severity: string(e.Severity), Message: e.Message})
	}
	return out
}

func (d *Daemon) ping(c ipc.Caller) api.PingResult {
	r := api.PingResult{
		DaemonVersion: d.o.Version, ProtocolVersion: api.ProtocolVersion,
		UID: c.Peer.UID, Role: c.Role, OperatorGroup: d.o.OperatorGroup, AdminGroup: d.o.AdminGroup,
		StartedAt: d.started,
	}
	if d.o.Backend != nil {
		r.Backend = d.o.Backend.Name()
	}
	if err := d.o.Store.ReadOnlyReason(); err != nil {
		r.PolicyReadOnly = err.Error()
	}
	return r
}

// Rescan forces configuration discovery and a monitoring cycle.
func (d *Daemon) Rescan() {
	d.tickMu.Lock()
	d.refreshDiscovery(d.now())
	d.tickMu.Unlock()
	d.Poke()
}

// List returns all tunnels.
func (d *Daemon) List() api.TunnelList {
	pol := d.o.Store.Get()
	d.mu.Lock()
	defer d.mu.Unlock()
	out := api.TunnelList{PolicyRev: pol.Revision, ConfigDir: d.o.ConfigDir, GeneratedAt: d.now()}
	out.DiscoveryErr = strings.TrimPrefix(strings.Join([]string{d.discErr, d.runtimeErr}, "; "), "; ")
	out.DiscoveryErr = strings.TrimSuffix(out.DiscoveryErr, "; ")
	names := make([]string, 0, len(d.tunnels))
	for n := range d.tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out.Tunnels = append(out.Tunnels, d.statusLocked(d.tunnels[n], pol, false))
	}
	return out
}

// Get returns one tunnel with its health history.
func (d *Daemon) Get(name string) (api.TunnelStatus, bool) {
	pol := d.o.Store.Get()
	d.mu.Lock()
	defer d.mu.Unlock()
	ts := d.tunnels[name]
	if ts == nil {
		return api.TunnelStatus{}, false
	}
	return d.statusLocked(ts, pol, true), true
}

func ageSec(now, t time.Time) float64 {
	if t.IsZero() {
		return -1
	}
	a := now.Sub(t).Seconds()
	if a < 0 {
		a = 0
	}
	return a
}

func (d *Daemon) statusLocked(ts *tunnelState, pol *config.File, withHistory bool) api.TunnelStatus {
	now := d.now()
	tp := pol.TunnelPolicy(ts.name)
	intent, _ := d.intentLocked(ts.name)
	st := api.TunnelStatus{
		Name: ts.name, Ownership: tp.Ownership, Autostart: tp.Autostart, Policy: tp, Intent: intent,
		ConfigChanged: ts.configChanged, ExternalOwner: ts.owner,
		KillSwitch:      pol.KillSwitch.Enabled && pol.KillSwitch.Tunnel == ts.name,
		InterfaceExists: ts.rt.Exists, InterfaceUp: ts.rt.Up, IsWireGuard: ts.rt.IsWireGuard,
		RuntimeError: ts.rt.Err, Addresses: ts.rt.Addresses, Routes: ts.rt.Routes,
		ListenPort: ts.rt.ListenPort, FwMark: ts.rt.FwMark,
		Health:    ts.machine.Snapshot(),
		Recovery:  ts.rec.Status(now),
		UpdatedAt: ts.last.At,
	}
	if d.o.Backend != nil {
		st.Backend = d.o.Backend.Name()
	}
	st.ManageBlocker = d.manageBlockerLocked(ts)
	st.Manageable = st.ManageBlocker == ""
	if !ts.upSince.IsZero() {
		u := ts.upSince
		st.UpSince = &u
	}
	cfgPeers := map[string]tunnel.PeerConfig{}
	if ts.disc != nil {
		st.ConfigPath = ts.disc.Path
		st.ConfigError = ts.disc.Err
		st.ConfigPresent = true
		if c := ts.disc.Config; c != nil {
			st.ConfigWarnings = c.Warnings
			st.Hooks = c.Hooks
			st.SaveConfig = c.SaveConfig
			st.FullTunnelV4, st.FullTunnelV6 = c.FullTunnel()
			st.DNS = c.DNS
			if len(st.Addresses) == 0 {
				st.Addresses = c.Addresses
			}
			for _, p := range c.Peers {
				cfgPeers[p.PublicKey] = p
			}
		}
	}
	rx, tx := ts.rt.RxTx()
	st.RxBytes, st.TxBytes = rx, tx
	st.RxRate, st.TxRate, st.RateValid = ts.last.Rx, ts.last.Tx, ts.last.Valid
	seen := map[string]bool{}
	for _, p := range ts.rt.Peers {
		seen[p.PublicKey] = true
		ps := api.PeerStatus{
			PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs,
			LastHandshake: p.LastHandshake, HandshakeAgeSec: ageSec(now, p.LastHandshake),
			PersistentKeepalive: int(p.PersistentKeepalive.Seconds()),
			RxBytes:             p.RxBytes, TxBytes: p.TxBytes,
		}
		if r, ok := ts.peerLast[p.PublicKey]; ok {
			ps.RxRate, ps.TxRate, ps.RateValid = r.Rx, r.Tx, r.Valid
		}
		if cp, ok := cfgPeers[p.PublicKey]; ok {
			ps.ConfiguredEndpoint = cp.Endpoint
			ps.HasPresharedKey = cp.HasPresharedKey
		}
		st.Peers = append(st.Peers, ps)
	}
	if ts.disc != nil && ts.disc.Config != nil {
		for _, cp := range ts.disc.Config.Peers {
			if seen[cp.PublicKey] {
				continue
			}
			st.Peers = append(st.Peers, api.PeerStatus{
				PublicKey: cp.PublicKey, ConfiguredEndpoint: cp.Endpoint, AllowedIPs: cp.AllowedIPs,
				HandshakeAgeSec: -1, PersistentKeepalive: cp.PersistentKeepalive, HasPresharedKey: cp.HasPresharedKey,
			})
		}
	}
	if withHistory {
		st.HealthHistory = ts.machine.History()
	}
	return st
}

func (d *Daemon) setTunnelPolicy(c ipc.Caller, p api.SetTunnelPolicyParams) (any, *api.Error) {
	if !config.ValidInterfaceName(p.Name) {
		return nil, api.Errf(api.CodeBadRequest, "invalid tunnel name")
	}
	if err := p.Policy.Validate(); err != nil {
		return nil, api.Errf(api.CodeBadRequest, err.Error())
	}
	cur := d.o.Store.Get().TunnelPolicy(p.Name)
	ownershipChange := cur.Ownership != p.Policy.Ownership || cur.Autostart != p.Policy.Autostart
	if ownershipChange && !auth.Allows(c.Role, api.RoleAdmin) {
		return nil, api.Errf(api.CodeForbidden, "changing ownership or autostart requires the admin role (member of "+d.o.AdminGroup+")")
	}
	d.mu.Lock()
	ts := d.tunnels[p.Name]
	_, hasConf := d.disc[p.Name]
	if ts == nil && !hasConf {
		d.mu.Unlock()
		return nil, api.Errf(api.CodeNotFound, "unknown tunnel "+p.Name)
	}
	if p.Policy.Ownership == config.OwnershipManaged && cur.Ownership != config.OwnershipManaged && ts != nil {
		if b := d.manageBlockerLocked(ts); b != "" {
			d.mu.Unlock()
			return nil, api.Errf(api.CodeConflict, "cannot manage "+p.Name+": "+b)
		}
	}
	d.mu.Unlock()

	f, err := d.o.Store.Update(p.ExpectedRevision, func(f *config.File) error {
		if f.Tunnels == nil {
			f.Tunnels = map[string]config.TunnelPolicy{}
		}
		f.Tunnels[p.Name] = p.Policy
		return nil
	})
	if err != nil {
		return nil, toAPIError(err)
	}
	d.applyPolicy(f)
	d.mu.Lock()
	if ts := d.tunnels[p.Name]; ts != nil && p.Policy.Ownership == config.OwnershipManaged && cur.Ownership != config.OwnershipManaged && ts.rt.Exists {
		// Adopting a running tunnel: keep it up from now on.
		fpr := ""
		if ts.disc != nil {
			fpr = fp(*ts.disc)
		}
		d.setIntentLocked(p.Name, health.IntentUp, fpr)
	}
	if ts := d.tunnels[p.Name]; ts != nil {
		ts.lastRound = time.Time{}
	}
	d.mu.Unlock()
	msg := "policy updated by uid " + uidStr(c)
	if cur.Ownership != p.Policy.Ownership {
		msg += "; ownership " + string(cur.Ownership) + " → " + string(p.Policy.Ownership)
	}
	if cur.Autostart != p.Policy.Autostart {
		if p.Policy.Autostart {
			msg += "; autostart enabled"
		} else {
			msg += "; autostart disabled"
		}
	}
	d.Events.Add(p.Name, events.KindConfig, events.Info, msg)
	d.Poke()
	st, _ := d.Get(p.Name)
	return st, nil
}

// KillSwitch returns the kill switch policy and its actual enforcement.
func (d *Daemon) KillSwitch() api.KillSwitchStatus {
	pol := d.o.Store.Get()
	out := api.KillSwitchStatus{Policy: pol.KillSwitch, PolicyRev: pol.Revision}
	if d.o.Firewall == nil {
		out.Status = firewall.Status{State: firewall.StateUnavailable, Reason: d.o.FirewallUnavailable}
		if out.Status.Reason == "" {
			out.Status.Reason = "nftables integration is not available"
		}
	} else {
		out.Status = d.o.Firewall.Status()
	}
	d.mu.Lock()
	out.Warnings = append([]string(nil), d.ksWarnings...)
	d.mu.Unlock()
	return out
}

func (d *Daemon) setKillSwitch(ctx context.Context, p api.SetKillSwitchParams) (any, *api.Error) {
	if d.o.Firewall == nil {
		return nil, api.Errf(api.CodeUnavailable, "kill switch unavailable: "+d.o.FirewallUnavailable)
	}
	if p.Policy.Mode == "" {
		p.Policy.Mode = config.KillSwitchFullTunnel
	}
	if err := p.Policy.Validate(); err != nil {
		return nil, api.Errf(api.CodeBadRequest, err.Error())
	}
	if p.Policy.Enabled {
		d.mu.Lock()
		nd, ok := d.disc[p.Policy.Tunnel]
		d.mu.Unlock()
		if !ok || nd.Config == nil {
			return nil, api.Errf(api.CodeBadRequest, "the kill switch can only protect a tunnel with a readable configuration in "+d.o.ConfigDir)
		}
		if v4, _ := nd.Config.FullTunnel(); !v4 {
			return nil, api.Errf(api.CodeBadRequest, "full-tunnel kill switch requires a peer with AllowedIPs 0.0.0.0/0; split-tunnel protection is not supported yet")
		}
		if err := d.resolveEndpoints(ctx, p.Policy.Tunnel); err != nil {
			d.Events.Add(p.Policy.Tunnel, events.KindKillSwitch, events.Warning, err.Error())
		}
	}
	_, err := d.o.Store.Update(p.ExpectedRevision, func(f *config.File) error {
		f.KillSwitch = p.Policy
		return nil
	})
	if err != nil {
		return nil, toAPIError(err)
	}
	verb := "disabled"
	if p.Policy.Enabled {
		verb = "enabled for " + p.Policy.Tunnel
	}
	d.Events.Add(p.Policy.Tunnel, events.KindKillSwitch, events.Info, "kill switch "+verb+" by administrator")
	d.reconcileKillSwitch(ctx, false)
	return d.KillSwitch(), nil
}

func (d *Daemon) metrics(ctx context.Context, p api.MetricsParams) (any, *api.Error) {
	if !config.ValidInterfaceName(p.Name) {
		return nil, api.Errf(api.CodeBadRequest, "invalid tunnel name")
	}
	if p.WindowSec < 0 || p.WindowSec > 3600 || p.HistoryHours < 0 || p.HistoryHours > 24*365 {
		return nil, api.Errf(api.CodeBadRequest, "window_sec must be 0..3600 and history_hours 0..8760")
	}
	if p.WindowSec == 0 && p.HistoryHours == 0 {
		p.WindowSec = 300
	}
	now := d.now()
	res := api.MetricsResult{Name: p.Name, Interval: d.o.Store.Get().Monitoring.SampleIntervalSec}
	d.mu.Lock()
	ts := d.tunnels[p.Name]
	if ts == nil {
		d.mu.Unlock()
		return nil, api.Errf(api.CodeNotFound, "unknown tunnel "+p.Name)
	}
	if p.WindowSec > 0 {
		since := now.Add(-time.Duration(p.WindowSec) * time.Second)
		for _, r := range ts.ring.Since(since) {
			res.Live = append(res.Live, api.MetricPoint{T: r.At, RxRate: r.Rx, TxRate: r.Tx, Valid: r.Valid})
		}
		for _, l := range ts.latency {
			if !l.T.Before(since) {
				res.Latency = append(res.Latency, l)
			}
		}
	}
	d.mu.Unlock()
	if p.HistoryHours > 0 {
		if d.o.History == nil {
			return nil, api.Errf(api.CodeUnavailable, "history persistence is disabled")
		}
		rows, err := d.o.History.Metrics(ctx, p.Name, now.Add(-time.Duration(p.HistoryHours)*time.Hour), 20000)
		if err != nil {
			return nil, api.Errf(api.CodeInternal, "cannot read history: "+err.Error())
		}
		for _, r := range rows {
			res.History = append(res.History, api.MetricPoint{T: r.Start, RxRate: r.RxRate, TxRate: r.TxRate, Valid: r.Seconds > 0, LatencyMs: r.LatencyMs})
		}
	}
	return res, nil
}

// Diagnostics returns a redacted, shareable report.
func (d *Daemon) Diagnostics(ctx context.Context) api.Diagnostics {
	out := api.Diagnostics{
		GeneratedAt: d.now(), DaemonVersion: d.o.Version,
		Host:    map[string]string{"go": runtime.Version(), "arch": runtime.GOARCH},
		Tools:   map[string]bool{},
		Configs: map[string]*tunnel.Config{},
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		out.Host["kernel"] = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				out.Host["os"] = strings.Trim(v, `"`)
			}
		}
	}
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			out.Host["selinux"] = "enforcing"
		} else {
			out.Host["selinux"] = "permissive"
		}
	} else {
		out.Host["selinux"] = "disabled or unavailable"
	}
	for _, t := range []string{"wg", "wg-quick", "ip", "nft", "nmcli", "systemctl"} {
		_, err := sysexec.Resolve(t)
		out.Tools[t] = err == nil
	}
	out.Tunnels = d.List().Tunnels
	d.mu.Lock()
	for n, nd := range d.disc {
		out.Configs[n] = nd.Config // redacted by construction
	}
	d.mu.Unlock()
	out.KillSwitch = d.KillSwitch()
	out.Policy = d.o.Store.Get()
	out.Events = toViews(d.Events.Query("", 0, 300))
	for i := range out.Events {
		out.Events[i].Message = sysexec.RedactKeys(out.Events[i].Message)
	}
	return out
}
