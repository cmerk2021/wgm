// Package service wires discovery, runtime reading, metrics, health,
// recovery, the kill switch and persistence into the wgmd daemon, and
// implements the IPC request handlers.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/backend"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/events"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/metrics"
	"github.com/cmerk2021/wgm/internal/recovery"
	"github.com/cmerk2021/wgm/internal/tunnel"
)

// Options configures a Daemon. Interfaces allow tests to inject fakes.
type Options struct {
	ConfigDir string
	Store     *config.Store
	StatePath string // "" disables runtime-state persistence
	Reader    tunnel.Reader
	Prober    health.Prober
	Backend   backend.Backend   // nil: tunnel management unavailable
	Firewall  *firewall.Manager // nil: kill switch unavailable
	History   *events.History   // nil: no persistent history
	Clock     health.Clock
	Log       *slog.Logger
	// Resolve resolves hostname endpoints (kill switch pinning).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)

	Version       string
	OperatorGroup string
	AdminGroup    string
	// FirewallUnavailable explains why Firewall is nil.
	FirewallUnavailable string

	// Synchronous runs probes and recovery actions inline (tests).
	Synchronous bool
	// LiveSamples is the live metrics ring size (default 3600).
	LiveSamples int
}

const (
	discoveryEvery = 5 * time.Second
	policyEvery    = 5 * time.Second
	killSwitchEvry = 5 * time.Second
	ownerEvery     = 30 * time.Second
	pruneEvery     = time.Hour
	maxLatencyPts  = 720
)

type tunnelState struct {
	name          string
	disc          *tunnel.Discovered
	baseline      string
	configChanged bool

	rt      tunnel.Runtime
	seen    bool
	upSince time.Time

	rate     metrics.RateCalc
	ring     *metrics.Ring
	last     metrics.Rate
	peerRate map[string]*metrics.RateCalc
	peerLast map[string]metrics.Rate
	latency  []api.MetricPoint
	agg      metrics.Aggregator

	machine *health.Machine
	rec     *recovery.Engine

	lastRound  time.Time
	probing    bool
	pending    []health.ProbeResult
	hasPending bool
	acting     bool
	lastRecMsg string

	owner   string
	ownerAt time.Time
}

// Daemon is the long-running wgmd service.
type Daemon struct {
	o      Options
	Events *events.Log

	tickMu     sync.Mutex // serializes Tick and Rescan
	mu         sync.Mutex
	tunnels    map[string]*tunnelState
	disc       map[string]tunnel.Discovered
	discErr    string
	runtimeErr string
	state      *runtimeState
	started    time.Time
	underlay   bool
	ksWarnings []string

	lastDiscovery, lastPolicy, lastKS, lastPrune time.Time
	policyErr                                    string

	wake   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	async  sync.WaitGroup
}

// New creates a daemon. It does not start any background work.
func New(o Options) (*Daemon, error) {
	if o.Store == nil || o.Reader == nil {
		return nil, errors.New("service: Store and Reader are required")
	}
	if o.Clock == nil {
		o.Clock = health.SystemClock{}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Prober == nil {
		o.Prober = health.InterfaceProber{}
	}
	if o.LiveSamples <= 0 {
		o.LiveSamples = 3600
	}
	if o.ConfigDir == "" {
		o.ConfigDir = tunnel.DefaultConfigDir
	}
	d := &Daemon{
		o:       o,
		tunnels: map[string]*tunnelState{},
		disc:    map[string]tunnel.Discovered{},
		wake:    make(chan struct{}, 1),
		started: o.Clock.Now(),
	}
	d.ctx, d.cancel = context.WithCancel(context.Background())

	var startID int64
	var sink events.Sink
	if o.History != nil {
		sink = o.History
		if id, err := o.History.MaxEventID(); err == nil {
			startID = id
		}
	}
	d.Events = events.NewLog(2000, startID, sink, o.Log)
	if o.History != nil {
		if evs, err := o.History.RecentEvents(500); err == nil {
			d.Events.Preload(evs)
		}
	}

	st, err := loadRuntimeState(o.StatePath)
	if err != nil {
		d.Events.Add("", events.KindDaemon, events.Warning, "runtime state could not be loaded and was reset: "+err.Error())
	}
	d.state = st

	if o.Firewall != nil {
		o.Firewall.OnChange = func(old, nw firewall.Status) {
			sev := events.Info
			switch nw.State {
			case firewall.StateError, firewall.StateUnavailable:
				sev = events.Error
			case firewall.StateRecovering:
				sev = events.Warning
			}
			msg := fmt.Sprintf("kill switch %s → %s", old.State, nw.State)
			if nw.Reason != "" {
				msg += ": " + nw.Reason
			}
			d.Events.Add(nw.Tunnel, events.KindKillSwitch, sev, msg)
		}
	}
	return d, nil
}

func (d *Daemon) now() time.Time { return d.o.Clock.Now() }

// Poke requests an immediate tick.
func (d *Daemon) Poke() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run executes the monitoring loop until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	d.Startup(ctx)
	interval := d.sampleInterval()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.Shutdown()
			return nil
		case <-t.C:
		case <-d.wake:
		}
		d.Tick(ctx)
		if iv := d.sampleInterval(); iv != interval {
			interval = iv
			t.Reset(iv)
		}
	}
}

func (d *Daemon) sampleInterval() time.Duration {
	s := d.o.Store.Get().Monitoring.SampleIntervalSec
	if s < 1 {
		s = 1
	}
	return time.Duration(s) * time.Second
}

// Startup performs initial discovery, kill switch reconciliation,
// adoption of running managed tunnels and autostart.
func (d *Daemon) Startup(ctx context.Context) {
	d.Events.Add("", events.KindDaemon, events.Info, "wgmd "+d.o.Version+" started")
	if err := d.o.Store.ReadOnlyReason(); err != nil {
		d.Events.Add("", events.KindConfig, events.Error, "policy file cannot be used and will not be modified: "+err.Error())
	}
	if d.o.Firewall == nil && d.o.FirewallUnavailable != "" {
		d.Events.Add("", events.KindKillSwitch, events.Warning, "kill switch unavailable: "+d.o.FirewallUnavailable)
	}
	// Kill switch first: protection must be in place before tunnels start.
	d.reconcileKillSwitch(ctx, true)
	d.Tick(ctx)

	pol := d.o.Store.Get()
	var toStart []string
	d.mu.Lock()
	for name, ts := range d.tunnels {
		tp := pol.TunnelPolicy(name)
		if tp.Ownership != config.OwnershipManaged {
			continue
		}
		rec, has := d.state.Intents[name]
		switch {
		case ts.rt.Exists && !has:
			d.setIntentLocked(name, health.IntentUp, "")
			d.Events.Add(name, events.KindAction, events.Info, "managed tunnel was already running; WGM will keep it up")
		case !ts.rt.Exists && tp.Autostart && (!has || rec.Intent != health.IntentDown):
			toStart = append(toStart, name)
		case !ts.rt.Exists && tp.Autostart:
			d.Events.Add(name, events.KindAction, events.Info, "autostart skipped: tunnel was manually disconnected")
		}
	}
	d.mu.Unlock()
	sort.Strings(toStart)
	for _, name := range toStart {
		d.Events.Add(name, events.KindAction, events.Info, "autostart: connecting")
		if err := d.Connect(ctx, name); err != nil {
			d.Events.Add(name, events.KindAction, events.Error, "autostart failed: "+err.Error())
		}
	}
}

// Shutdown stops background work. The kill switch is intentionally left
// in place: protection must not depend on the daemon running.
func (d *Daemon) Shutdown() {
	d.cancel()
	done := make(chan struct{})
	go func() { d.async.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	msg := "wgmd stopping"
	if d.o.Firewall != nil && d.o.Firewall.Status().State == firewall.StateEnforced {
		msg += "; kill switch rules remain enforced"
	}
	d.Events.Add("", events.KindDaemon, events.Info, msg)
	d.mu.Lock()
	d.saveStateLocked()
	d.mu.Unlock()
}

func (d *Daemon) saveStateLocked() {
	if err := d.state.save(d.o.StatePath); err != nil {
		d.o.Log.Error("cannot save runtime state", "err", err)
	}
}

func (d *Daemon) setIntentLocked(name string, in health.Intent, fingerprint string) {
	if in == health.IntentNone {
		if _, ok := d.state.Intents[name]; !ok {
			return
		}
		delete(d.state.Intents, name)
	} else {
		d.state.Intents[name] = IntentRecord{Intent: in, At: d.now(), Fingerprint: fingerprint}
	}
	d.saveStateLocked()
}

func (d *Daemon) intentLocked(name string) (health.Intent, time.Time) {
	r, ok := d.state.Intents[name]
	if !ok {
		return health.IntentNone, time.Time{}
	}
	return r.Intent, r.At
}

// Tick runs one monitoring cycle.
func (d *Daemon) Tick(ctx context.Context) {
	d.tickMu.Lock()
	defer d.tickMu.Unlock()
	now := d.now()
	d.maybeReloadPolicy(now)
	if now.Sub(d.lastDiscovery) >= discoveryEvery || d.lastDiscovery.IsZero() {
		d.refreshDiscovery(now)
	}
	pol := d.o.Store.Get()

	// Collect names: configs, live WireGuard interfaces, policies.
	nameSet := map[string]bool{}
	d.mu.Lock()
	for n := range d.disc {
		if config.ValidInterfaceName(n) {
			nameSet[n] = true
		}
	}
	d.mu.Unlock()
	wgNames, err := d.o.Reader.ListWireGuard(ctx)
	d.mu.Lock()
	if err != nil {
		d.runtimeErr = "cannot list WireGuard interfaces: " + err.Error()
	} else {
		d.runtimeErr = ""
	}
	d.mu.Unlock()
	for _, n := range wgNames {
		nameSet[n] = true
	}
	for n := range pol.Tunnels {
		nameSet[n] = true
	}

	rts := make(map[string]tunnel.Runtime, len(nameSet))
	for n := range nameSet {
		rt, err := d.o.Reader.Read(ctx, n)
		if err != nil {
			rt = tunnel.Runtime{Name: n, Err: err.Error()}
		}
		rts[n] = rt
	}

	// Only consult the routing table when a managed tunnel is unwell.
	if d.o.Backend != nil && d.anyManagedUnwell(pol) {
		up, err := d.o.Backend.UnderlayUp(ctx, "")
		d.mu.Lock()
		d.underlay = err == nil && up
		d.mu.Unlock()
	} else {
		d.mu.Lock()
		d.underlay = true
		d.mu.Unlock()
	}

	var probes []probeJob
	var actions []actionJob
	var ownerChecks []string
	d.mu.Lock()
	for n := range d.tunnels {
		if !nameSet[n] {
			delete(d.tunnels, n)
		}
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ts := d.tunnelLocked(n, pol)
		pj, aj := d.updateTunnelLocked(ts, rts[n], now, pol)
		if pj != nil {
			probes = append(probes, *pj)
		}
		if aj != nil {
			actions = append(actions, *aj)
		}
		if d.o.Backend != nil && ts.disc != nil && now.Sub(ts.ownerAt) >= ownerEvery {
			ts.ownerAt = now
			ownerChecks = append(ownerChecks, n)
		}
	}
	d.mu.Unlock()

	for _, n := range ownerChecks {
		owner, err := d.o.Backend.ExternalOwner(ctx, n)
		d.mu.Lock()
		if ts := d.tunnels[n]; ts != nil {
			if err != nil {
				owner = ""
			}
			if owner != ts.owner && owner != "" {
				d.Events.Add(n, events.KindDiscovery, events.Warning, "tunnel is controlled by "+owner+"; WGM will not manage it")
			}
			ts.owner = owner
		}
		d.mu.Unlock()
	}
	for _, pj := range probes {
		d.runAsync(func(c context.Context) { d.runProbes(c, pj) })
	}
	for _, aj := range actions {
		d.runAsync(func(c context.Context) { d.runAction(c, aj) })
	}

	if now.Sub(d.lastKS) >= killSwitchEvry {
		d.lastKS = now
		d.reconcileKillSwitch(ctx, false)
	}
	if now.Sub(d.lastPrune) >= pruneEvery {
		d.lastPrune = now
		d.prune(now, pol.Monitoring)
	}
}

func (d *Daemon) runAsync(fn func(context.Context)) {
	if d.o.Synchronous {
		fn(d.ctx)
		return
	}
	d.async.Add(1)
	go func() {
		defer d.async.Done()
		fn(d.ctx)
	}()
}

func (d *Daemon) anyManagedUnwell(pol *config.File) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for n, ts := range d.tunnels {
		if pol.TunnelPolicy(n).Ownership != config.OwnershipManaged {
			continue
		}
		switch ts.machine.Base() {
		case health.Healthy, health.ConnectedUnverified, health.Unknown:
		default:
			return true
		}
	}
	return false
}

func (d *Daemon) maybeReloadPolicy(now time.Time) {
	if now.Sub(d.lastPolicy) < policyEvery && !d.lastPolicy.IsZero() {
		return
	}
	d.lastPolicy = now
	changed, err := d.o.Store.ReloadIfChanged()
	if err != nil {
		msg := err.Error()
		if msg != d.policyErr {
			d.policyErr = msg
			d.Events.Add("", events.KindConfig, events.Error, "policy file changed on disk but is invalid; keeping previous policy: "+msg)
		}
		return
	}
	if changed {
		d.policyErr = ""
		d.Events.Add("", events.KindConfig, events.Info, "policy reloaded from disk")
		d.applyPolicy(d.o.Store.Get())
	}
}

func (d *Daemon) applyPolicy(pol *config.File) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for n, ts := range d.tunnels {
		tp := pol.TunnelPolicy(n)
		ts.machine.SetPolicy(tp.Health)
		if tp.Ownership != config.OwnershipManaged {
			if ts.rec.Active() || ts.rec.Exhausted() {
				ts.rec.Reset("tunnel is no longer managed by WGM", d.now())
			}
			d.setIntentLocked(n, health.IntentNone, "")
		}
	}
}

func (d *Daemon) refreshDiscovery(now time.Time) {
	d.lastDiscovery = now
	found, err := tunnel.Discover(d.o.ConfigDir)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		if d.discErr != err.Error() {
			d.Events.Add("", events.KindDiscovery, events.Error, "configuration discovery failed: "+err.Error())
		}
		d.discErr = err.Error()
		return // keep previous results
	}
	d.discErr = ""
	for n, nd := range found {
		old, had := d.disc[n]
		switch {
		case !had:
			msg := "discovered configuration " + nd.Path
			sev := events.Info
			if nd.Err != "" {
				msg += " (unusable: " + nd.Err + ")"
				sev = events.Warning
			}
			d.Events.Add(n, events.KindDiscovery, sev, msg)
		case old.Err != nd.Err && nd.Err != "":
			d.Events.Add(n, events.KindDiscovery, events.Warning, "configuration became unusable: "+nd.Err)
		case fp(old) != fp(nd):
			d.Events.Add(n, events.KindConfig, events.Info, "configuration file changed on disk")
		}
	}
	for n := range d.disc {
		if _, ok := found[n]; !ok {
			d.Events.Add(n, events.KindDiscovery, events.Warning, "configuration file was removed")
		}
	}
	d.disc = found
	for n, ts := range d.tunnels {
		d.attachDiscLocked(ts, n)
	}
}

func fp(d tunnel.Discovered) string {
	if d.Config == nil {
		return ""
	}
	return d.Config.Fingerprint
}

func (d *Daemon) attachDiscLocked(ts *tunnelState, n string) {
	if nd, ok := d.disc[n]; ok {
		c := nd
		ts.disc = &c
	} else {
		ts.disc = nil
	}
	cur := ""
	if ts.disc != nil {
		cur = fp(*ts.disc)
	}
	if ts.baseline == "" {
		if r, ok := d.state.Intents[n]; ok && r.Fingerprint != "" {
			ts.baseline = r.Fingerprint
		} else {
			ts.baseline = cur
		}
	}
	// A change only matters while the interface is running with the old
	// configuration; otherwise the next activation uses the new file.
	if ts.rt.Exists && cur != ts.baseline {
		if !ts.configChanged {
			ts.configChanged = true
			d.Events.Add(n, events.KindConfig, events.Warning, "configuration on disk differs from the running tunnel; reconnect to apply it")
		}
	} else if !ts.rt.Exists {
		ts.baseline, ts.configChanged = cur, false
	}
}

func (d *Daemon) tunnelLocked(n string, pol *config.File) *tunnelState {
	ts := d.tunnels[n]
	if ts != nil {
		return ts
	}
	tp := pol.TunnelPolicy(n)
	ts = &tunnelState{
		name:     n,
		ring:     metrics.NewRing(d.o.LiveSamples),
		peerRate: map[string]*metrics.RateCalc{},
		peerLast: map[string]metrics.Rate{},
		machine:  health.NewMachine(tp.Health),
		rec:      recovery.New(),
	}
	d.tunnels[n] = ts
	d.attachDiscLocked(ts, n)
	return ts
}

type probeJob struct {
	name   string
	specs  []config.ProbeSpec
	health config.HealthPolicy
}

type actionJob struct {
	name   string
	action recovery.Action
}

func (d *Daemon) updateTunnelLocked(ts *tunnelState, rt tunnel.Runtime, now time.Time, pol *config.File) (*probeJob, *actionJob) {
	tp := pol.TunnelPolicy(ts.name)
	prev := ts.rt
	ts.rt = rt
	structural := !ts.seen || prev.Exists != rt.Exists || prev.Up != rt.Up
	ts.seen = true

	if rt.Exists && !prev.Exists {
		ts.upSince = now
		d.attachDiscLocked(ts, ts.name)
	}
	if !rt.Exists {
		ts.upSince = time.Time{}
		if prev.Exists {
			d.attachDiscLocked(ts, ts.name)
		}
	}
	if rt.FwMark != 0 && d.state.FwMarks[ts.name] != uint32(rt.FwMark) {
		d.state.FwMarks[ts.name] = uint32(rt.FwMark)
		d.saveStateLocked()
	}

	// Metrics.
	interval := time.Duration(pol.Monitoring.SampleIntervalSec) * time.Second
	var r metrics.Rate
	if rt.Exists && rt.IsWireGuard {
		rx, tx := rt.RxTx()
		r = ts.rate.Add(metrics.Sample{At: now, Rx: rx, Tx: tx})
		seen := map[string]bool{}
		for _, p := range rt.Peers {
			seen[p.PublicKey] = true
			c := ts.peerRate[p.PublicKey]
			if c == nil {
				c = &metrics.RateCalc{}
				ts.peerRate[p.PublicKey] = c
			}
			ts.peerLast[p.PublicKey] = c.Add(metrics.Sample{At: now, Rx: p.RxBytes, Tx: p.TxBytes})
		}
		for k := range ts.peerRate {
			if !seen[k] {
				delete(ts.peerRate, k)
				delete(ts.peerLast, k)
			}
		}
	} else {
		ts.rate.Forget()
		ts.peerRate = map[string]*metrics.RateCalc{}
		ts.peerLast = map[string]metrics.Rate{}
		r = metrics.Rate{At: now}
	}
	ts.last = r
	ts.ring.Push(r)
	if b, ok := ts.agg.AddRate(r, interval); ok {
		d.storeBucket(ts.name, b, pol.Monitoring)
	}

	// Health rounds.
	intent, intentAt := d.intentLocked(ts.name)
	probesConfigured := 0
	if tp.Ownership != config.OwnershipDiscovered {
		probesConfigured = len(tp.Health.Probes)
	}
	var pj *probeJob
	observe := false
	var results []health.ProbeResult
	switch {
	case ts.hasPending:
		observe, results = true, ts.pending
		ts.pending, ts.hasPending = nil, false
		d.recordLatencyLocked(ts, results, pol.Monitoring)
	case now.Sub(ts.lastRound) >= time.Duration(tp.Health.IntervalSec)*time.Second && !ts.probing:
		ts.lastRound = now
		if probesConfigured > 0 && rt.Exists && rt.Up && rt.IsWireGuard {
			ts.probing = true
			pj = &probeJob{name: ts.name, specs: append([]config.ProbeSpec(nil), tp.Health.Probes...), health: tp.Health}
		} else {
			observe = true
		}
	case structural:
		observe = true
	}
	if observe {
		o := health.Observation{
			At: now, Exists: rt.Exists, Up: rt.Up, IsWireGuard: rt.IsWireGuard,
			ProbesConfigured: probesConfigured, Probes: results,
			Intent: intent, IntentAt: intentAt,
			Recovering: ts.rec.Active(), RecoveryExhausted: ts.rec.Exhausted(), RecoveryDetail: ts.rec.Detail(),
		}
		for _, p := range rt.Peers {
			o.Peers = append(o.Peers, health.PeerObs{LastHandshake: p.LastHandshake, Keepalive: p.PersistentKeepalive, Rx: p.RxBytes, Tx: p.TxBytes})
		}
		if t, ok := ts.machine.Observe(o); ok {
			sev := events.Info
			switch t.To {
			case health.Degraded, health.Recovering:
				sev = events.Warning
			case health.Error:
				sev = events.Error
			}
			d.Events.Add(ts.name, events.KindHealth, sev, fmt.Sprintf("%s → %s: %s", t.From.Label(), t.To.Label(), t.Reason))
		}
	}

	// Recovery.
	if ts.acting {
		return pj, nil
	}
	dec := ts.rec.Evaluate(recovery.Input{
		Now: now, Managed: tp.Ownership == config.OwnershipManaged && d.manageBlockerLocked(ts) == "",
		Policy: tp.Recovery, Health: ts.machine.Snapshot(), Intent: intent,
		InterfaceExists: rt.Exists, InterfaceUp: rt.Up, UnderlayUp: d.underlay,
	})
	if dec.Reason != "" && dec.Reason != ts.lastRecMsg {
		ts.lastRecMsg = dec.Reason
		sev := events.Info
		if dec.Action == recovery.ActionGiveUp {
			sev = events.Error
		} else if dec.Action != recovery.ActionNone {
			sev = events.Warning
		}
		d.Events.Add(ts.name, events.KindRecovery, sev, dec.Reason)
	}
	switch dec.Action {
	case recovery.ActionRecheck:
		ts.lastRound = time.Time{} // fresh health round next tick
		ts.rec.Report(now, dec.Action, nil)
	case recovery.ActionBringUp, recovery.ActionRestart:
		ts.acting = true
		return pj, &actionJob{name: ts.name, action: dec.Action}
	}
	return pj, nil
}

func (d *Daemon) recordLatencyLocked(ts *tunnelState, results []health.ProbeResult, mon config.MonitoringPrefs) {
	var sum float64
	var n int
	var at time.Time
	for _, r := range results {
		if r.OK && r.LatencyMs > 0 {
			sum += r.LatencyMs
			n++
			at = r.At
		}
	}
	if n == 0 {
		return
	}
	ms := sum / float64(n)
	ts.latency = append(ts.latency, api.MetricPoint{T: at, LatencyMs: ms, Valid: true})
	if len(ts.latency) > maxLatencyPts {
		ts.latency = ts.latency[len(ts.latency)-maxLatencyPts:]
	}
	if b, ok := ts.agg.AddLatency(at, ms); ok {
		d.storeBucket(ts.name, b, mon)
	}
}

func (d *Daemon) storeBucket(name string, b metrics.Bucket, mon config.MonitoringPrefs) {
	if d.o.History == nil || !mon.PersistHistory {
		return
	}
	rx, tx := b.AvgRates()
	row := events.MetricRow{Tunnel: name, Start: b.Start, RxRate: rx, TxRate: tx, Seconds: b.Seconds}
	if b.LatencyN > 0 {
		row.LatencyMs = b.LatencySum / float64(b.LatencyN)
	}
	if err := d.o.History.StoreMetric(row); err != nil {
		d.o.Log.Warn("cannot store metrics", "err", err)
	}
}

func (d *Daemon) runProbes(ctx context.Context, pj probeJob) {
	results := make([]health.ProbeResult, len(pj.specs))
	var wg sync.WaitGroup
	for i, s := range pj.specs {
		wg.Add(1)
		go func(i int, s config.ProbeSpec) {
			defer wg.Done()
			results[i] = d.o.Prober.Probe(ctx, pj.name, s)
		}(i, s)
	}
	wg.Wait()
	d.mu.Lock()
	if ts := d.tunnels[pj.name]; ts != nil {
		ts.probing = false
		ts.pending, ts.hasPending = results, true
	}
	d.mu.Unlock()
	if !d.o.Synchronous {
		d.Poke()
	}
}

func (d *Daemon) runAction(ctx context.Context, aj actionJob) {
	var err error
	if d.o.Backend == nil {
		err = errors.New("no backend")
	} else {
		actx, cancel := context.WithTimeout(ctx, 60*time.Second)
		switch aj.action {
		case recovery.ActionBringUp:
			err = d.o.Backend.Up(actx, aj.name)
		case recovery.ActionRestart:
			d.mu.Lock()
			exists := d.tunnels[aj.name] != nil && d.tunnels[aj.name].rt.Exists
			d.mu.Unlock()
			if exists {
				if derr := d.o.Backend.Down(actx, aj.name); derr != nil && errors.Is(derr, backend.ErrConflict) {
					err = derr
				}
			}
			if err == nil {
				err = d.o.Backend.Up(actx, aj.name)
			}
		}
		cancel()
	}
	d.mu.Lock()
	if ts := d.tunnels[aj.name]; ts != nil {
		ts.acting = false
		ts.rec.Report(d.now(), aj.action, err)
		ts.lastRound = time.Time{}
		if err != nil {
			d.Events.Add(aj.name, events.KindRecovery, events.Error, fmt.Sprintf("recovery action %s failed: %v", aj.action, err))
		} else {
			d.Events.Add(aj.name, events.KindRecovery, events.Info, fmt.Sprintf("recovery action %s executed; verifying with fresh health checks", aj.action))
			if ts.disc != nil {
				ts.baseline, ts.configChanged = fp(*ts.disc), false
				d.setIntentLocked(aj.name, health.IntentUp, ts.baseline)
			}
		}
	}
	d.mu.Unlock()
	if !d.o.Synchronous {
		d.Poke()
	}
}

// manageBlockerLocked explains why WGM cannot manage the tunnel, or "".
func (d *Daemon) manageBlockerLocked(ts *tunnelState) string {
	switch {
	case d.o.Backend == nil:
		return "no tunnel backend is available (is wireguard-tools installed?)"
	case ts.disc == nil:
		return "no configuration file in " + d.o.ConfigDir
	case ts.disc.Err != "":
		return "configuration is unusable: " + ts.disc.Err
	case ts.disc.Config == nil:
		return "configuration is unusable"
	case ts.disc.Config.SaveConfig:
		return "SaveConfig = true: wg-quick would rewrite the configuration file; WGM never modifies WireGuard configurations"
	case ts.owner != "":
		return "controlled by " + ts.owner
	case ts.rt.Exists && !ts.rt.IsWireGuard:
		return "an interface with this name exists but is not a WireGuard interface"
	}
	return ""
}

func (d *Daemon) prune(now time.Time, mon config.MonitoringPrefs) {
	if d.o.History == nil {
		return
	}
	n, err := d.o.History.Prune(now.AddDate(0, 0, -mon.EventRetentionDays), now.AddDate(0, 0, -mon.MetricsRetentionDays))
	if err != nil {
		d.o.Log.Warn("history prune failed", "err", err)
	} else if n > 0 {
		d.o.Log.Info("pruned history", "rows", n)
	}
}

// ---- kill switch ----

// killSwitchSpec builds the desired spec. It never returns nil when the
// policy is enabled: an incomplete spec fails validation inside the
// firewall manager, which keeps existing rules and reports Error.
func (d *Daemon) killSwitchSpecLocked(pol config.KillSwitchPolicy) (*firewall.Spec, []string) {
	if !pol.Enabled {
		return nil, nil
	}
	spec := &firewall.Spec{Interface: pol.Tunnel, AllowLAN: pol.AllowLAN, AllowDHCP: pol.AllowDHCP}
	var warnings []string
	eps := map[netip.AddrPort]bool{}
	ts := d.tunnels[pol.Tunnel]
	nd, hasConf := d.disc[pol.Tunnel]
	if !hasConf || nd.Config == nil {
		warnings = append(warnings, "the protected tunnel's configuration is missing or unusable; using last known endpoints")
	} else {
		v4, v6 := nd.Config.FullTunnel()
		if !v4 {
			warnings = append(warnings, "the protected tunnel does not route all IPv4 traffic; non-tunnel destinations will be unreachable")
		}
		if !v6 {
			warnings = append(warnings, "the tunnel does not carry IPv6; all IPv6 traffic outside the tunnel is blocked")
		}
		for _, p := range nd.Config.Peers {
			host, port, err := tunnel.EndpointHostPort(p.Endpoint)
			if err != nil || p.Endpoint == "" {
				continue
			}
			if a, err := netip.ParseAddr(host); err == nil {
				eps[netip.AddrPortFrom(a.Unmap(), uint16(port))] = true
			}
		}
	}
	for _, s := range d.state.Endpoints[pol.Tunnel] {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			eps[ap] = true
		}
	}
	if ts != nil {
		for _, p := range ts.rt.Peers {
			if ap, err := netip.ParseAddrPort(p.Endpoint); err == nil {
				eps[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = true
			}
		}
	}
	for ap := range eps {
		spec.Endpoints = append(spec.Endpoints, ap)
	}
	sort.Slice(spec.Endpoints, func(i, j int) bool { return spec.Endpoints[i].String() < spec.Endpoints[j].String() })
	switch {
	case ts != nil && ts.rt.FwMark != 0:
		spec.FwMark = uint32(ts.rt.FwMark)
	case d.state.FwMarks[pol.Tunnel] != 0:
		spec.FwMark = d.state.FwMarks[pol.Tunnel]
	case hasConf && nd.Config != nil && nd.Config.FwMark != "" && nd.Config.FwMark != "off":
		if v, err := strconv.ParseUint(nd.Config.FwMark, 0, 32); err == nil {
			spec.FwMark = uint32(v)
		}
	}
	if spec.FwMark == 0 {
		warnings = append(warnings, "WireGuard fwmark unknown: endpoint exceptions are restricted by address and port only")
	}
	return spec, warnings
}

// resolveEndpoints pins hostname endpoints of name to addresses (used when
// enabling the kill switch, while DNS still works).
func (d *Daemon) resolveEndpoints(ctx context.Context, name string) error {
	d.mu.Lock()
	nd, ok := d.disc[name]
	d.mu.Unlock()
	if !ok || nd.Config == nil || d.o.Resolve == nil {
		return nil
	}
	var out []string
	var errs []string
	for _, p := range nd.Config.Peers {
		host, port, err := tunnel.EndpointHostPort(p.Endpoint)
		if err != nil || p.Endpoint == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := d.o.Resolve(rctx, host)
		cancel()
		if err != nil {
			errs = append(errs, host+": "+err.Error())
			continue
		}
		for _, a := range addrs {
			if len(out) < 64 {
				out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(port)).String())
			}
		}
	}
	if len(out) > 0 {
		d.mu.Lock()
		d.state.Endpoints[name] = out
		d.saveStateLocked()
		d.mu.Unlock()
	}
	if len(errs) > 0 {
		return fmt.Errorf("cannot resolve endpoint(s): %v", errs)
	}
	return nil
}

func (d *Daemon) reconcileKillSwitch(ctx context.Context, startup bool) {
	if d.o.Firewall == nil {
		return
	}
	pol := d.o.Store.Get().KillSwitch
	if !pol.Enabled && d.o.Store.ReadOnlyReason() != nil {
		// The policy could not be read; never remove protection on the
		// basis of defaults.
		return
	}
	d.mu.Lock()
	spec, warnings := d.killSwitchSpecLocked(pol)
	d.ksWarnings = warnings
	d.mu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := d.o.Firewall.Reconcile(rctx, spec); err != nil && startup {
		d.o.Log.Error("kill switch reconcile failed", "err", err)
	}
}

// ---- tunnel control ----

// ErrBusy is returned when another action is running for the tunnel.
var ErrBusy = errors.New("another operation is in progress for this tunnel")

// Connect activates a managed tunnel and records the user's intent.
func (d *Daemon) Connect(ctx context.Context, name string) error {
	pol := d.o.Store.Get()
	d.mu.Lock()
	ts := d.tunnels[name]
	if ts == nil {
		d.mu.Unlock()
		return api.Errf(api.CodeNotFound, "unknown tunnel "+name)
	}
	if err := d.checkManagedLocked(ts, pol); err != nil {
		d.mu.Unlock()
		return err
	}
	if ts.acting {
		d.mu.Unlock()
		return api.Errf(api.CodeConflict, ErrBusy.Error())
	}
	ts.rec.Reset("user requested connect", d.now())
	fpr := fp(*ts.disc)
	d.setIntentLocked(name, health.IntentUp, fpr)
	if ts.rt.Exists {
		d.mu.Unlock()
		d.Events.Add(name, events.KindAction, events.Info, "connect requested; tunnel is already up")
		return nil
	}
	ts.acting = true
	ts.lastRound = time.Time{}
	d.mu.Unlock()

	d.Events.Add(name, events.KindAction, events.Info, "connecting")
	actx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err := d.o.Backend.Up(actx, name)
	cancel()

	d.mu.Lock()
	ts.acting = false
	if err != nil {
		if errors.Is(err, backend.ErrConflict) {
			d.setIntentLocked(name, health.IntentNone, "")
		}
		d.mu.Unlock()
		d.Events.Add(name, events.KindAction, events.Error, "connect failed: "+err.Error())
		d.Poke()
		return api.Errf(api.CodeUnavailable, "connect failed: "+err.Error())
	}
	ts.baseline, ts.configChanged = fpr, false
	d.mu.Unlock()
	d.Events.Add(name, events.KindAction, events.Info, "tunnel activated; verifying health")
	d.Poke()
	return nil
}

// Disconnect deactivates a managed tunnel. Recovery will not reconnect it
// unless the recovery policy explicitly allows it.
func (d *Daemon) Disconnect(ctx context.Context, name string) error {
	pol := d.o.Store.Get()
	d.mu.Lock()
	ts := d.tunnels[name]
	if ts == nil {
		d.mu.Unlock()
		return api.Errf(api.CodeNotFound, "unknown tunnel "+name)
	}
	if err := d.checkManagedLocked(ts, pol); err != nil {
		d.mu.Unlock()
		return err
	}
	if ts.acting {
		d.mu.Unlock()
		return api.Errf(api.CodeConflict, ErrBusy.Error())
	}
	ts.rec.Reset("user disconnected the tunnel", d.now())
	d.setIntentLocked(name, health.IntentDown, "")
	if !ts.rt.Exists {
		d.mu.Unlock()
		d.Events.Add(name, events.KindAction, events.Info, "disconnect requested; tunnel is already down")
		return nil
	}
	ts.acting = true
	d.mu.Unlock()

	d.Events.Add(name, events.KindAction, events.Info, "disconnecting (manual)")
	actx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err := d.o.Backend.Down(actx, name)
	cancel()
	d.mu.Lock()
	ts.acting = false
	d.mu.Unlock()
	d.Poke()
	if err != nil {
		d.Events.Add(name, events.KindAction, events.Error, "disconnect failed: "+err.Error())
		return api.Errf(api.CodeUnavailable, "disconnect failed: "+err.Error())
	}
	msg := "tunnel deactivated"
	if ks := pol.KillSwitch; ks.Enabled && ks.Tunnel == name {
		msg += "; kill switch remains active and blocks traffic outside the tunnel"
	}
	d.Events.Add(name, events.KindAction, events.Info, msg)
	return nil
}

func (d *Daemon) checkManagedLocked(ts *tunnelState, pol *config.File) error {
	if pol.TunnelPolicy(ts.name).Ownership != config.OwnershipManaged {
		return api.Errf(api.CodeForbidden, "WGM is not authorized to manage "+ts.name+"; set its ownership to \"managed\" first")
	}
	if b := d.manageBlockerLocked(ts); b != "" {
		return api.Errf(api.CodeConflict, b)
	}
	return nil
}
