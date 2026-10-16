package ui

import (
	"context"
	"fmt"
	"image/color"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/ipc"
)

var (
	rxColor = color.NRGBA{R: 0x1e, G: 0x88, B: 0xe5, A: 0xff}
	txColor = color.NRGBA{R: 0xfb, G: 0x8c, B: 0x00, A: 0xff}
	ltColor = color.NRGBA{R: 0x8e, G: 0x24, B: 0xaa, A: 0xff}
)

const (
	rangeLive  = "Live (5 min)"
	rangeHour  = "History: 1 hour"
	rangeDay   = "History: 24 hours"
	rangeWeek  = "History: 7 days"
	liveWindow = 300
)

type detailWindow struct {
	a      *App
	name   string
	win    fyne.Window
	cancel context.CancelFunc

	overview *widget.Label
	peers    *widget.Label
	rates    *widget.Label
	graph    *Graph
	latency  *Graph
	rangeSel *widget.Select
	healthL  *widget.Label
	signals  *widget.Label
	history  *widget.Label
	recovery *widget.Label
	events   *widget.Label

	form       *policyForm
	formLoaded bool
	rangeCh    chan string
}

func newDetailWindow(a *App, name string) *detailWindow {
	d := &detailWindow{a: a, name: name, rangeCh: make(chan string, 1)}
	d.win = a.fa.NewWindow("WGM — " + name)
	d.win.Resize(fyne.NewSize(860, 640))

	wrap := func() *widget.Label {
		l := widget.NewLabel("")
		l.Wrapping = fyne.TextWrapWord
		return l
	}
	d.overview, d.peers, d.healthL, d.signals, d.history, d.recovery, d.events = wrap(), wrap(), wrap(), wrap(), wrap(), wrap(), wrap()
	d.peers.TextStyle = fyne.TextStyle{Monospace: true}
	d.rates = wrap()
	d.graph = NewGraph(liveWindow, nil)
	d.graph.Span = liveWindow * time.Second
	d.latency = NewGraph(liveWindow, func(v float64) string { return fmt.Sprintf("%.0f ms", v) })
	d.latency.Span = liveWindow * time.Second
	d.rangeSel = widget.NewSelect([]string{rangeLive, rangeHour, rangeDay, rangeWeek}, func(s string) {
		select {
		case d.rangeCh <- s:
		default:
		}
	})
	d.rangeSel.SetSelected(rangeLive)

	d.form = newPolicyForm(d)

	overviewTab := container.NewVScroll(container.NewVBox(d.overview, widget.NewSeparator(),
		widget.NewLabelWithStyle("Peers", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), d.peers))
	trafficTab := container.NewBorder(container.NewVBox(d.rangeSel, d.rates), nil, nil, nil,
		container.NewGridWithRows(2,
			container.NewBorder(widget.NewLabel("Throughput (instantaneous rates; gaps = no valid sample)"), nil, nil, nil, d.graph),
			container.NewBorder(widget.NewLabel("Probe latency"), nil, nil, nil, d.latency)))
	healthTab := container.NewVScroll(container.NewVBox(d.healthL, d.signals, widget.NewSeparator(),
		widget.NewLabelWithStyle("Recovery", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), d.recovery, widget.NewSeparator(),
		widget.NewLabelWithStyle("Health history (newest first)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), d.history))
	tabs := container.NewAppTabs(
		container.NewTabItem("Overview", overviewTab),
		container.NewTabItem("Traffic", trafficTab),
		container.NewTabItem("Health", healthTab),
		container.NewTabItem("Settings", d.form.content),
		container.NewTabItem("Events", container.NewVScroll(d.events)),
	)
	d.win.SetContent(tabs)

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	go d.loop(ctx)
	return d
}

func (d *detailWindow) close() { d.cancel() }

// loop fetches metrics and events for this tunnel in the background.
func (d *detailWindow) loop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	sel := rangeLive
	n := 0
	for {
		var m api.MetricsResult
		p := api.MetricsParams{Name: d.name, WindowSec: liveWindow}
		switch sel {
		case rangeHour:
			p = api.MetricsParams{Name: d.name, HistoryHours: 1}
		case rangeDay:
			p = api.MetricsParams{Name: d.name, HistoryHours: 24}
		case rangeWeek:
			p = api.MetricsParams{Name: d.name, HistoryHours: 24 * 7}
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		merr := d.a.poll.Call(cctx, api.OpMetrics, p, &m)
		var evs []api.EventView
		var everr error
		fetchEvents := n%3 == 0
		if fetchEvents {
			everr = d.a.poll.Call(cctx, api.OpEvents, api.EventsParams{Tunnel: d.name, Limit: 200}, &evs)
		}
		cancel()
		n++
		curSel := sel
		fyne.Do(func() {
			d.setMetrics(curSel, &m, merr)
			if fetchEvents {
				d.setEvents(evs, everr)
			}
		})
		select {
		case <-ctx.Done():
			return
		case sel = <-d.rangeCh:
			n = 0
		case <-t.C:
		}
	}
}

func points(ps []api.MetricPoint, f func(api.MetricPoint) float64) ([]float64, []bool) {
	v := make([]float64, len(ps))
	ok := make([]bool, len(ps))
	for i, p := range ps {
		v[i], ok[i] = f(p), p.Valid
	}
	return v, ok
}

func (d *detailWindow) setMetrics(sel string, m *api.MetricsResult, err error) {
	if err != nil {
		d.rates.SetText("Metrics unavailable: " + ExplainError(err, d.a.socket))
		d.graph.SetSeries(nil)
		d.latency.SetSeries(nil)
		return
	}
	src := m.Live
	lat := m.Latency
	slots := liveWindow
	if m.Interval > 0 {
		slots = liveWindow / m.Interval
	}
	span := time.Duration(liveWindow) * time.Second
	if sel != rangeLive {
		src, lat = m.History, m.History
		slots = len(src)
		if len(src) > 1 {
			span = src[len(src)-1].T.Sub(src[0].T)
		}
		if len(src) == 0 {
			d.rates.SetText("No stored history yet for this range (history persistence may be disabled in Settings).")
		}
	}
	if slots < 2 {
		slots = 2
	}
	d.graph.Slots, d.latency.Slots = slots, slots
	d.graph.Span, d.latency.Span = span, span
	rx, rxOK := points(src, func(p api.MetricPoint) float64 { return p.RxRate })
	tx, txOK := points(src, func(p api.MetricPoint) float64 { return p.TxRate })
	d.graph.SetSeries([]Series{{Name: "download (rx)", Color: rxColor, Values: rx, Valid: rxOK}, {Name: "upload (tx)", Color: txColor, Values: tx, Valid: txOK}})
	lv, lok := points(lat, func(p api.MetricPoint) float64 { return p.LatencyMs })
	for i := range lv {
		lok[i] = lv[i] > 0
	}
	d.latency.SetSeries([]Series{{Name: "probe latency", Color: ltColor, Values: lv, Valid: lok}})
}

func (d *detailWindow) setEvents(evs []api.EventView, err error) {
	if err != nil {
		d.events.SetText("Events unavailable: " + ExplainError(err, d.a.socket))
		return
	}
	if len(evs) == 0 {
		d.events.SetText("No events recorded since the daemon started.")
		return
	}
	var b strings.Builder
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		fmt.Fprintf(&b, "%s  [%s] %s: %s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Severity, e.Kind, e.Message)
	}
	d.events.SetText(b.String())
}

func (d *detailWindow) update(t *api.TunnelStatus, stale bool) {
	if t == nil {
		if stale {
			d.overview.SetText("Daemon unavailable; no current information.")
		} else {
			d.overview.SetText("This tunnel is no longer present (configuration removed and interface gone).")
		}
		return
	}
	if !d.formLoaded {
		d.form.load(*t)
		d.formLoaded = true
	}
	var b strings.Builder
	if stale {
		b.WriteString("⚠ STALE: the daemon is unreachable; values below are the last known state.\n\n")
	}
	fmt.Fprintf(&b, "Ownership: %s\n", OwnershipLabel(*t))
	if t.ConfigPresent {
		fmt.Fprintf(&b, "Configuration: %s\n", t.ConfigPath)
	} else {
		b.WriteString("Configuration: no file (interface created outside /etc/wireguard)\n")
	}
	if t.ConfigError != "" {
		fmt.Fprintf(&b, "Configuration error: %s\n", t.ConfigError)
	}
	if t.ConfigChanged {
		b.WriteString("Configuration file changed on disk since WGM last read it; the running tunnel may differ.\n")
	}
	for _, w := range t.ConfigWarnings {
		fmt.Fprintf(&b, "Warning: %s\n", w)
	}
	if len(t.Hooks) > 0 {
		fmt.Fprintf(&b, "wg-quick hooks present: %s\n", strings.Join(t.Hooks, ", "))
	}
	fmt.Fprintf(&b, "Backend: %s", t.Backend)
	if t.ExternalOwner != "" {
		fmt.Fprintf(&b, " (also controlled by %s)", t.ExternalOwner)
	}
	b.WriteString("\n")
	if t.ManageBlocker != "" {
		fmt.Fprintf(&b, "Cannot be managed by WGM: %s\n", t.ManageBlocker)
	}
	fullTunnel := "no"
	switch {
	case t.FullTunnelV4 && t.FullTunnelV6:
		fullTunnel = "IPv4 + IPv6"
	case t.FullTunnelV4:
		fullTunnel = "IPv4 only"
	case t.FullTunnelV6:
		fullTunnel = "IPv6 only"
	}
	fmt.Fprintf(&b, "Full tunnel: %s\n", fullTunnel)
	fmt.Fprintf(&b, "Interface: %s", InterfaceSummary(*t))
	if t.RuntimeError != "" {
		fmt.Fprintf(&b, " (%s)", t.RuntimeError)
	}
	b.WriteString("\n")
	if t.UpSince != nil && t.InterfaceExists {
		fmt.Fprintf(&b, "Session uptime: %s\n", FormatDuration(time.Since(*t.UpSince)))
	}
	if len(t.Addresses) > 0 {
		fmt.Fprintf(&b, "Addresses: %s\n", strings.Join(t.Addresses, ", "))
	}
	if len(t.Routes) > 0 {
		fmt.Fprintf(&b, "Routes: %s\n", strings.Join(t.Routes, ", "))
	}
	if len(t.DNS) > 0 {
		fmt.Fprintf(&b, "DNS (from config): %s\n", strings.Join(t.DNS, ", "))
	}
	if t.ListenPort > 0 {
		fmt.Fprintf(&b, "Listen port: %d\n", t.ListenPort)
	}
	if t.FwMark > 0 {
		fmt.Fprintf(&b, "Firewall mark: 0x%x\n", t.FwMark)
	}
	fmt.Fprintf(&b, "Total transferred: ↓ %s  ↑ %s (cumulative counters)\n", FormatBytes(t.RxBytes), FormatBytes(t.TxBytes))
	d.overview.SetText(b.String())

	var pb strings.Builder
	if len(t.Peers) == 0 {
		pb.WriteString("No peers (interface not running, or configuration has no peers).")
	}
	for _, p := range t.Peers {
		fmt.Fprintf(&pb, "Public key:   %s\n", p.PublicKey)
		ep := p.Endpoint
		if ep == "" {
			ep = p.ConfiguredEndpoint
		}
		if ep == "" {
			ep = "(none)"
		}
		fmt.Fprintf(&pb, "Endpoint:     %s\n", ep)
		fmt.Fprintf(&pb, "Allowed IPs:  %s\n", strings.Join(p.AllowedIPs, ", "))
		hs := FormatAge(p.HandshakeAgeSec)
		if !p.LastHandshake.IsZero() && p.HandshakeAgeSec >= 0 {
			hs += " (" + p.LastHandshake.Local().Format("15:04:05") + ")"
		}
		fmt.Fprintf(&pb, "Handshake:    %s\n", hs)
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&pb, "Keepalive:    every %ds\n", p.PersistentKeepalive)
		}
		if p.HasPresharedKey {
			pb.WriteString("Preshared key: yes (not shown)\n")
		}
		fmt.Fprintf(&pb, "Transfer:     ↓ %s  ↑ %s total; now ↓ %s  ↑ %s\n\n", FormatBytes(p.RxBytes), FormatBytes(p.TxBytes),
			FormatRate(p.RxRate, p.RateValid && !stale), FormatRate(p.TxRate, p.RateValid && !stale))
	}
	d.peers.SetText(pb.String())

	d.rates.SetText(fmt.Sprintf("Now: ↓ %s  ↑ %s   ·   Total: ↓ %s  ↑ %s",
		FormatRate(t.RxRate, t.RateValid && !stale), FormatRate(t.TxRate, t.RateValid && !stale), FormatBytes(t.RxBytes), FormatBytes(t.TxBytes)))

	h := t.Health
	hs := fmt.Sprintf("%s %s since %s\n%s", HealthIcon(h.State), h.State.Label(), h.Since.Local().Format("15:04:05"), h.Reason)
	if stale {
		hs = "(stale) " + hs
	}
	d.healthL.SetText(hs)
	s := h.Signals
	var sb strings.Builder
	fmt.Fprintf(&sb, "Newest handshake: %s (fresh: %v, keepalive configured: %v)\n", FormatAge(s.NewestHandshakeAgeSec), s.HandshakeFresh, s.KeepaliveConfigured)
	fmt.Fprintf(&sb, "Receiving: %v · Sending: %v\n", s.RxAdvancing, s.TxAdvancing)
	if s.ProbesConfigured == 0 {
		sb.WriteString("No connectivity probes configured: end-to-end reachability is not verified.\n")
	} else {
		fmt.Fprintf(&sb, "Probes: %d configured, %d consecutive failures, %d consecutive successes", s.ProbesConfigured, s.ConsecutiveProbeFailures, s.ConsecutiveProbeSuccesses)
		if s.LastProbeLatencyMs > 0 {
			fmt.Fprintf(&sb, ", last latency %.1f ms", s.LastProbeLatencyMs)
		}
		sb.WriteString("\n")
		for _, p := range h.LastProbes {
			res := "FAIL"
			if p.OK {
				res = fmt.Sprintf("ok %.1f ms", p.LatencyMs)
			}
			fmt.Fprintf(&sb, "  • %s: %s %s\n", p.Probe, res, p.Detail)
		}
	}
	d.signals.SetText(sb.String())

	r := t.Recovery
	rs := RecoverySummary(r, time.Now())
	if rs == "" {
		rs = "Idle."
	}
	if !t.Policy.Recovery.Enabled {
		rs += " Automatic recovery is disabled for this tunnel."
	} else if t.Ownership != config.OwnershipManaged {
		rs += " WGM only repairs tunnels it manages."
	}
	if r.LastResult != "" && !r.Exhausted {
		rs += fmt.Sprintf("\nLast result (%s): %s", r.LastResultAt.Local().Format("15:04:05"), r.LastResult)
	}
	rs += fmt.Sprintf("\nRetry budget: %d/%d used", r.BudgetUsed, r.BudgetMax)
	d.recovery.SetText(rs)

	var hb strings.Builder
	for i := len(t.HealthHistory) - 1; i >= 0; i-- {
		tr := t.HealthHistory[i]
		fmt.Fprintf(&hb, "%s  %s → %s: %s\n", tr.At.Local().Format("01-02 15:04:05"), tr.From.Label(), tr.To.Label(), tr.Reason)
	}
	if hb.Len() == 0 {
		hb.WriteString("No transitions recorded yet.")
	}
	d.history.SetText(hb.String())
	d.form.setEnabled(!stale && d.a.role() != api.RoleNone)
}

// policyForm edits a tunnel's WGM policy.
type policyForm struct {
	d       *detailWindow
	content fyne.CanvasObject

	ownership                           *widget.Select
	autostart                           *widget.Check
	interval, stale, failT, recT, grace *widget.Entry
	probes                              *widget.Entry
	recEnabled, recManual               *widget.Check
	maxAtt, initB, maxB, budget, window *widget.Entry
	verify                              *widget.Entry
	mult, jitter                        *widget.Entry
	save, reload                        *widget.Button
	loaded                              api.TunnelStatus
}

var ownershipOptions = map[string]config.Ownership{
	"Discovered (ignore)":             config.OwnershipDiscovered,
	"Monitored (read-only)":           config.OwnershipMonitored,
	"Managed (WGM may start/stop it)": config.OwnershipManaged,
}

func ownershipName(o config.Ownership) string {
	for k, v := range ownershipOptions {
		if v == o {
			return k
		}
	}
	return ""
}

func newPolicyForm(d *detailWindow) *policyForm {
	f := &policyForm{d: d}
	f.ownership = widget.NewSelect([]string{"Discovered (ignore)", "Monitored (read-only)", "Managed (WGM may start/stop it)"}, nil)
	f.autostart = widget.NewCheck("Start automatically when the daemon starts", nil)
	e := func() *widget.Entry { return widget.NewEntry() }
	f.interval, f.stale, f.failT, f.recT, f.grace = e(), e(), e(), e(), e()
	f.probes = widget.NewMultiLineEntry()
	f.probes.SetPlaceHolder("one per line, e.g.\nicmp 10.8.0.1\ntcp 10.8.0.1:443\ndns 10.8.0.1 example.com timeout=2000")
	f.probes.SetMinRowsVisible(4)
	f.recEnabled = widget.NewCheck("Automatic recovery enabled", nil)
	f.recManual = widget.NewCheck("Reconnect even after a manual disconnect (not recommended)", nil)
	f.maxAtt, f.initB, f.maxB, f.budget, f.window, f.verify, f.mult, f.jitter = e(), e(), e(), e(), e(), e(), e(), e()

	health := widget.NewForm(
		widget.NewFormItem("Check interval (s)", f.interval),
		widget.NewFormItem("Handshake stale after (s)", f.stale),
		widget.NewFormItem("Failed rounds before degraded", f.failT),
		widget.NewFormItem("Good rounds before healthy", f.recT),
		widget.NewFormItem("Connect grace period (s)", f.grace),
		widget.NewFormItem("Connectivity probes", f.probes),
	)
	rec := widget.NewForm(
		widget.NewFormItem("", f.recEnabled),
		widget.NewFormItem("", f.recManual),
		widget.NewFormItem("Max attempts per incident", f.maxAtt),
		widget.NewFormItem("Initial backoff (s)", f.initB),
		widget.NewFormItem("Max backoff (s)", f.maxB),
		widget.NewFormItem("Backoff multiplier", f.mult),
		widget.NewFormItem("Jitter fraction (0–0.5)", f.jitter),
		widget.NewFormItem("Retry budget (attempts)", f.budget),
		widget.NewFormItem("Budget window (s)", f.window),
		widget.NewFormItem("Verify timeout (s)", f.verify),
	)
	f.save = widget.NewButton("Save policy", f.submit)
	f.save.Importance = widget.HighImportance
	f.reload = widget.NewButton("Discard changes", func() { f.load(*d.a.tunnelByName(d.name)) })
	note := widget.NewLabel("Probes are sent through the tunnel interface only, so a full-tunnel test cannot succeed over the physical network. " +
		"Changing ownership or autostart requires the admin role. WireGuard keys and peers are never edited here: /etc/wireguard stays the source of truth.")
	note.Wrapping = fyne.TextWrapWord
	f.content = container.NewVScroll(container.NewVBox(
		widget.NewForm(widget.NewFormItem("Ownership", f.ownership), widget.NewFormItem("", f.autostart)),
		widget.NewCard("Health checks", "", health),
		widget.NewCard("Recovery", "", rec),
		note,
		container.NewHBox(f.save, f.reload),
	))
	return f
}

func itoa(v int) string { return strconv.Itoa(v) }

func ftoa(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func (f *policyForm) load(t api.TunnelStatus) {
	f.loaded = t
	p := t.Policy
	f.ownership.SetSelected(ownershipName(p.Ownership))
	f.autostart.SetChecked(p.Autostart)
	h := p.Health
	f.interval.SetText(itoa(h.IntervalSec))
	f.stale.SetText(itoa(h.HandshakeStaleSec))
	f.failT.SetText(itoa(h.FailureThreshold))
	f.recT.SetText(itoa(h.RecoveryThreshold))
	f.grace.SetText(itoa(h.ConnectGraceSec))
	f.probes.SetText(FormatProbes(h.Probes))
	r := p.Recovery
	f.recEnabled.SetChecked(r.Enabled)
	f.recManual.SetChecked(r.ReconnectAfterManualDisconnect)
	f.maxAtt.SetText(itoa(r.MaxAttempts))
	f.initB.SetText(itoa(r.InitialBackoffSec))
	f.maxB.SetText(itoa(r.MaxBackoffSec))
	f.mult.SetText(ftoa(r.Multiplier))
	f.jitter.SetText(ftoa(r.JitterFraction))
	f.budget.SetText(itoa(r.BudgetMax))
	f.window.SetText(itoa(r.BudgetWindowSec))
	f.verify.SetText(itoa(r.VerifyTimeoutSec))
}

func (f *policyForm) setEnabled(on bool) {
	if on {
		f.save.Enable()
	} else {
		f.save.Disable()
	}
}

// read builds a policy from the form, reporting the first invalid field.
func (f *policyForm) read() (config.TunnelPolicy, error) {
	var p config.TunnelPolicy
	var firstErr error
	num := func(name string, e *widget.Entry) int {
		v, err := strconv.Atoi(strings.TrimSpace(e.Text))
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s must be a whole number", name)
		}
		return v
	}
	flt := func(name string, e *widget.Entry) float64 {
		v, err := strconv.ParseFloat(strings.TrimSpace(e.Text), 64)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s must be a number", name)
		}
		return v
	}
	o, ok := ownershipOptions[f.ownership.Selected]
	if !ok {
		return p, fmt.Errorf("choose an ownership level")
	}
	p.Ownership = o
	p.Autostart = f.autostart.Checked
	p.Health = config.HealthPolicy{
		IntervalSec: num("Check interval", f.interval), HandshakeStaleSec: num("Handshake stale", f.stale),
		FailureThreshold: num("Failed rounds", f.failT), RecoveryThreshold: num("Good rounds", f.recT),
		ConnectGraceSec: num("Connect grace", f.grace),
	}
	p.Recovery = config.RecoveryPolicy{
		Enabled: f.recEnabled.Checked, ReconnectAfterManualDisconnect: f.recManual.Checked,
		MaxAttempts: num("Max attempts", f.maxAtt), InitialBackoffSec: num("Initial backoff", f.initB),
		MaxBackoffSec: num("Max backoff", f.maxB), Multiplier: flt("Multiplier", f.mult), JitterFraction: flt("Jitter", f.jitter),
		BudgetMax: num("Retry budget", f.budget), BudgetWindowSec: num("Budget window", f.window), VerifyTimeoutSec: num("Verify timeout", f.verify),
	}
	if firstErr != nil {
		return p, firstErr
	}
	probes, err := ParseProbes(f.probes.Text)
	if err != nil {
		return p, fmt.Errorf("probes: %w", err)
	}
	p.Health.Probes = probes
	if p.Autostart && p.Ownership != config.OwnershipManaged {
		return p, fmt.Errorf("autostart requires ownership 'Managed'")
	}
	return p, p.Validate()
}

func (f *policyForm) submit() {
	d := f.d
	p, err := f.read()
	if err != nil {
		dialog.ShowError(err, d.win)
		return
	}
	var rev uint64
	if d.a.tunnels != nil {
		rev = d.a.tunnels.PolicyRev
	}
	send := func() {
		f.save.Disable()
		d.a.do("Save policy", func(ctx context.Context, c *ipc.Client) error {
			return c.Call(ctx, api.OpSetTunnelPolicy, api.SetTunnelPolicyParams{Name: d.name, Policy: p, ExpectedRevision: rev}, nil)
		}, func() {
			f.save.Enable()
			d.formLoaded = false // reload what the daemon stored on next update
		})
	}
	if p.Ownership == config.OwnershipManaged && f.loaded.Ownership != config.OwnershipManaged {
		msg := "WGM will be allowed to bring " + d.name + " up and down and to restart it during automatic recovery.\n" +
			"The WireGuard configuration file itself is never modified."
		if f.loaded.InterfaceExists {
			msg += "\nThe tunnel is currently running; WGM will adopt it as connected without restarting it."
		}
		dialog.ShowConfirm("Let WGM manage "+d.name+"?", msg, func(ok bool) {
			if ok {
				send()
			}
		}, d.win)
		return
	}
	if f.loaded.Ownership == config.OwnershipManaged && p.Ownership != config.OwnershipManaged && f.loaded.KillSwitch {
		dialog.ShowInformation("Kill switch in use", "Disable or move the kill switch before releasing management of "+d.name+".", d.win)
		return
	}
	send()
}
