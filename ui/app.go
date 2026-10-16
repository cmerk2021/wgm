package ui

import (
	"context"
	"fmt"
	"image/color"
	"sort"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/health"
	"github.com/cmerk2021/wgm/internal/ipc"
)

// PollInterval is how often the dashboard refreshes.
const PollInterval = time.Second

// staleAfter is how old the last successful fetch may be before data is
// presented as stale.
const staleAfter = 4 * time.Second

// App is the WGM desktop client.
type App struct {
	fa     fyne.App
	win    fyne.Window
	socket string

	// Separate connections: actions such as connect may take tens of
	// seconds and must not stall polling.
	poll *ipc.Client
	act  *ipc.Client

	// The fields below are only touched on the Fyne main goroutine.
	banner     *widget.Label
	bannerBox  *fyne.Container
	bannerBg   *canvas.Rectangle
	ksLabel    *widget.Label
	roleLabel  *widget.Label
	list       *fyne.Container
	emptyLabel *widget.Label
	rows       map[string]*tunnelRow
	details    map[string]*detailWindow
	ksWin      *killSwitchWindow

	ping      *api.PingResult
	tunnels   *api.TunnelList
	ks        *api.KillSwitchStatus
	fetchedAt time.Time
	lastErr   error
	notified  map[string]health.State
	ksNotif   string
}

// New creates the application window.
func New(fa fyne.App, socket string) *App {
	a := &App{
		fa: fa, socket: socket,
		poll: ipc.NewClient(socket), act: ipc.NewClient(socket),
		rows: map[string]*tunnelRow{}, details: map[string]*detailWindow{},
		notified: map[string]health.State{},
	}
	a.win = fa.NewWindow("WGM — WireGuard Manager")
	a.win.Resize(fyne.NewSize(980, 620))
	a.build()
	return a
}

// ShowAndRun starts polling and runs the event loop.
func (a *App) ShowAndRun() {
	ctx, cancel := context.WithCancel(context.Background())
	go a.pollLoop(ctx)
	a.win.SetOnClosed(func() {
		cancel()
		a.poll.Close()
		a.act.Close()
	})
	a.win.SetMaster()
	a.win.ShowAndRun()
}

func (a *App) build() {
	a.banner = widget.NewLabel("Connecting to the WGM daemon…")
	a.banner.Wrapping = fyne.TextWrapWord
	a.bannerBg = canvas.NewRectangle(color.Transparent)
	a.bannerBox = container.NewStack(a.bannerBg, container.NewPadded(a.banner))

	a.ksLabel = widget.NewLabel("Kill switch: unknown")
	a.roleLabel = widget.NewLabel("")
	toolbar := container.NewHBox(
		widget.NewButtonWithIcon("Rescan", theme.ViewRefreshIcon(), a.rescan),
		widget.NewButtonWithIcon("Kill switch…", theme.WarningIcon(), a.openKillSwitch),
		widget.NewButtonWithIcon("Events", theme.ListIcon(), func() { a.openEvents("") }),
		widget.NewButtonWithIcon("Settings…", theme.SettingsIcon(), a.openMonitoring),
		widget.NewButtonWithIcon("Export diagnostics…", theme.DocumentSaveIcon(), a.exportDiagnostics),
		layout.NewSpacer(),
		a.roleLabel,
	)
	a.emptyLabel = widget.NewLabel("No WireGuard tunnels found yet.")
	a.list = container.NewVBox(a.emptyLabel)
	header := container.NewVBox(toolbar, a.bannerBox, container.NewHBox(widget.NewIcon(theme.WarningIcon()), a.ksLabel), widget.NewSeparator())
	a.win.SetContent(container.NewBorder(header, nil, nil, nil, container.NewVScroll(a.list)))
}

type pollResult struct {
	ping *api.PingResult
	list *api.TunnelList
	ks   *api.KillSwitchStatus
	err  error
	at   time.Time
}

func (a *App) pollLoop(ctx context.Context) {
	t := time.NewTicker(PollInterval)
	defer t.Stop()
	var ping *api.PingResult
	for {
		res := pollResult{at: time.Now()}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if ping == nil {
			var p api.PingResult
			if err := a.poll.Call(cctx, api.OpPing, nil, &p); err == nil {
				ping = &p
			} else {
				res.err = err
			}
		}
		if res.err == nil {
			var l api.TunnelList
			var ks api.KillSwitchStatus
			if err := a.poll.Call(cctx, api.OpListTunnels, nil, &l); err != nil {
				res.err = err
			} else if err := a.poll.Call(cctx, api.OpGetKillSwitch, nil, &ks); err != nil {
				res.err = err
			} else {
				res.list, res.ks = &l, &ks
			}
		}
		cancel()
		if res.err != nil {
			ping = nil // re-ping after reconnect: role or daemon may have changed
		}
		res.ping = ping
		fyne.Do(func() { a.apply(res) })
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) apply(r pollResult) {
	if r.err != nil {
		a.lastErr = r.err
	} else {
		a.lastErr = nil
		a.ping, a.tunnels, a.ks, a.fetchedAt = r.ping, r.list, r.ks, r.at
	}
	stale := r.err != nil || IsStale(a.fetchedAt, time.Now(), staleAfter)
	a.renderBanner(stale)
	a.renderRole()
	a.renderKillSwitch(stale)
	a.renderTunnels(stale)
	if !stale {
		a.notify()
	}
	for _, d := range a.details {
		d.update(a.tunnelByName(d.name), stale)
	}
	if a.ksWin != nil {
		a.ksWin.update(a.ks, stale)
	}
}

func (a *App) setBanner(text string, sev Severity) {
	a.banner.SetText(text)
	a.bannerBg.FillColor = sevBackground(sev)
	a.bannerBg.Refresh()
	if text == "" {
		a.bannerBox.Hide()
	} else {
		a.bannerBox.Show()
	}
}

func (a *App) renderBanner(stale bool) {
	switch {
	case a.lastErr != nil && a.fetchedAt.IsZero():
		a.setBanner(ExplainError(a.lastErr, a.socket), SevBad)
	case a.lastErr != nil:
		a.setBanner(fmt.Sprintf("%s\nThe data below is STALE (last updated %s ago) and does not reflect current state.",
			ExplainError(a.lastErr, a.socket), FormatDuration(time.Since(a.fetchedAt))), SevBad)
	case a.ping != nil && a.ping.Role == api.RoleNone:
		a.setBanner(fmt.Sprintf("You are connected but not authorised. Add your user to the '%s' group and log in again.", a.ping.OperatorGroup), SevWarn)
	case a.ping != nil && a.ping.PolicyReadOnly != "":
		a.setBanner("Policy store is read-only: "+a.ping.PolicyReadOnly, SevWarn)
	case a.tunnels != nil && a.tunnels.DiscoveryErr != "":
		a.setBanner("Discovery problem: "+a.tunnels.DiscoveryErr, SevWarn)
	case stale:
		a.setBanner("Waiting for fresh data from the daemon…", SevWarn)
	default:
		a.setBanner("", SevNeutral)
	}
}

func (a *App) renderRole() {
	if a.ping == nil {
		a.roleLabel.SetText("daemon: not connected")
		return
	}
	a.roleLabel.SetText(fmt.Sprintf("wgmd %s · role: %s · backend: %s", a.ping.DaemonVersion, a.ping.Role, a.ping.Backend))
}

func (a *App) renderKillSwitch(stale bool) {
	if a.ks == nil {
		a.ksLabel.SetText("Kill switch: unknown (daemon not reachable)")
		return
	}
	s := "Kill switch: " + KillSwitchLabel(*a.ks)
	if a.ks.Status.Reason != "" && a.ks.Status.State != "enforced" {
		s += " — " + a.ks.Status.Reason
	}
	if stale {
		s += " (stale: last known state)"
	}
	a.ksLabel.SetText(s)
}

func (a *App) tunnelByName(name string) *api.TunnelStatus {
	if a.tunnels == nil {
		return nil
	}
	for i := range a.tunnels.Tunnels {
		if a.tunnels.Tunnels[i].Name == name {
			return &a.tunnels.Tunnels[i]
		}
	}
	return nil
}

func (a *App) role() api.Role {
	if a.ping == nil {
		return api.RoleNone
	}
	return a.ping.Role
}

func (a *App) renderTunnels(stale bool) {
	if a.tunnels == nil {
		return
	}
	names := make([]string, 0, len(a.tunnels.Tunnels))
	for _, t := range a.tunnels.Tunnels {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	changed := len(names) != len(a.rows)
	for _, n := range names {
		if _, ok := a.rows[n]; !ok {
			a.rows[n] = newTunnelRow(a, n)
			changed = true
		}
	}
	for n := range a.rows {
		if a.tunnelByName(n) == nil {
			delete(a.rows, n)
			changed = true
		}
	}
	if changed {
		objs := []fyne.CanvasObject{}
		for _, n := range names {
			objs = append(objs, a.rows[n].card)
		}
		if len(objs) == 0 {
			a.emptyLabel.SetText(fmt.Sprintf("No WireGuard tunnels found in %s and no WireGuard interfaces are active.", a.tunnels.ConfigDir))
			objs = append(objs, a.emptyLabel)
		}
		a.list.Objects = objs
		a.list.Refresh()
	}
	for _, n := range names {
		a.rows[n].update(*a.tunnelByName(n), a.ks, stale, a.role())
	}
}

// notify sends desktop notifications for important transitions.
func (a *App) notify() {
	for _, t := range a.tunnels.Tunnels {
		prev, seen := a.notified[t.Name]
		cur := t.Health.State
		a.notified[t.Name] = cur
		if !seen || prev == cur || t.Ownership == config.OwnershipDiscovered {
			continue
		}
		switch {
		case cur == health.Degraded, cur == health.Error, cur == health.Recovering:
			a.fa.SendNotification(fyne.NewNotification("WGM: "+t.Name+" "+cur.Label(), t.Health.Reason))
		case cur == health.Healthy && HealthSeverity(prev) != SevGood && prev != health.Connecting && prev != health.Disconnected:
			a.fa.SendNotification(fyne.NewNotification("WGM: "+t.Name+" recovered", t.Health.Reason))
		}
	}
	if a.ks != nil {
		lbl := KillSwitchLabel(*a.ks)
		if a.ksNotif != "" && lbl != a.ksNotif && KillSwitchSeverity(*a.ks) == SevBad {
			a.fa.SendNotification(fyne.NewNotification("WGM kill switch: "+lbl, a.ks.Status.Reason))
		}
		a.ksNotif = lbl
	}
}

// do runs fn on the action client in the background and reports errors.
func (a *App) do(what string, fn func(ctx context.Context, c *ipc.Client) error, done func()) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		err := fn(ctx, a.act)
		fyne.Do(func() {
			if err != nil {
				dialog.ShowError(fmt.Errorf("%s failed: %s", what, ExplainError(err, a.socket)), a.win)
			}
			if done != nil {
				done()
			}
		})
	}()
}

func (a *App) rescan() {
	a.do("Rescan", func(ctx context.Context, c *ipc.Client) error {
		return c.Call(ctx, api.OpRescan, nil, nil)
	}, nil)
}

func (a *App) connect(name string, done func()) {
	a.do("Connect "+name, func(ctx context.Context, c *ipc.Client) error {
		return c.Call(ctx, api.OpConnect, api.NameParams{Name: name}, nil)
	}, done)
}

func (a *App) disconnect(name string, done func()) {
	run := func() {
		a.do("Disconnect "+name, func(ctx context.Context, c *ipc.Client) error {
			return c.Call(ctx, api.OpDisconnect, api.NameParams{Name: name}, nil)
		}, done)
	}
	if a.ks != nil && a.ks.Status.Tunnel == name && a.ks.Status.State == "enforced" {
		dialog.ShowConfirm("Disconnect "+name+"?",
			"The kill switch stays enforced: all non-tunnel traffic will remain BLOCKED while "+name+" is disconnected.\nDisable the kill switch first if you need normal connectivity.",
			func(ok bool) {
				if ok {
					run()
				} else if done != nil {
					done()
				}
			}, a.win)
		return
	}
	run()
}

func (a *App) openDetails(name string) {
	if d, ok := a.details[name]; ok {
		d.win.RequestFocus()
		return
	}
	d := newDetailWindow(a, name)
	a.details[name] = d
	d.win.SetOnClosed(func() {
		d.close()
		delete(a.details, name)
	})
	d.update(a.tunnelByName(name), a.lastErr != nil)
	d.win.Show()
}

func (a *App) openKillSwitch() {
	if a.ksWin != nil {
		a.ksWin.win.RequestFocus()
		return
	}
	a.ksWin = newKillSwitchWindow(a)
	a.ksWin.win.SetOnClosed(func() { a.ksWin = nil })
	a.ksWin.update(a.ks, a.lastErr != nil)
	a.ksWin.win.Show()
}

// sevBackground returns a subtle background colour for a severity.
func sevBackground(s Severity) color.Color {
	switch s {
	case SevBad:
		return color.NRGBA{R: 0xd3, G: 0x2f, B: 0x2f, A: 0x40}
	case SevWarn:
		return color.NRGBA{R: 0xf5, G: 0xa6, B: 0x23, A: 0x40}
	case SevGood:
		return color.NRGBA{R: 0x2e, G: 0x7d, B: 0x32, A: 0x30}
	}
	return color.Transparent
}

// tunnelRow is one dashboard card, updated in place.
type tunnelRow struct {
	a                *App
	name             string
	card             fyne.CanvasObject
	bg               *canvas.Rectangle
	title            *widget.Label
	owner            *widget.Label
	healthL          *widget.Label
	reason           *widget.Label
	stats            *widget.Label
	recov            *widget.Label
	connectB, discoB *widget.Button
	busy             bool
}

func newTunnelRow(a *App, name string) *tunnelRow {
	r := &tunnelRow{a: a, name: name}
	r.title = widget.NewLabelWithStyle(name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	r.owner = widget.NewLabel("")
	r.healthL = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	r.reason = widget.NewLabel("")
	r.reason.Wrapping = fyne.TextWrapWord
	r.stats = widget.NewLabel("")
	r.recov = widget.NewLabel("")
	r.recov.Wrapping = fyne.TextWrapWord
	r.connectB = widget.NewButtonWithIcon("Connect", theme.MediaPlayIcon(), func() {
		r.setBusy(true)
		a.connect(name, func() { r.setBusy(false) })
	})
	r.discoB = widget.NewButtonWithIcon("Disconnect", theme.MediaStopIcon(), func() {
		r.setBusy(true)
		a.disconnect(name, func() { r.setBusy(false) })
	})
	details := widget.NewButtonWithIcon("Details…", theme.InfoIcon(), func() { a.openDetails(name) })
	r.bg = canvas.NewRectangle(color.Transparent)
	r.bg.CornerRadius = 6
	top := container.NewHBox(r.title, r.healthL, layout.NewSpacer(), r.owner)
	actions := container.NewHBox(layout.NewSpacer(), r.connectB, r.discoB, details)
	body := container.NewVBox(top, r.reason, r.stats, r.recov, actions)
	r.card = container.NewVBox(container.NewStack(r.bg, container.NewPadded(body)), widget.NewSeparator())
	return r
}

func (r *tunnelRow) setBusy(b bool) {
	r.busy = b
	if b {
		r.connectB.Disable()
		r.discoB.Disable()
	}
}

func (r *tunnelRow) update(t api.TunnelStatus, ks *api.KillSwitchStatus, stale bool, role api.Role) {
	st := t.Health.State
	label := HealthIcon(st) + " " + st.Label()
	if stale {
		label = "? " + st.Label() + " (stale)"
	}
	r.healthL.SetText(label)
	r.owner.SetText(OwnershipLabel(t))
	reason := t.Health.Reason
	if t.ConfigError != "" {
		reason = "Configuration error: " + t.ConfigError
	} else if t.ConfigChanged {
		reason += " · configuration file changed on disk since it was last read"
	}
	r.reason.SetText(reason)

	ksText := "off"
	if ks != nil && ks.Status.Tunnel == t.Name && ks.Policy.Enabled {
		ksText = KillSwitchLabel(*ks)
	}
	hs := NewestHandshake(t)
	stats := fmt.Sprintf("Interface: %s · Handshake: %s · ↓ %s  ↑ %s · Total ↓ %s  ↑ %s · Kill switch: %s",
		InterfaceSummary(t), FormatAge(hs), FormatRate(t.RxRate, t.RateValid && !stale), FormatRate(t.TxRate, t.RateValid && !stale),
		FormatBytes(t.RxBytes), FormatBytes(t.TxBytes), ksText)
	if t.UpSince != nil && t.InterfaceExists {
		stats += " · Up " + FormatDuration(time.Since(*t.UpSince))
	}
	r.stats.SetText(stats)
	rec := RecoverySummary(t.Recovery, time.Now())
	if !t.Manageable && t.Ownership == config.OwnershipManaged && t.ManageBlocker != "" {
		rec = strings.TrimSpace(rec + " Cannot manage: " + t.ManageBlocker)
	}
	r.recov.SetText(rec)
	if rec == "" {
		r.recov.Hide()
	} else {
		r.recov.Show()
	}
	sev := HealthSeverity(st)
	if stale {
		sev = SevNeutral
	}
	r.bg.FillColor = sevBackground(sev)
	r.bg.Refresh()

	canControl := !stale && !r.busy && t.Manageable && t.Ownership == config.OwnershipManaged && role != api.RoleNone
	if canControl && !(t.Intent == health.IntentUp && t.InterfaceExists) {
		r.connectB.Enable()
	} else {
		r.connectB.Disable()
	}
	if canControl && (t.InterfaceExists || t.Intent == health.IntentUp) {
		r.discoB.Enable()
	} else {
		r.discoB.Disable()
	}
}
