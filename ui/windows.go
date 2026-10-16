package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/firewall"
	"github.com/cmerk2021/wgm/internal/ipc"
)

// killSwitchWindow shows and edits the kill switch.
type killSwitchWindow struct {
	a      *App
	win    fyne.Window
	status *widget.Label
	enable *widget.Check
	tunnel *widget.Select
	lan    *widget.Check
	dhcp   *widget.Check
	apply  *widget.Button
	loaded bool
}

func newKillSwitchWindow(a *App) *killSwitchWindow {
	k := &killSwitchWindow{a: a}
	k.win = a.fa.NewWindow("WGM — Kill switch")
	k.win.Resize(fyne.NewSize(640, 520))
	k.status = widget.NewLabel("")
	k.status.Wrapping = fyne.TextWrapWord
	k.enable = widget.NewCheck("Block all traffic that does not go through the VPN", nil)
	k.tunnel = widget.NewSelect(nil, nil)
	k.lan = widget.NewCheck("Allow local network (RFC 1918 / link-local) — weakens protection on untrusted networks", nil)
	k.dhcp = widget.NewCheck("Allow DHCP (recommended so the physical link keeps its address)", nil)
	k.apply = widget.NewButton("Apply…", k.submit)
	k.apply.Importance = widget.DangerImportance
	about := widget.NewLabel("The kill switch is a WGM-owned nftables table (inet wgm_killswitch). It only allows traffic through the selected " +
		"tunnel, the tunnel's own WireGuard packets to its endpoint, loopback and (optionally) DHCP/LAN. DNS outside the tunnel is blocked. " +
		"It stays in force when this window or the daemon is closed, when the tunnel fails and across reboots, until you disable it here. " +
		"Requires the admin role. Only full-tunnel (0.0.0.0/0) managed tunnels can be protected.\n\n" +
		"Emergency recovery from a terminal: sudo wgmd killswitch-disable")
	about.Wrapping = fyne.TextWrapWord
	k.win.SetContent(container.NewVScroll(container.NewVBox(
		widget.NewCard("Enforcement state", "Read from the live firewall, not from the requested setting", k.status),
		widget.NewCard("Policy", "", widget.NewForm(
			widget.NewFormItem("", k.enable),
			widget.NewFormItem("Protected tunnel", k.tunnel),
			widget.NewFormItem("", k.dhcp),
			widget.NewFormItem("", k.lan),
		)),
		container.NewHBox(k.apply),
		about,
	)))
	return k
}

func (k *killSwitchWindow) update(ks *api.KillSwitchStatus, stale bool) {
	if ks == nil {
		k.status.SetText("Unknown: the daemon is not reachable.")
		k.apply.Disable()
		return
	}
	var opts []string
	if k.a.tunnels != nil {
		for _, t := range k.a.tunnels.Tunnels {
			if t.Ownership == config.OwnershipManaged && t.FullTunnelV4 {
				opts = append(opts, t.Name)
			}
		}
	}
	k.tunnel.Options = opts
	if !k.loaded {
		k.enable.SetChecked(ks.Policy.Enabled)
		k.tunnel.SetSelected(ks.Policy.Tunnel)
		k.lan.SetChecked(ks.Policy.AllowLAN)
		k.dhcp.SetChecked(ks.Policy.AllowDHCP || !ks.Policy.Enabled)
		k.loaded = true
	}
	k.tunnel.Refresh()
	st := ks.Status
	var b strings.Builder
	if stale {
		b.WriteString("⚠ STALE: last known state; the daemon is unreachable.\n")
	}
	fmt.Fprintf(&b, "%s (since %s)\n", KillSwitchLabel(*ks), st.Since.Local().Format("2006-01-02 15:04:05"))
	if st.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", st.Reason)
	}
	if !st.LastVerified.IsZero() {
		fmt.Fprintf(&b, "Last verified against the live ruleset: %s ago\n", FormatDuration(time.Since(st.LastVerified)))
	}
	if len(st.Endpoints) > 0 {
		fmt.Fprintf(&b, "Endpoint exceptions: %s", strings.Join(st.Endpoints, ", "))
		if st.MarkRestricted {
			b.WriteString(" (only for WireGuard's own marked packets)")
		}
		b.WriteString("\n")
	}
	if st.State == firewall.StateEnforced {
		fmt.Fprintf(&b, "LAN allowed: %v · DHCP allowed: %v\n", st.AllowLAN, st.AllowDHCP)
	}
	for _, w := range ks.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", w)
	}
	k.status.SetText(b.String())
	if stale || k.a.role() != api.RoleAdmin {
		k.apply.Disable()
	} else {
		k.apply.Enable()
	}
}

func (k *killSwitchWindow) submit() {
	pol := config.KillSwitchPolicy{
		Enabled: k.enable.Checked, Tunnel: k.tunnel.Selected, Mode: config.KillSwitchFullTunnel,
		AllowLAN: k.lan.Checked, AllowDHCP: k.dhcp.Checked,
	}
	if pol.Enabled && pol.Tunnel == "" {
		dialog.ShowError(fmt.Errorf("choose the tunnel to protect (only managed full-tunnel tunnels are listed)"), k.win)
		return
	}
	var rev uint64
	if k.a.ks != nil {
		rev = k.a.ks.PolicyRev
	}
	title, msg := "Enable kill switch?", "All IPv4 and IPv6 traffic that does not go through "+pol.Tunnel+" will be blocked, including when the tunnel is down or WGM is not running. "+
		"Other applications' connections outside the VPN will fail."
	if !pol.Enabled {
		title, msg = "Disable kill switch?", "Traffic will be allowed outside the VPN again. Applications may leak traffic over the physical network if the tunnel fails."
	}
	dialog.ShowConfirm(title, msg, func(ok bool) {
		if !ok {
			return
		}
		k.apply.Disable()
		var res api.KillSwitchStatus
		k.a.do("Kill switch update", func(ctx context.Context, c *ipc.Client) error {
			return c.Call(ctx, api.OpSetKillSwitch, api.SetKillSwitchParams{Policy: pol, ExpectedRevision: rev}, &res)
		}, func() {
			k.loaded = false
			if res.Status.State != "" && pol.Enabled && res.Status.State != firewall.StateEnforced {
				dialog.ShowError(fmt.Errorf("the kill switch is NOT enforced: %s", res.Status.Reason), k.win)
			}
		})
	}, k.win)
}

// openEvents shows the daemon's recent events.
func (a *App) openEvents(tunnel string) {
	w := a.fa.NewWindow("WGM — Events")
	w.Resize(fyne.NewSize(820, 520))
	lbl := widget.NewLabel("Loading…")
	lbl.Wrapping = fyne.TextWrapWord
	load := func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var evs []api.EventView
			err := a.poll.Call(ctx, api.OpEvents, api.EventsParams{Tunnel: tunnel, Limit: 1000}, &evs)
			fyne.Do(func() {
				if err != nil {
					lbl.SetText("Events unavailable: " + ExplainError(err, a.socket))
					return
				}
				var b strings.Builder
				for i := len(evs) - 1; i >= 0; i-- {
					e := evs[i]
					name := e.Tunnel
					if name == "" {
						name = "-"
					}
					fmt.Fprintf(&b, "%s  %-8s %-6s %s: %s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Severity, name, e.Kind, e.Message)
				}
				if b.Len() == 0 {
					b.WriteString("No events recorded since the daemon started.")
				}
				lbl.SetText(b.String())
			})
		}()
	}
	w.SetContent(container.NewBorder(container.NewHBox(widget.NewButton("Refresh", load)), nil, nil, nil, container.NewVScroll(lbl)))
	load()
	w.Show()
}

// openMonitoring edits sampling and retention preferences.
func (a *App) openMonitoring() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var f config.File
		err := a.poll.Call(ctx, api.OpGetPolicy, nil, &f)
		fyne.Do(func() {
			if err != nil {
				dialog.ShowError(fmt.Errorf("cannot load settings: %s", ExplainError(err, a.socket)), a.win)
				return
			}
			a.showMonitoringForm(f)
		})
	}()
}

func (a *App) showMonitoringForm(f config.File) {
	m := f.Monitoring
	interval := widget.NewEntry()
	interval.SetText(strconv.Itoa(m.SampleIntervalSec))
	persist := widget.NewCheck("Store metrics and events on disk (SQLite)", nil)
	persist.SetChecked(m.PersistHistory)
	metricsDays := widget.NewEntry()
	metricsDays.SetText(strconv.Itoa(m.MetricsRetentionDays))
	eventDays := widget.NewEntry()
	eventDays.SetText(strconv.Itoa(m.EventRetentionDays))
	items := []*widget.FormItem{
		widget.NewFormItem("Sample interval (s)", interval),
		widget.NewFormItem("", persist),
		widget.NewFormItem("Keep metrics (days)", metricsDays),
		widget.NewFormItem("Keep events (days)", eventDays),
	}
	dialog.ShowForm("Monitoring settings (admin)", "Save", "Cancel", items, func(ok bool) {
		if !ok {
			return
		}
		var nm config.MonitoringPrefs
		var err error
		atoi := func(s string) int {
			v, e := strconv.Atoi(strings.TrimSpace(s))
			if e != nil && err == nil {
				err = fmt.Errorf("%q is not a whole number", s)
			}
			return v
		}
		nm.SampleIntervalSec = atoi(interval.Text)
		nm.PersistHistory = persist.Checked
		nm.MetricsRetentionDays = atoi(metricsDays.Text)
		nm.EventRetentionDays = atoi(eventDays.Text)
		if err == nil {
			err = nm.Validate()
		}
		if err != nil {
			dialog.ShowError(err, a.win)
			return
		}
		a.do("Save monitoring settings", func(ctx context.Context, c *ipc.Client) error {
			return c.Call(ctx, api.OpSetMonitoring, api.SetMonitoringParams{Monitoring: nm, ExpectedRevision: f.Revision}, nil)
		}, nil)
	}, a.win)
}

// exportDiagnostics saves the daemon's redacted diagnostic report.
func (a *App) exportDiagnostics() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var raw json.RawMessage
		err := a.poll.Call(ctx, api.OpDiagnostics, nil, &raw)
		fyne.Do(func() {
			if err != nil {
				dialog.ShowError(fmt.Errorf("cannot collect diagnostics: %s", ExplainError(err, a.socket)), a.win)
				return
			}
			var pretty any
			data := []byte(raw)
			if json.Unmarshal(raw, &pretty) == nil {
				if b, err := json.MarshalIndent(pretty, "", "  "); err == nil {
					data = b
				}
			}
			d := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
				if err != nil {
					dialog.ShowError(err, a.win)
					return
				}
				if w == nil {
					return
				}
				defer w.Close()
				if _, err := w.Write(data); err != nil {
					dialog.ShowError(err, a.win)
					return
				}
				dialog.ShowInformation("Diagnostics saved", "Saved to "+w.URI().Path()+".\nPrivate and preshared keys are never included; review the file before sharing (it contains addresses and endpoints).", a.win)
			}, a.win)
			d.SetFileName("wgm-diagnostics-" + time.Now().Format("20060102-150405") + ".json")
			d.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
			d.Show()
		})
	}()
}
