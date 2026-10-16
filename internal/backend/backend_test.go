package backend

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type call struct {
	name string
	args []string
}

type fakeRunner struct {
	available map[string]bool
	outputs   map[string]string // key: name + " " + args joined
	errs      map[string]error
	calls     []call
}

func (f *fakeRunner) Available(name string) bool { return f.available[name] }

func (f *fakeRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
	key := name + " " + strings.Join(args, " ")
	return []byte(f.outputs[key]), f.errs[key]
}

func TestUpDownUsesArgumentArrays(t *testing.T) {
	r := &fakeRunner{available: map[string]bool{"wg-quick": true}}
	b := &WGQuick{Runner: r, ConfigDir: "/etc/wireguard"}
	if err := b.Up(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	if err := b.Down(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 || r.calls[0].name != "wg-quick" || strings.Join(r.calls[0].args, "|") != "up|/etc/wireguard/wg0.conf" {
		t.Fatalf("calls = %+v", r.calls)
	}
	for _, bad := range []string{"../etc/passwd", "wg0; reboot", "", "a/b"} {
		if err := b.Up(context.Background(), bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestConflictRefusesControl(t *testing.T) {
	r := &fakeRunner{
		available: map[string]bool{"wg-quick": true, "systemctl": true},
		outputs: map[string]string{
			"systemctl is-active wg-quick@wg0.service":  "inactive\n",
			"systemctl is-enabled wg-quick@wg0.service": "enabled\n",
		},
	}
	b := &WGQuick{Runner: r, ConfigDir: "/etc/wireguard"}
	err := b.Up(context.Background(), "wg0")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	for _, c := range r.calls {
		if c.name == "wg-quick" {
			t.Fatal("wg-quick must not run on conflict")
		}
	}
}

func TestNetworkManagerConflict(t *testing.T) {
	r := &fakeRunner{
		available: map[string]bool{"nmcli": true},
		outputs: map[string]string{
			"nmcli -t -f NAME,TYPE connection show":                        "Wired:802-3-ethernet\nmy\\:vpn:wireguard\nwg1:wireguard\n",
			"nmcli -g connection.interface-name connection show id my:vpn": "wg0\n",
			"nmcli -g connection.interface-name connection show id wg1":    "wg1\n",
		},
	}
	b := &WGQuick{Runner: r}
	owner, err := b.ExternalOwner(context.Background(), "wg0")
	if err != nil || !strings.Contains(owner, `"my:vpn"`) {
		t.Fatalf("owner=%q err=%v", owner, err)
	}
	owner, _ = b.ExternalOwner(context.Background(), "wg2")
	if owner != "" {
		t.Fatalf("unexpected owner %q", owner)
	}
}

func TestUnderlay(t *testing.T) {
	if !hasUnderlayDefault([]byte(`[{"dst":"default","gateway":"192.168.1.1","dev":"wlp2s0"}]`), "wg0") {
		t.Fatal("physical default route not detected")
	}
	if hasUnderlayDefault([]byte(`[{"dst":"default","dev":"wg0"}]`), "wg0") {
		t.Fatal("tunnel default route is not an underlay")
	}
	if hasUnderlayDefault([]byte(`[]`), "wg0") || hasUnderlayDefault([]byte(`garbage`), "wg0") {
		t.Fatal("no routes means no underlay")
	}
}
