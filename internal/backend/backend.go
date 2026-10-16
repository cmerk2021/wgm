// Package backend activates and deactivates tunnels. The first release
// ships one backend, wg-quick, and detects other managers
// (NetworkManager, systemd wg-quick@ units) so that two managers never
// control the same tunnel.
package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/sysexec"
)

// Backend controls tunnel activation.
type Backend interface {
	Name() string
	Up(ctx context.Context, name string) error
	Down(ctx context.Context, name string) error
	// ExternalOwner returns a description of another manager controlling
	// the tunnel, or "" if none was detected.
	ExternalOwner(ctx context.Context, name string) (string, error)
	// UnderlayUp reports whether a non-tunnel default route exists.
	UnderlayUp(ctx context.Context, tunnel string) (bool, error)
}

// ErrConflict is returned when another manager controls the tunnel.
var ErrConflict = errors.New("tunnel is controlled by another manager")

// WGQuick drives wg-quick(8) with configuration files in ConfigDir.
type WGQuick struct {
	Runner    sysexec.Runner
	ConfigDir string
}

// Name implements Backend.
func (w *WGQuick) Name() string { return "wg-quick" }

func (w *WGQuick) confPath(name string) (string, error) {
	if !config.ValidInterfaceName(name) {
		return "", fmt.Errorf("invalid tunnel name %q", name)
	}
	return filepath.Join(w.ConfigDir, name+".conf"), nil
}

func (w *WGQuick) guard(ctx context.Context, name string) (string, error) {
	path, err := w.confPath(name)
	if err != nil {
		return "", err
	}
	if !w.Runner.Available("wg-quick") {
		return "", errors.New("wg-quick is not installed (install wireguard-tools)")
	}
	owner, err := w.ExternalOwner(ctx, name)
	if err != nil {
		return "", fmt.Errorf("cannot determine whether another manager controls %s: %w", name, err)
	}
	if owner != "" {
		return "", fmt.Errorf("%w: %s", ErrConflict, owner)
	}
	return path, nil
}

// Up implements Backend.
func (w *WGQuick) Up(ctx context.Context, name string) error {
	path, err := w.guard(ctx, name)
	if err != nil {
		return err
	}
	_, err = w.Runner.Run(ctx, nil, "wg-quick", "up", path)
	return err
}

// Down implements Backend.
func (w *WGQuick) Down(ctx context.Context, name string) error {
	path, err := w.guard(ctx, name)
	if err != nil {
		return err
	}
	_, err = w.Runner.Run(ctx, nil, "wg-quick", "down", path)
	return err
}

// ExternalOwner implements Backend. It checks for an active or enabled
// systemd wg-quick@ unit and for NetworkManager WireGuard profiles bound
// to the interface. Missing tools mean that manager is not in use.
func (w *WGQuick) ExternalOwner(ctx context.Context, name string) (string, error) {
	if !config.ValidInterfaceName(name) {
		return "", fmt.Errorf("invalid tunnel name %q", name)
	}
	if w.Runner.Available("systemctl") {
		unit := "wg-quick@" + name + ".service"
		active, _ := w.Runner.Run(ctx, nil, "systemctl", "is-active", unit)
		enabled, _ := w.Runner.Run(ctx, nil, "systemctl", "is-enabled", unit)
		a, e := strings.TrimSpace(string(active)), strings.TrimSpace(string(enabled))
		if a == "active" || a == "activating" || e == "enabled" {
			return fmt.Sprintf("systemd unit %s (%s, %s)", unit, a, e), nil
		}
	}
	if w.Runner.Available("nmcli") {
		out, err := w.Runner.Run(ctx, nil, "nmcli", "-t", "-f", "NAME,TYPE", "connection", "show")
		if err != nil {
			// NetworkManager installed but not running: not a conflict.
			return "", nil
		}
		for _, profile := range parseNMProfiles(out) {
			ifn, err := w.Runner.Run(ctx, nil, "nmcli", "-g", "connection.interface-name", "connection", "show", "id", profile)
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(ifn)) == name {
				return fmt.Sprintf("NetworkManager connection profile %q", profile), nil
			}
		}
	}
	return "", nil
}

// parseNMProfiles extracts names of WireGuard profiles from
// `nmcli -t -f NAME,TYPE connection show` (colons in names are escaped).
func parseNMProfiles(out []byte) []string {
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		// Split on the last unescaped colon.
		idx := -1
		for i := len(line) - 1; i >= 0; i-- {
			if line[i] == ':' && (i == 0 || line[i-1] != '\\') {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}
		if line[idx+1:] == "wireguard" {
			names = append(names, strings.ReplaceAll(line[:idx], `\:`, ":"))
		}
	}
	return names
}

type route struct {
	Dst string `json:"dst"`
	Dev string `json:"dev"`
}

// UnderlayUp implements Backend.
func (w *WGQuick) UnderlayUp(ctx context.Context, tunnel string) (bool, error) {
	var lastErr error
	for _, fam := range []string{"-4", "-6"} {
		out, err := w.Runner.Run(ctx, nil, "ip", "-j", fam, "route", "show", "default")
		if err != nil {
			lastErr = err
			continue
		}
		if hasUnderlayDefault(out, tunnel) {
			return true, nil
		}
	}
	return false, lastErr
}

func hasUnderlayDefault(data []byte, tunnel string) bool {
	var rs []route
	if json.Unmarshal(data, &rs) != nil {
		return false
	}
	for _, r := range rs {
		if r.Dev != "" && r.Dev != tunnel {
			return true
		}
	}
	return false
}
