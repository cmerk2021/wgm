package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/cmerk2021/wgm/internal/sysexec"
)

// PeerRuntime is live peer state reported by the kernel.
type PeerRuntime struct {
	PublicKey           string        `json:"public_key"`
	Endpoint            string        `json:"endpoint,omitempty"`
	AllowedIPs          []string      `json:"allowed_ips,omitempty"`
	LastHandshake       time.Time     `json:"last_handshake"` // zero: never
	PersistentKeepalive time.Duration `json:"persistent_keepalive"`
	RxBytes             uint64        `json:"rx_bytes"`
	TxBytes             uint64        `json:"tx_bytes"`
}

// Runtime is a point-in-time view of an interface. It never contains the
// private key.
type Runtime struct {
	Name        string        `json:"name"`
	Exists      bool          `json:"exists"`
	Up          bool          `json:"up"`
	IsWireGuard bool          `json:"is_wireguard"`
	Addresses   []string      `json:"addresses,omitempty"`
	Routes      []string      `json:"routes,omitempty"`
	ListenPort  int           `json:"listen_port,omitempty"`
	FwMark      int           `json:"fwmark,omitempty"`
	Peers       []PeerRuntime `json:"peers,omitempty"`
	// Err reports a non-fatal problem gathering runtime details.
	Err string `json:"error,omitempty"`
}

// RxTx sums peer counters.
func (r Runtime) RxTx() (rx, tx uint64) {
	for _, p := range r.Peers {
		rx += p.RxBytes
		tx += p.TxBytes
	}
	return
}

// Reader reads runtime interface state.
type Reader interface {
	Read(ctx context.Context, name string) (Runtime, error)
	// ListWireGuard returns names of all existing WireGuard interfaces.
	ListWireGuard(ctx context.Context) ([]string, error)
}

// LinuxReader reads state via WireGuard generic netlink (wgctrl), the
// standard library and `ip -j route`.
type LinuxReader struct {
	Runner sysexec.Runner

	mu     sync.Mutex
	client *wgctrl.Client
}

func (l *LinuxReader) wg() (*wgctrl.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wireguard netlink unavailable: %w", err)
	}
	l.client = c
	return c, nil
}

// Close releases the netlink handle.
func (l *LinuxReader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		err := l.client.Close()
		l.client = nil
		return err
	}
	return nil
}

// ListWireGuard implements Reader.
func (l *LinuxReader) ListWireGuard(ctx context.Context) ([]string, error) {
	c, err := l.wg()
	if err != nil {
		return nil, err
	}
	devs, err := c.Devices()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(devs))
	for _, d := range devs {
		names = append(names, d.Name)
	}
	sort.Strings(names)
	return names, nil
}

// Read implements Reader.
func (l *LinuxReader) Read(ctx context.Context, name string) (Runtime, error) {
	rt := Runtime{Name: name}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		// Interface absent is a normal state, not an error.
		return rt, nil
	}
	rt.Exists = true
	rt.Up = ifc.Flags&net.FlagUp != 0
	if addrs, err := ifc.Addrs(); err == nil {
		for _, a := range addrs {
			rt.Addresses = append(rt.Addresses, a.String())
		}
	}
	var problems []string
	c, err := l.wg()
	if err != nil {
		problems = append(problems, err.Error())
	} else if dev, err := c.Device(name); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, "read wireguard device: "+err.Error())
		}
	} else {
		rt.IsWireGuard = true
		rt.ListenPort = dev.ListenPort
		rt.FwMark = dev.FirewallMark
		for _, p := range dev.Peers {
			pr := PeerRuntime{
				PublicKey:           p.PublicKey.String(),
				LastHandshake:       p.LastHandshakeTime,
				PersistentKeepalive: p.PersistentKeepaliveInterval,
				RxBytes:             uint64(p.ReceiveBytes),
				TxBytes:             uint64(p.TransmitBytes),
			}
			if p.LastHandshakeTime.Unix() <= 0 {
				pr.LastHandshake = time.Time{}
			}
			if p.Endpoint != nil {
				pr.Endpoint = p.Endpoint.String()
			}
			for _, ip := range p.AllowedIPs {
				pr.AllowedIPs = append(pr.AllowedIPs, ip.String())
			}
			rt.Peers = append(rt.Peers, pr)
		}
	}
	if l.Runner != nil {
		routes, err := readRoutes(ctx, l.Runner, name)
		if err != nil {
			problems = append(problems, "read routes: "+err.Error())
		}
		rt.Routes = routes
	}
	rt.Err = strings.Join(problems, "; ")
	return rt, nil
}

type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Table   string `json:"table"`
	Type    string `json:"type"`
}

func readRoutes(ctx context.Context, r sysexec.Runner, name string) ([]string, error) {
	var out []string
	for _, fam := range []string{"-4", "-6"} {
		data, err := r.Run(ctx, nil, "ip", "-j", fam, "route", "show", "table", "all", "dev", name)
		if err != nil {
			return out, err
		}
		routes, err := parseIPRoutes(data)
		if err != nil {
			return out, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

func parseIPRoutes(data []byte) ([]string, error) {
	var routes []ipRoute
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range routes {
		if r.Table == "local" || r.Type == "local" || r.Type == "broadcast" || r.Type == "multicast" {
			continue
		}
		s := r.Dst
		if r.Gateway != "" {
			s += " via " + r.Gateway
		}
		if r.Table != "" && r.Table != "main" {
			s += " table " + r.Table
		}
		out = append(out, s)
	}
	return out, nil
}
