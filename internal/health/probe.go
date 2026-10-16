package health

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/cmerk2021/wgm/internal/config"
)

// Prober executes connectivity probes through a specific interface.
type Prober interface {
	Probe(ctx context.Context, iface string, spec config.ProbeSpec) ProbeResult
}

// DefaultProbeTimeout applies when a probe has no explicit timeout.
const DefaultProbeTimeout = 2 * time.Second

// InterfaceProber implements probes with sockets bound to the tunnel
// interface (SO_BINDTODEVICE). Binding guarantees that a probe can only
// succeed through the tunnel: if the interface is missing the bind fails,
// and traffic can never fall back to a physical interface.
type InterfaceProber struct{}

func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("bind to %s: %w", iface, serr)
		}
		return nil
	}
}

// Probe implements Prober.
func (InterfaceProber) Probe(ctx context.Context, iface string, spec config.ProbeSpec) ProbeResult {
	res := ProbeResult{Probe: spec.String(), At: time.Now()}
	if err := config.ValidateProbe(spec); err != nil {
		res.Detail = err.Error()
		return res
	}
	if !config.ValidInterfaceName(iface) {
		res.Detail = "invalid interface name"
		return res
	}
	timeout := DefaultProbeTimeout
	if spec.TimeoutMs > 0 {
		timeout = time.Duration(spec.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := netip.MustParseAddr(spec.Target)
	start := time.Now()
	var detail string
	var err error
	switch spec.Type {
	case config.ProbeICMP:
		err = icmpEcho(ctx, iface, target)
	case config.ProbeTCP:
		detail, err = tcpConnect(ctx, iface, netip.AddrPortFrom(target, uint16(spec.Port)))
	case config.ProbeDNS:
		detail, err = dnsQuery(ctx, iface, target, spec.Query)
	default:
		err = errors.New("unsupported probe type")
	}
	elapsed := time.Since(start)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	res.OK = true
	res.Detail = detail
	res.LatencyMs = float64(elapsed.Microseconds()) / 1000
	return res
}

func icmpEcho(ctx context.Context, iface string, target netip.Addr) error {
	network, proto := "ip4:icmp", 1
	var typ icmp.Type = ipv4.ICMPTypeEcho
	var reply icmp.Type = ipv4.ICMPTypeEchoReply
	if target.Is6() && !target.Is4In6() {
		network, proto = "ip6:ipv6-icmp", 58
		typ, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	lc := net.ListenConfig{Control: bindToDevice(iface)}
	pc, err := lc.ListenPacket(ctx, network, "")
	if err != nil {
		return fmt.Errorf("open icmp socket: %w", err)
	}
	defer pc.Close()
	var idb [4]byte
	_, _ = rand.Read(idb[:])
	id := int(binary.BigEndian.Uint16(idb[:2]))
	seq := int(binary.BigEndian.Uint16(idb[2:]))
	payload := []byte("wgm-health-probe")
	msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
	b, err := msg.Marshal(nil) // ICMPv6 checksum is filled in by the kernel
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(dl)
	}
	dst := &net.IPAddr{IP: net.IP(target.AsSlice())}
	if _, err := pc.WriteTo(b, dst); err != nil {
		return fmt.Errorf("send echo: %w", err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return errors.New("no echo reply before timeout")
			}
			return err
		}
		if ip, ok := from.(*net.IPAddr); !ok || !ip.IP.Equal(dst.IP) {
			continue
		}
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || m.Type != reply {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id && e.Seq == seq {
			return nil
		}
	}
}

func tcpConnect(ctx context.Context, iface string, ap netip.AddrPort) (string, error) {
	d := net.Dialer{Control: bindToDevice(iface)}
	c, err := d.DialContext(ctx, "tcp", ap.String())
	if err == nil {
		c.Close()
		return "connected", nil
	}
	// A RST proves the host was reached through the tunnel.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection refused (host reachable)", nil
	}
	return "", err
}

func dnsQuery(ctx context.Context, iface string, server netip.Addr, name string) (string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Control: bindToDevice(iface)}
			return d.DialContext(ctx, network, net.JoinHostPort(server.String(), strconv.Itoa(53)))
		},
	}
	addrs, err := r.LookupHost(ctx, name)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return "NXDOMAIN (server reachable)", nil
		}
		return "", err
	}
	return fmt.Sprintf("resolved %d address(es)", len(addrs)), nil
}
