// Package tunnel discovers WireGuard configurations and reads runtime
// interface state. Private and preshared keys are never retained: the
// parser records only whether they are present.
package tunnel

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MaxConfigSize bounds the WireGuard configuration files we parse.
const MaxConfigSize = 256 << 10

// PeerConfig is the non-secret part of a [Peer] section.
type PeerConfig struct {
	PublicKey           string   `json:"public_key"`
	HasPresharedKey     bool     `json:"has_preshared_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// Config is the redacted view of a wg-quick configuration file.
type Config struct {
	Addresses     []string     `json:"addresses,omitempty"`
	ListenPort    int          `json:"listen_port,omitempty"`
	DNS           []string     `json:"dns,omitempty"`
	MTU           int          `json:"mtu,omitempty"`
	Table         string       `json:"table,omitempty"`
	FwMark        string       `json:"fwmark,omitempty"`
	HasPrivateKey bool         `json:"has_private_key"`
	Hooks         []string     `json:"hooks,omitempty"` // names of PreUp/PostUp/... present
	SaveConfig    bool         `json:"save_config"`
	Peers         []PeerConfig `json:"peers,omitempty"`
	Warnings      []string     `json:"warnings,omitempty"`
	// Fingerprint is a hash of the redacted, normalised configuration. It
	// changes when the meaningful configuration changes and contains no
	// secret material.
	Fingerprint string `json:"fingerprint"`
}

// FullTunnel reports whether any peer routes all IPv4 or IPv6 traffic.
func (c *Config) FullTunnel() (v4, v6 bool) {
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			pf, err := netip.ParsePrefix(a)
			if err != nil || pf.Bits() != 0 {
				continue
			}
			if pf.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
		}
	}
	return
}

// ParseError identifies the line of a syntax error without echoing values
// (the line could contain a key).
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

var secretKeys = map[string]bool{"privatekey": true, "presharedkey": true}

// ParseConfig parses a wg-quick style configuration.
func ParseConfig(data []byte) (*Config, error) {
	if len(data) > MaxConfigSize {
		return nil, fmt.Errorf("configuration exceeds %d bytes", MaxConfigSize)
	}
	c := &Config{}
	section := ""
	var peer *PeerConfig
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), MaxConfigSize)
	line := 0
	hooks := map[string]bool{}
	for sc.Scan() {
		line++
		raw := sc.Text()
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = raw[:i]
		}
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "[") {
			if !strings.HasSuffix(s, "]") {
				return nil, &ParseError{line, "malformed section header"}
			}
			section = strings.ToLower(strings.TrimSpace(s[1 : len(s)-1]))
			switch section {
			case "interface":
			case "peer":
				c.Peers = append(c.Peers, PeerConfig{})
				peer = &c.Peers[len(c.Peers)-1]
			default:
				return nil, &ParseError{line, "unknown section"}
			}
			continue
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, &ParseError{line, "expected key = value"}
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		val := strings.TrimSpace(s[eq+1:])
		if secretKeys[key] {
			// Only record presence; never keep the value.
			if section == "interface" && key == "privatekey" {
				c.HasPrivateKey = val != ""
			} else if section == "peer" && key == "presharedkey" && peer != nil {
				peer.HasPresharedKey = val != ""
			} else {
				return nil, &ParseError{line, "key not valid in this section"}
			}
			continue
		}
		switch section {
		case "interface":
			if err := c.setInterface(key, val, hooks); err != nil {
				return nil, &ParseError{line, err.Error()}
			}
		case "peer":
			if err := setPeer(peer, key, val); err != nil {
				return nil, &ParseError{line, err.Error()}
			}
		default:
			return nil, &ParseError{line, "key outside of a section"}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !c.HasPrivateKey {
		c.Warnings = append(c.Warnings, "no PrivateKey in [Interface]")
	}
	if len(c.Peers) == 0 {
		c.Warnings = append(c.Warnings, "no [Peer] sections")
	}
	for i, p := range c.Peers {
		if p.PublicKey == "" {
			c.Warnings = append(c.Warnings, fmt.Sprintf("peer %d has no PublicKey", i+1))
		}
	}
	for _, h := range []string{"PreUp", "PostUp", "PreDown", "PostDown"} {
		if hooks[strings.ToLower(h)] {
			c.Hooks = append(c.Hooks, h)
		}
	}
	c.Fingerprint = c.fingerprint()
	return c, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) setInterface(key, val string, hooks map[string]bool) error {
	switch key {
	case "address":
		for _, a := range splitList(val) {
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err2 := netip.ParseAddr(a); err2 != nil {
					return fmt.Errorf("invalid Address entry %q", a)
				}
			}
			c.Addresses = append(c.Addresses, a)
		}
	case "listenport":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("invalid ListenPort")
		}
		c.ListenPort = n
	case "dns":
		c.DNS = append(c.DNS, splitList(val)...)
	case "mtu":
		n, err := strconv.Atoi(val)
		if err != nil || n < 576 || n > 65535 {
			return fmt.Errorf("invalid MTU")
		}
		c.MTU = n
	case "table":
		c.Table = val
	case "fwmark":
		c.FwMark = val
	case "saveconfig":
		c.SaveConfig = strings.EqualFold(val, "true")
	case "preup", "postup", "predown", "postdown":
		// Hook commands may embed secrets; record only their presence.
		hooks[key] = true
	default:
		c.Warnings = append(c.Warnings, fmt.Sprintf("unknown [Interface] key %q", key))
	}
	return nil
}

func setPeer(p *PeerConfig, key, val string) error {
	switch key {
	case "publickey":
		p.PublicKey = val
	case "endpoint":
		p.Endpoint = val
	case "allowedips":
		for _, a := range splitList(val) {
			if _, err := netip.ParsePrefix(a); err != nil {
				return fmt.Errorf("invalid AllowedIPs entry %q", a)
			}
			p.AllowedIPs = append(p.AllowedIPs, a)
		}
	case "persistentkeepalive":
		if strings.EqualFold(val, "off") {
			p.PersistentKeepalive = 0
			return nil
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("invalid PersistentKeepalive")
		}
		p.PersistentKeepalive = n
	default:
		return fmt.Errorf("unknown [Peer] key %q", key)
	}
	return nil
}

func (c *Config) fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "a=%v|lp=%d|dns=%v|mtu=%d|t=%s|fw=%s|pk=%v|hooks=%v|save=%v\n",
		c.Addresses, c.ListenPort, c.DNS, c.MTU, c.Table, c.FwMark, c.HasPrivateKey, c.Hooks, c.SaveConfig)
	for _, p := range c.Peers {
		fmt.Fprintf(h, "peer=%s|psk=%v|ep=%s|ips=%v|ka=%d\n", p.PublicKey, p.HasPresharedKey, p.Endpoint, p.AllowedIPs, p.PersistentKeepalive)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// EndpointHostPort splits an Endpoint value into host and port.
func EndpointHostPort(ep string) (host string, port int, err error) {
	i := strings.LastIndexByte(ep, ':')
	if i <= 0 {
		return "", 0, fmt.Errorf("endpoint %q has no port", ep)
	}
	host = strings.TrimSuffix(strings.TrimPrefix(ep[:i], "["), "]")
	port, err = strconv.Atoi(ep[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("endpoint %q has an invalid port", ep)
	}
	return host, port, nil
}
