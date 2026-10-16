// Package firewall implements WGM's nftables kill switch.
//
// Ownership: WGM only ever touches the table `inet wgm_killswitch`. It never
// flushes the global ruleset or edits tables owned by firewalld or other
// software. Because every nftables base chain on a hook must accept a
// packet for it to pass, WGM's drop policy is effective regardless of other
// tables, and WGM's accepts can never weaken another firewall's drops.
//
// Lifecycle: rules live in the kernel independently of wgmd. A daemon crash
// or stop leaves them in place (fail closed); only an explicit disable
// removes them. The rendered ruleset is also saved so it can be restored
// early at boot (wgm-killswitch.service) before networking starts.
package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/cmerk2021/wgm/internal/config"
)

// TableName is the WGM-owned nftables table (family inet).
const TableName = "wgm_killswitch"

// markerPrefix tags the final rule; the suffix is a hash of the ruleset so
// verification can detect stale or tampered rules.
const markerPrefix = "wgm-killswitch:"

// Spec is the fully resolved input for a full-tunnel kill switch.
type Spec struct {
	Interface string           `json:"interface"`
	Endpoints []netip.AddrPort `json:"endpoints"`
	// FwMark is WireGuard's socket mark. When non-zero the endpoint
	// exception only matches packets carrying it, which only the kernel
	// WireGuard socket (or a CAP_NET_ADMIN process) can set.
	FwMark    uint32 `json:"fwmark"`
	AllowLAN  bool   `json:"allow_lan"`
	AllowDHCP bool   `json:"allow_dhcp"`
}

// MarkRestricted reports whether endpoint exceptions are tied to the
// WireGuard fwmark.
func (s Spec) MarkRestricted() bool { return s.FwMark != 0 }

// Validate checks that the spec is safe to render.
func (s Spec) Validate() error {
	if !config.ValidInterfaceName(s.Interface) || s.Interface == "lo" {
		return fmt.Errorf("invalid VPN interface name %q", s.Interface)
	}
	if len(s.Endpoints) == 0 {
		return errors.New("no peer endpoint addresses are known; the tunnel could never connect through the kill switch")
	}
	if len(s.Endpoints) > 64 {
		return errors.New("too many endpoint addresses")
	}
	for _, ep := range s.Endpoints {
		a := ep.Addr()
		if !ep.IsValid() || ep.Port() == 0 || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return fmt.Errorf("invalid endpoint %s", ep)
		}
	}
	return nil
}

var (
	lan4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	lan6 = []string{"fe80::/10", "fc00::/7"}
)

// Ruleset is a rendered kill switch.
type Ruleset struct {
	Text      string // nft -f input, replaces the WGM table atomically
	Hash      string // short hash of the policy body
	Marker    string // comment carried by the final rule
	RuleCount int    // rules in the output chain (for verification)
	FwdCount  int    // rules in the forward chain
}

func q(s string) string { return `"` + s + `"` }

// Render produces the nftables ruleset for spec. All interpolated values
// are validated (interface names against a strict character set, addresses
// parsed) so no untrusted text can reach nft.
func Render(s Spec) (Ruleset, error) {
	if err := s.Validate(); err != nil {
		return Ruleset{}, err
	}
	eps := append([]netip.AddrPort(nil), s.Endpoints...)
	sort.Slice(eps, func(i, j int) bool { return eps[i].String() < eps[j].String() })
	var out []string
	add := func(r string) { out = append(out, r) }

	add(`oifname "lo" accept`)
	add(`oifname ` + q(s.Interface) + ` accept`)
	mark := ""
	if s.FwMark != 0 {
		mark = fmt.Sprintf("meta mark 0x%08x ", s.FwMark)
	}
	for _, ep := range eps {
		fam := "ip"
		if ep.Addr().Is6() && !ep.Addr().Is4In6() {
			fam = "ip6"
		}
		add(fmt.Sprintf("%s%s daddr %s udp dport %d accept", mark, fam, ep.Addr().Unmap(), ep.Port()))
	}
	// IPv6 neighbour discovery is link-local, required for any IPv6 link
	// (including an IPv6 endpoint) and cannot carry routed traffic.
	add(`icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept`)
	if s.AllowDHCP {
		add(`ip version 4 udp sport 68 udp dport 67 accept`)
		add(`ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept`)
	}
	// DNS outside the tunnel is never allowed, even to LAN resolvers.
	add(`meta l4proto { tcp, udp } th dport { 53, 853 } counter drop`)
	if s.AllowLAN {
		add(`ip daddr { ` + strings.Join(lan4, ", ") + ` } accept`)
		add(`ip6 daddr { ` + strings.Join(lan6, ", ") + ` } accept`)
	}
	body := strings.Join(out, "\n")
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%+v", body, s.AllowLAN)))
	hash := hex.EncodeToString(sum[:])[:16]
	marker := markerPrefix + hash
	add(`counter drop comment ` + q(marker))

	var fwd []string
	fwd = append(fwd, `oifname `+q(s.Interface)+` accept`, `iifname `+q(s.Interface)+` accept`)
	if s.AllowLAN {
		fwd = append(fwd, `meta l4proto { tcp, udp } th dport { 53, 853 } oifname != `+q(s.Interface)+` drop`)
		fwd = append(fwd, `ip daddr { `+strings.Join(lan4, ", ")+` } accept`, `ip6 daddr { `+strings.Join(lan6, ", ")+` } accept`)
	}
	fwd = append(fwd, `counter drop comment `+q(marker))

	var b strings.Builder
	// Declaring then deleting makes the replace idempotent whether or not
	// the table exists; the whole file is applied as one transaction.
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", TableName, TableName)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n")
	for _, r := range out {
		b.WriteString("\t\t" + r + "\n")
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n")
	for _, r := range fwd {
		b.WriteString("\t\t" + r + "\n")
	}
	b.WriteString("\t}\n}\n")
	return Ruleset{Text: b.String(), Hash: hash, Marker: marker, RuleCount: len(out), FwdCount: len(fwd)}, nil
}
