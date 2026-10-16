package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/sysexec"
)

// State is the kill switch lifecycle state.
type State string

const (
	StateDisabled    State = "disabled"
	StateInstalling  State = "installing"
	StateEnforced    State = "enforced"
	StateError       State = "error"
	StateRecovering  State = "recovering"
	StateUnavailable State = "unavailable"
)

// NFT abstracts the nftables control surface used by the manager.
type NFT interface {
	// Available returns nil if nftables can be driven.
	Available() error
	// Apply runs a ruleset file as one atomic transaction.
	Apply(ctx context.Context, ruleset string) error
	// ListTable returns the JSON listing of the WGM table, or exists=false.
	ListTable(ctx context.Context) (data []byte, exists bool, err error)
	// DeleteTable removes the WGM table (only).
	DeleteTable(ctx context.Context) error
}

// NftCLI drives the nft utility. NetNS, if set, runs nft inside a named
// network namespace via `ip netns exec` (used by integration tests).
type NftCLI struct {
	Runner sysexec.Runner
	NetNS  string
}

func (n NftCLI) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if n.NetNS != "" {
		if !config.ValidInterfaceName(n.NetNS) {
			return nil, errors.New("invalid netns name")
		}
		return n.Runner.Run(ctx, stdin, "ip", append([]string{"netns", "exec", n.NetNS, "nft"}, args...)...)
	}
	return n.Runner.Run(ctx, stdin, "nft", args...)
}

// Available implements NFT.
func (n NftCLI) Available() error {
	if !n.Runner.Available("nft") {
		return errors.New("nft (nftables) is not installed")
	}
	if os.Geteuid() != 0 {
		return errors.New("controlling nftables requires root (wgmd is not running as root)")
	}
	return nil
}

// Apply implements NFT.
func (n NftCLI) Apply(ctx context.Context, ruleset string) error {
	_, err := n.run(ctx, []byte(ruleset), "-f", "-")
	return err
}

// ListTable implements NFT.
func (n NftCLI) ListTable(ctx context.Context) ([]byte, bool, error) {
	tables, err := n.run(ctx, nil, "-j", "list", "tables", "inet")
	if err != nil {
		return nil, false, err
	}
	found, err := tableListed(tables)
	if err != nil || !found {
		return nil, false, err
	}
	data, err := n.run(ctx, nil, "-j", "list", "table", "inet", TableName)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// DeleteTable implements NFT.
func (n NftCLI) DeleteTable(ctx context.Context) error {
	_, exists, err := n.ListTable(ctx)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	_, err = n.run(ctx, nil, "delete", "table", "inet", TableName)
	return err
}

type nftDoc struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftRule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Comment string `json:"comment"`
}

func tableListed(data []byte) (bool, error) {
	var doc nftDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, fmt.Errorf("parse nft table list: %w", err)
	}
	for _, obj := range doc.Nftables {
		if raw, ok := obj["table"]; ok {
			var t nftTable
			if json.Unmarshal(raw, &t) == nil && t.Family == "inet" && t.Name == TableName {
				return true, nil
			}
		}
	}
	return false, nil
}

// Verify checks a JSON listing of the WGM table against the expected
// ruleset. It returns a reason when the kernel state does not match.
func Verify(data []byte, want Ruleset) (bool, string) {
	var doc nftDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, "cannot parse nft output: " + err.Error()
	}
	chains := map[string]nftChain{}
	rules := map[string][]nftRule{}
	for _, obj := range doc.Nftables {
		if raw, ok := obj["chain"]; ok {
			var c nftChain
			if json.Unmarshal(raw, &c) == nil && c.Table == TableName && c.Family == "inet" {
				chains[c.Name] = c
			}
		}
		if raw, ok := obj["rule"]; ok {
			var r nftRule
			if json.Unmarshal(raw, &r) == nil && r.Table == TableName && r.Family == "inet" {
				rules[r.Chain] = append(rules[r.Chain], r)
			}
		}
	}
	check := func(name, hook string, count int) string {
		c, ok := chains[name]
		if !ok {
			return fmt.Sprintf("chain %s is missing", name)
		}
		if c.Type != "filter" || c.Hook != hook || c.Policy != "drop" {
			return fmt.Sprintf("chain %s is not a drop-policy %s hook (type=%s hook=%s policy=%s)", name, hook, c.Type, c.Hook, c.Policy)
		}
		rs := rules[name]
		if len(rs) != count {
			return fmt.Sprintf("chain %s has %d rules, expected %d", name, len(rs), count)
		}
		if rs[len(rs)-1].Comment != want.Marker {
			return fmt.Sprintf("chain %s does not carry the expected policy marker (stale or modified rules)", name)
		}
		return ""
	}
	if r := check("output", "output", want.RuleCount); r != "" {
		return false, r
	}
	if r := check("forward", "forward", want.FwdCount); r != "" {
		return false, r
	}
	if len(chains) != 2 {
		return false, "unexpected chains in WGM table"
	}
	return true, ""
}

// Status is the externally visible kill switch state.
type Status struct {
	State          State     `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	Tunnel         string    `json:"tunnel,omitempty"`
	Since          time.Time `json:"since"`
	LastVerified   time.Time `json:"last_verified,omitempty"`
	RulesetHash    string    `json:"ruleset_hash,omitempty"`
	Endpoints      []string  `json:"endpoints,omitempty"`
	MarkRestricted bool      `json:"mark_restricted"`
	AllowLAN       bool      `json:"allow_lan"`
	AllowDHCP      bool      `json:"allow_dhcp"`
}

// Manager owns the kill switch lifecycle. Safe for concurrent use.
type Manager struct {
	NFT NFT
	// BootFile stores the last enforced ruleset for early-boot restore.
	BootFile string
	Now      func() time.Time
	// OnChange, if set, is called after every state change.
	OnChange func(old, new Status)

	mu     sync.Mutex
	status Status
	want   *Ruleset
	spec   Spec
}

// NewManager creates a manager in the Disabled state.
func NewManager(nft NFT, bootFile string) *Manager {
	m := &Manager{NFT: nft, BootFile: bootFile, Now: time.Now}
	m.status = Status{State: StateDisabled, Since: m.Now()}
	return m
}

// Status returns the current status.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Endpoints = append([]string(nil), s.Endpoints...)
	return s
}

func (m *Manager) set(st State, reason string) {
	old := m.status
	if old.State != st {
		m.status.Since = m.Now()
	}
	m.status.State, m.status.Reason = st, reason
	if m.OnChange != nil && (old.State != st || old.Reason != reason) {
		m.OnChange(old, m.status)
	}
}

func (m *Manager) describe(s Spec, rs Ruleset) {
	m.status.Tunnel = s.Interface
	m.status.RulesetHash = rs.Hash
	m.status.MarkRestricted = s.MarkRestricted()
	m.status.AllowLAN, m.status.AllowDHCP = s.AllowLAN, s.AllowDHCP
	m.status.Endpoints = m.status.Endpoints[:0]
	for _, ep := range s.Endpoints {
		m.status.Endpoints = append(m.status.Endpoints, ep.String())
	}
}

// Enable installs (or updates) the kill switch for spec. On failure the
// previous kernel ruleset is left untouched (nft applies atomically) and
// the state becomes Error; protection is never removed as a side effect.
func (m *Manager) Enable(ctx context.Context, s Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enableLocked(ctx, s, StateInstalling)
}

func (m *Manager) enableLocked(ctx context.Context, s Spec, transitional State) error {
	if err := m.NFT.Available(); err != nil {
		m.set(StateUnavailable, err.Error())
		return err
	}
	rs, err := Render(s)
	if err != nil {
		m.set(StateError, "cannot build kill switch policy: "+err.Error())
		return err
	}
	m.set(transitional, "applying nftables policy")
	if m.BootFile != "" {
		if err := config.WriteFileAtomic(m.BootFile, []byte(rs.Text), 0o600); err != nil {
			m.set(StateError, "cannot save boot-time policy: "+err.Error())
			return err
		}
	}
	if err := m.NFT.Apply(ctx, rs.Text); err != nil {
		m.set(StateError, "nft rejected the policy: "+err.Error())
		return err
	}
	m.want, m.spec = &rs, s
	m.describe(s, rs)
	return m.verifyLocked(ctx)
}

func (m *Manager) verifyLocked(ctx context.Context) error {
	data, exists, err := m.NFT.ListTable(ctx)
	if err != nil {
		m.set(StateError, "cannot read back nftables state: "+err.Error())
		return err
	}
	if !exists {
		m.set(StateError, "WGM nftables table is not present")
		return errors.New("kill switch table missing")
	}
	if ok, why := Verify(data, *m.want); !ok {
		m.set(StateError, "enforcement check failed: "+why)
		return errors.New(why)
	}
	m.status.LastVerified = m.Now()
	m.set(StateEnforced, "nftables policy verified in kernel")
	return nil
}

// Disable removes the WGM table and the boot-time policy.
func (m *Manager) Disable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.NFT.Available(); err != nil {
		m.set(StateUnavailable, err.Error())
		return err
	}
	if m.BootFile != "" {
		if err := os.Remove(m.BootFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			m.set(StateError, "cannot remove boot-time policy: "+err.Error())
			return err
		}
	}
	if err := m.NFT.DeleteTable(ctx); err != nil {
		m.set(StateError, "failed to remove kill switch rules (they may still be active): "+err.Error())
		return err
	}
	if _, exists, err := m.NFT.ListTable(ctx); err != nil || exists {
		m.set(StateError, "kill switch rules still present after removal")
		return errors.New("kill switch rules still present")
	}
	m.want = nil
	m.status = Status{State: m.status.State, Since: m.status.Since}
	m.set(StateDisabled, "kill switch disabled by policy")
	return nil
}

// Reconcile makes kernel state match the desired spec (nil = disabled).
// When enabled, missing or modified rules are re-installed (Recovering);
// a changed spec (e.g. new endpoint address or fwmark) is re-applied.
func (m *Manager) Reconcile(ctx context.Context, desired *Spec) error {
	if desired == nil {
		m.mu.Lock()
		st := m.status.State
		m.mu.Unlock()
		if err := m.NFT.Available(); err != nil {
			m.mu.Lock()
			m.set(StateDisabled, "kill switch disabled; "+err.Error())
			m.mu.Unlock()
			return nil
		}
		_, exists, err := m.NFT.ListTable(ctx)
		if err != nil {
			return err
		}
		if exists || st != StateDisabled {
			return m.Disable(ctx)
		}
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rs, err := Render(*desired)
	if err != nil {
		// Keep whatever is enforced; report the problem.
		m.set(StateError, "cannot build kill switch policy: "+err.Error())
		return err
	}
	if m.want != nil && m.want.Text == rs.Text {
		if err := m.NFT.Available(); err != nil {
			m.set(StateUnavailable, err.Error())
			return err
		}
		if err := m.verifyLocked(ctx); err == nil {
			return nil
		}
		return m.enableLocked(ctx, *desired, StateRecovering)
	}
	trans := StateInstalling
	if m.status.State == StateEnforced || m.status.State == StateError {
		trans = StateRecovering
	}
	return m.enableLocked(ctx, *desired, trans)
}

// RestoreBootFile applies a previously saved ruleset (early boot). The file
// must be root-owned and not writable by group/other, and must only define
// the WGM table.
func RestoreBootFile(ctx context.Context, nft NFT, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // kill switch not enabled
		}
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := checkOwnership(st); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return err
	}
	text := string(data)
	if err := checkOnlyWGMTable(text); err != nil {
		return err
	}
	return nft.Apply(ctx, text)
}

func checkOnlyWGMTable(text string) error {
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "table ") || strings.HasPrefix(l, "delete ") || strings.HasPrefix(l, "flush ") ||
			strings.HasPrefix(l, "add ") || strings.HasPrefix(l, "include") {
			ok := l == "table inet "+TableName || l == "table inet "+TableName+" {" || l == "delete table inet "+TableName
			if !ok {
				return fmt.Errorf("boot policy contains a statement outside the WGM table: %q", l)
			}
		}
	}
	return nil
}
