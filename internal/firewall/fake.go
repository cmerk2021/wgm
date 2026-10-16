package firewall

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// FakeNFT is an in-memory NFT used by tests. It models the kernel's view
// of the WGM table by interpreting the rendered ruleset text. It never
// touches the host firewall.
type FakeNFT struct {
	mu         sync.Mutex
	Table      string // currently applied ruleset text ("" = absent)
	ApplyErr   error
	DeleteErr  error
	ApplyCount int
	Unavail    error
}

// Available implements NFT.
func (f *FakeNFT) Available() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Unavail
}

// Apply implements NFT.
func (f *FakeNFT) Apply(_ context.Context, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ApplyErr != nil {
		return f.ApplyErr
	}
	f.ApplyCount++
	f.Table = text
	return nil
}

// DeleteTable implements NFT.
func (f *FakeNFT) DeleteTable(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	f.Table = ""
	return nil
}

// Present reports whether a WGM table is installed.
func (f *FakeNFT) Present() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Table != ""
}

var commentRE = regexp.MustCompile(`comment "([^"]+)"`)

// ListTable implements NFT.
func (f *FakeNFT) ListTable(context.Context) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Table == "" {
		return nil, false, nil
	}
	doc := nftDoc{}
	add := func(kind string, v any) {
		raw, _ := json.Marshal(v)
		doc.Nftables = append(doc.Nftables, map[string]json.RawMessage{kind: raw})
	}
	add("table", nftTable{Family: "inet", Name: TableName})
	chain := ""
	for _, line := range strings.Split(f.Table, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "chain "):
			chain = strings.Fields(l)[1]
		case strings.HasPrefix(l, "type filter hook"):
			hook := strings.Fields(l)[3]
			policy := strings.TrimSuffix(strings.Fields(l)[len(strings.Fields(l))-1], ";")
			add("chain", nftChain{Family: "inet", Table: TableName, Name: chain, Type: "filter", Hook: hook, Policy: policy})
		case l == "}" || l == "" || strings.HasPrefix(l, "table") || strings.HasPrefix(l, "delete"):
		default:
			r := nftRule{Family: "inet", Table: TableName, Chain: chain}
			if m := commentRE.FindStringSubmatch(l); m != nil {
				r.Comment = m[1]
			}
			add("rule", r)
		}
	}
	data, _ := json.Marshal(doc)
	return data, true, nil
}
