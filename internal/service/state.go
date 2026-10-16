package service

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
	"github.com/cmerk2021/wgm/internal/health"
)

// stateVersion is the schema of /var/lib/wgm/state.json.
const stateVersion = 1

// IntentRecord is a persisted user/autostart intent.
type IntentRecord struct {
	Intent health.Intent `json:"intent"`
	At     time.Time     `json:"at"`
	// Fingerprint of the configuration that was activated (change detection).
	Fingerprint string `json:"fingerprint,omitempty"`
}

// runtimeState is mutable daemon state that must survive restarts. It
// contains no secrets.
type runtimeState struct {
	Version int                     `json:"version"`
	Intents map[string]IntentRecord `json:"intents"`
	// FwMarks remembers the last observed WireGuard fwmark per tunnel so
	// the kill switch can stay mark-restricted while the interface is down.
	FwMarks map[string]uint32 `json:"fwmarks,omitempty"`
	// Endpoints caches resolved endpoint addresses (hostname endpoints
	// cannot be resolved while the kill switch blocks DNS).
	Endpoints map[string][]string `json:"endpoints,omitempty"`
}

func newRuntimeState() *runtimeState {
	return &runtimeState{Version: stateVersion, Intents: map[string]IntentRecord{}, FwMarks: map[string]uint32{}, Endpoints: map[string][]string{}}
}

func loadRuntimeState(path string) (*runtimeState, error) {
	st := newRuntimeState()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	var in runtimeState
	if err := json.Unmarshal(data, &in); err != nil {
		return st, err
	}
	if in.Version > stateVersion {
		return st, errors.New("state file is from a newer WGM version")
	}
	for k, v := range in.Intents {
		if config.ValidInterfaceName(k) && (v.Intent == health.IntentUp || v.Intent == health.IntentDown) {
			st.Intents[k] = v
		}
	}
	for k, v := range in.FwMarks {
		if config.ValidInterfaceName(k) {
			st.FwMarks[k] = v
		}
	}
	for k, v := range in.Endpoints {
		if config.ValidInterfaceName(k) && len(v) <= 64 {
			st.Endpoints[k] = v
		}
	}
	return st, nil
}

func (s *runtimeState) save(path string) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(path, append(data, '\n'), 0o600)
}
