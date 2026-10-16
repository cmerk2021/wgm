package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxPolicyFileSize bounds the policy file we are willing to parse.
const MaxPolicyFileSize = 1 << 20

// ErrConflict is returned when an update was based on a stale revision.
var ErrConflict = errors.New("policy was modified concurrently; refresh and retry")

// migration upgrades a raw JSON document from version N to N+1.
type migration func(doc map[string]any) error

// migrations[i] upgrades schema i to i+1.
var migrations = []migration{
	// 0 -> 1: unversioned pre-release documents. They used the same field
	// names; only the version marker and container defaults were missing.
	func(doc map[string]any) error {
		if _, ok := doc["tunnels"]; !ok {
			doc["tunnels"] = map[string]any{}
		}
		doc["schema_version"] = 1
		return nil
	},
}

// Migrate decodes raw policy JSON, upgrading older schemas in memory.
// It returns the decoded file and whether a migration was applied.
func Migrate(data []byte) (*File, bool, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("parse policy: %w", err)
	}
	if doc == nil {
		return nil, false, errors.New("parse policy: document is not a JSON object")
	}
	version := 0
	if v, ok := doc["schema_version"]; ok {
		f, ok := v.(float64)
		if !ok || f < 0 || f != float64(int(f)) {
			return nil, false, errors.New("parse policy: schema_version must be a non-negative integer")
		}
		version = int(f)
	}
	if version > CurrentSchemaVersion {
		return nil, false, fmt.Errorf("%w (file has %d, supported %d)", ErrUnsupportedSchema, version, CurrentSchemaVersion)
	}
	migrated := version != CurrentSchemaVersion
	for v := version; v < CurrentSchemaVersion; v++ {
		if err := migrations[v](doc); err != nil {
			return nil, false, fmt.Errorf("migrate policy schema %d->%d: %w", v, v+1, err)
		}
	}
	norm, err := json.Marshal(doc)
	if err != nil {
		return nil, false, err
	}
	f := Default()
	if err := json.Unmarshal(norm, f); err != nil {
		return nil, false, fmt.Errorf("decode policy: %w", err)
	}
	f.fillDefaults()
	return f, migrated, nil
}

// fillDefaults replaces zero values (e.g. from hand-written partial files)
// with defaults so that validation errors only flag genuinely bad values.
func (f *File) fillDefaults() {
	if f.Tunnels == nil {
		f.Tunnels = map[string]TunnelPolicy{}
	}
	dh, dr := DefaultHealthPolicy(), DefaultRecoveryPolicy()
	for name, t := range f.Tunnels {
		if t.Ownership == "" {
			t.Ownership = OwnershipDiscovered
		}
		h := &t.Health
		setIfZero(&h.IntervalSec, dh.IntervalSec)
		setIfZero(&h.HandshakeStaleSec, dh.HandshakeStaleSec)
		setIfZero(&h.FailureThreshold, dh.FailureThreshold)
		setIfZero(&h.RecoveryThreshold, dh.RecoveryThreshold)
		setIfZero(&h.ConnectGraceSec, dh.ConnectGraceSec)
		r := &t.Recovery
		setIfZero(&r.MaxAttempts, dr.MaxAttempts)
		setIfZero(&r.InitialBackoffSec, dr.InitialBackoffSec)
		setIfZero(&r.MaxBackoffSec, dr.MaxBackoffSec)
		if r.Multiplier == 0 {
			r.Multiplier = dr.Multiplier
		}
		setIfZero(&r.BudgetMax, dr.BudgetMax)
		setIfZero(&r.BudgetWindowSec, dr.BudgetWindowSec)
		setIfZero(&r.VerifyTimeoutSec, dr.VerifyTimeoutSec)
		f.Tunnels[name] = t
	}
	if f.KillSwitch.Mode == "" {
		f.KillSwitch.Mode = KillSwitchFullTunnel
	}
	dm := DefaultMonitoringPrefs()
	setIfZero(&f.Monitoring.SampleIntervalSec, dm.SampleIntervalSec)
	setIfZero(&f.Monitoring.MetricsRetentionDays, dm.MetricsRetentionDays)
	setIfZero(&f.Monitoring.EventRetentionDays, dm.EventRetentionDays)
}

func setIfZero(v *int, d int) {
	if *v == 0 {
		*v = d
	}
}

// Store persists the policy file with atomic writes and optimistic
// concurrency control. It is safe for concurrent use.
type Store struct {
	path string

	mu       sync.Mutex
	cur      *File
	modTime  time.Time
	size     int64
	readOnly error // non-nil when the on-disk file must not be overwritten
}

// OpenStore loads the policy at path. A missing file yields defaults (the
// file is created on first update). A file that cannot be parsed or comes
// from a newer schema is never overwritten: the store becomes read-only
// with defaults in memory and the error is returned alongside the store.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, cur: Default()}
	err := s.load()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.readOnly = err
		return s, err
	}
	return s, nil
}

func (s *Store) load() error {
	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	if st.Size() > MaxPolicyFileSize {
		return fmt.Errorf("policy file %s exceeds %d bytes", s.path, MaxPolicyFileSize)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	f, _, err := Migrate(data)
	if err != nil {
		return err
	}
	if err := f.Validate(); err != nil {
		return err
	}
	s.cur, s.modTime, s.size = f, st.ModTime(), st.Size()
	return nil
}

// Path returns the backing file path.
func (s *Store) Path() string { return s.path }

// ReadOnlyReason returns why updates are refused, or nil.
func (s *Store) ReadOnlyReason() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readOnly
}

// Get returns a copy of the current policy.
func (s *Store) Get() *File {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Clone()
}

// ReloadIfChanged re-reads the file when it was modified externally (for
// example by an administrator with a text editor). On a parse error the
// previous in-memory policy is kept and the error returned.
func (s *Store) ReloadIfChanged() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if st.ModTime().Equal(s.modTime) && st.Size() == s.size {
		return false, nil
	}
	prev := s.cur
	if err := s.load(); err != nil {
		s.cur = prev
		s.modTime, s.size = st.ModTime(), st.Size() // do not re-report every tick
		s.readOnly = err
		return false, err
	}
	s.readOnly = nil
	return true, nil
}

// Update applies fn to a copy of the policy, validates it and persists it.
// If expectedRevision is non-zero it must match the current revision.
func (s *Store) Update(expectedRevision uint64, fn func(*File) error) (*File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly != nil {
		return nil, fmt.Errorf("policy store is read-only: %w", s.readOnly)
	}
	if expectedRevision != 0 && expectedRevision != s.cur.Revision {
		return nil, ErrConflict
	}
	next := s.cur.Clone()
	if err := fn(next); err != nil {
		return nil, err
	}
	next.SchemaVersion = CurrentSchemaVersion
	if err := next.Validate(); err != nil {
		return nil, err
	}
	next.Revision = s.cur.Revision + 1
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(s.path, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.modTime, s.size = st.ModTime(), st.Size()
	}
	s.cur = next
	return next.Clone(), nil
}

// WriteFileAtomic writes data to path via a temporary file in the same
// directory, fsyncs it and renames it into place.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
