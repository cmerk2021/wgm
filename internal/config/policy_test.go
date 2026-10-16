package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidInterfaceName(t *testing.T) {
	good := []string{"wg0", "home-vpn", "a", "wg_1.x=+", "abcdefghijklmno"}
	bad := []string{"", "abcdefghijklmnop", "wg 0", "../x", "wg/0", "..", ".", "wg0;rm", "wg\n"}
	for _, n := range good {
		if !ValidInterfaceName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if ValidInterfaceName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestProbeValidation(t *testing.T) {
	cases := []struct {
		p  ProbeSpec
		ok bool
	}{
		{ProbeSpec{Type: ProbeICMP, Target: "10.0.0.1"}, true},
		{ProbeSpec{Type: ProbeICMP, Target: "2001:db8::1"}, true},
		{ProbeSpec{Type: ProbeICMP, Target: "example.com"}, false},
		{ProbeSpec{Type: ProbeICMP, Target: "127.0.0.1"}, false},
		{ProbeSpec{Type: ProbeICMP, Target: "0.0.0.0"}, false},
		{ProbeSpec{Type: ProbeICMP, Target: "224.0.0.1"}, false},
		{ProbeSpec{Type: ProbeICMP, Target: "fe80::1%eth0"}, false},
		{ProbeSpec{Type: ProbeICMP, Target: "10.0.0.1", Port: 80}, false},
		{ProbeSpec{Type: ProbeTCP, Target: "10.0.0.1", Port: 443}, true},
		{ProbeSpec{Type: ProbeTCP, Target: "10.0.0.1"}, false},
		{ProbeSpec{Type: ProbeTCP, Target: "10.0.0.1", Port: 70000}, false},
		{ProbeSpec{Type: ProbeDNS, Target: "10.0.0.53", Query: "fedoraproject.org"}, true},
		{ProbeSpec{Type: ProbeDNS, Target: "10.0.0.53", Query: "bad name"}, false},
		{ProbeSpec{Type: ProbeDNS, Target: "10.0.0.53", Query: "x.org", Port: 5353}, false},
		{ProbeSpec{Type: "exec", Target: "10.0.0.1"}, false},
		{ProbeSpec{Type: ProbeICMP, Target: "10.0.0.1", TimeoutMs: 5}, false},
	}
	for _, c := range cases {
		err := ValidateProbe(c.p)
		if (err == nil) != c.ok {
			t.Errorf("%+v: ok=%v err=%v", c.p, c.ok, err)
		}
	}
}

func TestTunnelPolicyValidation(t *testing.T) {
	p := DefaultTunnelPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	p.Autostart = true
	if err := p.Validate(); err == nil {
		t.Fatal("autostart on non-managed tunnel must be rejected")
	}
	p.Ownership = OwnershipManaged
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Ownership = "root"
	if err := p.Validate(); err == nil {
		t.Fatal("unknown ownership must be rejected")
	}
	p = DefaultTunnelPolicy()
	p.Recovery.MaxBackoffSec = 1
	p.Recovery.InitialBackoffSec = 10
	if err := p.Validate(); err == nil {
		t.Fatal("max < initial backoff must be rejected")
	}
	p = DefaultTunnelPolicy()
	p.Health.IntervalSec = 0
	if err := p.Validate(); err == nil {
		t.Fatal("zero interval must be rejected")
	}
}

func TestKillSwitchValidation(t *testing.T) {
	k := Default().KillSwitch
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	k.Enabled = true
	if err := k.Validate(); err == nil {
		t.Fatal("enabled kill switch without tunnel must be rejected")
	}
	k.Tunnel = "wg0"
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	k.Mode = "split"
	if err := k.Validate(); err == nil {
		t.Fatal("unsupported mode must be rejected")
	}
}

func TestMigrateUnversioned(t *testing.T) {
	f, migrated, err := Migrate([]byte(`{"tunnels":{"wg0":{"ownership":"managed","health":{"interval_sec":5}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !migrated || f.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("expected migration to v%d, got v%d migrated=%v", CurrentSchemaVersion, f.SchemaVersion, migrated)
	}
	tp := f.Tunnels["wg0"]
	if tp.Health.IntervalSec != 5 || tp.Health.FailureThreshold != DefaultHealthPolicy().FailureThreshold {
		t.Fatalf("defaults not filled: %+v", tp.Health)
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateRejectsFuture(t *testing.T) {
	_, _, err := Migrate([]byte(`{"schema_version": 99}`))
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema, got %v", err)
	}
	if _, _, err := Migrate([]byte(`{"schema_version": "1"}`)); err == nil {
		t.Fatal("string version must be rejected")
	}
	if _, _, err := Migrate([]byte(`[]`)); err == nil {
		t.Fatal("non-object must be rejected")
	}
}

func TestStoreRoundTripAndConflict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("store must not create the file before the first update")
	}
	f, err := s.Update(0, func(f *File) error {
		tp := DefaultTunnelPolicy()
		tp.Ownership = OwnershipManaged
		f.Tunnels["wg0"] = tp
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Revision != 1 {
		t.Fatalf("revision = %d", f.Revision)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("policy file mode %v, want 0600", st.Mode().Perm())
	}
	if _, err := s.Update(5, func(*File) error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	if _, err := s.Update(1, func(f *File) error {
		tp := f.Tunnels["wg0"]
		tp.Health.IntervalSec = 1
		f.Tunnels["wg0"] = tp
		return nil
	}); err == nil {
		t.Fatal("invalid update must be rejected")
	}
	if s.Get().Tunnels["wg0"].Health.IntervalSec != DefaultHealthPolicy().IntervalSec {
		t.Fatal("rejected update must not change state")
	}

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Get().Tunnels["wg0"].Ownership; got != OwnershipManaged {
		t.Fatalf("reloaded ownership = %q", got)
	}
}

func TestStoreNeverOverwritesUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	orig := `{"schema_version": 42, "future": true}`
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err == nil {
		t.Fatal("expected error for future schema")
	}
	if _, err := s.Update(0, func(*File) error { return nil }); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("update must be refused, got %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != orig {
		t.Fatal("file was modified")
	}
}

func TestStoreReloadIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	s, _ := OpenStore(path)
	if _, err := s.Update(0, func(f *File) error { f.Monitoring.EventRetentionDays = 10; return nil }); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.ReloadIfChanged(); changed || err != nil {
		t.Fatalf("no change expected: %v %v", changed, err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"revision":7,"monitoring":{"event_retention_days":99}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := s.ReloadIfChanged()
	if err != nil || !changed {
		t.Fatalf("expected reload: %v %v", changed, err)
	}
	if s.Get().Monitoring.EventRetentionDays != 99 {
		t.Fatal("reload did not apply")
	}
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReloadIfChanged(); err == nil {
		t.Fatal("expected parse error")
	}
	if s.Get().Monitoring.EventRetentionDays != 99 {
		t.Fatal("bad reload must keep previous policy")
	}
	if s.ReadOnlyReason() == nil {
		t.Fatal("store must refuse writes while file is corrupt")
	}
}
