package sysexec

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResolveAllowlist(t *testing.T) {
	for _, name := range []string{"sh", "bash", "/bin/sh", "../usr/bin/nft", "nft; rm -rf /", "python3", ""} {
		if _, err := Resolve(name); err == nil {
			t.Errorf("Resolve(%q) succeeded for a non-allowlisted name", name)
		}
	}
}

func TestResolveOnlyTrustedDirs(t *testing.T) {
	old := TrustedDirs
	defer func() { TrustedDirs = old }()
	TrustedDirs = []string{t.TempDir()}
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	if _, err := Resolve("ip"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound outside trusted dirs, got %v", err)
	}
	if (System{}).Available("ip") {
		t.Fatal("Available must not fall back to $PATH")
	}
}

func TestRunRejectsUnlisted(t *testing.T) {
	if _, err := (System{}).Run(context.Background(), nil, "sh", "-c", "true"); err == nil {
		t.Fatal("shell execution must be rejected")
	}
}

func TestRunNoShellInterpretation(t *testing.T) {
	if !(System{}).Available("ip") {
		t.Skip("ip not installed")
	}
	// Shell metacharacters are passed as literal arguments, so ip rejects them.
	_, err := (System{}).Run(context.Background(), nil, "ip", "link", "show", "dev", "x;touch /tmp/wgm-pwned")
	var ee *ExecError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExecError, got %v", err)
	}
}

func TestRedactKeys(t *testing.T) {
	key := "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	s := RedactKeys("private key " + key + " end")
	if strings.Contains(s, key) || !strings.Contains(s, "[redacted-key]") {
		t.Fatalf("key not redacted: %q", s)
	}
	if got := RedactKeys("interface wg0 10.0.0.1"); got != "interface wg0 10.0.0.1" {
		t.Fatalf("non-key text altered: %q", got)
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	w := &limitedWriter{buf: &buf, max: 4}
	if n, err := w.Write([]byte("abcdef")); n != 6 || err != nil {
		t.Fatalf("Write must report full length: %d %v", n, err)
	}
	w.Write([]byte("gh"))
	if buf.String() != "abcd" {
		t.Fatalf("got %q", buf.String())
	}
}
