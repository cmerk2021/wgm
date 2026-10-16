// Package sysexec runs a small, fixed set of system utilities without a
// shell. Binaries are resolved only from trusted system directories and run
// with a minimal environment, so neither $PATH nor IPC input can influence
// which executable is started.
package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// TrustedDirs are the only directories binaries are resolved from.
var TrustedDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// allowed lists the utilities WGM is permitted to execute.
var allowed = map[string]bool{
	"wg":        true,
	"wg-quick":  true,
	"ip":        true,
	"nft":       true,
	"nmcli":     true,
	"systemctl": true,
}

// ErrNotFound means the utility is not installed in a trusted directory.
var ErrNotFound = errors.New("utility not found in trusted system directories")

// Runner executes allowlisted utilities.
type Runner interface {
	// Run executes name with args and optional stdin, returning stdout.
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
	// Available reports whether name can be executed.
	Available(name string) bool
}

// ExecError carries the exit status and a bounded excerpt of stderr.
type ExecError struct {
	Name   string
	Args   []string
	Err    error
	Stderr string
}

func (e *ExecError) Error() string {
	msg := fmt.Sprintf("%s %s: %v", e.Name, strings.Join(e.Args, " "), e.Err)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *ExecError) Unwrap() error { return e.Err }

// System is the real Runner.
type System struct {
	// DefaultTimeout applies when ctx has no deadline.
	DefaultTimeout time.Duration
}

// Resolve returns the absolute path of an allowlisted utility.
func Resolve(name string) (string, error) {
	if !allowed[name] {
		return "", fmt.Errorf("utility %q is not allowlisted", name)
	}
	for _, d := range TrustedDirs {
		p := filepath.Join(d, name)
		st, err := os.Stat(p)
		if err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, ErrNotFound)
}

// Available implements Runner.
func (s System) Available(name string) bool {
	_, err := Resolve(name)
	return err == nil
}

const maxStderr = 2048

// Run implements Runner.
func (s System) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	path, err := Resolve(name)
	if err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		t := s.DefaultTimeout
		if t == 0 {
			t = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &limitedWriter{buf: &stderr, max: maxStderr}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (%v)", ctx.Err(), err)
		}
		return stdout.Bytes(), &ExecError{Name: name, Args: args, Err: err, Stderr: RedactKeys(strings.TrimSpace(stderr.String()))}
	}
	return stdout.Bytes(), nil
}

type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// keyLike matches base64-encoded 32-byte WireGuard keys.
var keyLike = regexp.MustCompile(`[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=`)

// RedactKeys replaces anything that looks like a WireGuard key with a
// placeholder. Used for subprocess output that may end up in logs.
func RedactKeys(s string) string {
	return keyLike.ReplaceAllString(s, "[redacted-key]")
}
