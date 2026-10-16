package tunnel

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cmerk2021/wgm/internal/config"
)

// DefaultConfigDir is where wg-quick configurations live.
const DefaultConfigDir = "/etc/wireguard"

// Discovered describes one configuration file found on disk.
type Discovered struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	ModTime time.Time `json:"mod_time"`
	Config  *Config   `json:"config,omitempty"`
	// Err is a human-readable parse or access error (never contains key
	// material).
	Err string `json:"error,omitempty"`
}

// Discover scans dir for *.conf files. It never modifies anything. Errors
// for individual files are reported in the result; only a failure to read
// the directory itself is returned as an error. A missing directory yields
// an empty result.
func Discover(dir string) (map[string]Discovered, error) {
	out := map[string]Discovered{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		return out, fmt.Errorf("read %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, fname := range names {
		if !strings.HasSuffix(fname, ".conf") {
			continue
		}
		name := strings.TrimSuffix(fname, ".conf")
		path := filepath.Join(dir, fname)
		d := Discovered{Name: name, Path: path}
		if !config.ValidInterfaceName(name) {
			d.Err = "file name is not a valid WireGuard interface name"
			out[name] = d
			continue
		}
		d.Config, d.ModTime, d.Err = loadOne(path)
		out[name] = d
	}
	return out, nil
}

func loadOne(path string) (*Config, time.Time, string) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, time.Time{}, "permission denied (wgmd must run as root to read WireGuard configurations)"
		}
		return nil, time.Time{}, err.Error()
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err.Error()
	}
	if !st.Mode().IsRegular() {
		return nil, st.ModTime(), "not a regular file"
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil {
		return nil, st.ModTime(), err.Error()
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, st.ModTime(), "parse error: " + err.Error()
	}
	if st.Mode().Perm()&0o077 != 0 {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("file mode %04o is readable by non-root users; 0600 is recommended", st.Mode().Perm()))
	}
	return cfg, st.ModTime(), ""
}
