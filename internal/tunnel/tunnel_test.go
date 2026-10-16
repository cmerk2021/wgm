package tunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testPriv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	testPSK  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
	testPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

var sample = `
# home tunnel
[Interface]
PrivateKey = ` + testPriv + `
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.0.0.1
ListenPort = 51820
PostUp = echo secret-token-123

[Peer]
PublicKey = ` + testPub + `
PresharedKey = ` + testPSK + `
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseConfigRedacts(t *testing.T) {
	c, err := ParseConfig([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasPrivateKey || len(c.Peers) != 1 || !c.Peers[0].HasPresharedKey {
		t.Fatalf("unexpected parse: %+v", c)
	}
	if c.Peers[0].PersistentKeepalive != 25 || c.Peers[0].Endpoint != "vpn.example.org:51820" {
		t.Fatalf("peer: %+v", c.Peers[0])
	}
	if len(c.Hooks) != 1 || c.Hooks[0] != "PostUp" {
		t.Fatalf("hooks: %v", c.Hooks)
	}
	v4, v6 := c.FullTunnel()
	if !v4 || !v6 {
		t.Fatal("expected full tunnel for both families")
	}
	out, _ := json.Marshal(c)
	for _, secret := range []string{testPriv, testPSK, "secret-token-123"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("secret %q leaked into parsed config", secret)
		}
	}
}

func TestParseErrorsDoNotLeak(t *testing.T) {
	bad := "[Interface]\nPrivateKey = " + testPriv + "\nAddress = not-an-ip " + testPriv + "\n"
	_, err := ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("expected error")
	}
	// Address values may be echoed, but a private key line itself must
	// never be.
	bad2 := "PrivateKey = " + testPriv + "\n"
	_, err = ParseConfig([]byte(bad2))
	if err == nil || strings.Contains(err.Error(), testPriv) {
		t.Fatalf("error leaks key or missing: %v", err)
	}
	for _, s := range []string{"[Interface", "[Foo]\n", "[Interface]\nnoequals\n", "[Peer]\nAllowedIPs = 1.2.3.4/99\n", "[Peer]\nBogus = 1\n"} {
		if _, err := ParseConfig([]byte(s)); err == nil {
			t.Errorf("%q: expected parse error", s)
		}
	}
}

func TestFingerprintChanges(t *testing.T) {
	a, _ := ParseConfig([]byte(sample))
	b, _ := ParseConfig([]byte(strings.Replace(sample, "25", "15", 1)))
	c, _ := ParseConfig([]byte(sample + "\n# trailing comment\n"))
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("fingerprint should change with keepalive")
	}
	if a.Fingerprint != c.Fingerprint {
		t.Fatal("fingerprint should ignore comments")
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("wg0.conf", sample, 0o600)
	write("broken.conf", "[Interface]\nAddress = nope\n", 0o600)
	write("open.conf", sample, 0o644)
	write("this-name-is-way-too-long.conf", sample, 0o600)
	write("notes.txt", "ignore me", 0o600)
	if err := os.Mkdir(filepath.Join(dir, "dir.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "wg0.conf"))

	got, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d entries: %v", len(got), got)
	}
	if got["wg0"].Err != "" || got["wg0"].Config == nil {
		t.Fatalf("wg0: %+v", got["wg0"])
	}
	if !strings.Contains(got["broken"].Err, "parse error") {
		t.Fatalf("broken: %+v", got["broken"])
	}
	if got["this-name-is-way-too-long"].Err == "" {
		t.Fatal("invalid name should be reported")
	}
	if got["dir"].Err != "not a regular file" {
		t.Fatalf("dir: %+v", got["dir"])
	}
	found := false
	for _, w := range got["open"].Config.Warnings {
		if strings.Contains(w, "readable by non-root") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected permission warning")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "wg0.conf"))
	if string(before) != string(after) {
		t.Fatal("discovery modified a configuration file")
	}

	missing, err := Discover(filepath.Join(dir, "nope"))
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing dir: %v %v", missing, err)
	}
}

func TestParseIPRoutes(t *testing.T) {
	data := `[{"dst":"default","dev":"wg0","table":"51820","flags":[]},{"type":"local","dst":"10.0.0.2","table":"local"},{"dst":"10.0.0.0/24","gateway":"10.0.0.1"}]`
	routes, err := parseIPRoutes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0] != "default table 51820" || routes[1] != "10.0.0.0/24 via 10.0.0.1" {
		t.Fatalf("routes: %v", routes)
	}
}

func TestEndpointHostPort(t *testing.T) {
	for in, want := range map[string]string{"1.2.3.4:51820": "1.2.3.4", "[2001:db8::1]:443": "2001:db8::1", "vpn.example.org:1": "vpn.example.org"} {
		h, _, err := EndpointHostPort(in)
		if err != nil || h != want {
			t.Errorf("%s: %s %v", in, h, err)
		}
	}
	for _, in := range []string{"1.2.3.4", "host:0", "host:x"} {
		if _, _, err := EndpointHostPort(in); err == nil {
			t.Errorf("%s: expected error", in)
		}
	}
}
