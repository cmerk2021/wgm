package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/auth"
)

type echoHandler struct{ block chan struct{} }

func (h *echoHandler) Handle(ctx context.Context, c Caller, op string, params json.RawMessage) (any, *api.Error) {
	switch op {
	case api.OpPing:
		return api.PingResult{UID: c.Peer.UID, Role: c.Role, ProtocolVersion: api.ProtocolVersion}, nil
	case api.OpGetTunnel:
		var p api.NameParams
		if e := DecodeParams(params, &p); e != nil {
			return nil, e
		}
		if p.Name == "panic" {
			panic("boom")
		}
		if p.Name == "block" {
			select {
			case <-h.block:
			case <-ctx.Done():
			}
			return nil, api.Errf(api.CodeTimeout, "cancelled")
		}
		return api.TunnelStatus{Name: p.Name}, nil
	}
	return nil, api.Errf(api.CodeUnknownOp, op)
}

func startServer(t *testing.T, role api.Role) (*Server, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "wgmipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	uid := uint32(os.Getuid())
	var a *auth.Authorizer
	switch role {
	case api.RoleOperator:
		a = auth.NewAuthorizerWithGIDs(777777, -1, func(u uint32) ([]uint32, error) {
			if u == uid {
				return []uint32{777777}, nil
			}
			return nil, errors.New("x")
		})
	default:
		a = auth.NewAuthorizerWithGIDs(-1, -1, func(uint32) ([]uint32, error) { return nil, nil })
	}
	s := &Server{Path: path, SocketGID: -1, Auth: a, Handler: &echoHandler{block: make(chan struct{})}, MaxConns: 2, RequestTimeout: 2 * time.Second}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Shutdown(time.Second) })
	return s, path
}

func TestPingAndRoles(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("role tests assume a non-root test user")
	}
	_, path := startServer(t, api.RoleNone)
	c := NewClient(path)
	defer c.Close()
	var pr api.PingResult
	if err := c.Call(context.Background(), api.OpPing, nil, &pr); err != nil {
		t.Fatal(err)
	}
	if pr.UID != uint32(os.Getuid()) || pr.Role != api.RoleNone {
		t.Fatalf("%+v", pr)
	}
	err := c.Call(context.Background(), api.OpGetTunnel, api.NameParams{Name: "wg0"}, nil)
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeForbidden {
		t.Fatalf("want forbidden, got %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
}

func TestOperatorRequests(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("role tests assume a non-root test user")
	}
	_, path := startServer(t, api.RoleOperator)
	c := NewClient(path)
	defer c.Close()
	var ts api.TunnelStatus
	if err := c.Call(context.Background(), api.OpGetTunnel, api.NameParams{Name: "wg0"}, &ts); err != nil || ts.Name != "wg0" {
		t.Fatal(err, ts)
	}
	// Unknown param fields are rejected.
	err := c.Call(context.Background(), api.OpGetTunnel, map[string]string{"name": "x", "cmd": "rm -rf /"}, nil)
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeBadRequest {
		t.Fatalf("got %v", err)
	}
	// Unknown ops are rejected regardless of role.
	if err := c.Call(context.Background(), "exec", nil, nil); !errors.As(err, &ae) || ae.Code != api.CodeUnknownOp {
		t.Fatalf("got %v", err)
	}
	// Admin-only op.
	if err := c.Call(context.Background(), api.OpSetKillSwitch, api.SetKillSwitchParams{}, nil); !errors.As(err, &ae) || ae.Code != api.CodeForbidden {
		t.Fatalf("got %v", err)
	}
	// Handler panic becomes internal error and the connection stays usable.
	if err := c.Call(context.Background(), api.OpGetTunnel, api.NameParams{Name: "panic"}, nil); !errors.As(err, &ae) || ae.Code != api.CodeInternal {
		t.Fatalf("got %v", err)
	}
	if err := c.Call(context.Background(), api.OpPing, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func rawExchange(t *testing.T, path, line string) api.Response {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var r api.Response
	if err := json.Unmarshal(buf[:n], &r); err != nil {
		t.Fatal(err, string(buf[:n]))
	}
	return r
}

func TestProtocolErrors(t *testing.T) {
	_, path := startServer(t, api.RoleOperator)
	if r := rawExchange(t, path, `{"version":99,"id":1,"op":"ping"}`); r.Error == nil || r.Error.Code != api.CodeUnsupportedVersion {
		t.Fatalf("%+v", r)
	}
	if r := rawExchange(t, path, `not json`); r.Error == nil || r.Error.Code != api.CodeBadRequest {
		t.Fatalf("%+v", r)
	}
	if r := rawExchange(t, path, `{"version":1,"id":1,"op":"ping","extra":1}`); r.Error == nil || r.Error.Code != api.CodeBadRequest {
		t.Fatalf("%+v", r)
	}
	big := `{"version":1,"id":1,"op":"ping","params":"` + strings.Repeat("a", api.MaxRequestSize) + `"}`
	if r := rawExchange(t, path, big); r.Error == nil || r.Error.Code != api.CodeBadRequest {
		t.Fatalf("%+v", r)
	}
}

func TestConnectionLimit(t *testing.T) {
	_, path := startServer(t, api.RoleOperator)
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	if r := rawExchange(t, path, `{"version":1,"id":1,"op":"ping"}`); r.Error == nil || r.Error.Code != api.CodeBusy {
		t.Fatalf("%+v", r)
	}
}

func TestClientReconnectsAfterRestart(t *testing.T) {
	s, path := startServer(t, api.RoleOperator)
	c := NewClient(path)
	defer c.Close()
	if err := c.Call(context.Background(), api.OpPing, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.Shutdown(time.Second)
	if err := c.Call(context.Background(), api.OpPing, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	s2 := &Server{Path: path, SocketGID: -1, Auth: s.Auth, Handler: s.Handler}
	if err := s2.Listen(); err != nil {
		t.Fatal(err)
	}
	go s2.Serve()
	defer s2.Shutdown(time.Second)
	if err := c.Call(context.Background(), api.OpPing, nil, nil); err != nil {
		t.Fatalf("after restart: %v", err)
	}
}

func TestShutdownCancelsInflight(t *testing.T) {
	s, path := startServer(t, api.RoleOperator)
	c := NewClient(path)
	defer c.Close()
	errc := make(chan error, 1)
	go func() { errc <- c.Call(context.Background(), api.OpGetTunnel, api.NameParams{Name: "block"}, nil) }()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	s.Shutdown(2 * time.Second)
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal("shutdown did not cancel in-flight request promptly")
	}
	if err := <-errc; err == nil {
		t.Fatal("expected error")
	}
}

func TestRefusesNonSocketPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	os.WriteFile(p, []byte("x"), 0o600)
	s := &Server{Path: p, SocketGID: -1}
	if err := s.Listen(); err == nil {
		t.Fatal("must refuse to replace a regular file")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("file was removed")
	}
}

func TestClientContextCancel(t *testing.T) {
	_, path := startServer(t, api.RoleOperator)
	c := NewClient(path)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.Call(ctx, api.OpGetTunnel, api.NameParams{Name: "block"}, nil); err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("context cancel not honoured")
	}
}
