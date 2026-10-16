// Package ipc implements the WGM control-socket transport: a Unix domain
// socket server that authenticates peers with SO_PEERCRED, enforces the
// operation allowlist and role table, and a matching client.
package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/internal/auth"
)

// Handler executes an authorized request.
type Handler interface {
	Handle(ctx context.Context, c Caller, op string, params json.RawMessage) (any, *api.Error)
}

// Caller describes the authenticated peer of a request.
type Caller struct {
	Peer auth.Peer
	Role api.Role
}

// Server serves the control socket.
type Server struct {
	Path           string
	SocketGID      int64 // -1: leave group unchanged
	Auth           *auth.Authorizer
	Handler        Handler
	Log            *slog.Logger
	MaxConns       int
	IdleTimeout    time.Duration
	RequestTimeout time.Duration
	// Credentials overrides peer-credential lookup (tests on non-unix conns).
	Credentials func(net.Conn) (auth.Peer, error)

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Listen creates the socket with mode 0660 and the configured group.
// A stale socket from a previous run is removed only if it is a socket.
func (s *Server) Listen() error {
	if s.MaxConns <= 0 {
		s.MaxConns = 32
	}
	if s.IdleTimeout <= 0 {
		s.IdleTimeout = 10 * time.Minute
	}
	if s.RequestTimeout <= 0 {
		s.RequestTimeout = 90 * time.Second
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Credentials == nil {
		s.Credentials = PeerCred
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(s.Path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket; refusing to remove it", s.Path)
		}
		if c, err := net.DialTimeout("unix", s.Path, time.Second); err == nil {
			c.Close()
			return fmt.Errorf("another daemon is already listening on %s", s.Path)
		}
		if err := os.Remove(s.Path); err != nil {
			return err
		}
	}
	// Create the socket with a restrictive umask window by chmod-ing
	// immediately; the parent directory is not world-writable.
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(s.Path, 0o660); err != nil {
		ln.Close()
		return err
	}
	if s.SocketGID >= 0 {
		if err := os.Chown(s.Path, 0, int(s.SocketGID)); err != nil {
			ln.Close()
			return fmt.Errorf("chown socket: %w", err)
		}
	}
	s.mu.Lock()
	s.ln = ln
	s.conns = map[net.Conn]struct{}{}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.mu.Unlock()
	return nil
}

// Serve accepts connections until Shutdown.
func (s *Server) Serve() error {
	sem := make(chan struct{}, s.MaxConns)
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			writeResponse(c, api.Response{Version: api.ProtocolVersion, Error: api.Errf(api.CodeBusy, "too many connections")})
			c.Close()
			continue
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				c.Close()
				<-sem
				s.wg.Done()
			}()
			s.serveConn(c)
		}()
	}
}

// Shutdown stops accepting, cancels in-flight requests and waits (bounded).
func (s *Server) Shutdown(timeout time.Duration) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.conns {
		// Unblock readers; in-flight handlers see ctx cancellation.
		c.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	}
}

func (s *Server) serveConn(c net.Conn) {
	peer, err := s.Credentials(c)
	if err != nil {
		s.Log.Warn("ipc: cannot read peer credentials", "err", err)
		writeResponse(c, api.Response{Version: api.ProtocolVersion, Error: api.Errf(api.CodeForbidden, "cannot authenticate peer")})
		return
	}
	r := bufio.NewReaderSize(c, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(s.IdleTimeout))
		line, err := readLine(r, api.MaxRequestSize)
		if err != nil {
			if errors.Is(err, errTooLong) {
				writeResponse(c, api.Response{Version: api.ProtocolVersion, Error: api.Errf(api.CodeBadRequest, "request too large")})
			}
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		resp := s.dispatch(peer, line)
		c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := writeResponse(c, resp); err != nil {
			return
		}
		if s.ctx.Err() != nil {
			return
		}
	}
}

func (s *Server) dispatch(peer auth.Peer, line []byte) api.Response {
	var req api.Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return api.Response{Version: api.ProtocolVersion, Error: api.Errf(api.CodeBadRequest, "malformed request")}
	}
	resp := api.Response{Version: api.ProtocolVersion, ID: req.ID}
	if req.Version != api.ProtocolVersion {
		resp.Error = api.Errf(api.CodeUnsupportedVersion, fmt.Sprintf("protocol version %d not supported (want %d)", req.Version, api.ProtocolVersion))
		return resp
	}
	role := s.Auth.RoleOf(peer)
	if e := auth.Check(role, req.Op); e != nil {
		if e.Code == api.CodeForbidden {
			s.Log.Warn("ipc: denied", "op", req.Op, "uid", peer.UID, "pid", peer.PID, "role", role)
		}
		resp.Error = e
		return resp
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.RequestTimeout)
	defer cancel()
	res, aerr := s.safeHandle(ctx, Caller{Peer: peer, Role: role}, req)
	if aerr == nil && ctx.Err() != nil {
		aerr = api.Errf(api.CodeTimeout, "request timed out or daemon is shutting down")
	}
	if aerr != nil {
		resp.Error = aerr
		return resp
	}
	b, err := json.Marshal(res)
	if err != nil {
		resp.Error = api.Errf(api.CodeInternal, "cannot encode result")
		return resp
	}
	resp.OK = true
	resp.Result = b
	return resp
}

func (s *Server) safeHandle(ctx context.Context, c Caller, req api.Request) (res any, aerr *api.Error) {
	defer func() {
		if r := recover(); r != nil {
			s.Log.Error("ipc: handler panic", "op", req.Op, "panic", r)
			res, aerr = nil, api.Errf(api.CodeInternal, "internal error")
		}
	}()
	return s.Handler.Handle(ctx, c, req.Op, req.Params)
}

var errTooLong = errors.New("line too long")

func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		if len(buf)+len(chunk) > max {
			return nil, errTooLong
		}
		buf = append(buf, chunk...)
		if !isPrefix {
			return buf, nil
		}
	}
}

func writeResponse(w io.Writer, r api.Response) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// DecodeParams strictly decodes request parameters.
func DecodeParams(raw json.RawMessage, v any) *api.Error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return api.Errf(api.CodeBadRequest, "invalid parameters: "+err.Error())
	}
	if dec.More() {
		return api.Errf(api.CodeBadRequest, "invalid parameters: trailing data")
	}
	return nil
}
