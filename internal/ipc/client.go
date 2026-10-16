package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cmerk2021/wgm/internal/api"
)

// ErrUnavailable indicates the daemon could not be reached.
var ErrUnavailable = errors.New("daemon unavailable")

// Client is a reconnecting control-socket client. It is safe for
// concurrent use; requests are serialized over one connection.
type Client struct {
	Path        string
	DialTimeout time.Duration

	mu     sync.Mutex
	conn   net.Conn
	r      *bufio.Reader
	nextID uint64
}

// NewClient returns a client for path.
func NewClient(path string) *Client {
	return &Client{Path: path, DialTimeout: 2 * time.Second}
}

// Close drops the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropLocked()
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.r = nil, nil
	return err
}

func (c *Client) connectLocked() error {
	if c.conn != nil {
		return nil
	}
	d := net.Dialer{Timeout: c.DialTimeout}
	conn, err := d.Dial("unix", c.Path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.conn = conn
	c.r = bufio.NewReaderSize(conn, 64<<10)
	return nil
}

// Call performs op with params and decodes the result into out (may be nil).
// Daemon-reported errors are returned as *api.Error.
func (c *Client) Call(ctx context.Context, op string, params, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	var lastErr error
	// One transparent retry if a cached connection turned out to be dead
	// (e.g. daemon restarted).
	for attempt := 0; attempt < 2; attempt++ {
		fresh := c.conn == nil
		if err := c.connectLocked(); err != nil {
			return err
		}
		resp, err := c.roundTripLocked(ctx, op, raw)
		if err != nil {
			c.dropLocked()
			lastErr = err
			if fresh || ctx.Err() != nil {
				break
			}
			continue
		}
		if !resp.OK {
			if resp.Error == nil {
				return api.Errf(api.CodeInternal, "daemon returned failure without error")
			}
			return resp.Error
		}
		if out != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, out)
		}
		return nil
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, lastErr)
}

func (c *Client) roundTripLocked(ctx context.Context, op string, params json.RawMessage) (*api.Response, error) {
	c.nextID++
	req := api.Request{Version: api.ProtocolVersion, ID: c.nextID, Op: op, Params: params}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(120 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	conn := c.conn
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := readLine(c.r, api.MaxResponseSize)
	if err != nil {
		return nil, err
	}
	var resp api.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("malformed response: %w", err)
	}
	if resp.ID != req.ID && resp.ID != 0 {
		return nil, fmt.Errorf("response id %d does not match request %d", resp.ID, req.ID)
	}
	return &resp, nil
}
