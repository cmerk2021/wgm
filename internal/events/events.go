// Package events records diagnostic events in a bounded in-memory log
// with optional persistence to SQLite history.
package events

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Severity of an event.
type Severity string

const (
	Info    Severity = "info"
	Warning Severity = "warning"
	Error   Severity = "error"
)

// Kind groups events by subsystem.
type Kind string

const (
	KindHealth     Kind = "health"
	KindRecovery   Kind = "recovery"
	KindKillSwitch Kind = "killswitch"
	KindAction     Kind = "action"
	KindConfig     Kind = "config"
	KindDaemon     Kind = "daemon"
	KindDiscovery  Kind = "discovery"
)

// Event is one diagnostic record. Messages never contain key material.
type Event struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Tunnel   string    `json:"tunnel,omitempty"`
	Kind     Kind      `json:"kind"`
	Severity Severity  `json:"severity"`
	Message  string    `json:"message"`
}

// Sink persists events.
type Sink interface {
	StoreEvent(Event) error
}

// Log is a bounded, concurrency-safe event log.
type Log struct {
	mu     sync.Mutex
	ring   []Event
	cap    int
	nextID int64
	sink   Sink
	logger *slog.Logger
	now    func() time.Time
}

// NewLog creates a log keeping up to capacity events in memory. Events
// are numbered from startID+1 so IDs stay monotonic across restarts.
func NewLog(capacity int, startID int64, sink Sink, logger *slog.Logger) *Log {
	if capacity < 1 {
		capacity = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Log{cap: capacity, nextID: startID + 1, sink: sink, logger: logger, now: time.Now}
}

// Preload seeds the in-memory log (e.g. from history after a restart).
func (l *Log) Preload(evs []Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range evs {
		l.push(e)
		if e.ID >= l.nextID {
			l.nextID = e.ID + 1
		}
	}
}

func (l *Log) push(e Event) {
	l.ring = append(l.ring, e)
	if len(l.ring) > l.cap {
		l.ring = append([]Event(nil), l.ring[len(l.ring)-l.cap:]...)
	}
}

// Add records an event.
func (l *Log) Add(tunnel string, kind Kind, sev Severity, msg string) Event {
	l.mu.Lock()
	e := Event{ID: l.nextID, Time: l.now(), Tunnel: tunnel, Kind: kind, Severity: sev, Message: msg}
	l.nextID++
	l.push(e)
	sink := l.sink
	l.mu.Unlock()

	level := slog.LevelInfo
	switch sev {
	case Warning:
		level = slog.LevelWarn
	case Error:
		level = slog.LevelError
	}
	l.logger.Log(context.Background(), level, msg, "tunnel", tunnel, "kind", string(kind), "event_id", e.ID)
	if sink != nil {
		if err := sink.StoreEvent(e); err != nil {
			l.logger.Warn("persist event failed", "err", err)
		}
	}
	return e
}

// Query returns events with ID > sinceID, optionally filtered by tunnel,
// newest last, limited to limit entries (most recent kept).
func (l *Log) Query(tunnel string, sinceID int64, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.ring {
		if e.ID <= sinceID || (tunnel != "" && e.Tunnel != tunnel) {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
