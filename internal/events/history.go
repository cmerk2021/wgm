package events

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo in the daemon)
)

// HistorySchemaVersion is the SQLite schema version.
const HistorySchemaVersion = 1

// MetricRow is one persisted per-minute aggregate.
type MetricRow struct {
	Tunnel    string    `json:"tunnel"`
	Start     time.Time `json:"start"`
	RxRate    float64   `json:"rx_rate"`
	TxRate    float64   `json:"tx_rate"`
	Seconds   float64   `json:"seconds"`
	LatencyMs float64   `json:"latency_ms,omitempty"` // 0: no probe data
}

// History persists events and metric aggregates in SQLite.
type History struct {
	mu sync.Mutex
	db *sql.DB
}

// OpenHistory opens (creating if needed) the database at path.
func OpenHistory(path string) (*History, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	h := &History{db: db}
	if err := h.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return h, nil
}

func (h *History) migrate() error {
	if _, err := h.db.Exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := h.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'`).Scan(&v)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if v > HistorySchemaVersion {
		return fmt.Errorf("history database schema %d is newer than supported %d", v, HistorySchemaVersion)
	}
	if v < 1 {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, tunnel TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL)`,
			`CREATE INDEX IF NOT EXISTS events_ts ON events(ts)`,
			`CREATE TABLE IF NOT EXISTS metrics (tunnel TEXT NOT NULL, ts INTEGER NOT NULL, rx_rate REAL NOT NULL, tx_rate REAL NOT NULL, seconds REAL NOT NULL, latency_ms REAL NOT NULL, PRIMARY KEY (tunnel, ts))`,
			`CREATE INDEX IF NOT EXISTS metrics_ts ON metrics(ts)`,
			`INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '1')`,
		}
		for _, s := range stmts {
			if _, err := h.db.Exec(s); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close closes the database.
func (h *History) Close() error { return h.db.Close() }

// StoreEvent implements Sink.
func (h *History) StoreEvent(e Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.db.Exec(`INSERT OR REPLACE INTO events(id, ts, tunnel, kind, severity, message) VALUES (?,?,?,?,?,?)`,
		e.ID, e.Time.UnixMilli(), e.Tunnel, string(e.Kind), string(e.Severity), e.Message)
	return err
}

// RecentEvents returns up to limit most recent events, oldest first.
func (h *History) RecentEvents(limit int) ([]Event, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rows, err := h.db.Query(`SELECT id, ts, tunnel, kind, severity, message FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var kind, sev string
		if err := rows.Scan(&e.ID, &ts, &e.Tunnel, &kind, &sev, &e.Message); err != nil {
			return nil, err
		}
		e.Time, e.Kind, e.Severity = time.UnixMilli(ts), Kind(kind), Severity(sev)
		out = append(out, e)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// MaxEventID returns the highest stored event ID.
func (h *History) MaxEventID() (int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var id sql.NullInt64
	err := h.db.QueryRow(`SELECT MAX(id) FROM events`).Scan(&id)
	return id.Int64, err
}

// StoreMetric persists one aggregate row.
func (h *History) StoreMetric(r MetricRow) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.db.Exec(`INSERT OR REPLACE INTO metrics(tunnel, ts, rx_rate, tx_rate, seconds, latency_ms) VALUES (?,?,?,?,?,?)`,
		r.Tunnel, r.Start.Unix(), r.RxRate, r.TxRate, r.Seconds, r.LatencyMs)
	return err
}

// Metrics returns aggregates for tunnel since the given time, oldest first,
// capped at limit rows.
func (h *History) Metrics(ctx context.Context, tunnel string, since time.Time, limit int) ([]MetricRow, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rows, err := h.db.QueryContext(ctx, `SELECT ts, rx_rate, tx_rate, seconds, latency_ms FROM metrics WHERE tunnel=? AND ts>=? ORDER BY ts ASC LIMIT ?`,
		tunnel, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricRow
	for rows.Next() {
		r := MetricRow{Tunnel: tunnel}
		var ts int64
		if err := rows.Scan(&ts, &r.RxRate, &r.TxRate, &r.Seconds, &r.LatencyMs); err != nil {
			return nil, err
		}
		r.Start = time.Unix(ts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune deletes events and metrics older than the given cutoffs.
func (h *History) Prune(eventsBefore, metricsBefore time.Time) (int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r1, err := h.db.Exec(`DELETE FROM events WHERE ts < ?`, eventsBefore.UnixMilli())
	if err != nil {
		return 0, err
	}
	r2, err := h.db.Exec(`DELETE FROM metrics WHERE ts < ?`, metricsBefore.Unix())
	if err != nil {
		return 0, err
	}
	a, _ := r1.RowsAffected()
	b, _ := r2.RowsAffected()
	return a + b, nil
}
