// Package metrics turns cumulative WireGuard byte counters into rates and
// keeps bounded in-memory history. It is pure computation and has no
// Linux dependencies.
package metrics

import (
	"sync"
	"time"
)

// Sample is a cumulative counter reading.
type Sample struct {
	At time.Time
	Rx uint64
	Tx uint64
}

// Rate is the throughput between two samples, in bytes per second.
type Rate struct {
	At    time.Time `json:"t"`
	Rx    float64   `json:"rx"`
	Tx    float64   `json:"tx"`
	Valid bool      `json:"valid"`
	// Reset is set when the counters went backwards (interface recreated,
	// peer removed, daemon attached to a new interface).
	Reset bool `json:"reset,omitempty"`
	// Gap is set when the interval was too long, zero or negative (missed
	// samples, suspend/resume or a clock step).
	Gap bool `json:"gap,omitempty"`
}

// RateCalc computes rates from successive samples. The zero value is
// usable; MaxGap defaults to 30 seconds.
type RateCalc struct {
	MaxGap time.Duration
	prev   *Sample
}

// Add records s and returns the rate since the previous sample. Rates are
// never fabricated: the first sample, counter decreases and implausible
// intervals all yield an invalid rate instead of a spike.
func (c *RateCalc) Add(s Sample) Rate {
	maxGap := c.MaxGap
	if maxGap == 0 {
		maxGap = 30 * time.Second
	}
	r := Rate{At: s.At}
	prev := c.prev
	c.prev = &s
	if prev == nil {
		return r
	}
	dt := s.At.Sub(prev.At)
	if dt <= 0 || dt > maxGap {
		r.Gap = true
		return r
	}
	if s.Rx < prev.Rx || s.Tx < prev.Tx {
		r.Reset = true
		return r
	}
	secs := dt.Seconds()
	r.Rx = float64(s.Rx-prev.Rx) / secs
	r.Tx = float64(s.Tx-prev.Tx) / secs
	r.Valid = true
	return r
}

// Forget discards the previous sample (e.g. when the interface vanished).
func (c *RateCalc) Forget() { c.prev = nil }

// Ring is a fixed-capacity circular buffer of rates.
type Ring struct {
	mu   sync.Mutex
	buf  []Rate
	next int
	full bool
}

// NewRing returns a ring holding up to n entries.
func NewRing(n int) *Ring {
	if n < 1 {
		n = 1
	}
	return &Ring{buf: make([]Rate, n)}
}

// Push appends r, evicting the oldest entry when full.
func (g *Ring) Push(r Rate) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.buf[g.next] = r
	g.next = (g.next + 1) % len(g.buf)
	if g.next == 0 {
		g.full = true
	}
}

// Since returns entries with At >= since, oldest first.
func (g *Ring) Since(since time.Time) []Rate {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Rate
	n := g.next
	if g.full {
		n = len(g.buf)
	}
	start := 0
	if g.full {
		start = g.next
	}
	for i := 0; i < n; i++ {
		r := g.buf[(start+i)%len(g.buf)]
		if !r.At.Before(since) {
			out = append(out, r)
		}
	}
	return out
}

// Last returns the most recent entry.
func (g *Ring) Last() (Rate, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.full && g.next == 0 {
		return Rate{}, false
	}
	return g.buf[(g.next-1+len(g.buf))%len(g.buf)], true
}

// Bucket is a per-minute aggregate suitable for persistence.
type Bucket struct {
	Start      time.Time
	RxBytes    float64
	TxBytes    float64
	Seconds    float64
	LatencySum float64
	LatencyN   int
}

// AvgRates returns the average rx/tx rate over the bucket's valid seconds.
func (b Bucket) AvgRates() (rx, tx float64) {
	if b.Seconds <= 0 {
		return 0, 0
	}
	return b.RxBytes / b.Seconds, b.TxBytes / b.Seconds
}

// Aggregator folds rates into fixed-width buckets to keep disk writes low.
type Aggregator struct {
	Width time.Duration
	cur   *Bucket
	last  time.Time
}

// AddRate folds a valid rate in; it returns a completed bucket when r
// falls into a new window.
func (a *Aggregator) AddRate(r Rate, interval time.Duration) (Bucket, bool) {
	done, ok := a.roll(r.At)
	if r.Valid {
		a.cur.RxBytes += r.Rx * interval.Seconds()
		a.cur.TxBytes += r.Tx * interval.Seconds()
		a.cur.Seconds += interval.Seconds()
	}
	return done, ok
}

// AddLatency records a probe latency in milliseconds.
func (a *Aggregator) AddLatency(at time.Time, ms float64) (Bucket, bool) {
	done, ok := a.roll(at)
	a.cur.LatencySum += ms
	a.cur.LatencyN++
	return done, ok
}

func (a *Aggregator) roll(at time.Time) (Bucket, bool) {
	w := a.Width
	if w == 0 {
		w = time.Minute
	}
	start := at.Truncate(w)
	if a.cur == nil {
		a.cur = &Bucket{Start: start}
		return Bucket{}, false
	}
	if start.Equal(a.cur.Start) {
		return Bucket{}, false
	}
	done := *a.cur
	a.cur = &Bucket{Start: start}
	return done, true
}
