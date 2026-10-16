package metrics

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestRateCalc(t *testing.T) {
	var c RateCalc
	if r := c.Add(Sample{At: t0, Rx: 1000, Tx: 500}); r.Valid {
		t.Fatal("first sample must not produce a rate")
	}
	r := c.Add(Sample{At: t0.Add(2 * time.Second), Rx: 3000, Tx: 1500})
	if !r.Valid || r.Rx != 1000 || r.Tx != 500 {
		t.Fatalf("rate = %+v", r)
	}
	// Counter reset (interface recreated): no spike, no negative rate.
	r = c.Add(Sample{At: t0.Add(3 * time.Second), Rx: 10, Tx: 10})
	if r.Valid || !r.Reset {
		t.Fatalf("reset not detected: %+v", r)
	}
	r = c.Add(Sample{At: t0.Add(4 * time.Second), Rx: 110, Tx: 10})
	if !r.Valid || r.Rx != 100 || r.Tx != 0 {
		t.Fatalf("after reset: %+v", r)
	}
	// Clock stepped backwards.
	r = c.Add(Sample{At: t0.Add(1 * time.Second), Rx: 200, Tx: 20})
	if r.Valid || !r.Gap {
		t.Fatalf("backwards clock: %+v", r)
	}
	// Long gap (suspend): bytes accumulated over hours must not be
	// reported as a one-second spike.
	r = c.Add(Sample{At: t0.Add(2 * time.Hour), Rx: 1 << 40, Tx: 20})
	if r.Valid || !r.Gap {
		t.Fatalf("gap: %+v", r)
	}
	// Uint64 wrap-like huge decrease.
	c.Forget()
	c.Add(Sample{At: t0, Rx: math.MaxUint64 - 10})
	if r := c.Add(Sample{At: t0.Add(time.Second), Rx: 5}); r.Valid {
		t.Fatal("wrap must not yield a rate")
	}
}

func TestRing(t *testing.T) {
	g := NewRing(3)
	if _, ok := g.Last(); ok {
		t.Fatal("empty ring has no last")
	}
	for i := 0; i < 5; i++ {
		g.Push(Rate{At: t0.Add(time.Duration(i) * time.Second), Rx: float64(i)})
	}
	all := g.Since(time.Time{})
	if len(all) != 3 || all[0].Rx != 2 || all[2].Rx != 4 {
		t.Fatalf("ring = %+v", all)
	}
	if got := g.Since(t0.Add(4 * time.Second)); len(got) != 1 {
		t.Fatalf("since = %+v", got)
	}
	if l, _ := g.Last(); l.Rx != 4 {
		t.Fatalf("last = %+v", l)
	}
}

func TestAggregator(t *testing.T) {
	a := Aggregator{Width: time.Minute}
	for i := 0; i < 60; i++ {
		if _, ok := a.AddRate(Rate{At: t0.Add(time.Duration(i) * time.Second), Rx: 100, Tx: 10, Valid: true}, time.Second); ok {
			t.Fatal("bucket closed early")
		}
	}
	a.AddLatency(t0.Add(30*time.Second), 20)
	a.AddLatency(t0.Add(40*time.Second), 40)
	b, ok := a.AddRate(Rate{At: t0.Add(time.Minute), Valid: false}, time.Second)
	if !ok {
		t.Fatal("bucket should close")
	}
	rx, tx := b.AvgRates()
	if rx != 100 || tx != 10 || b.Seconds != 60 || b.LatencySum/float64(b.LatencyN) != 30 {
		t.Fatalf("bucket = %+v", b)
	}
	if (Bucket{}).Seconds != 0 {
		t.Fatal()
	}
	if rx, tx := (Bucket{}).AvgRates(); rx != 0 || tx != 0 {
		t.Fatal("empty bucket rates must be zero")
	}
}
