package events

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLogBoundedAndQuery(t *testing.T) {
	l := NewLog(3, 0, nil, quiet())
	for i := 0; i < 5; i++ {
		tun := "wg0"
		if i%2 == 1 {
			tun = "wg1"
		}
		l.Add(tun, KindHealth, Info, "e")
	}
	all := l.Query("", 0, 0)
	if len(all) != 3 || all[0].ID != 3 || all[2].ID != 5 {
		t.Fatalf("%+v", all)
	}
	if got := l.Query("wg0", 0, 0); len(got) != 2 {
		t.Fatalf("filter: %+v", got)
	}
	if got := l.Query("", 4, 0); len(got) != 1 || got[0].ID != 5 {
		t.Fatalf("since: %+v", got)
	}
	if got := l.Query("", 0, 1); len(got) != 1 || got[0].ID != 5 {
		t.Fatalf("limit: %+v", got)
	}
}

func TestHistoryPersistenceAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	h, err := OpenHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(10, 0, h, quiet())
	old := time.Now().Add(-48 * time.Hour)
	l.now = func() time.Time { return old }
	l.Add("wg0", KindRecovery, Warning, "old event")
	l.now = time.Now
	l.Add("wg0", KindRecovery, Info, "new event")
	now := time.Now().Truncate(time.Minute)
	for i := 0; i < 3; i++ {
		if err := h.StoreMetric(MetricRow{Tunnel: "wg0", Start: now.Add(time.Duration(i-2) * 24 * time.Hour), RxRate: float64(i), Seconds: 60}); err != nil {
			t.Fatal(err)
		}
	}
	h.Close()

	// Reopen: IDs continue, events survive restart.
	h, err = OpenHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	maxID, _ := h.MaxEventID()
	if maxID != 2 {
		t.Fatalf("max id %d", maxID)
	}
	evs, _ := h.RecentEvents(10)
	if len(evs) != 2 || evs[0].Message != "old event" {
		t.Fatalf("%+v", evs)
	}
	l2 := NewLog(10, maxID, h, quiet())
	if e := l2.Add("", KindDaemon, Info, "restart"); e.ID != 3 {
		t.Fatalf("id after restart %d", e.ID)
	}
	n, err := h.Prune(time.Now().Add(-24*time.Hour), time.Now().Add(-25*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d %v", n, err)
	}
	rows, _ := h.Metrics(context.Background(), "wg0", time.Time{}, 100)
	if len(rows) != 2 {
		t.Fatalf("metrics after prune: %+v", rows)
	}
}
