package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/config"
)

// E2E round 3 (t_alert_outage, t_alert_outage2): with ClickHouse stopped, a
// critical alert and its acknowledgement were kept in memory only. Nothing
// wrote them once ClickHouse was back, the acknowledgement answered 500,
// and a restart lost both.

// alertStore is a database/sql driver standing in for the ClickHouse alerts
// table. While down every statement fails like a stopped server.
type alertStore struct {
	mu     sync.Mutex
	down   bool
	stored map[string][]string // alert_id -> status of every stored version
}

func newAlertStore() *alertStore { return &alertStore{stored: make(map[string][]string)} }

func (s *alertStore) Connect(context.Context) (driver.Conn, error) { return &alertStoreConn{s: s}, nil }
func (s *alertStore) Driver() driver.Driver                        { return alertStoreDriver{} }

func (s *alertStore) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// statuses returns the status of every stored version of an alert.
func (s *alertStore) statuses(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.stored[id]...)
}

type alertStoreDriver struct{}

func (alertStoreDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use the connector")
}

type alertStoreConn struct{ s *alertStore }

var errAlertStoreDown = errors.New("dial tcp 127.0.0.1:19423: connect: connection refused")

func (c *alertStoreConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not supported")
}
func (c *alertStoreConn) Close() error                             { return nil }
func (c *alertStoreConn) Begin() (driver.Tx, error)                { return nil, errors.New("not supported") }
func (c *alertStoreConn) CheckNamedValue(*driver.NamedValue) error { return nil }

// ExecContext stores an INSERT INTO alerts, whose first two arguments are
// alert_id and rule_id and fifth status (see alertInsertQuery).
func (c *alertStoreConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.down {
		return nil, errAlertStoreDown
	}
	if !strings.Contains(query, "INSERT INTO alerts") || len(args) < 5 {
		return nil, fmt.Errorf("unexpected statement: %s", query)
	}
	id := fmt.Sprint(args[0].Value)
	c.s.stored[id] = append(c.s.stored[id], fmt.Sprint(args[4].Value))
	return driver.RowsAffected(1), nil
}

func (c *alertStoreConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if c.s.down {
		return nil, errAlertStoreDown
	}
	return noRows{}, nil
}

type noRows struct{}

func (noRows) Columns() []string         { return nil }
func (noRows) Close() error              { return nil }
func (noRows) Next([]driver.Value) error { return io.EOF }

// startAppWithAlertStore starts the service with in-memory event storage
// and alerts persisted to store. The caller shuts it down.
func startAppWithAlertStore(t *testing.T, cfg *config.Config, store *alertStore) *App {
	t.Helper()
	db := sql.OpenDB(store)
	t.Cleanup(func() { db.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, Options{Store: newMemStore(), Listener: ln, AlertDB: db})
	if err != nil {
		_ = ln.Close()
		t.Fatalf("New: %v", err)
	}
	if err := a.Start(); err != nil {
		a.Shutdown(5 * time.Second)
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { a.Shutdown(5 * time.Second) })
	return a
}

func metricsBody(t *testing.T, a *App) string {
	t.Helper()
	resp, err := http.Get("http://" + a.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestAlerts_RaisedDuringStorageOutagePersistedOnRecovery(t *testing.T) {
	store := newAlertStore()
	a := startAppWithAlertStore(t, testConfig(t), store)

	store.setDown(true)
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers("outage-key-ao2", "10.78.0.31")); code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}
	alert := waitForAlert(t, a, "sec-005")
	waitFor(t, "both alerts queued", func() bool { return a.alertMgr.PersistenceMetrics().PendingWrites == 2 })
	if m := metricsBody(t, a); !strings.Contains(m, "siem_alerts_pending_writes 2\n") || !strings.Contains(m, "siem_alerts_write_failures_total 2\n") {
		t.Errorf("/metrics does not report the 2 pending alert writes:\n%s", m)
	}

	// The acknowledgement is applied, so it succeeds; a repeat conflicts
	// with the acknowledged state it reported.
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/alerts/"+alert.ID+"/acknowledge", map[string]string{"user": "outage-analyst"}); code != http.StatusOK {
		t.Fatalf("acknowledge during the outage = %d %s, want 200", code, body)
	}
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/alerts/"+alert.ID+"/acknowledge", map[string]string{"user": "retry"}); code != http.StatusConflict {
		t.Errorf("repeated acknowledge = %d %s, want 409", code, body)
	}
	if got := store.statuses(alert.ID); len(got) != 0 {
		t.Fatalf("stored while storage was down: %v", got)
	}

	store.setDown(false)
	waitFor(t, "the alert and its acknowledgement to be stored", func() bool {
		got := store.statuses(alert.ID)
		return len(got) > 0 && got[len(got)-1] == "acknowledged"
	})
	waitFor(t, "no pending alert writes", func() bool { return a.alertMgr.PersistenceMetrics().PendingWrites == 0 })
	if m := metricsBody(t, a); !strings.Contains(m, "siem_alerts_pending_writes 0\n") || !strings.Contains(m, "siem_alerts_writes_retried_total 2\n") {
		t.Errorf("/metrics after recovery:\n%s", m)
	}
	if report := a.Shutdown(5 * time.Second); report.AlertsUnpersisted != 0 || report.AlertWritesDropped != 0 {
		t.Errorf("report = %+v, want every alert change persisted", report)
	}
}

func TestShutdown_FlushesAndReportsUnpersistedAlerts(t *testing.T) {
	for _, recover := range []bool{true, false} {
		t.Run(fmt.Sprintf("storage back before shutdown=%v", recover), func(t *testing.T) {
			store := newAlertStore()
			cfg := testConfig(t)
			cfg.Server.ShutdownTimeout = 3 * time.Second
			a := startAppWithAlertStore(t, cfg, store)

			store.setDown(true)
			if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers("shutdown-key", "10.78.0.32")); code != http.StatusOK {
				t.Fatalf("POST /v1/events = %d %s", code, body)
			}
			alert := waitForAlert(t, a, "sec-005")
			waitFor(t, "both alerts queued", func() bool { return a.alertMgr.PersistenceMetrics().PendingWrites == 2 })
			if recover {
				// Back too late for the background writer (first retry after
				// 1s): only the final flush can write them.
				store.setDown(false)
			}

			start := time.Now()
			report := a.Shutdown(cfg.Server.ShutdownTimeout)
			if elapsed := time.Since(start); elapsed > cfg.Server.ShutdownTimeout+time.Second {
				t.Errorf("shutdown took %v, budget %v", elapsed, cfg.Server.ShutdownTimeout)
			}
			stored := len(store.statuses(alert.ID)) > 0
			if recover {
				if report.AlertsUnpersisted != 0 || !stored {
					t.Errorf("report = %+v, stored = %v: the final flush must write the queued alerts", report, stored)
				}
				return
			}
			if report.AlertsUnpersisted != 2 || stored {
				t.Errorf("report = %+v, stored = %v: want the 2 alerts reported as not persisted", report, stored)
			}
		})
	}
}
