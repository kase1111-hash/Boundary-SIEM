package alerting

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// E2E round 3: alerts raised, merged or changed while ClickHouse was
// unreachable were applied in memory only. The failed write was logged and
// never retried, so the change (a critical key-export alert in the e2e run)
// was lost on the next restart, and API actions answered 500 for a change
// they had in fact applied, so a retry got 409.

// ---------------------------------------------------------------------------
// A database/sql driver that can be taken down and brought back
// ---------------------------------------------------------------------------

// errStorageDown is what outageDB returns while it is down, like the driver
// against a stopped ClickHouse.
var errStorageDown = errors.New("dial tcp 127.0.0.1:19000: connect: connection refused")

// outageDB records the alert rows it stored. While down, every Exec and
// Query fails with errStorageDown, or, while hung, blocks until its context
// is done, like a frozen server.
type outageDB struct {
	mu       sync.Mutex
	down     bool
	hang     bool
	stored   []recordedExec
	attempts int
	failures int
}

func (o *outageDB) Connect(context.Context) (driver.Conn, error) { return &outageConn{db: o}, nil }
func (o *outageDB) Driver() driver.Driver                        { return recordingDriver{} }

func (o *outageDB) setDown(down bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.down = down
}

func (o *outageDB) setHang(hang bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hang = hang
}

// counts returns the number of writes attempted and failed so far.
func (o *outageDB) counts() (attempts, failures int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.attempts, o.failures
}

// rows returns the stored versions of an alert, oldest write first.
func (o *outageDB) rows(t *testing.T, id uuid.UUID) []map[string]driver.Value {
	t.Helper()
	o.mu.Lock()
	stored := append([]recordedExec(nil), o.stored...)
	o.mu.Unlock()
	var out []map[string]driver.Value
	for _, e := range stored {
		row := insertedRow(t, e)
		if fmt.Sprint(row["alert_id"]) == id.String() {
			out = append(out, row)
		}
	}
	return out
}

// latest returns the version of an alert a read selects (the greatest
// updated_at, as in ReplacingMergeTree(updated_at)), or nil.
func (o *outageDB) latest(t *testing.T, id uuid.UUID) map[string]driver.Value {
	t.Helper()
	var best map[string]driver.Value
	for _, row := range o.rows(t, id) {
		if best == nil || fmt.Sprint(row["updated_at"]) >= fmt.Sprint(best["updated_at"]) {
			best = row
		}
	}
	return best
}

type outageConn struct{ db *outageDB }

func (c *outageConn) Prepare(string) (driver.Stmt, error)      { return nil, errors.New("not supported") }
func (c *outageConn) Close() error                             { return nil }
func (c *outageConn) Begin() (driver.Tx, error)                { return nil, errors.New("not supported") }
func (c *outageConn) CheckNamedValue(*driver.NamedValue) error { return nil }

func (c *outageConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.db.mu.Lock()
	c.db.attempts++
	down, hang := c.db.down, c.db.hang
	if down || hang {
		c.db.failures++
	}
	c.db.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if down {
		return nil, errStorageDown
	}
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	c.db.mu.Lock()
	c.db.stored = append(c.db.stored, recordedExec{query: query, args: vals})
	c.db.mu.Unlock()
	return driver.RowsAffected(1), nil
}

func (c *outageConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.db.mu.Lock()
	down := c.db.down
	c.db.mu.Unlock()
	if down {
		return nil, errStorageDown
	}
	return emptyRows{}, nil
}

// outageConfig retries quickly so that tests do not wait for the default
// one-second backoff.
func outageConfig() ManagerConfig {
	cfg := DefaultManagerConfig()
	cfg.PersistRetryInitial = 10 * time.Millisecond
	cfg.PersistRetryMax = 40 * time.Millisecond
	cfg.PersistTimeout = time.Second
	return cfg
}

func newOutageManager(t *testing.T, cfg ManagerConfig) (*Manager, *outageDB) {
	t.Helper()
	fdb := &outageDB{}
	db := sql.OpenDB(fdb)
	mgr := NewManager(cfg, db)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		mgr.Close(ctx)
		db.Close()
	})
	return mgr, fdb
}

// eventually polls cond for up to 5 seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// logBuffer collects what slog's default logger writes during a test.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLogs(t *testing.T) *logBuffer {
	t.Helper()
	logs := &logBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return logs
}

// ---------------------------------------------------------------------------
// Finding 0: an alert raised during an outage is written once storage is back
// ---------------------------------------------------------------------------

func TestAlertRaisedDuringOutageIsPersistedOnceStorageRecovers(t *testing.T) {
	mgr, fdb := newOutageManager(t, outageConfig())
	ctx := context.Background()
	mgr.Start(ctx)

	fdb.setDown(true)
	critical := makeCorrelationAlert("sec-005", "[target=outage-key-ao2]", "Key export", 9)
	if err := mgr.HandleCorrelationAlert(ctx, critical); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	if got, err := mgr.GetAlert(ctx, critical.ID); err != nil || got.Status != StatusNew {
		t.Fatalf("alert not served from memory during the outage: %+v, %v", got, err)
	}
	// A recurrence during the outage is merged and queued with the alert.
	again := makeCorrelationAlert("sec-005", "[target=outage-key-ao2]", "Key export", 9)
	if err := mgr.HandleCorrelationAlert(ctx, again); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	other := makeCorrelationAlert("sec-001", "[actor.ip=10.78.0.9]", "Blocked RPC", 9)
	if err := mgr.HandleCorrelationAlert(ctx, other); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	if m := mgr.PersistenceMetrics(); m.PendingWrites != 2 || m.FailedWrites != 3 {
		t.Fatalf("metrics during the outage = %+v, want 2 pending alerts after 3 failed writes", m)
	}

	// While storage stays down the writer retries with growing delays (10,
	// 20, 40, 40 ms ...), one write per attempt however many alerts wait.
	_, before := fdb.counts()
	time.Sleep(400 * time.Millisecond)
	_, after := fdb.counts()
	if retries := after - before; retries < 2 || retries > 20 {
		t.Errorf("%d failed retries in 400ms of outage, want a few (backoff 10ms doubling to 40ms, one write per attempt)", retries)
	}
	if fdb.latest(t, critical.ID) != nil {
		t.Fatal("stored while storage was down")
	}

	fdb.setDown(false)
	eventually(t, "the alerts raised during the outage to be stored", func() bool {
		return mgr.PersistenceMetrics().PendingWrites == 0
	})
	row := fdb.latest(t, critical.ID)
	if row == nil || row["status"] != "new" || row["severity"] != "critical" || fmt.Sprint(row["event_count"]) != "2" {
		t.Fatalf("stored row = %v, want the new critical alert with the merged recurrence (event_count 2)", row)
	}
	if fdb.latest(t, other.ID) == nil {
		t.Error("second alert raised during the outage was not stored")
	}
	if m := mgr.PersistenceMetrics(); m.RetriedWrites != 2 || m.DroppedWrites != 0 {
		t.Errorf("metrics after recovery = %+v, want 2 retried writes and none dropped", m)
	}
}

// ---------------------------------------------------------------------------
// Finding 1: lifecycle actions during an outage succeed and are persisted
// ---------------------------------------------------------------------------

func TestAlertActionDuringOutageSucceedsAndIsPersistedLater(t *testing.T) {
	mgr, fdb := newOutageManager(t, outageConfig())
	ctx := context.Background()
	mgr.Start(ctx)

	corrAlert := makeCorrelationAlert("sec-005", "[target=outage-key-ao1]", "Key export", 9)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	mux := http.NewServeMux()
	NewHandler(mgr).RegisterRoutes(mux)
	post := func(action, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/alerts/"+corrAlert.ID.String()+"/"+action, strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	fdb.setDown(true)
	if w := post("acknowledge", `{"user":"outage-analyst"}`); w.Code != http.StatusOK {
		t.Fatalf("acknowledge during the outage = %d %s, want 200 (the change is applied)", w.Code, w.Body.String())
	}
	got, err := mgr.GetAlert(ctx, corrAlert.ID)
	if err != nil || got.Status != StatusAcknowledged || got.AckedBy != "outage-analyst" {
		t.Fatalf("acknowledgement not applied: %+v, %v", got, err)
	}
	// Repeating the action is judged against the state the 200 reported,
	// exactly as it will be once stored.
	if w := post("acknowledge", `{"user":"retry"}`); w.Code != http.StatusConflict {
		t.Errorf("repeated acknowledge = %d %s, want 409", w.Code, w.Body.String())
	}
	if got, _ := mgr.GetAlert(ctx, corrAlert.ID); got.AckedBy != "outage-analyst" {
		t.Errorf("repeated acknowledge changed acked_by to %q", got.AckedBy)
	}
	for _, step := range []struct{ action, body string }{
		{"notes", `{"author":"outage-analyst","content":"exported during the outage"}`},
		{"assign", `{"assignee":"bob"}`},
		{"resolve", `{"user":"carol"}`},
	} {
		if w := post(step.action, step.body); w.Code != http.StatusOK {
			t.Fatalf("%s during the outage = %d %s, want 200", step.action, w.Code, w.Body.String())
		}
	}
	if m := mgr.PersistenceMetrics(); m.PendingWrites != 1 {
		t.Fatalf("metrics during the outage = %+v, want the one changed alert pending", m)
	}
	want, _ := mgr.GetAlert(ctx, corrAlert.ID)
	storedBefore := len(fdb.rows(t, corrAlert.ID))

	fdb.setDown(false)
	eventually(t, "the changes made during the outage to be stored", func() bool {
		return mgr.PersistenceMetrics().PendingWrites == 0
	})
	// The latest version is written once, not once per change.
	if n := len(fdb.rows(t, corrAlert.ID)) - storedBefore; n != 1 {
		t.Errorf("%d versions written after recovery, want 1 (the latest)", n)
	}
	row := fdb.latest(t, corrAlert.ID)
	checks := map[string]string{
		"status":          "resolved",
		"acknowledged_by": "outage-analyst",
		"assignee":        "bob",
		"resolved_by":     "carol",
		"updated_at":      formatDBTime(want.UpdatedAt),
	}
	for col, wantVal := range checks {
		if got := fmt.Sprint(row[col]); got != wantVal {
			t.Errorf("stored %s = %q, want %q", col, got, wantVal)
		}
	}
	if notes := fmt.Sprint(row["notes"]); !strings.Contains(notes, "exported during the outage") {
		t.Errorf("stored notes %q do not contain the note added during the outage", notes)
	}
}

// An escalation note added during an outage is applied and queued like any
// other change (it used to fail with "failed to add escalation note").
func TestEscalationNoteDuringOutageIsQueued(t *testing.T) {
	mgr, fdb := newOutageManager(t, outageConfig())
	ctx := context.Background()
	corrAlert := makeCorrelationAlert("esc-outage", "g", "Unacknowledged", 9)
	corrAlert.Timestamp = time.Now().Add(-20 * time.Minute) // critical: the 15m step is due
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatal(err)
	}
	fdb.setDown(true)
	engine := NewEscalationEngine(mgr)
	engine.RegisterChannel(newMockChannel(DefaultChannelName))
	for _, p := range BuiltinEscalationPolicies() {
		engine.AddPolicy(p)
	}
	engine.checkEscalations(ctx)
	if notes := escalationNoteContents(t, mgr, corrAlert.ID); len(notes) != 1 {
		t.Fatalf("escalation notes = %q, want 1", notes)
	}
	if m := mgr.PersistenceMetrics(); m.PendingWrites != 1 {
		t.Fatalf("metrics = %+v, want the escalated alert pending", m)
	}
	fdb.setDown(false)
	closeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if left := mgr.Close(closeCtx); left != 0 {
		t.Fatalf("Close left %d alerts unpersisted", left)
	}
	if notes := fmt.Sprint(fdb.latest(t, corrAlert.ID)["notes"]); !strings.Contains(notes, "Escalated by policy") {
		t.Errorf("stored notes %q lack the escalation note", notes)
	}
}

// ---------------------------------------------------------------------------
// Shutdown: one final bounded attempt; what is left is logged at ERROR
// ---------------------------------------------------------------------------

func TestCloseWritesPendingAlerts(t *testing.T) {
	logs := captureLogs(t)
	mgr, fdb := newOutageManager(t, outageConfig()) // background writer not started
	ctx := context.Background()

	fdb.setDown(true)
	corrAlert := makeCorrelationAlert("close-flush", "g", "Raised during the outage", 9)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatal(err)
	}
	fdb.setDown(false)

	closeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if left := mgr.Close(closeCtx); left != 0 {
		t.Fatalf("Close left %d alerts unpersisted, want 0", left)
	}
	if fdb.latest(t, corrAlert.ID) == nil {
		t.Fatal("Close did not write the pending alert")
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("ERROR logged although every alert was written:\n%s", logs)
	}
}

func TestCloseReportsUnpersistedAlerts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*outageDB)
	}{
		{"storage refuses connections", func(o *outageDB) { o.setDown(true) }},
		{"storage hangs", func(o *outageDB) { o.setHang(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			cfg := outageConfig()
			cfg.PersistTimeout = 50 * time.Millisecond
			mgr, fdb := newOutageManager(t, cfg)
			ctx := context.Background()
			mgr.Start(ctx)

			tc.setup(fdb)
			var ids []uuid.UUID
			for i := 0; i < 3; i++ {
				a := makeCorrelationAlert("close-lost", fmt.Sprint(i), "Lost at shutdown", 9)
				if err := mgr.HandleCorrelationAlert(ctx, a); err != nil {
					t.Fatal(err)
				}
				ids = append(ids, a.ID)
			}

			closeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			left := mgr.Close(closeCtx)
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("Close took %v with a 200ms budget", elapsed)
			}
			if left != 3 {
				t.Errorf("Close returned %d unpersisted alerts, want 3", left)
			}
			out := logs.String()
			if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "unpersisted_alerts=3") {
				t.Fatalf("no ERROR log with the number of unpersisted alerts:\n%s", out)
			}
			for _, id := range ids {
				if !strings.Contains(out, id.String()) {
					t.Errorf("ERROR log does not name alert %s", id)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The pending set is bounded
// ---------------------------------------------------------------------------

func TestPendingWritesAreBounded(t *testing.T) {
	logs := captureLogs(t)
	cfg := outageConfig()
	cfg.MaxPendingWrites = 2
	mgr, fdb := newOutageManager(t, cfg)
	ctx := context.Background()

	fdb.setDown(true)
	var alerts []*Alert
	for i := 0; i < 3; i++ {
		a := makeCorrelationAlert("bounded", fmt.Sprint(i), "Bounded", 7)
		if err := mgr.HandleCorrelationAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		got, _ := mgr.GetAlert(ctx, a.ID)
		alerts = append(alerts, got)
	}
	if m := mgr.PersistenceMetrics(); m.PendingWrites != 2 || m.DroppedWrites != 1 {
		t.Fatalf("metrics = %+v, want 2 pending and 1 dropped", m)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), alerts[2].ID.String()) {
		t.Errorf("the dropped write was not logged at ERROR:\n%s", logs)
	}
	// A further change of an alert already pending is not a new entry.
	if err := mgr.AcknowledgeAlert(ctx, alerts[0].ID, "analyst"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if m := mgr.PersistenceMetrics(); m.PendingWrites != 2 || m.DroppedWrites != 1 {
		t.Fatalf("metrics after a change of a pending alert = %+v, want 2 pending and 1 dropped", m)
	}
	// The dropped alert is still served from memory.
	if got, err := mgr.GetAlert(ctx, alerts[2].ID); err != nil || got.ID != alerts[2].ID {
		t.Errorf("dropped alert not in memory: %v", err)
	}

	fdb.setDown(false)
	closeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if left := mgr.Close(closeCtx); left != 0 {
		t.Fatalf("Close left %d alerts unpersisted", left)
	}
	if row := fdb.latest(t, alerts[0].ID); row == nil || row["status"] != "acknowledged" {
		t.Errorf("pending alert stored as %v, want acknowledged", row)
	}
	if fdb.latest(t, alerts[1].ID) == nil {
		t.Error("pending alert not stored")
	}
	if !strings.Contains(logs.String(), "dropped_writes=1") {
		t.Errorf("Close did not report the dropped write at ERROR:\n%s", logs)
	}
}

// An alert whose latest change is not stored stays in memory, where its
// only copy is, until it is written.
func TestCleanupKeepsAlertsWithPendingWrites(t *testing.T) {
	cfg := outageConfig()
	cfg.RetentionPeriod = time.Minute
	mgr, fdb := newOutageManager(t, cfg)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("cleanup-pending", "g", "Old", 5)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatal(err)
	}
	fdb.setDown(true)
	if err := mgr.ResolveAlert(ctx, corrAlert.ID, "analyst"); err != nil {
		t.Fatal(err)
	}
	mgr.mu.Lock()
	mgr.alerts[corrAlert.ID].CreatedAt = time.Now().Add(-time.Hour)
	mgr.mu.Unlock()

	if n := mgr.Cleanup(ctx); n != 0 {
		t.Fatalf("Cleanup removed %d alerts whose resolution is not stored", n)
	}
	fdb.setDown(false)
	closeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if left := mgr.Close(closeCtx); left != 0 {
		t.Fatalf("Close left %d alerts unpersisted", left)
	}
	if row := fdb.latest(t, corrAlert.ID); row == nil || row["status"] != "resolved" {
		t.Fatalf("stored row = %v, want resolved", row)
	}
	if n := mgr.Cleanup(ctx); n != 1 {
		t.Errorf("Cleanup removed %d alerts once stored, want 1", n)
	}
}

// Whatever the interleaving of changes, failed writes and retries, once
// storage is back every alert's stored latest version is its in-memory
// state.
func TestPendingWritesConvergeUnderConcurrentChanges(t *testing.T) {
	mgr, fdb := newOutageManager(t, outageConfig())
	ctx := context.Background()
	mgr.Start(ctx)

	const alerts, writers, notesPerWriter = 8, 4, 25
	ids := make([]uuid.UUID, alerts)
	for i := range ids {
		a := makeCorrelationAlert("converge", fmt.Sprint(i), "Converge", 7)
		if err := mgr.HandleCorrelationAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		ids[i] = a.ID
	}

	stop := make(chan struct{})
	flapped := make(chan struct{})
	go func() {
		defer close(flapped)
		for down := true; ; down = !down {
			fdb.setDown(down)
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Millisecond):
			}
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for n := 0; n < notesPerWriter; n++ {
				id := ids[(w+n)%alerts]
				if err := mgr.AddNote(ctx, id, fmt.Sprint("writer-", w), fmt.Sprint("note ", n)); err != nil {
					t.Errorf("AddNote: %v", err)
				}
				time.Sleep(time.Millisecond)
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-flapped
	fdb.setDown(false)

	eventually(t, "every pending write to be stored", func() bool {
		return mgr.PersistenceMetrics().PendingWrites == 0
	})
	for _, id := range ids {
		want, _ := mgr.GetAlert(ctx, id)
		row := fdb.latest(t, id)
		if row == nil {
			t.Fatalf("alert %s never stored", id)
		}
		if got := fmt.Sprint(row["updated_at"]); got != formatDBTime(want.UpdatedAt) {
			t.Errorf("alert %s: stored updated_at %s, in memory %s", id, got, formatDBTime(want.UpdatedAt))
		}
		if got := strings.Count(fmt.Sprint(row["notes"]), `"content"`); got != len(want.Notes) {
			t.Errorf("alert %s: %d notes stored, %d in memory", id, got, len(want.Notes))
		}
	}
	if m := mgr.PersistenceMetrics(); m.FailedWrites == 0 {
		t.Errorf("metrics = %+v: storage never failed, so the test proved nothing", m)
	}
}

// Retrying writes the alert's full current row again. Against the real
// table, repeating a version, or a late retry of an older version landing
// after a newer one, must not change what reads return.
func TestRetriedWritesAreIdempotentClickHouse(t *testing.T) {
	db := openTestClickHouse(t)
	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), db)

	corrAlert := makeCorrelationAlert("retry-idem", "g", "Retried", 9)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatal(err)
	}
	created, _ := mgr.GetAlert(ctx, corrAlert.ID)
	if err := mgr.AcknowledgeAlert(ctx, corrAlert.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	acked, _ := mgr.GetAlert(ctx, corrAlert.ID)
	for _, version := range []*Alert{acked, acked, created} {
		if err := mgr.persistAlert(ctx, version); err != nil {
			t.Fatalf("rewrite: %v", err)
		}
	}

	fresh := NewManager(DefaultManagerConfig(), db)
	got, err := fresh.GetAlert(ctx, corrAlert.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertSameAlert(t, got, acked)
	for status, want := range map[AlertStatus]int{StatusNew: 0, StatusAcknowledged: 1} {
		s := status
		list, err := fresh.ListAlerts(ctx, AlertFilter{Status: &s, RuleID: "retry-idem"})
		if err != nil || len(list) != want {
			t.Errorf("ListAlerts(status=%s) = %d alerts, %v; want %d", s, len(list), err, want)
		}
	}
	if n, err := fresh.LoadFromDB(ctx); err != nil || n != 1 {
		t.Errorf("LoadFromDB = %d, %v; want 1 alert", n, err)
	}
}

// ---------------------------------------------------------------------------
// Finding 3: merged recurrences are published
// ---------------------------------------------------------------------------

func TestOnRecurrenceReceivesMergedAlert(t *testing.T) {
	mgr, fdb := newOutageManager(t, outageConfig())
	ctx := context.Background()

	var mu sync.Mutex
	var got []*Alert
	mgr.OnRecurrence(func(a *Alert) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, a)
	})
	received := func() []*Alert {
		mu.Lock()
		defer mu.Unlock()
		return append([]*Alert(nil), got...)
	}

	first := makeCorrelationAlert("sec-005", "[target=wsm-m1]", "Key export", 9)
	if err := mgr.HandleCorrelationAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	if n := len(received()); n != 0 {
		t.Fatalf("listener called %d times for a new alert, want 0 (channels notify new alerts)", n)
	}
	for occurrence := 2; occurrence <= 3; occurrence++ {
		if occurrence == 3 {
			fdb.setDown(true) // published even when the write fails
		}
		again := makeCorrelationAlert("sec-005", "[target=wsm-m1]", "Key export", 9)
		if err := mgr.HandleCorrelationAlert(ctx, again); err != nil {
			t.Fatal(err)
		}
		r := received()
		if len(r) != occurrence-1 {
			t.Fatalf("listener called %d times after %d occurrences, want %d", len(r), occurrence, occurrence-1)
		}
		last := r[len(r)-1]
		if last.ID != first.ID || last.EventCount != occurrence || last.Metadata[metaOccurrences] != occurrence {
			t.Errorf("published alert = id %s event_count %d occurrences %v, want %s with %d",
				last.ID, last.EventCount, last.Metadata[metaOccurrences], first.ID, occurrence)
		}
	}
	// A resolved alert's recurrence raises a new alert instead.
	fdb.setDown(false)
	if err := mgr.ResolveAlert(ctx, first.ID, "analyst"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.HandleCorrelationAlert(ctx, makeCorrelationAlert("sec-005", "[target=wsm-m1]", "Key export", 9)); err != nil {
		t.Fatal(err)
	}
	if n := len(received()); n != 2 {
		t.Errorf("listener called %d times, want 2 (no merge into a resolved alert)", n)
	}
}
