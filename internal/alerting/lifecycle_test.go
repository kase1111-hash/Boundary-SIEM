package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Snapshot isolation (regression: API encoded live *Alert values that
// AddNote/AcknowledgeAlert mutate under the manager lock -> data race)
// ---------------------------------------------------------------------------

func TestAlertSnapshotsAreIsolated(t *testing.T) {
	tests := []struct {
		name string
		// snapshot returns the alert the way a caller outside the manager sees it.
		snapshot func(t *testing.T, mgr *Manager, ch *mockChannel, id uuid.UUID) *Alert
	}{
		{
			name: "GetAlert",
			snapshot: func(t *testing.T, mgr *Manager, _ *mockChannel, id uuid.UUID) *Alert {
				a, err := mgr.GetAlert(context.Background(), id)
				if err != nil {
					t.Fatalf("GetAlert: %v", err)
				}
				return a
			},
		},
		{
			name: "ListAlerts",
			snapshot: func(t *testing.T, mgr *Manager, _ *mockChannel, id uuid.UUID) *Alert {
				list, err := mgr.ListAlerts(context.Background(), AlertFilter{})
				if err != nil {
					t.Fatalf("ListAlerts: %v", err)
				}
				for _, a := range list {
					if a.ID == id {
						return a
					}
				}
				t.Fatalf("alert %s not listed", id)
				return nil
			},
		},
		{
			name: "notification payload",
			snapshot: func(t *testing.T, _ *Manager, ch *mockChannel, _ uuid.UUID) *Alert {
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					if sent := ch.getSentAlerts(); len(sent) > 0 {
						return sent[0]
					}
					time.Sleep(5 * time.Millisecond)
				}
				t.Fatal("notification was not delivered")
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mgr := NewManager(DefaultManagerConfig(), nil)
			ch := newMockChannel("capture")
			mgr.AddChannel(ch)

			corrAlert := makeCorrelationAlert("snap-rule", "snap-group", "Snapshot", 7)
			if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
				t.Fatalf("HandleCorrelationAlert: %v", err)
			}

			snap := tt.snapshot(t, mgr, ch, corrAlert.ID)

			// Later writes must not show through an earlier snapshot.
			if err := mgr.AddNote(ctx, corrAlert.ID, "analyst", "looking"); err != nil {
				t.Fatalf("AddNote: %v", err)
			}
			if err := mgr.AcknowledgeAlert(ctx, corrAlert.ID, "analyst"); err != nil {
				t.Fatalf("AcknowledgeAlert: %v", err)
			}
			if snap.Status != StatusNew {
				t.Errorf("snapshot status changed to %q after acknowledge", snap.Status)
			}
			if len(snap.Notes) != 0 {
				t.Errorf("snapshot gained %d notes after AddNote", len(snap.Notes))
			}

			// Writes to a snapshot must not leak back into the manager.
			snap.Status = StatusSuppressed
			snap.Tags = append(snap.Tags[:0], "tampered")
			if len(snap.EventIDs) > 0 {
				snap.EventIDs[0] = uuid.Nil
			}
			current, err := mgr.GetAlert(ctx, corrAlert.ID)
			if err != nil {
				t.Fatalf("GetAlert: %v", err)
			}
			if current.Status != StatusAcknowledged {
				t.Errorf("manager status = %q, want acknowledged", current.Status)
			}
			if len(current.Tags) != 1 || current.Tags[0] != "test" {
				t.Errorf("manager tags modified through snapshot: %v", current.Tags)
			}
			if len(current.EventIDs) != 1 || current.EventIDs[0] == uuid.Nil {
				t.Errorf("manager event IDs modified through snapshot: %v", current.EventIDs)
			}
			if len(current.Notes) != 1 {
				t.Errorf("manager has %d notes, want 1", len(current.Notes))
			}
		})
	}
}

// TestAlertAPIConcurrentReadsAndWrites exercises the HTTP read paths while
// the same alert is being mutated. Run with -race: before snapshots were
// returned, encoding/json read Status/Notes/UpdatedAt without the lock while
// AddNote and AssignAlert wrote them.
func TestAlertAPIConcurrentReadsAndWrites(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), nil)
	corrAlert := makeCorrelationAlert("race-rule", "race-group", "Race", 7)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}

	mux := http.NewServeMux()
	NewHandler(mgr).RegisterRoutes(mux)
	id := corrAlert.ID.String()

	const iterations = 200
	var wg sync.WaitGroup
	for _, path := range []string{"/v1/alerts/" + id, "/v1/alerts"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != http.StatusOK {
					t.Errorf("GET %s: status %d", path, rec.Code)
					return
				}
			}
		}(path)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := mgr.AddNote(ctx, corrAlert.ID, "analyst", fmt.Sprintf("note %d", i)); err != nil {
				t.Errorf("AddNote: %v", err)
				return
			}
			if err := mgr.AssignAlert(ctx, corrAlert.ID, fmt.Sprintf("analyst-%d", i)); err != nil {
				t.Errorf("AssignAlert: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	final, err := mgr.GetAlert(ctx, corrAlert.ID)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if len(final.Notes) != iterations {
		t.Errorf("expected %d notes, got %d", iterations, len(final.Notes))
	}
}

// TestListAlertsCopiesOnlyTheReturnedPage guards the cost of snapshots.
// ListAlerts deep-copied every matching alert (with its event IDs) before
// paginating, so GET /v1/alerts?limit=10 with 100k alerts in memory copied
// all 100k (about 140 MB and 250 ms per request with 50 event IDs each), and
// so did every escalation tick. Pages must still be ordered newest first,
// with ties broken deterministically so consecutive pages neither repeat nor
// skip alerts.
func TestListAlertsCopiesOnlyTheReturnedPage(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), nil)
	base := time.Now()
	const total = 2000
	for i := 0; i < total; i++ {
		a := &Alert{
			ID:       uuid.New(),
			Status:   StatusNew,
			Severity: "high",
			// Groups of four alerts share a creation time.
			CreatedAt: base.Add(-time.Duration(i/4) * time.Second),
			EventIDs:  make([]uuid.UUID, 100),
			Tags:      []string{"t"},
			Metadata:  map[string]interface{}{"k": "v"},
		}
		mgr.alerts[a.ID] = a
	}

	allocs := testing.AllocsPerRun(5, func() {
		page, err := mgr.ListAlerts(ctx, AlertFilter{Limit: 10})
		if err != nil || len(page) != 10 {
			t.Fatalf("ListAlerts: %d alerts, %v", len(page), err)
		}
	})
	if allocs > 300 {
		t.Errorf("ListAlerts(limit=10) over %d alerts made %.0f allocations; only the page should be copied", total, allocs)
	}

	seen := make(map[uuid.UUID]bool, total)
	var prev *Alert
	for offset := 0; offset < total; offset += 7 {
		page, err := mgr.ListAlerts(ctx, AlertFilter{Limit: 7, Offset: offset})
		if err != nil {
			t.Fatalf("ListAlerts(offset=%d): %v", offset, err)
		}
		for _, a := range page {
			if seen[a.ID] {
				t.Fatalf("alert %s returned on more than one page", a.ID)
			}
			seen[a.ID] = true
			if prev != nil && a.CreatedAt.After(prev.CreatedAt) {
				t.Fatalf("alerts not ordered newest first at offset %d", offset)
			}
			prev = a
		}
	}
	if len(seen) != total {
		t.Errorf("paging returned %d distinct alerts, want %d", len(seen), total)
	}

	// A page past the end of the in-memory matches is empty; it does not
	// fall back to the database.
	if page, err := mgr.ListAlerts(ctx, AlertFilter{Limit: 10, Offset: total}); err != nil || len(page) != 0 {
		t.Errorf("ListAlerts past the end = %d alerts, %v; want none", len(page), err)
	}
}

// ---------------------------------------------------------------------------
// State machine (regression: a resolved alert could be re-acknowledged,
// regressing its status and hiding it from ?status=resolved)
// ---------------------------------------------------------------------------

type alertAction string

const (
	actAck     alertAction = "acknowledge"
	actAssign  alertAction = "assign"
	actResolve alertAction = "resolve"
	actNote    alertAction = "note"
)

func applyAction(ctx context.Context, mgr *Manager, id uuid.UUID, a alertAction) error {
	switch a {
	case actAck:
		return mgr.AcknowledgeAlert(ctx, id, "analyst")
	case actAssign:
		return mgr.AssignAlert(ctx, id, "analyst")
	case actResolve:
		return mgr.ResolveAlert(ctx, id, "analyst")
	case actNote:
		return mgr.AddNote(ctx, id, "analyst", "note")
	}
	return fmt.Errorf("unknown action %q", a)
}

func TestAlertStateTransitions(t *testing.T) {
	tests := []struct {
		name       string
		setup      []alertAction // applied first, must succeed
		action     alertAction
		wantErr    error // nil = allowed
		wantStatus AlertStatus
	}{
		{"new -> acknowledge", nil, actAck, nil, StatusAcknowledged},
		{"new -> assign", nil, actAssign, nil, StatusInProgress},
		{"new -> resolve", nil, actResolve, nil, StatusResolved},
		{"acknowledged -> acknowledge", []alertAction{actAck}, actAck, ErrInvalidTransition, StatusAcknowledged},
		{"acknowledged -> assign", []alertAction{actAck}, actAssign, nil, StatusInProgress},
		{"acknowledged -> resolve", []alertAction{actAck}, actResolve, nil, StatusResolved},
		{"in_progress -> acknowledge", []alertAction{actAssign}, actAck, ErrInvalidTransition, StatusInProgress},
		{"in_progress -> reassign", []alertAction{actAssign}, actAssign, nil, StatusInProgress},
		{"in_progress -> resolve", []alertAction{actAssign}, actResolve, nil, StatusResolved},
		{"resolved -> acknowledge", []alertAction{actResolve}, actAck, ErrInvalidTransition, StatusResolved},
		{"resolved -> assign", []alertAction{actResolve}, actAssign, ErrInvalidTransition, StatusResolved},
		{"resolved -> resolve", []alertAction{actResolve}, actResolve, ErrInvalidTransition, StatusResolved},
		{"resolved -> note", []alertAction{actAck, actResolve}, actNote, nil, StatusResolved},
		{"full lifecycle then acknowledge", []alertAction{actAck, actNote, actAssign, actResolve}, actAck, ErrInvalidTransition, StatusResolved},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mgr := NewManager(DefaultManagerConfig(), nil)
			corrAlert := makeCorrelationAlert("fsm-rule", "fsm-group", "FSM", 5)
			if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
				t.Fatalf("HandleCorrelationAlert: %v", err)
			}
			for _, a := range tt.setup {
				if err := applyAction(ctx, mgr, corrAlert.ID, a); err != nil {
					t.Fatalf("setup %s: %v", a, err)
				}
			}
			before, _ := mgr.GetAlert(ctx, corrAlert.ID)

			err := applyAction(ctx, mgr, corrAlert.ID, tt.action)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("%s: unexpected error %v", tt.action, err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("%s: error = %v, want %v", tt.action, err, tt.wantErr)
			}

			after, _ := mgr.GetAlert(ctx, corrAlert.ID)
			if after.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", after.Status, tt.wantStatus)
			}
			if tt.wantErr != nil {
				// A rejected transition must not touch the alert at all.
				if !after.UpdatedAt.Equal(before.UpdatedAt) || after.AckedBy != before.AckedBy ||
					after.AssignedTo != before.AssignedTo || after.ResolvedBy != before.ResolvedBy {
					t.Errorf("rejected %s modified the alert: before=%+v after=%+v", tt.action, before, after)
				}
			}
		})
	}
}

func TestAlertStateTransitionsUnknownAlert(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	for _, a := range []alertAction{actAck, actAssign, actResolve, actNote} {
		err := applyAction(context.Background(), mgr, uuid.New(), a)
		if !errors.Is(err, ErrAlertNotFound) {
			t.Errorf("%s on unknown alert: error = %v, want ErrAlertNotFound", a, err)
		}
	}
}

func TestHandlerLifecycleStatusCodes(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(DefaultManagerConfig(), nil)
	corrAlert := makeCorrelationAlert("http-fsm", "http-fsm", "HTTP FSM", 5)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert: %v", err)
	}
	mux := http.NewServeMux()
	NewHandler(mgr).RegisterRoutes(mux)
	base := "/v1/alerts/" + corrAlert.ID.String()

	post := func(path string, body map[string]string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	steps := []struct {
		name     string
		path     string
		body     map[string]string
		wantCode int
		wantErr  string
	}{
		{"acknowledge", base + "/acknowledge", map[string]string{"user": "a"}, http.StatusOK, ""},
		{"add note", base + "/notes", map[string]string{"author": "a", "content": "c"}, http.StatusOK, ""},
		{"assign", base + "/assign", map[string]string{"assignee": "b"}, http.StatusOK, ""},
		{"resolve", base + "/resolve", map[string]string{"user": "b"}, http.StatusOK, ""},
		{"re-acknowledge resolved", base + "/acknowledge", map[string]string{"user": "a"}, http.StatusConflict, "invalid_transition"},
		{"re-resolve resolved", base + "/resolve", map[string]string{"user": "a"}, http.StatusConflict, "invalid_transition"},
		{"assign resolved", base + "/assign", map[string]string{"assignee": "a"}, http.StatusConflict, "invalid_transition"},
		{"note on resolved", base + "/notes", map[string]string{"author": "a", "content": "post-mortem"}, http.StatusOK, ""},
		{"acknowledge unknown", "/v1/alerts/" + uuid.New().String() + "/acknowledge", map[string]string{"user": "a"}, http.StatusNotFound, "not_found"},
	}
	for _, s := range steps {
		rec := post(s.path, s.body)
		if rec.Code != s.wantCode {
			t.Fatalf("%s: status %d, want %d (%s)", s.name, rec.Code, s.wantCode, rec.Body.String())
		}
		if s.wantErr != "" {
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s: decode: %v", s.name, err)
			}
			if resp["code"] != s.wantErr {
				t.Errorf("%s: code %q, want %q", s.name, resp["code"], s.wantErr)
			}
		}
	}

	// The alert must still be listed as resolved.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/alerts?status=resolved", nil))
	var list struct {
		Alerts []Alert `json:"alerts"`
		Total  int     `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Total != 1 || len(list.Alerts) != 1 || list.Alerts[0].ID != corrAlert.ID {
		t.Fatalf("expected the alert under status=resolved, got %s", rec.Body.String())
	}
	if got := list.Alerts[0]; got.AckedBy != "a" || got.ResolvedBy != "b" || got.AssignedTo != "b" || len(got.Notes) != 2 {
		t.Errorf("unexpected final alert: %+v", got)
	}
}
