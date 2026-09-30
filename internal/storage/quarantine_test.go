package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"boundary-siem/internal/schema"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// rowBatch records the rows appended to it.
type rowBatch struct {
	mockBatch
	rows [][]any
	sent bool
}

func (b *rowBatch) Append(v ...any) error {
	b.rows = append(b.rows, v)
	return nil
}

func (b *rowBatch) Send() error {
	b.sent = true
	return nil
}

func TestQuarantineDeadLetterStoresEvents(t *testing.T) {
	batch := &rowBatch{}
	var query string
	conn := &mockConn{prepareBatchFunc: func(_ context.Context, q string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
		query = q
		return batch, nil
	}}
	qw := NewQuarantineWriter(newMockClient(conn))

	ev := newTestEvent()
	ev.Actor = &schema.Actor{IPAddress: "10.0.0.7"}
	if err := qw.DeadLetter(context.Background(), []*schema.Event{ev}, errors.New("code: 252, too many parts")); err != nil {
		t.Fatalf("DeadLetter() error = %v", err)
	}

	if !strings.Contains(query, "INSERT INTO events_quarantine") {
		t.Errorf("query = %q, want an events_quarantine insert", query)
	}
	if !batch.sent || len(batch.rows) != 1 {
		t.Fatalf("sent=%v rows=%d, want one sent row", batch.sent, len(batch.rows))
	}
	row := batch.rows[0]
	// quarantine_id, raw_event, source_ip, source_format, validation_errors, error_code
	var stored schema.Event
	if err := json.Unmarshal([]byte(row[1].(string)), &stored); err != nil || stored.EventID != ev.EventID {
		t.Errorf("raw_event = %q (err %v), want the event's JSON", row[1], err)
	}
	if row[2] != "10.0.0.7" || row[3] != QuarantineFormatJSON || row[5] != QuarantineCodeStorageFailed {
		t.Errorf("source_ip, format, code = %v, %v, %v", row[2], row[3], row[5])
	}
	if errs := row[4].([]string); len(errs) != 1 || !strings.Contains(errs[0], "too many parts") {
		t.Errorf("validation_errors = %v, want the insert error", errs)
	}
}

func TestNewQuarantineEntry(t *testing.T) {
	e := NewQuarantineEntry("CEF:0|bad", "192.0.2.1", QuarantineFormatCEF, QuarantineCodeParseFailed, "missing header field")
	if e.RawEvent != "CEF:0|bad" || e.SourceIP != "192.0.2.1" || e.SourceFormat != "cef" ||
		e.ErrorCode != "parse_failed" || len(e.ValidationErrors) != 1 {
		t.Errorf("entry = %+v", e)
	}

	ev := newTestEvent()
	ev.Severity = 99
	e = QuarantineEntryForEvent(ev, "", QuarantineFormatJSON, QuarantineCodeValidationFailed, "severity: must be 1-10")
	if !strings.Contains(e.RawEvent, ev.EventID.String()) || e.ErrorCode != "validation_failed" {
		t.Errorf("entry = %+v", e)
	}
}
