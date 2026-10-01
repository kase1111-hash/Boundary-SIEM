package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/ingest"
)

func TestStorageHealth(t *testing.T) {
	var pingErr error
	block := make(chan struct{})
	defer close(block)
	hang := false

	h := newStorageHealth(func(ctx context.Context) error {
		if hang {
			<-block // a driver that ignores its context
			return nil
		}
		return pingErr
	})
	ctx := context.Background()

	h.check(ctx, 0)
	if status, _ := h.get(); status != ingest.StatusUp {
		t.Fatalf("status = %s, want up", status)
	}

	h.check(ctx, 3)
	if status, msg := h.get(); status != ingest.StatusDegraded || !strings.Contains(msg, "3 failed flushes") {
		t.Errorf("after flush failures: %s %q, want degraded", status, msg)
	}

	pingErr = errors.New("dial tcp 10.0.0.5:9000: connect: connection refused")
	h.check(ctx, 0)
	status, msg := h.get()
	if status != ingest.StatusDown || msg != "ping failed" {
		t.Errorf("ping error: %s %q, want down/ping failed", status, msg)
	}
	if strings.Contains(msg, "10.0.0.5") {
		t.Error("unauthenticated health message leaks the storage address")
	}

	// A ping that never returns is bounded and reported as a timeout; the
	// next check does not start a second ping while it hangs.
	hang = true
	start := time.Now()
	h.check(ctx, 0)
	if elapsed := time.Since(start); elapsed > storagePingTimeout+time.Second {
		t.Errorf("hung ping held the check for %v", elapsed)
	}
	if status, msg := h.get(); status != ingest.StatusDown || msg != "ping timed out" {
		t.Errorf("hung ping: %s %q", status, msg)
	}
	start = time.Now()
	h.check(ctx, 0)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("second check waited %v on the pending ping", elapsed)
	}
	if status, _ := h.get(); status != ingest.StatusDown {
		t.Errorf("status = %s while the ping is still pending, want down", status)
	}

	// Without a ping function (storage disabled or a test store) nothing
	// is checked and the status stays up.
	none := newStorageHealth(nil)
	none.check(ctx, 5)
	if status, _ := none.get(); status != ingest.StatusUp {
		t.Errorf("no-ping status = %s", status)
	}
}
