package evm

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"boundary-siem/internal/queue"
)

func TestBlockTimestamp(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()

	tests := []struct {
		name string
		sec  uint64
		want time.Time
	}{
		{name: "zero", sec: 0, want: epoch},
		{name: "typical block time", sec: 1700000000, want: time.Unix(1700000000, 0).UTC()},
		{name: "latest representable", sec: maxBlockTimestamp, want: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
		{name: "past latest representable", sec: maxBlockTimestamp + 1, want: epoch},
		{name: "max int64", sec: math.MaxInt64, want: epoch},
		{name: "just past max int64", sec: math.MaxInt64 + 1, want: epoch},
		{name: "max uint64", sec: math.MaxUint64, want: epoch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blockTimestamp(tt.sec)
			if !got.Equal(tt.want) {
				t.Errorf("blockTimestamp(%d) = %v, want %v", tt.sec, got, tt.want)
			}
			if got.Before(epoch) {
				t.Errorf("blockTimestamp(%d) = %v, must never wrap to before the epoch", tt.sec, got)
			}
		})
	}
}

// TestPoller_StopAbortsHungRPC is the regression test for shutdown waiting
// on the EVM poller: an RPC endpoint that never answers held Stop for the
// HTTP client timeout (30s per call), which delayed the queue drain past the
// orchestrator's kill deadline.
func TestPoller_StopAbortsHungRPC(t *testing.T) {
	requested := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	p := NewPoller(Config{
		Enabled:      true,
		PollInterval: 10 * time.Millisecond,
		StartBlock:   "latest", // resolving it calls the hung endpoint
		Chains:       []ChainConfig{{Name: "test", ChainID: 1, RPCURL: srv.URL, Enabled: true}},
	}, queue.NewRingBuffer(10))
	p.Start(context.Background())

	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("poller never called the RPC endpoint")
	}

	stopped := make(chan struct{})
	start := time.Now()
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return while an RPC call hung")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Stop took %v with a hung RPC endpoint", elapsed)
	}
	p.Stop() // idempotent
}
