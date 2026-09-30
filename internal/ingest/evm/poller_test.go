package evm

import (
	"math"
	"testing"
	"time"
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
