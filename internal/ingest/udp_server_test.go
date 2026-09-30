package ingest

import (
	"context"
	"net"
	"testing"
	"time"

	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

func newTestUDPServer(t *testing.T) (*UDPServer, *queue.RingBuffer) {
	t.Helper()

	cfg := DefaultUDPServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.Workers = 2
	cfg.BufferSize = 1 << 20

	q := queue.NewRingBuffer(100)
	srv := NewUDPServer(cfg,
		cef.NewParser(cef.DefaultParserConfig()),
		cef.NewNormalizer(cef.DefaultNormalizerConfig()),
		schema.NewValidator(),
		q)
	return srv, q
}

// TestUDPServer_SyslogFramedCEF is a regression test for syslog-framed CEF
// datagrams being rejected, and checks the parse error breakdown.
func TestUDPServer_SyslogFramedCEF(t *testing.T) {
	srv, q := newTestUDPServer(t)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer stopWithin(t, srv.Stop, 3*time.Second)

	conn, err := net.Dial("udp", srv.conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	now := time.Now().UTC()
	datagrams := []string{
		validCEFLine(),
		"<134>" + now.Format("Jan _2 15:04:05") + " fw01 " + validCEFLine(),
		"<134>1 " + now.Format(time.RFC3339) + " fw02 app - - - " + validCEFLine(),
		"garbage",
	}
	for _, d := range datagrams {
		if _, err := conn.Write([]byte(d)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	if !waitForCondition(3*time.Second, func() bool {
		m := srv.Metrics()
		return m.Queued+m.Errors >= uint64(len(datagrams))
	}) {
		t.Fatalf("timed out; metrics=%+v", srv.Metrics())
	}

	m := srv.Metrics()
	if m.Queued != 3 || m.ParseErrors != 1 || m.Errors != 1 {
		t.Errorf("metrics = %+v, want Queued=3 ParseErrors=1 Errors=1", m)
	}

	hosts := map[string]bool{}
	for {
		ev, _ := q.Pop()
		if ev == nil {
			break
		}
		hosts[ev.Source.Host] = true
	}
	for _, want := range []string{"fw01", "fw02", "127.0.0.1"} {
		if !hosts[want] {
			t.Errorf("no queued event with Source.Host %q; got %v", want, hosts)
		}
	}
}
