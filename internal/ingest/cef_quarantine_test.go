package ingest

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/storage"
)

// tooOldCEFLine parses and normalizes but fails validation: its rt (2001)
// is far older than the validator's maximum event age.
const tooOldCEFLine = "CEF:0|Security|TestProduct|1.0|100|Session Created|5|rt=1000000000000 src=192.168.1.1 outcome=success"

// TestCEFServers_QuarantineRejectedMessages checks that CEF messages a
// transport rejects are stored in events_quarantine with the raw line, the
// sender and the rejection kind, like rejected JSON events, while valid
// messages are still queued.
func TestCEFServers_QuarantineRejectedMessages(t *testing.T) {
	type server struct {
		start   func(*Quarantiner) (network, addr string, stop func(), metrics func() (queued, errs uint64))
		newline bool
	}
	servers := map[string]server{
		"tcp": {newline: true, start: func(qr *Quarantiner) (string, string, func(), func() (uint64, uint64)) {
			srv, _ := newTestTCPServer(t)
			srv.WithQuarantine(qr)
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			return "tcp", srv.listener.Addr().String(), srv.Stop, func() (uint64, uint64) {
				m := srv.Metrics()
				return m.Queued, m.Errors
			}
		}},
		"udp": {start: func(qr *Quarantiner) (string, string, func(), func() (uint64, uint64)) {
			srv, _ := newTestUDPServer(t)
			srv.WithQuarantine(qr)
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			return "udp", srv.conn.LocalAddr().String(), srv.Stop, func() (uint64, uint64) {
				m := srv.Metrics()
				return m.Queued, m.Errors
			}
		}},
		"dtls-insecure": {start: func(qr *Quarantiner) (string, string, func(), func() (uint64, uint64)) {
			srv, _ := newTestDTLSServer(t, func(c *DTLSServerConfig) { c.AllowInsecure = true })
			srv.WithQuarantine(qr)
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			return "udp", srv.udpConn.LocalAddr().String(), srv.Stop, func() (uint64, uint64) {
				m := srv.Metrics()
				return m.Queued, m.Errors
			}
		}},
	}

	for name, s := range servers {
		t.Run(name, func(t *testing.T) {
			store := &memQuarantine{}
			qr := NewQuarantiner(store, 100)
			network, addr, stop, metrics := s.start(qr)

			conn, err := net.Dial(network, addr)
			if err != nil {
				stop()
				t.Fatalf("dial: %v", err)
			}
			for _, msg := range []string{"NOT_A_CEF_MESSAGE", tooOldCEFLine, strings.TrimSuffix(validCEFLine(), "\n")} {
				if s.newline {
					msg += "\n"
				}
				if _, err := conn.Write([]byte(msg)); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			_ = conn.Close()

			if !waitForCondition(5*time.Second, func() bool {
				queued, errs := metrics()
				return queued == 1 && errs == 2
			}) {
				queued, errs := metrics()
				t.Fatalf("queued=%d errors=%d, want 1 and 2", queued, errs)
			}
			stopWithin(t, stop, 3*time.Second)
			if err := qr.Close(context.Background()); err != nil {
				t.Fatal(err)
			}

			byCode := map[string]*storage.QuarantineEntry{}
			for _, e := range store.all() {
				byCode[e.ErrorCode] = e
			}
			if len(store.all()) != 2 {
				t.Fatalf("quarantined %d entries, want 2: %+v", len(store.all()), store.all())
			}
			for code, raw := range map[string]string{
				storage.QuarantineCodeParseFailed:      "NOT_A_CEF_MESSAGE",
				storage.QuarantineCodeValidationFailed: tooOldCEFLine,
			} {
				e := byCode[code]
				if e == nil {
					t.Errorf("no %s entry", code)
					continue
				}
				if e.RawEvent != raw || e.SourceFormat != storage.QuarantineFormatCEF ||
					e.SourceIP != "127.0.0.1" || len(e.ValidationErrors) != 1 || e.ValidationErrors[0] == "" {
					t.Errorf("%s entry = %+v, want raw %q from 127.0.0.1 in cef format with the error", code, e, raw)
				}
			}
		})
	}
}
