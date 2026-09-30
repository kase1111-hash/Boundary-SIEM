package ingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"

	"github.com/pion/dtls/v3"
)

// writeSelfSignedCert generates a self-signed ECDSA certificate for
// 127.0.0.1/localhost and writes it and its key as PEM files in a temp dir.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// newTestDTLSServer creates a DTLSServer with a real CEF pipeline listening
// on a kernel-assigned localhost port.
func newTestDTLSServer(t *testing.T, overrides ...func(*DTLSServerConfig)) (*DTLSServer, *queue.RingBuffer) {
	t.Helper()

	cfg := DefaultDTLSServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.Workers = 2
	cfg.ConnectionTimeout = 5 * time.Second
	for _, fn := range overrides {
		fn(&cfg)
	}

	q := queue.NewRingBuffer(100)
	srv, err := NewDTLSServer(cfg,
		cef.NewParser(cef.DefaultParserConfig()),
		cef.NewNormalizer(cef.DefaultNormalizerConfig()),
		schema.NewValidator(),
		q, nil)
	if err != nil {
		t.Fatalf("NewDTLSServer: %v", err)
	}
	return srv, q
}

// stopWithin calls srv.Stop and fails the test if it does not return in time.
func stopWithin(t *testing.T, stop func(), d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("Stop() did not return within %v", d)
	}
}

// dialDTLSWith opens a DTLS client connection to addr and runs the handshake.
func dialDTLSWith(t *testing.T, addr net.Addr, opts ...dtls.ClientOption) (*dtls.Conn, error) {
	t.Helper()
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener address %T is not *net.UDPAddr", addr)
	}
	conn, err := dtls.DialWithOptions("udp", udpAddr, opts...)
	if err != nil {
		t.Fatalf("DTLS dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialDTLS opens a DTLS client connection to addr and completes the handshake.
func dialDTLS(t *testing.T, addr net.Addr) net.Conn {
	t.Helper()
	conn, err := dialDTLSWith(t, addr,
		dtls.WithInsecureSkipVerify(true), // throwaway self-signed test server
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	)
	if err != nil {
		t.Fatalf("DTLS handshake: %v", err)
	}
	return conn
}

// TestDTLSServer_SecureRoundTripAndStop is a regression test for Stop()
// deadlocking in secure mode: the accept loop returned without closing the
// message channel, so the workers never exited. It also covers a full DTLS
// round trip with a self-signed certificate.
func TestDTLSServer_SecureRoundTripAndStop(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srv, q := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.CertFile = certFile
		c.KeyFile = keyFile
	})

	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !srv.IsSecure() {
		t.Error("IsSecure() = false for a server started with a certificate")
	}

	client := dialDTLS(t, srv.listener.Addr())
	defer client.Close()

	if _, err := client.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("client write: %v", err)
	}

	var event *schema.Event
	if !waitForCondition(5*time.Second, func() bool {
		event, _ = q.Pop()
		return event != nil
	}) {
		t.Fatalf("no event queued; metrics=%+v", srv.Metrics())
	}
	if event.Action != "session.created" || event.Source.Product != "TestProduct" {
		t.Errorf("event = action %q product %q, want session.created/TestProduct", event.Action, event.Source.Product)
	}

	// The client stays connected and idle: Stop must still return promptly.
	stopWithin(t, srv.Stop, 3*time.Second)

	m := srv.Metrics()
	if m.Connections != 1 || m.Handshakes != 1 || m.Queued != 1 {
		t.Errorf("metrics = %+v, want 1 connection, 1 handshake, 1 queued", m)
	}
}

// TestDTLSServer_SecureStopWithoutClients checks that Stop returns when the
// accept loop is blocked in Accept with no client ever connecting.
func TestDTLSServer_SecureStopWithoutClients(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srv, _ := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.CertFile = certFile
		c.KeyFile = keyFile
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	stopWithin(t, srv.Stop, 3*time.Second)
}

// TestDTLSServer_SecureContextCancelThenStop checks the context path: after
// cancellation the connection handlers and workers exit without sending on a
// closed channel, and a later Stop returns.
func TestDTLSServer_SecureContextCancelThenStop(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srv, _ := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.CertFile = certFile
		c.KeyFile = keyFile
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	client := dialDTLS(t, srv.listener.Addr())
	defer client.Close()
	if _, err := client.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !waitForCondition(5*time.Second, func() bool { return srv.Metrics().Queued == 1 }) {
		t.Fatalf("no event queued; metrics=%+v", srv.Metrics())
	}

	cancel()
	stopWithin(t, srv.Stop, 3*time.Second)
}

// TestDTLSServer_InsecureRoundTripAndStop covers the plain-UDP fallback.
func TestDTLSServer_InsecureRoundTripAndStop(t *testing.T) {
	srv, q := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.AllowInsecure = true
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if srv.IsSecure() {
		t.Error("IsSecure() = true for the plain UDP fallback")
	}

	conn, err := net.Dial("udp", srv.udpConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !waitForCondition(5*time.Second, func() bool {
		ev, _ := q.Pop()
		return ev != nil
	}) {
		t.Fatalf("no event queued; metrics=%+v", srv.Metrics())
	}
	stopWithin(t, srv.Stop, 3*time.Second)
}

// TestDTLSServer_SecureRejectsPlaintext checks that a plain UDP datagram sent
// to the secure listener never reaches the pipeline.
func TestDTLSServer_SecureRejectsPlaintext(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srv, q := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.CertFile = certFile
		c.KeyFile = keyFile
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stopWithin(t, srv.Stop, 3*time.Second)

	conn, err := net.Dial("udp", srv.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if ev, _ := q.Pop(); ev != nil {
		t.Fatalf("plaintext datagram was queued on the DTLS listener: %+v", ev)
	}
}

// TestDTLSServer_RequiresExtendedMasterSecret guards the security settings of
// the secure listener: extended master secret is required.
func TestDTLSServer_RequiresExtendedMasterSecret(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srv, _ := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.CertFile = certFile
		c.KeyFile = keyFile
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stopWithin(t, srv.Stop, 3*time.Second)

	conn, err := dialDTLSWith(t, srv.listener.Addr(),
		dtls.WithInsecureSkipVerify(true), // throwaway self-signed test server
		dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret),
	)
	if err == nil {
		conn.Close()
		t.Fatal("handshake without extended master secret succeeded, want failure")
	}
	if !waitForCondition(3*time.Second, func() bool { return srv.Metrics().HandshakeErrs == 1 }) {
		t.Errorf("metrics = %+v, want HandshakeErrs=1", srv.Metrics())
	}
}

// TestDTLSServer_MutualTLS checks client certificate enforcement.
func TestDTLSServer_MutualTLS(t *testing.T) {
	serverCert, serverKey := writeSelfSignedCert(t)
	clientCertFile, clientKeyFile := writeSelfSignedCert(t)
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	srv, q := newTestDTLSServer(t, func(c *DTLSServerConfig) {
		c.CertFile = serverCert
		c.KeyFile = serverKey
		c.RequireClientCert = true
		c.CAFile = clientCertFile // the self-signed client cert is its own CA
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stopWithin(t, srv.Stop, 3*time.Second)

	// Without a client certificate the handshake fails.
	if conn, err := dialDTLSWith(t, srv.listener.Addr(),
		dtls.WithInsecureSkipVerify(true), // throwaway self-signed test server
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	); err == nil {
		conn.Close()
		t.Fatal("handshake without a client certificate succeeded, want failure")
	}

	// With the trusted client certificate it succeeds end to end.
	conn, err := dialDTLSWith(t, srv.listener.Addr(),
		dtls.WithInsecureSkipVerify(true), // throwaway self-signed test server
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCertificates(clientCert),
	)
	if err != nil {
		t.Fatalf("handshake with client certificate: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !waitForCondition(5*time.Second, func() bool {
		ev, _ := q.Pop()
		return ev != nil
	}) {
		t.Fatalf("no event queued; metrics=%+v", srv.Metrics())
	}
}

func TestDefaultDTLSServerConfig(t *testing.T) {
	cfg := DefaultDTLSServerConfig()

	if cfg.Address == "" {
		t.Error("Address should have default value")
	}
	if cfg.Workers <= 0 {
		t.Error("Workers should be positive")
	}
	if cfg.MaxMessageSize <= 0 {
		t.Error("MaxMessageSize should be positive")
	}
	if cfg.ConnectionTimeout <= 0 {
		t.Error("ConnectionTimeout should be positive")
	}
	if cfg.IdleTimeout <= 0 {
		t.Error("IdleTimeout should be positive")
	}
	if cfg.AllowInsecure {
		t.Error("AllowInsecure should be false by default")
	}
}

func TestNewDTLSServer_RequiresCertificate(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	// No cert file configured, AllowInsecure is false

	_, err := NewDTLSServer(cfg, nil, nil, nil, nil, nil)
	if err != ErrDTLSCertRequired {
		t.Errorf("Expected ErrDTLSCertRequired, got %v", err)
	}
}

func TestNewDTLSServer_AllowInsecure(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true

	server, err := NewDTLSServer(cfg, nil, nil, nil, nil, nil)
	if err != nil {
		t.Errorf("AllowInsecure should allow creation without certs: %v", err)
	}
	if server == nil {
		t.Error("Server should not be nil")
	}
}

func TestNewDTLSServer_MutualTLSRequiresCA(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true
	cfg.RequireClientCert = true
	// No CA file configured

	_, err := NewDTLSServer(cfg, nil, nil, nil, nil, nil)
	if err != ErrDTLSClientCertRequired {
		t.Errorf("Expected ErrDTLSClientCertRequired, got %v", err)
	}
}

func TestDTLSServerMetrics(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true

	server, _ := NewDTLSServer(cfg, nil, nil, nil, nil, nil)

	metrics := server.Metrics()

	// Initial metrics should be zero
	if metrics.Connections != 0 {
		t.Errorf("Connections = %d, want 0", metrics.Connections)
	}
	if metrics.Received != 0 {
		t.Errorf("Received = %d, want 0", metrics.Received)
	}
	if metrics.Errors != 0 {
		t.Errorf("Errors = %d, want 0", metrics.Errors)
	}
	if metrics.InsecureWarned {
		t.Error("InsecureWarned should be false until started")
	}
}

func TestDTLSServer_IsSecure(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true

	server, _ := NewDTLSServer(cfg, nil, nil, nil, nil, nil)

	// Before starting, should not be secure
	if server.IsSecure() {
		t.Error("Should not be secure before starting")
	}
}

func TestDTLSServerConfig_Defaults(t *testing.T) {
	cfg := DefaultDTLSServerConfig()

	// Check specific values
	if cfg.Address != ":5516" {
		t.Errorf("Address = %s, want :5516", cfg.Address)
	}
	if cfg.Workers != 8 {
		t.Errorf("Workers = %d, want 8", cfg.Workers)
	}
	if cfg.MaxMessageSize != 65535 {
		t.Errorf("MaxMessageSize = %d, want 65535", cfg.MaxMessageSize)
	}
	if cfg.ConnectionTimeout != 30*time.Second {
		t.Errorf("ConnectionTimeout = %v, want 30s", cfg.ConnectionTimeout)
	}
	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", cfg.IdleTimeout)
	}
}
