package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"boundary-siem/internal/config"
)

// writeTestCert writes a self-signed certificate for 127.0.0.1 and its key
// as PEM files.
func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// E2E round 2 (runI): an environment-only deployment with
// SIEM_CEF_DTLS_ENABLED=true exited with "DTLS requires certificate and
// key", since no variable set them; and SIEM_STORAGE_ENABLED=false still
// connected to ClickHouse.
func TestEnvOnlyDTLSAndStorageOff(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	t.Setenv("SIEM_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("SIEM_API_KEY", testAPIKey)
	t.Setenv("SIEM_STORAGE_ENABLED", "false")
	t.Setenv("SIEM_CEF_UDP_ENABLED", "false")
	t.Setenv("SIEM_CEF_TCP_ENABLED", "false")
	t.Setenv("SIEM_CEF_DTLS_ENABLED", "true")
	t.Setenv("SIEM_CEF_DTLS_ADDRESS", "127.0.0.1:0")
	t.Setenv("SIEM_CEF_DTLS_CERT_FILE", certFile)
	t.Setenv("SIEM_CEF_DTLS_KEY_FILE", keyFile)
	t.Setenv("SIEM_RULES_DIR", filepath.Join(t.TempDir(), "rules"))

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Storage.Enabled {
		t.Fatal("SIEM_STORAGE_ENABLED=false left storage enabled")
	}
	cfg.Correlation.SeedRulesDir = filepath.Join("..", "..", "rules")
	cfg.WebSocket.StatsInterval = 0

	a := startApp(t, cfg, nil)
	if dtls := a.components()["cef_dtls"]; !dtls.Enabled || dtls.Status != "up" {
		t.Errorf("cef_dtls = %+v, want enabled and up", dtls)
	}
	if storage := a.components()["storage"]; storage.Enabled {
		t.Errorf("storage = %+v, want disabled", storage)
	}
}
