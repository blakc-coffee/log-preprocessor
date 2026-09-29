package source_test

import (
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
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/frame"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
)

// pki is a throwaway certificate authority for one test.
type pki struct {
	dir     string
	caPEM   string
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	srvCert string
	srvKey  string
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	p := &pki{dir: dir, caCert: caCert, caKey: caKey}
	p.caPEM = filepath.Join(dir, "ca.pem")
	writeTestPEM(t, p.caPEM, "CERTIFICATE", caDER)

	p.srvCert, p.srvKey = p.issue(t, "server", x509.ExtKeyUsageServerAuth,
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	return p
}

// issue signs a leaf certificate and returns the cert and key paths.
func (p *pki) issue(t *testing.T, name string, usage x509.ExtKeyUsage, dns []string, ips []net.IP) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(p.dir, name+".pem")
	keyPath := filepath.Join(p.dir, name+".key")
	writeTestPEM(t, certPath, "CERTIFICATE", der)

	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, keyPath, "PRIVATE KEY", kder)
	return certPath, keyPath
}

func writeTestPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	buf := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
}

// clientTLS builds a client configuration trusting this CA.
func (p *pki) clientTLS(t *testing.T) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	raw, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(raw) {
		t.Fatal("the CA did not parse")
	}
	return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

func startTLS(t *testing.T, cfg *tls.Config) (*source.TCP, *harness) {
	t.Helper()
	src, err := source.NewTCP(source.TCPConfig{
		ID: "syslog-tls", Listen: "127.0.0.1:0", Framing: frame.ModeLF, TLS: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	return src, start(t, src)
}

// TestTLSCarriesRecords is the base case, and it also checks the origin kind:
// a TLS record must be distinguishable from a plaintext one, or lineage cannot
// say how an event arrived.
func TestTLSCarriesRecords(t *testing.T) {
	p := newPKI(t)
	cfg, err := source.TLSConfig(p.srvCert, p.srvKey, "")
	if err != nil {
		t.Fatal(err)
	}
	src, h := startTLS(t, cfg)

	conn, err := tls.Dial("tcp", src.Addr().String(), p.clientTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("<166>over tls\nsecond\n")); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	got := h.waitFor(2)
	if strings.Join(raws(got), ",") != "<166>over tls,second" {
		t.Errorf("got %q", raws(got))
	}
	for _, ev := range got {
		if ev.Origin.Kind != types.OriginTLS {
			t.Errorf("record %d has origin kind %d, want TLS", ev.ID, ev.Origin.Kind)
		}
	}
}

// TestTLSRejectsAnUntrustedServer is really a check on the test's own PKI: if
// a client trusting the wrong CA succeeded, every other assertion here would
// be meaningless.
func TestTLSRejectsAnUntrustedServer(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t)

	cfg, err := source.TLSConfig(p.srvCert, p.srvKey, "")
	if err != nil {
		t.Fatal(err)
	}
	src, _ := startTLS(t, cfg)

	if conn, err := tls.Dial("tcp", src.Addr().String(), other.clientTLS(t)); err == nil {
		conn.Close()
		t.Fatal("a client trusting a different CA completed the handshake")
	}
}

// TestTLSRefusesOldProtocolVersions. TLS 1.1 and below have known-broken
// cipher suites, and a log shipper carrying authentication events is exactly
// the traffic not to carry over them.
func TestTLSRefusesOldProtocolVersions(t *testing.T) {
	p := newPKI(t)
	cfg, err := source.TLSConfig(p.srvCert, p.srvKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion is %x, want TLS 1.2", cfg.MinVersion)
	}
	src, _ := startTLS(t, cfg)

	old := p.clientTLS(t)
	old.MinVersion = tls.VersionTLS10
	old.MaxVersion = tls.VersionTLS11

	if conn, err := tls.Dial("tcp", src.Addr().String(), old); err == nil {
		conn.Close()
		t.Fatal("a TLS 1.1 client was accepted")
	}
}

// TestMutualTLS: with client_ca set, a client certificate is required and
// verified. "Requested but not verified" would look like mutual TLS in the
// config and authenticate nobody.
func TestMutualTLS(t *testing.T) {
	p := newPKI(t)
	clientCert, clientKey := p.issue(t, "client", x509.ExtKeyUsageClientAuth, nil, nil)

	cfg, err := source.TLSConfig(p.srvCert, p.srvKey, p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth is %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	src, h := startTLS(t, cfg)

	t.Run("a client with no certificate is refused", func(t *testing.T) {
		conn, err := tls.Dial("tcp", src.Addr().String(), p.clientTLS(t))
		if err == nil {
			// Depending on the version, the rejection lands on the first
			// write or read rather than in Dial.
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, werr := conn.Write([]byte("should not arrive\n"))
			_, rerr := conn.Read(make([]byte, 1))
			conn.Close()
			if werr == nil && rerr == nil {
				t.Fatal("a client with no certificate was accepted")
			}
		}
	})

	t.Run("a client signed by another CA is refused", func(t *testing.T) {
		other := newPKI(t)
		otherCert, otherKey := other.issue(t, "intruder", x509.ExtKeyUsageClientAuth, nil, nil)
		pair, err := tls.LoadX509KeyPair(otherCert, otherKey)
		if err != nil {
			t.Fatal(err)
		}
		cc := p.clientTLS(t)
		cc.Certificates = []tls.Certificate{pair}

		conn, err := tls.Dial("tcp", src.Addr().String(), cc)
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, werr := conn.Write([]byte("should not arrive\n"))
			_, rerr := conn.Read(make([]byte, 1))
			conn.Close()
			if werr == nil && rerr == nil {
				t.Fatal("a client certificate from an unrelated CA was accepted")
			}
		}
	})

	t.Run("a properly signed client is accepted", func(t *testing.T) {
		pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			t.Fatal(err)
		}
		cc := p.clientTLS(t)
		cc.Certificates = []tls.Certificate{pair}

		conn, err := tls.Dial("tcp", src.Addr().String(), cc)
		if err != nil {
			t.Fatalf("a valid client certificate was rejected: %v", err)
		}
		conn.Write([]byte("mutually authenticated\n"))
		conn.Close()

		got := h.waitFor(1)
		if string(got[len(got)-1].Raw) != "mutually authenticated" {
			t.Errorf("got %q", got[len(got)-1].Raw)
		}
	})
}

func TestTLSConfigValidation(t *testing.T) {
	p := newPKI(t)

	if _, err := source.TLSConfig("", "", ""); err == nil {
		t.Error("a TLS config was built with no cert or key")
	}
	if _, err := source.TLSConfig(p.srvCert, "", ""); err == nil {
		t.Error("a TLS config was built with a cert but no key")
	}
	if _, err := source.TLSConfig("/nonexistent.pem", "/nonexistent.key", ""); err == nil {
		t.Error("a TLS config was built from files that do not exist")
	}

	t.Run("a client CA with no certificates is an error", func(t *testing.T) {
		// Otherwise the listener rejects every client, which looks like a
		// network problem rather than a configuration one.
		empty := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := source.TLSConfig(p.srvCert, p.srvKey, empty); err == nil {
			t.Error("a client CA file containing no PEM certificates was accepted")
		}
	})
}
