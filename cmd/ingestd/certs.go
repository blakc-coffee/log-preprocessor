package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Development certificates.
//
//	ingestd certs --out ./certs
//
// Generates a CA, a server certificate and a client certificate, so TLS
// syslog and mutual TLS can be exercised without anyone having to learn
// openssl's argument order.
//
// # These are for development
//
// They are self-signed, valid for a year, and their private keys are written
// to a directory on this machine. Nothing about that is suitable for
// production, and the generated README says so next to the files rather than
// somewhere an operator has to go looking.

const (
	certValidity = 365 * 24 * time.Hour
	// ECDSA P-256 rather than RSA: far faster handshakes, universally
	// supported by anything speaking TLS 1.2 or later, and it keeps the files
	// small enough to read.
	certCurve = "P-256"
)

func generateCerts(args []string, stdout, stderr io.Writer) int {
	out := "./certs"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out", "-out":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "ingestd certs: --out needs a directory")
				return exitUsage
			}
			out = args[i+1]
			i++
		default:
			fmt.Fprintf(stderr, "ingestd certs: unknown argument %q\n", args[i])
			return exitUsage
		}
	}

	if err := writeDevCerts(out); err != nil {
		fmt.Fprintf(stderr, "ingestd certs: %v\n", err)
		return exitUsage
	}

	fmt.Fprintf(stdout, "wrote development certificates to %s\n", out)
	for _, f := range []string{"ca.pem", "server.pem", "server.key", "client.pem", "client.key"} {
		fmt.Fprintf(stdout, "  %s\n", filepath.Join(out, f))
	}
	fmt.Fprintln(stdout, "\nThese are self-signed development certificates. Do not use them in production.")
	return exitOK
}

// writeDevCerts creates the CA and the two leaf certificates.
func writeDevCerts(dir string) error {
	// 0700: the private keys live here.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	caKey, caDER, caCert, err := newCA()
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "ca.key"), caKey); err != nil {
		return err
	}

	// The server certificate covers loopback by name and by address, because
	// a client dialling 127.0.0.1 verifies against the IP SAN and one
	// dialling localhost against the DNS SAN.
	serverKey, serverDER, err := newLeaf(caCert, caKey, "ulpf-ingestd", false,
		[]string{"localhost", "ingestd"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "server.pem"), "CERTIFICATE", serverDER, 0o644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "server.key"), serverKey); err != nil {
		return err
	}

	clientKey, clientDER, err := newLeaf(caCert, caKey, "ulpf-client", true, nil, nil)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "client.pem"), "CERTIFICATE", clientDER, 0o644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "client.key"), clientKey); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(certsReadme), 0o644)
}

func newCA() (*ecdsa.PrivateKey, []byte, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ULPF development CA", Organization: []string{"ULPF (development)"}},
		NotBefore:             time.Now().Add(-time.Hour), // tolerate a little clock skew
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, der, cert, nil
}

func newLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, client bool, dns []string, ips []net.IP) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}

	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"ULPF (development)"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// newSerial draws a random 128-bit serial. Sequential serials leak how many
// certificates have been issued and collide across independent runs.
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	buf := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if buf == nil {
		return fmt.Errorf("encoding %s", path)
	}
	return os.WriteFile(path, buf, mode)
}

// writeKey writes a private key at 0600. A key file anyone can read is not a
// key.
func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

const certsReadme = `# Development certificates

Generated by ` + "`ingestd certs`" + `. **Self-signed, and for development only.**

| File | What it is |
|---|---|
| ` + "`ca.pem`" + ` | the CA. Give this to clients as their trust root, and to ingestd as ` + "`client_ca`" + ` for mutual TLS |
| ` + "`ca.key`" + ` | the CA private key |
| ` + "`server.pem`" + ` / ` + "`server.key`" + ` | the listener's certificate. SANs: localhost, ingestd, 127.0.0.1, ::1 |
| ` + "`client.pem`" + ` / ` + "`client.key`" + ` | a client certificate, for testing mutual TLS |

ECDSA P-256, valid for one year. Private keys are mode 0600.

    sources:
      - id: syslog-tls
        type: tls
        listen: "127.0.0.1:6514"
        framing: auto
        cert: ./certs/server.pem
        key: ./certs/server.key
        client_ca: ./certs/ca.pem    # optional; enables REQUIRED client certs

Setting ` + "`client_ca`" + ` requires and verifies client certificates. It is not
an "ask nicely" setting: optional client auth looks like mutual TLS in the
config and authenticates nobody.

Test it:

    openssl s_client -connect 127.0.0.1:6514 -CAfile ca.pem \
      -cert client.pem -key client.key
`
