package source

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSConfig builds a server TLS configuration from files on disk.
//
// TLS 1.2 is the floor and 1.3 is preferred, which Go negotiates on its own.
// Anything older has known-broken cipher suites, and a log shipper carrying
// authentication events is exactly the traffic not to carry over them.
//
// When clientCAFile is set, client certificates are **required and verified**,
// not merely requested. Optional client auth is the worst of both worlds: it
// looks like mutual TLS in the configuration and authenticates nobody.
//
// # Testing mutual TLS is misleading under TLS 1.3
//
// In TLS 1.3 the client finishes its half of the handshake before the server
// has validated the client certificate, so a client with no certificate sees
// Dial and Handshake succeed, and its first Write succeed into a buffer. The
// rejection arrives as an alert on a later read.
//
// Nothing is wrong: the records never reach the vault. But a test — or an
// operator with a one-line client — that only checks whether the connection
// opened will conclude mutual TLS is not working when it is, or worse,
// conclude it is working when it is not. Check what arrived, not what
// connected.
func TLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("source: tls needs both cert and key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("source: loading the tls key pair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientCAFile == "" {
		return cfg, nil
	}

	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("source: reading the client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		// A CA file that parses to nothing would otherwise produce a
		// listener that rejects every client, which looks like a network
		// problem rather than a configuration one.
		return nil, fmt.Errorf("source: %s contains no PEM certificates", clientCAFile)
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}
