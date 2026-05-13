// backends.go — mock backend servers for simulation tests
//
// Each backend is a plain TCP server that speaks HTTP/1.1 and responds
// with JSON containing its identity so tests can assert which backend
// served the request.  TLS backends use a self-signed cert generated
// at startup.
package sim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
)

// MockBackend wraps an httptest-like server.
type MockBackend struct {
	ID       string
	listener net.Listener
	server   *http.Server
	TLS      bool
}

// BackendAddr returns the backend's "host:port".
func (b *MockBackend) BackendAddr() string {
	return b.listener.Addr().String()
}

// Close shuts the backend down.
func (b *MockBackend) Close() {
	b.server.Close()
}

// StartHTTPBackend spins up a plain-HTTP backend that always replies with
// JSON {"backend": "<id>"}.
func StartHTTPBackend(id string) (*MockBackend, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-ID", id)
		fmt.Fprintf(w, `{"backend":%q,"host":%q,"path":%q}`, id, r.Host, r.URL.Path)
	})
	srv := &http.Server{Handler: mux}
	b := &MockBackend{ID: id, listener: l, server: srv}
	go srv.Serve(l)
	return b, nil
}

// StartTLSBackend spins up an HTTPS backend using a self-signed cert for
// the given hostname.  Returns the backend and the PEM-encoded CA cert
// (which is the self-signed cert itself) so test clients can trust it.
func StartTLSBackend(id, hostname string) (*MockBackend, []byte, error) {
	// Generate ECDSA key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("gen key: %w", err)
	}

	// Self-signed cert.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("key pair: %w", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("tls listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-ID", id)
		fmt.Fprintf(w, `{"backend":%q,"host":%q}`, id, r.Host)
	})
	srv := &http.Server{Handler: mux}
	b := &MockBackend{ID: id, listener: l, server: srv, TLS: true}
	go srv.Serve(l)
	return b, certPEM, nil
}
