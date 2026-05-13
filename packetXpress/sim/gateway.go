// gateway.go — userspace simulation of the XDP DNAT balancer
//
// Implements the exact same forwarding logic as pxp_balancer.c but in Go,
// so it can be tested without a Linux kernel or root access.
//
// Flow (mirrors XDP data plane):
//  1. New connection arrives.
//  2. Check conntrack (LRU map) — if hit, forward to same backend.
//  3. If miss: peek first bytes → parse SNI (TLS) or Host (HTTP).
//  4. Look up service by hostname.
//  5. Pick backend: Maglev hash on 5-tuple.
//  6. Install conntrack entry.
//  7. "DNAT": open TCP connection to backend, splice bytes bidirectionally.
//  8. On close: remove conntrack entry.
package sim

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// BackendInfo describes a single backend server.
type BackendInfo struct {
	ID      string // unique name for Maglev hashing
	Address string // "host:port"
}

// ServiceConfig maps a hostname → a set of backends with their Maglev table.
type ServiceConfig struct {
	Name     string
	Backends []BackendInfo
	maglev   *MaglevTable
}

// Gateway is the simulated L4 reverse proxy.
type Gateway struct {
	listener net.Listener
	services map[string]*ServiceConfig // hostname (SNI/Host) → service

	ct   *ConnTrack
	mu   sync.RWMutex

	// Observability hooks (set in tests)
	OnRoute func(conn net.Conn, sni string, backend BackendInfo)
}

// NewGateway creates a gateway listening on addr.
func NewGateway(addr string) (*Gateway, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return &Gateway{
		listener: l,
		services: make(map[string]*ServiceConfig),
		ct:       NewConnTrack(1 << 16),
	}, nil
}

// Addr returns the listening address (useful when port 0 was given).
func (g *Gateway) Addr() string {
	return g.listener.Addr().String()
}

// AddService registers a hostname → backends mapping and pre-builds the Maglev table.
func (g *Gateway) AddService(hostname string, backends []BackendInfo) {
	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = b.ID
	}
	g.mu.Lock()
	g.services[hostname] = &ServiceConfig{
		Name:     hostname,
		Backends: backends,
		maglev:   BuildMaglev(names, 65537),
	}
	g.mu.Unlock()
}

// RebuildMaglev rebuilds a service's Maglev table (called when backends change).
func (g *Gateway) RebuildMaglev(hostname string, backends []BackendInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	svc, ok := g.services[hostname]
	if !ok {
		return
	}
	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = b.ID
	}
	svc.Backends = backends
	svc.maglev = BuildMaglev(names, 65537)
}

// Serve accepts connections until the gateway is closed.
func (g *Gateway) Serve() {
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			return // closed
		}
		go g.handleConn(conn)
	}
}

// Close shuts the gateway down.
func (g *Gateway) Close() error {
	return g.listener.Close()
}

// --- connection handling ---

const peekSize = 4096 // bytes to read for protocol detection

func (g *Gateway) handleConn(client net.Conn) {
	defer client.Close()

	// ── Step 1: peek first bytes ──────────────────────────────────────────
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	peek := make([]byte, peekSize)
	n, err := client.Read(peek)
	if err != nil || n == 0 {
		return
	}
	client.SetReadDeadline(time.Time{}) // clear deadline
	peek = peek[:n]

	// ── Step 2: detect protocol and extract hostname ──────────────────────
	var hostname string
	if IsTLSClientHello(peek) {
		hostname = ParseSNI(peek)
	} else {
		hostname = ParseHTTPHost(peek)
	}

	// ── Step 3: look up service ───────────────────────────────────────────
	g.mu.RLock()
	svc, ok := g.services[hostname]
	g.mu.RUnlock()
	if !ok {
		// No matching service — drop (mirrors XDP_DROP on no-route).
		log.Printf("[gw] no service for hostname=%q, dropping", hostname)
		return
	}

	// ── Step 4: conntrack lookup (fast path) ─────────────────────────────
	fk := MakeFlowKey(client, 6) // 6 = TCP
	var backend BackendInfo

	if entry, hit := g.ct.Lookup(fk); hit {
		// Fast path: same backend as before.
		backend = svc.Backends[entry.BackendIdx]
	} else {
		// Slow path: Maglev select.
		h := Hash5Tuple(fk.SrcIP, fk.SrcPort, fk.DstIP, fk.DstPort, fk.Proto)
		idx := svc.maglev.Lookup(h)
		if idx < 0 || idx >= len(svc.Backends) {
			log.Printf("[gw] maglev returned invalid index %d", idx)
			return
		}
		backend = svc.Backends[idx]
		g.ct.Insert(fk, FlowEntry{BackendIdx: idx, BackendID: backend.ID})
	}

	if g.OnRoute != nil {
		g.OnRoute(client, hostname, backend)
	}

	// ── Step 5: DNAT — open TCP to backend ───────────────────────────────
	// This mirrors bpf_redirect_neigh(): rewrite dst to backend, forward.
	upstream, err := net.DialTimeout("tcp", backend.Address, 5*time.Second)
	if err != nil {
		log.Printf("[gw] dial backend %s: %v", backend.Address, err)
		g.ct.Delete(fk)
		return
	}
	defer upstream.Close()

	// Replay the peeked bytes to the backend (they were already consumed from client).
	if _, err := upstream.Write(peek); err != nil {
		return
	}

	// ── Step 6: bidirectional splice ────────────────────────────────────
	// In XDP this happens automatically; here we goroutine-splice.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, client)
		upstream.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		client.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done

	g.ct.Delete(fk)
}
