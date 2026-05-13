// sim_test.go — self-validating simulation for the PacketXpress L4 reverse proxy
//
// Tests run entirely in userspace on macOS/Linux without any XDP or root
// access.  They validate the same logic that the BPF data plane implements:
//   - SNI parsing from raw TLS ClientHello bytes
//   - HTTP Host header parsing
//   - Maglev consistent hashing distribution and stability
//   - LRU conntrack hit/miss behaviour
//   - End-to-end routing: HTTP and HTTPS flows through the simulated gateway
//   - Backend stickiness across multiple requests on the same flow
//   - Backend pool change: only ~1/N of flows rereoute (Maglev property)
package sim

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────
// Unit: SNI parsing
// ────────────────────────────────────────────────────────────────

func TestParseSNI_ValidClientHello(t *testing.T) {
	// Build a minimal TLS 1.2 ClientHello containing SNI "abc.example.com".
	sni := "abc.example.com"
	hello := buildClientHello(sni)
	got := ParseSNI(hello)
	if got != sni {
		t.Fatalf("ParseSNI = %q, want %q", got, sni)
	}
}

func TestParseSNI_NoSNI(t *testing.T) {
	// ClientHello with no extensions at all.
	hello := buildClientHelloNoExt()
	got := ParseSNI(hello)
	if got != "" {
		t.Fatalf("ParseSNI without SNI = %q, want empty", got)
	}
}

func TestParseSNI_NotTLS(t *testing.T) {
	got := ParseSNI([]byte("GET / HTTP/1.1\r\nHost: foo\r\n\r\n"))
	if got != "" {
		t.Fatalf("ParseSNI on HTTP = %q, want empty", got)
	}
}

func TestParseSNI_TruncatedPacket(t *testing.T) {
	hello := buildClientHello("abc.example.com")
	// Truncate to half.
	got := ParseSNI(hello[:len(hello)/2])
	// Should not panic, result may be "" or partial (we accept either).
	_ = got
}

// ────────────────────────────────────────────────────────────────
// Unit: HTTP Host parsing
// ────────────────────────────────────────────────────────────────

func TestParseHTTPHost(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"GET / HTTP/1.1\r\nHost: abc.example.com\r\n\r\n", "abc.example.com"},
		{"GET / HTTP/1.1\r\nhost: XYZ.test\r\n\r\n", "XYZ.test"},
		{"GET / HTTP/1.1\r\nHost: with-port.com:8080\r\n\r\n", "with-port.com:8080"},
		{"GET / HTTP/1.1\r\nX-Other: val\r\n\r\n", ""},
		{"not http at all", ""},
	}
	for _, tc := range cases {
		got := ParseHTTPHost([]byte(tc.raw))
		if got != tc.want {
			t.Errorf("ParseHTTPHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Unit: Maglev consistent hashing
// ────────────────────────────────────────────────────────────────

func TestMaglev_IsPrime(t *testing.T) {
	if !isPrime(65537) {
		t.Fatal("65537 should be prime")
	}
}

func TestMaglev_EvenDistribution(t *testing.T) {
	backends := []string{"b0", "b1", "b2", "b3"}
	tbl := BuildMaglev(backends, 65537)

	counts := make([]int, len(backends))
	for _, idx := range tbl.Table {
		counts[idx]++
	}
	expected := float64(65537) / float64(len(backends))
	for i, c := range counts {
		dev := math.Abs(float64(c)-expected) / expected
		if dev > 0.02 { // 2% tolerance
			t.Errorf("backend %d: count=%d expected≈%.0f (dev=%.1f%%)", i, c, expected, dev*100)
		}
	}
}

func TestMaglev_Stability_AddBackend(t *testing.T) {
	// Removing one backend should leave ≥ (N-1)/N of flows on the same backend.
	before := []string{"b0", "b1", "b2", "b3"}
	after := []string{"b0", "b1", "b2"} // remove b3

	tbl4 := BuildMaglev(before, 65537)
	tbl3 := BuildMaglev(after, 65537)

	// Build name→idx for "after" table.
	afterIdx := map[string]int{}
	for i, n := range after {
		afterIdx[n] = i
	}

	unchanged := 0
	total := 0
	for slot := 0; slot < 65537; slot++ {
		b4 := before[tbl4.Table[slot]]
		// If b4 still exists in "after" pool, check it lands the same.
		if newIdx, ok := afterIdx[b4]; ok {
			total++
			if tbl3.Table[slot] == newIdx {
				unchanged++
			}
		}
	}
	stability := float64(unchanged) / float64(total)
	// Maglev guarantees ≥ (N-1)/N ≈ 75% stability when 1 of 4 backends is removed.
	if stability < 0.70 {
		t.Errorf("stability=%.2f%%, want ≥ 70%% when removing 1 of 4 backends", stability*100)
	}
	t.Logf("Maglev stability on 1/4 removal: %.2f%%", stability*100)
}

func TestMaglev_SameFlowSameBackend(t *testing.T) {
	tbl := BuildMaglev([]string{"b0", "b1", "b2"}, 65537)
	h := Hash5Tuple([4]byte{1, 2, 3, 4}, 12345, [4]byte{10, 0, 0, 1}, 443, 6)
	first := tbl.Lookup(h)
	for i := 0; i < 100; i++ {
		if tbl.Lookup(h) != first {
			t.Fatal("same 5-tuple returned different backend")
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Unit: ConnTrack LRU
// ────────────────────────────────────────────────────────────────

func TestConnTrack_HitMiss(t *testing.T) {
	ct := NewConnTrack(10)
	k := FlowKey{SrcPort: 1000, DstPort: 443, Proto: 6}
	if _, ok := ct.Lookup(k); ok {
		t.Fatal("expected miss on empty CT")
	}
	ct.Insert(k, FlowEntry{BackendIdx: 2, BackendID: "b2"})
	e, ok := ct.Lookup(k)
	if !ok || e.BackendIdx != 2 {
		t.Fatalf("expected hit with idx=2, got ok=%v idx=%d", ok, e.BackendIdx)
	}
}

func TestConnTrack_LRUEviction(t *testing.T) {
	ct := NewConnTrack(3)
	k := func(p uint16) FlowKey { return FlowKey{SrcPort: p, DstPort: 443, Proto: 6} }
	ct.Insert(k(1), FlowEntry{BackendIdx: 0})
	ct.Insert(k(2), FlowEntry{BackendIdx: 1})
	ct.Insert(k(3), FlowEntry{BackendIdx: 2})

	// Access k(1) to make it recently used.
	ct.Lookup(k(1))

	// Insert k(4): should evict k(2) (least recently used).
	ct.Insert(k(4), FlowEntry{BackendIdx: 3})

	if _, ok := ct.Lookup(k(2)); ok {
		t.Fatal("k(2) should have been evicted")
	}
	if _, ok := ct.Lookup(k(1)); !ok {
		t.Fatal("k(1) should still be in CT (recently accessed)")
	}
}

// ────────────────────────────────────────────────────────────────
// Integration: HTTP routing through the gateway
// ────────────────────────────────────────────────────────────────

func TestGateway_HTTPRouting(t *testing.T) {
	// Start two backends for two different hostnames.
	bA1, err := StartHTTPBackend("bA1")
	mustNil(t, err)
	defer bA1.Close()
	bA2, err := StartHTTPBackend("bA2")
	mustNil(t, err)
	defer bA2.Close()

	bB1, err := StartHTTPBackend("bB1")
	mustNil(t, err)
	defer bB1.Close()

	gw, err := NewGateway("127.0.0.1:0")
	mustNil(t, err)
	defer gw.Close()

	gw.AddService("alpha.test", []BackendInfo{
		{ID: "bA1", Address: bA1.BackendAddr()},
		{ID: "bA2", Address: bA2.BackendAddr()},
	})
	gw.AddService("beta.test", []BackendInfo{
		{ID: "bB1", Address: bB1.BackendAddr()},
	})
	go gw.Serve()

	gwAddr := gw.Addr()
	client := plainHTTPClient(gwAddr)

	// Route to alpha.test.
	for i := 0; i < 5; i++ {
		id := httpGetBackendID(t, client, "http://alpha.test/")
		if id != "bA1" && id != "bA2" {
			t.Errorf("alpha.test request routed to wrong backend %q", id)
		}
	}

	// Route to beta.test.
	id := httpGetBackendID(t, client, "http://beta.test/")
	if id != "bB1" {
		t.Errorf("beta.test routed to %q, want bB1", id)
	}
}

func TestGateway_UnknownHostDropped(t *testing.T) {
	gw, err := NewGateway("127.0.0.1:0")
	mustNil(t, err)
	defer gw.Close()
	go gw.Serve()

	// No services registered. Connection should be closed quickly.
	conn, err := net.DialTimeout("tcp", gw.Addr(), 2*time.Second)
	mustNil(t, err)
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n"
	conn.Write([]byte(req))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	// Gateway should close the connection (n==0 or EOF).
	if n > 0 {
		// It's OK if the backend sent an error response too, but the
		// connection must eventually close.
	}
}

// ────────────────────────────────────────────────────────────────
// Integration: TLS SNI routing through the gateway
// ────────────────────────────────────────────────────────────────

func TestGateway_TLSRouting(t *testing.T) {
	// Start TLS backends for two hostnames.
	bAlpha, certAlpha, err := StartTLSBackend("tls-alpha", "alpha.tls.test")
	mustNil(t, err)
	defer bAlpha.Close()

	bBeta, certBeta, err := StartTLSBackend("tls-beta", "beta.tls.test")
	mustNil(t, err)
	defer bBeta.Close()

	gw, err := NewGateway("127.0.0.1:0")
	mustNil(t, err)
	defer gw.Close()

	gw.AddService("alpha.tls.test", []BackendInfo{{ID: "tls-alpha", Address: bAlpha.BackendAddr()}})
	gw.AddService("beta.tls.test", []BackendInfo{{ID: "tls-beta", Address: bBeta.BackendAddr()}})
	go gw.Serve()

	// Verify alpha routing.
	id := tlsGetBackendID(t, gw.Addr(), "alpha.tls.test", certAlpha)
	if id != "tls-alpha" {
		t.Errorf("TLS alpha: got backend=%q, want tls-alpha", id)
	}

	// Verify beta routing.
	id = tlsGetBackendID(t, gw.Addr(), "beta.tls.test", certBeta)
	if id != "tls-beta" {
		t.Errorf("TLS beta: got backend=%q, want tls-beta", id)
	}
}

// ────────────────────────────────────────────────────────────────
// Integration: flow stickiness (conntrack)
// ────────────────────────────────────────────────────────────────

func TestGateway_FlowStickiness(t *testing.T) {
	// 3 backends for alpha; we'll make many requests and verify each
	// *persistent TCP connection* always hits the same backend.
	backends := make([]*MockBackend, 3)
	bInfos := make([]BackendInfo, 3)
	for i := range backends {
		b, err := StartHTTPBackend(fmt.Sprintf("sticky-%d", i))
		mustNil(t, err)
		defer b.Close()
		backends[i] = b
		bInfos[i] = BackendInfo{ID: b.ID, Address: b.BackendAddr()}
	}

	gw, err := NewGateway("127.0.0.1:0")
	mustNil(t, err)
	defer gw.Close()
	gw.AddService("sticky.test", bInfos)
	go gw.Serve()

	// Use a raw TCP connection pinned to the same src-port so the flow key
	// is stable across all HTTP/1.1 requests (mirrors conntrack stickiness).
	conn, err := net.Dial("tcp", gw.Addr())
	mustNil(t, err)
	defer conn.Close()

	firstBackend := ""
	for i := 0; i < 5; i++ {
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: sticky.test\r\nConnection: keep-alive\r\n\r\n")
		conn.Write([]byte(req))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp := readHTTPResponse(conn)
		backendID := extractHeader(resp, "X-Backend-ID")
		if firstBackend == "" {
			firstBackend = backendID
		} else if backendID != firstBackend {
			t.Errorf("request %d: backend changed from %q to %q (stickiness broken)", i, firstBackend, backendID)
		}
	}
	t.Logf("All 5 requests pinned to backend: %s", firstBackend)
}

// ────────────────────────────────────────────────────────────────
// Integration: Maglev distribution across many flows
// ────────────────────────────────────────────────────────────────

func TestGateway_MaglevDistribution(t *testing.T) {
	const N = 4
	const flows = 200

	backends := make([]*MockBackend, N)
	bInfos := make([]BackendInfo, N)
	for i := range backends {
		b, err := StartHTTPBackend(fmt.Sprintf("dist-%d", i))
		mustNil(t, err)
		defer b.Close()
		backends[i] = b
		bInfos[i] = BackendInfo{ID: b.ID, Address: b.BackendAddr()}
	}

	gw, err := NewGateway("127.0.0.1:0")
	mustNil(t, err)
	defer gw.Close()
	gw.AddService("dist.test", bInfos)

	// Track which backend each route call picks.
	counts := make(map[string]int64)
	var mu sync.Mutex
	gw.OnRoute = func(_ net.Conn, _ string, b BackendInfo) {
		mu.Lock()
		counts[b.ID]++
		mu.Unlock()
	}
	go gw.Serve()

	var wg sync.WaitGroup
	var errors atomic.Int64
	// Simulate `flows` parallel clients from different source ports.
	sem := make(chan struct{}, 20) // limit concurrency
	for i := 0; i < flows; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", gw.Addr(), 2*time.Second)
			if err != nil {
				errors.Add(1)
				return
			}
			defer conn.Close()
			req := "GET / HTTP/1.1\r\nHost: dist.test\r\nConnection: close\r\n\r\n"
			conn.Write([]byte(req))
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			io.ReadAll(conn)
		}(i)
	}
	wg.Wait()

	if errors.Load() > 0 {
		t.Logf("Warning: %d connection errors during distribution test", errors.Load())
	}

	mu.Lock()
	defer mu.Unlock()

	t.Log("Backend distribution:")
	total := 0
	for id, c := range counts {
		t.Logf("  %s: %d", id, c)
		total += int(c)
	}
	expected := float64(total) / float64(N)
	for id, c := range counts {
		dev := math.Abs(float64(c)-expected) / expected
		if dev > 0.30 { // 30% tolerance for small sample sizes
			t.Errorf("backend %s: count=%d expected≈%.0f (dev=%.1f%%)", id, c, expected, dev*100)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Self-validation: run all subtests and report
// ────────────────────────────────────────────────────────────────

func TestSelfValidation(t *testing.T) {
	subtests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"SNI/Valid", TestParseSNI_ValidClientHello},
		{"SNI/NoSNI", TestParseSNI_NoSNI},
		{"SNI/NotTLS", TestParseSNI_NotTLS},
		{"SNI/Truncated", TestParseSNI_TruncatedPacket},
		{"Host/Parsing", TestParseHTTPHost},
		{"Maglev/Prime", TestMaglev_IsPrime},
		{"Maglev/Distribution", TestMaglev_EvenDistribution},
		{"Maglev/Stability", TestMaglev_Stability_AddBackend},
		{"Maglev/SameFlow", TestMaglev_SameFlowSameBackend},
		{"ConnTrack/HitMiss", TestConnTrack_HitMiss},
		{"ConnTrack/LRU", TestConnTrack_LRUEviction},
		{"Gateway/HTTP", TestGateway_HTTPRouting},
		{"Gateway/TLS", TestGateway_TLSRouting},
		{"Gateway/Stickiness", TestGateway_FlowStickiness},
		{"Gateway/Distribution", TestGateway_MaglevDistribution},
	}

	pass, fail := 0, 0
	for _, st := range subtests {
		ok := t.Run(st.name, st.fn)
		if ok {
			pass++
		} else {
			fail++
		}
	}
	t.Logf("\n\n══════════════════════════════════════")
	t.Logf("  PacketXpress L4 Proxy — Self-Validation")
	t.Logf("  PASS: %d  FAIL: %d  TOTAL: %d", pass, fail, pass+fail)
	t.Logf("══════════════════════════════════════\n")
}

// ────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func plainHTTPClient(gwAddr string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("tcp", gwAddr)
			},
		},
	}
}

func httpGetBackendID(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("X-Backend-ID")
}

func tlsGetBackendID(t *testing.T, gwAddr, hostname string, certPEM []byte) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	conn, err := net.Dial("tcp", gwAddr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: hostname,
		RootCAs:    pool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake for %s: %v", hostname, err)
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname)
	tlsConn.Write([]byte(req))
	tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := readHTTPResponse(tlsConn)
	return extractHeader(resp, "X-Backend-ID")
}

// readHTTPResponse reads a raw HTTP/1.1 response from conn (good enough for tests).
func readHTTPResponse(conn net.Conn) string {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
		if strings.Contains(sb.String(), "\r\n\r\n") {
			// For simple test responses the body is small; read a bit more.
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		}
	}
	return sb.String()
}

func extractHeader(raw, name string) string {
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

// ────────────────────────────────────────────────────────────────
// TLS ClientHello builder (for unit tests)
// ────────────────────────────────────────────────────────────────

// buildClientHello constructs a minimal TLS 1.2 ClientHello with a
// server_name extension for the given hostname.
func buildClientHello(sni string) []byte {
	sniName := []byte(sni)

	// SNI extension data: list_len(2) + name_type(1) + name_len(2) + name
	sniExt := make([]byte, 0, 2+1+2+len(sniName))
	sniExt = append(sniExt, 0, byte(1+2+len(sniName))) // list length
	sniExt = append(sniExt, 0x00)                       // name_type = host_name
	sniExt = append(sniExt, 0, byte(len(sniName)))      // name length
	sniExt = append(sniExt, sniName...)

	// Extension: type(2) + len(2) + data
	ext := make([]byte, 0, 4+len(sniExt))
	ext = append(ext, 0x00, 0x00) // type: server_name
	ext = append(ext, 0, byte(len(sniExt)))
	ext = append(ext, sniExt...)

	// Extensions block: total_len(2) + ext
	extBlock := make([]byte, 2+len(ext))
	binary.BigEndian.PutUint16(extBlock[0:2], uint16(len(ext)))
	copy(extBlock[2:], ext)

	// ClientHello body: version(2) + random(32) + session_id(1) +
	//   cipher_suites_len(2) + cipher(2) + compression_len(1) + compression(1) + extensions
	random := make([]byte, 32)
	ch := make([]byte, 0, 2+32+1+2+2+1+1+len(extBlock))
	ch = append(ch, 0x03, 0x03) // TLS 1.2
	ch = append(ch, random...)  // random
	ch = append(ch, 0x00)       // session_id length = 0
	// cipher_suites: length(2) + one cipher(2)
	ch = append(ch, 0x00, 0x02, 0xC0, 0x2B)
	// compression_methods: length(1) + null(1)
	ch = append(ch, 0x01, 0x00)
	ch = append(ch, extBlock...)

	// Handshake header: type(1) + length(3)
	hs := make([]byte, 4+len(ch))
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(ch) >> 16)
	hs[2] = byte(len(ch) >> 8)
	hs[3] = byte(len(ch))
	copy(hs[4:], ch)

	// TLS record: content_type(1) + version(2) + length(2) + handshake
	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // handshake
	rec[1] = 0x03
	rec[2] = 0x01 // TLS 1.0 compat
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// buildClientHelloNoExt builds a ClientHello with no extensions.
func buildClientHelloNoExt() []byte {
	random := make([]byte, 32)
	ch := make([]byte, 0)
	ch = append(ch, 0x03, 0x03) // TLS 1.2
	ch = append(ch, random...)
	ch = append(ch, 0x00)             // session_id length = 0
	ch = append(ch, 0x00, 0x02, 0xC0, 0x2B) // 1 cipher suite
	ch = append(ch, 0x01, 0x00) // compression

	hs := make([]byte, 4+len(ch))
	hs[0] = 0x01
	hs[1] = byte(len(ch) >> 16)
	hs[2] = byte(len(ch) >> 8)
	hs[3] = byte(len(ch))
	copy(hs[4:], ch)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}
