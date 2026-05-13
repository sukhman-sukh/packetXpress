// host.go — HTTP/1.x Host header extractor
//
// Scans the first bytes of a raw TCP payload for the "Host:" header.
// Returns "" if not found (plaintext HTTP not yet buffered, or non-HTTP).
package sim

import (
	"bytes"
	"strings"
)

// ParseHTTPHost extracts the Host header value from a raw HTTP/1.x request.
// Only looks in the first 8 KB to stay bounded.
func ParseHTTPHost(data []byte) string {
	if len(data) > 8192 {
		data = data[:8192]
	}

	// Must start with an HTTP method.
	if !looksLikeHTTP(data) {
		return ""
	}

	// Scan line-by-line for "Host:" (case-insensitive per RFC 7230 §3.2).
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines[1:] { // skip request line
		if len(line) == 0 {
			break // end of headers
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(string(line[:colon]))
		if strings.EqualFold(name, "host") {
			return strings.TrimSpace(string(line[colon+1:]))
		}
	}
	return ""
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}

func looksLikeHTTP(data []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, []byte(m)) {
			return true
		}
	}
	return false
}
