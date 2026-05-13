// sni.go — TLS ClientHello SNI extractor
//
// Parses the server_name extension (type 0x0000) from a raw TLS ClientHello
// record without decryption.  Works for TLS 1.0–1.3.
//
// Wire format reference:
//   TLS Record (5 bytes): content_type(1) version(2) length(2)
//   Handshake (4 bytes):  type(1) length(3)
//   ClientHello:          client_version(2) random(32) session_id(1+N)
//                         cipher_suites(2+N) compression(1+N) extensions(2+N...)
//   SNI extension:        type=0x0000, list_len(2), name_type(1)=0, name_len(2), name
package sim

import "encoding/binary"

// ParseSNI extracts the server name from the first bytes of a TLS ClientHello.
// Returns "" if the bytes don't look like a ClientHello or no SNI is present.
func ParseSNI(data []byte) string {
	// TLS record header: 5 bytes
	// content_type = 0x16 (handshake)
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	// version: 0x0301 (TLS 1.0 compat) or 0x0303
	if data[1] != 0x03 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return "" // record not fully buffered
	}
	payload := data[5 : 5+recLen]

	// Handshake header: 4 bytes
	if len(payload) < 4 || payload[0] != 0x01 { // 0x01 = ClientHello
		return ""
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+hsLen {
		return ""
	}
	ch := payload[4 : 4+hsLen]

	// ClientHello body
	// client_version(2) + random(32) = 34 bytes minimum before session_id
	if len(ch) < 34 {
		return ""
	}
	pos := 34 // skip client_version + random

	// session_id: 1-byte length + N bytes
	if pos >= len(ch) {
		return ""
	}
	sessionLen := int(ch[pos])
	pos += 1 + sessionLen
	if pos+2 > len(ch) {
		return ""
	}

	// cipher_suites: 2-byte length + N bytes
	csLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(ch) {
		return ""
	}

	// compression_methods: 1-byte length + N bytes
	cmLen := int(ch[pos])
	pos += 1 + cmLen
	if pos+2 > len(ch) {
		return "" // no extensions
	}

	// extensions: 2-byte total length
	extTotal := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(ch) {
		extEnd = len(ch)
	}

	// Walk extensions looking for type 0x0000 (server_name)
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(ch[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(ch[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		extData := ch[pos : pos+extLen]
		pos += extLen

		if extType != 0x0000 { // not server_name
			continue
		}
		// Server name list: 2-byte list_len
		if len(extData) < 2 {
			break
		}
		listLen := int(binary.BigEndian.Uint16(extData[0:2]))
		if len(extData) < 2+listLen {
			break
		}
		listData := extData[2 : 2+listLen]

		// Each entry: name_type(1) + name_len(2) + name
		if len(listData) < 3 {
			break
		}
		if listData[0] != 0x00 { // name_type must be host_name (0)
			break
		}
		nameLen := int(binary.BigEndian.Uint16(listData[1:3]))
		if len(listData) < 3+nameLen {
			break
		}
		return string(listData[3 : 3+nameLen])
	}
	return ""
}

// IsTLSClientHello returns true if buf starts with a TLS ClientHello record.
func IsTLSClientHello(buf []byte) bool {
	return len(buf) >= 3 && buf[0] == 0x16 && buf[1] == 0x03
}
