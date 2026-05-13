// maglev.go — Maglev consistent hashing for the userspace control plane
//
// Builds the lookup table that the XDP balancer's conntrack entries are
// derived from.  When the table is rebuilt (backend add/remove), userspace
// updates rp_flow_ct by replacing the BPF map atomically.
package utils

import (
	"encoding/binary"
	"hash/fnv"
)

// MaglevTable is an immutable lookup structure: slot → backend index.
type MaglevTable struct {
	Table []int    // length = Size; value = index into the Backends slice
	Names []string // backend IDs used to build this table
	Size  int
}

// BuildMaglev builds a Maglev lookup table for the given backend names.
// size must be prime; pass 0 to use MaglevTableSize (65537).
func BuildMaglev(names []string, size int) *MaglevTable {
	if size == 0 {
		size = MaglevTableSize
	}
	M := size
	N := len(names)

	table := make([]int, M)
	for i := range table {
		table[i] = -1
	}
	if N == 0 {
		return &MaglevTable{Table: table, Names: names, Size: M}
	}

	offsets := make([]int, N)
	skips := make([]int, N)
	for i, name := range names {
		offsets[i] = int(maglevH1(name) % uint64(M))
		skips[i] = int(maglevH2(name)%uint64(M-1)) + 1
	}

	next := make([]int, N)
	filled := 0
	for filled < M {
		for i := 0; i < N; i++ {
			c := (offsets[i] + next[i]*skips[i]) % M
			for table[c] != -1 {
				next[i]++
				c = (offsets[i] + next[i]*skips[i]) % M
			}
			table[c] = i
			next[i]++
			filled++
			if filled == M {
				break
			}
		}
	}
	return &MaglevTable{Table: table, Names: names, Size: M}
}

// Lookup returns the backend index for a given hash value.
func (m *MaglevTable) Lookup(hash uint64) int {
	if m.Size == 0 {
		return -1
	}
	return m.Table[hash%uint64(m.Size)]
}

// Hash5Tuple hashes a 5-tuple into a uint64 for Maglev lookups.
func Hash5Tuple(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, proto uint8) uint64 {
	h := fnv.New64a()
	h.Write(srcIP[:])
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], srcPort)
	h.Write(buf[:])
	h.Write(dstIP[:])
	binary.BigEndian.PutUint16(buf[:], dstPort)
	h.Write(buf[:])
	h.Write([]byte{proto})
	return h.Sum64()
}

func maglevH1(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	h.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	return h.Sum64()
}

func maglevH2(s string) uint64 {
	h := fnv.New64()
	h.Write([]byte(s))
	h.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE})
	return h.Sum64()
}
