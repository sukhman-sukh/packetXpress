// maglev.go — Maglev consistent hashing
//
// Based on Google's Maglev paper (NSDI 2016).
// Builds a lookup table of size M (prime) where each backend occupies ~M/N slots.
// Adding/removing a backend reshuffles ≤ 1/N of slots.
package sim

import (
	"encoding/binary"
	"hash/fnv"
	"math"
)

const defaultTableSize = 65537 // smallest prime ≥ 65536

// MaglevTable is an immutable lookup structure mapping slot → backend index.
type MaglevTable struct {
	Table    []int    // slot → backend index (-1 = empty)
	Names    []string // backend names (for rebuilding)
	Size     int
}

// BuildMaglev builds a Maglev table for the given backend names.
// Size must be a prime; if 0 the default (65537) is used.
func BuildMaglev(names []string, size int) *MaglevTable {
	if size == 0 {
		size = defaultTableSize
	}
	if len(names) == 0 {
		return &MaglevTable{Table: make([]int, size), Names: names, Size: size}
	}

	N := len(names)
	M := size

	// For each backend compute offset and skip via two independent hashes.
	offsets := make([]int, N)
	skips := make([]int, N)
	for i, name := range names {
		offsets[i] = int(h1(name) % uint64(M))
		skips[i] = int(h2(name)%uint64(M-1)) + 1
	}

	// Build preference lists: next[i] tracks how far backend i has advanced.
	next := make([]int, N)
	table := make([]int, M)
	for j := range table {
		table[j] = -1
	}

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

// Lookup returns the backend index for a 5-tuple hash value.
func (m *MaglevTable) Lookup(hash uint64) int {
	if m.Size == 0 {
		return -1
	}
	return m.Table[hash%uint64(m.Size)]
}

// Hash5Tuple hashes a 5-tuple (src_ip, src_port, dst_ip, dst_port, proto)
// into a uint64 for Maglev lookups and flow-CT keys.
func Hash5Tuple(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, proto uint8) uint64 {
	h := fnv.New64a()
	h.Write(srcIP[:])
	binary.Write(h, binary.BigEndian, srcPort)
	h.Write(dstIP[:])
	binary.Write(h, binary.BigEndian, dstPort)
	h.Write([]byte{proto})
	return h.Sum64()
}

// --- internal hash helpers ---

func h1(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	h.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	return h.Sum64()
}

func h2(s string) uint64 {
	h := fnv.New64()
	h.Write([]byte(s))
	h.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE})
	return h.Sum64()
}

// isPrime is a helper for tests to verify the table size constraint.
func isPrime(n int) bool {
	if n < 2 {
		return false
	}
	for i := 2; i <= int(math.Sqrt(float64(n))); i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}
