package utils

import (
	"fmt"
	"math/rand"
	"testing"
)

func BenchmarkMaglevBuild(b *testing.B) {
	for _, n := range []int{2, 4, 8, 16, 32, 64, 128, 256} {
		n := n
		b.Run(fmt.Sprintf("Backends%d", n), func(b *testing.B) {
			names := make([]string, n)
			for i := range names {
				names[i] = fmt.Sprintf("be-%d.example", i)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = BuildMaglev(names, 0)
			}
		})
	}
}

func BenchmarkMaglevLookup(b *testing.B) {
	names := make([]string, 32)
	for i := range names {
		names[i] = fmt.Sprintf("be-%d", i)
	}
	m := BuildMaglev(names, 0)
	rng := rand.New(rand.NewSource(42))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Lookup(rng.Uint64())
	}
}

func BenchmarkHash5Tuple(b *testing.B) {
	var sip, dip [4]byte
	sip[0], dip[0] = 10, 10
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Hash5Tuple(sip, 12345, dip, 443, 6)
	}
}
