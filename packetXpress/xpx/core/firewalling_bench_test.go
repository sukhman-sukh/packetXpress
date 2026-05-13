package core

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"testing"

	"packetXpress/utils"
)

// fwTuple is a synthetic 5-tuple in host byte order for uint32 ports/proto.
type fwTuple struct {
	srcIP, dstIP   uint32
	srcPort, dstPort uint32
	proto          uint32
	forwardChain   bool // false = INPUT, true = FORWARD
}

// --- iptables-like: ordered linear scan, first full match wins ---

func linearFirstMatch(rules []utils.FwRule, t fwTuple) (matched bool, ruleIdx int, action uint32) {
	chain := "INPUT"
	if t.forwardChain {
		chain = "FORWARD"
	}
	for i := range rules {
		r := &rules[i]
		if r.Chain != chain {
			continue
		}
		if !fieldMatch(r.SrcIP, t.srcIP) {
			continue
		}
		if !fieldMatch(r.DstIP, t.dstIP) {
			continue
		}
		if r.SrcPort != 0 && r.SrcPort != t.srcPort {
			continue
		}
		if r.DstPort != 0 && r.DstPort != t.dstPort {
			continue
		}
		if r.Protocol != 0 && r.Protocol != t.proto {
			continue
		}
		return true, i, actionStringToUint(r.Action)
	}
	return false, -1, utils.FwActionAccept
}

func fieldMatch(ipStr string, pkt uint32) bool {
	v := ipToUint32(ipStr)
	if v == 0 {
		return true
	}
	return v == pkt
}

// --- BPF-style multi-level trie on destination IPv4 (4 x 8-bit levels).
// Each leaf keeps rule indices in priority order; classify walks the trie then scans the leaf.

type dstOctTrie struct {
	root *dstOctNode
}

type dstOctNode struct {
	child [256]*dstOctNode
	rules []int
}

func newDstOctTrie() *dstOctTrie {
	return &dstOctTrie{root: &dstOctNode{}}
}

func (tr *dstOctTrie) insert(ruleIdx int, dstIP uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], dstIP)
	n := tr.root
	for i := 0; i < 4; i++ {
		c := b[i]
		if n.child[c] == nil {
			n.child[c] = &dstOctNode{}
		}
		n = n.child[c]
	}
	n.rules = append(n.rules, ruleIdx)
}

func (tr *dstOctTrie) classify(rules []utils.FwRule, t fwTuple) (matched bool, ruleIdx int, action uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], t.dstIP)
	n := tr.root
	for i := 0; i < 4; i++ {
		c := b[i]
		if n.child[c] == nil {
			return linearFirstMatch(rules, t)
		}
		n = n.child[c]
	}
	chain := "INPUT"
	if t.forwardChain {
		chain = "FORWARD"
	}
	for _, ri := range n.rules {
		r := &rules[ri]
		if r.Chain != chain {
			continue
		}
		if !fieldMatch(r.SrcIP, t.srcIP) {
			continue
		}
		if !fieldMatch(r.DstIP, t.dstIP) {
			continue
		}
		if r.SrcPort != 0 && r.SrcPort != t.srcPort {
			continue
		}
		if r.DstPort != 0 && r.DstPort != t.dstPort {
			continue
		}
		if r.Protocol != 0 && r.Protocol != t.proto {
			continue
		}
		return true, ri, actionStringToUint(r.Action)
	}
	return false, -1, utils.FwActionAccept
}

// --- LBVS hot path (mirrors pxp_firewall.c bitvector AND + first-set-bit) ---

func lbvsClassify(d *lbvsData, t fwTuple) (matched bool, ruleIdx int, action uint32) {
	chain := uint32(utils.FwChainInput)
	if t.forwardChain {
		chain = uint32(utils.FwChainForward)
	}
	chainMask := d.chainMask[chain]
	if chainMask == 0 {
		return false, -1, utils.FwActionAccept
	}

	result := uint64(0xffffffffffffffff)

	andField := func(bv *uint64, has bool, wildIdx int) bool {
		if has {
			result &= *bv
		} else {
			w := d.wildcardBV[wildIdx]
			if w == 0 {
				result = 0
			} else {
				result &= w
			}
		}
		return result != 0
	}

	bv, ok := d.srcIPBV[t.srcIP]
	if !andField(&bv, ok, 0) {
		return false, -1, utils.FwActionAccept
	}
	bv, ok = d.dstIPBV[t.dstIP]
	if !andField(&bv, ok, 1) {
		return false, -1, utils.FwActionAccept
	}
	bv, ok = d.srcPortBV[t.srcPort]
	if !andField(&bv, ok, 2) {
		return false, -1, utils.FwActionAccept
	}
	bv, ok = d.dstPortBV[t.dstPort]
	if !andField(&bv, ok, 3) {
		return false, -1, utils.FwActionAccept
	}
	bv, ok = d.protoBV[t.proto]
	if !andField(&bv, ok, 4) {
		return false, -1, utils.FwActionAccept
	}

	result &= chainMask
	if result == 0 {
		return false, -1, utils.FwActionAccept
	}
	ri := bits.TrailingZeros64(result)
	if ri >= len(d.actions) {
		return false, -1, utils.FwActionAccept
	}
	return true, ri, d.actions[ri]
}

// genRulesLastWins builds n FORWARD rules with distinct dst IPs; only the last rule matches pkt.
func genRulesLastWins(n int) ([]utils.FwRule, fwTuple) {
	if n < 1 || n > utils.FwMaxRules {
		panic(fmt.Sprintf("n out of range: %d", n))
	}
	rules := make([]utils.FwRule, n)
	for i := 0; i < n; i++ {
		dst := fmt.Sprintf("10.0.0.%d", i+1)
		sp := uint32(5000 + i)
		dp := uint32(80)
		if i == n-1 {
			dp = 443
		}
		rules[i] = utils.FwRule{
			ID: i + 1, Chain: "FORWARD",
			SrcIP: "192.168.1.1", DstIP: dst,
			SrcPort: sp, DstPort: dp,
			Protocol: 6, Action: "accept",
		}
	}
	last := rules[n-1]
	pkt := fwTuple{
		srcIP:        ipToUint32(last.SrcIP),
		dstIP:        ipToUint32(last.DstIP),
		srcPort:      last.SrcPort,
		dstPort:      last.DstPort,
		proto:        last.Protocol,
		forwardChain: true,
	}
	return rules, pkt
}

func TestFirewallBenchModelsAgree(t *testing.T) {
	for _, n := range []int{1, 3, 16, 64} {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			rules, pkt := genRulesLastWins(n)
			lm, li, la := linearFirstMatch(rules, pkt)
			tr := newDstOctTrie()
			for i := range rules {
				tr.insert(i, ipToUint32(rules[i].DstIP))
			}
			tm, ti, ta := tr.classify(rules, pkt)
			d := computeLBVS(rules)
			bm, bi, ba := lbvsClassify(d, pkt)
			if !lm || !tm || !bm || li != n-1 || ti != n-1 || bi != n-1 {
				t.Fatalf("linear=%v@%d trie=%v@%d lbvs=%v@%d", lm, li, tm, ti, bm, bi)
			}
			if la != ta || la != ba {
				t.Fatalf("action mismatch %d %d %d", la, ta, ba)
			}
		})
	}
}

func BenchmarkFW_Linear_LastMatch(b *testing.B) {
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64} {
		n := n
		b.Run(fmt.Sprintf("Rules%d", n), func(b *testing.B) {
			rules, pkt := genRulesLastWins(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				linearFirstMatch(rules, pkt)
			}
		})
	}
}

func BenchmarkFW_TrieOct_LastMatch(b *testing.B) {
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64} {
		n := n
		b.Run(fmt.Sprintf("Rules%d", n), func(b *testing.B) {
			rules, pkt := genRulesLastWins(n)
			tr := newDstOctTrie()
			for i := range rules {
				tr.insert(i, ipToUint32(rules[i].DstIP))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tr.classify(rules, pkt)
			}
		})
	}
}

func BenchmarkFW_LBVS_LastMatch(b *testing.B) {
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64} {
		n := n
		b.Run(fmt.Sprintf("Rules%d", n), func(b *testing.B) {
			rules, pkt := genRulesLastWins(n)
			d := computeLBVS(rules)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lbvsClassify(d, pkt)
			}
		})
	}
}

func BenchmarkFW_LBVS_Rebuild(b *testing.B) {
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64} {
		n := n
		b.Run(fmt.Sprintf("Rules%d", n), func(b *testing.B) {
			rules, _ := genRulesLastWins(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = computeLBVS(rules)
			}
		})
	}
}
