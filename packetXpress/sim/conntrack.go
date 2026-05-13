// conntrack.go — LRU flow connection tracking table
//
// Models the BPF LRU_HASH map that maps a 5-tuple to a backend index.
// Simulates exactly what the XDP fast-path does: O(1) lookup.
package sim

import (
	"container/list"
	"net"
	"sync"
)

// FlowKey is the 5-tuple used as the conntrack key (mirrors BPF map key).
type FlowKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
	Proto   uint8
}

// FlowEntry holds the result of a conntrack lookup.
type FlowEntry struct {
	BackendIdx int
	BackendID  string
}

// ConnTrack is a thread-safe LRU map from FlowKey → FlowEntry.
type ConnTrack struct {
	mu       sync.RWMutex
	capacity int
	items    map[FlowKey]*list.Element
	order    *list.List
}

type ctItem struct {
	key   FlowKey
	value FlowEntry
}

func NewConnTrack(capacity int) *ConnTrack {
	if capacity <= 0 {
		capacity = 1 << 20 // 1M default, same as BPF map
	}
	return &ConnTrack{
		capacity: capacity,
		items:    make(map[FlowKey]*list.Element),
		order:    list.New(),
	}
}

// Lookup returns (entry, true) if the flow is tracked.
func (ct *ConnTrack) Lookup(k FlowKey) (FlowEntry, bool) {
	ct.mu.RLock()
	el, ok := ct.items[k]
	ct.mu.RUnlock()
	if !ok {
		return FlowEntry{}, false
	}
	ct.mu.Lock()
	ct.order.MoveToFront(el)
	ct.mu.Unlock()
	return el.Value.(*ctItem).value, true
}

// Insert adds or updates a flow entry, evicting the oldest if at capacity.
func (ct *ConnTrack) Insert(k FlowKey, v FlowEntry) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if el, ok := ct.items[k]; ok {
		el.Value.(*ctItem).value = v
		ct.order.MoveToFront(el)
		return
	}
	if ct.order.Len() >= ct.capacity {
		// Evict LRU (back of list).
		back := ct.order.Back()
		if back != nil {
			ct.order.Remove(back)
			delete(ct.items, back.Value.(*ctItem).key)
		}
	}
	el := ct.order.PushFront(&ctItem{k, v})
	ct.items[k] = el
}

// Delete removes a flow (e.g. on TCP FIN/RST).
func (ct *ConnTrack) Delete(k FlowKey) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if el, ok := ct.items[k]; ok {
		ct.order.Remove(el)
		delete(ct.items, k)
	}
}

// Len returns the current number of tracked flows.
func (ct *ConnTrack) Len() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.items)
}

// MakeFlowKey converts a net.Conn's local/remote addresses to a FlowKey.
// From the client's perspective: src=client, dst=gateway.
func MakeFlowKey(conn net.Conn, proto uint8) FlowKey {
	src := conn.RemoteAddr().(*net.TCPAddr)
	dst := conn.LocalAddr().(*net.TCPAddr)
	var k FlowKey
	copy(k.SrcIP[:], src.IP.To4())
	k.SrcPort = uint16(src.Port)
	copy(k.DstIP[:], dst.IP.To4())
	k.DstPort = uint16(dst.Port)
	k.Proto = proto
	return k
}
