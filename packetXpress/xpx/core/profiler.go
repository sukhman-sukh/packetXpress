// userspace/profiler.go
package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// pxpEvent layout must match bpf/pxp_structs.h
type pxpEvent struct {
	TsNs    uint64
	SrcIP   uint32
	DstIP   uint32
	Ifindex uint32
	CPU     uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	TcpF    uint8
	TTL     uint8
	Pad     uint8
	ICMPType uint8
	ICMPCode uint8
	_       [6]byte // reserved
}

func StartProfiler(ctx context.Context, eventsMap *ebpf.Map, outPath string) error {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	// caller will close when context done
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	// open file for append
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		// ignore
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		rd.Close()
		return fmt.Errorf("open out file: %w", err)
	}

	log.Printf("profiler: writing events to %s", outPath)

	go func() {
		defer f.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				// closed
				return
			}
			var ev pxpEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("profiler: parse event: %v", err)
				continue
			}

			src := net.IPv4(byte(ev.SrcIP>>24), byte(ev.SrcIP>>16), byte(ev.SrcIP>>8), byte(ev.SrcIP)).String()
			dst := net.IPv4(byte(ev.DstIP>>24), byte(ev.DstIP>>16), byte(ev.DstIP>>8), byte(ev.DstIP)).String()
			ts := time.Unix(0, int64(ev.TsNs)).Format(time.RFC3339Nano)
			line := fmt.Sprintf("%s cpu=%d if=%d proto=%d flags=0x%x ttl=%d %s:%d -> %s:%d icmp=%d/%d\n",
				ts, ev.CPU, ev.Ifindex, ev.Proto, ev.TcpF, ev.TTL,
				src, ev.SrcPort, dst, ev.DstPort, ev.ICMPType, ev.ICMPCode)
			if _, err := f.WriteString(line); err != nil {
				log.Printf("profiler: write log: %v", err)
			}
		}
	}()

	return nil
}
