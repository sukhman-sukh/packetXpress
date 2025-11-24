#include "linux_includes/bpf.h"

struct pxp_packet_event
{
    __u64 timestamp_ns; // 0..7
    __u32 src_ip;       // 8..11  network byte order
    __u32 dst_ip;       // 12..15
    __u32 ifindex;      // 16..19
    __u32 cpu;          // 20..23
    __u16 src_port;     // 24..25 (network byte order for ports)
    __u16 dst_port;     // 26..27
    __u8 protocol;      // 28
    __u8 tcp_flags;     // 29
    __u8 ttl;           // 30
    __u8 pad;           // 31
    __u8 icmp_type;     // 32
    __u8 icmp_code;     // 33
    __u8 _reserved[6];  // 34..39 to round to 40 bytes
};