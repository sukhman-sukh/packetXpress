
#include "bpf.h"
#include "bpf_helpers.h"

SEC("xdp_packet_profiler")
int pxp_packet_profiler(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";