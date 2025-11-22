
#include "bpf.h"
#include "bpf_helpers.h"

SEC("xdp_forwarder")
int pxp_forwarder(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";