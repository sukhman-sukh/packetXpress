
#include "bpf.h"
#include "bpf_helpers.h"

SEC("xdp_balancer")
int pxp_balancer(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";