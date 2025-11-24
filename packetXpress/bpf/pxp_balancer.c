#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pxp_constants.h"
#include "pxp_maps.h"

SEC("xdp_balancer")
int pxp_balancer(struct xdp_md *ctx)
{
    // bpf_printk("Recieved a packet at balancer");
    bpf_tail_call(ctx, &master_array, 2);
    bpf_printk("Tail call to packetprofiler failed!");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";