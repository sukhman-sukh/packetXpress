#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pxp_maps.h"

SEC("xdp_firewall")
int pxp_firewall(struct xdp_md* ctx) {
    // bpf_printk("Recieved a packet at firewall");
    
    bpf_tail_call(ctx, &master_array, 1);
        bpf_printk("Tail call to balancer failed!");
    // if (bpf_tail_call(ctx, &master_array, 1) != 0)
    // {
    // }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";