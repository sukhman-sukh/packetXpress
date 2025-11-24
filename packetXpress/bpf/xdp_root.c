#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pxp_constants.h"
#include "pxp_maps.h"

SEC("xdp")
int xdp_root(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *role_mode = bpf_map_lookup_elem(&role_array, &key);
    
    // Tail call to Agent (role_mode == 1 or NULL defaults to agent)
    if (!role_mode || *role_mode == ROLE_MODE_AGENT)
    {
        // bpf_printk("Recieved a packet at xdproot Agent");
#pragma clang loop unroll(full)
        for (__u32 i = 0; i < AGENT_ARRAY_SIZE; i++)
        {
            bpf_tail_call(ctx, &agent_array, i);
        }
    }
    // Tail call to Master (role_mode == 0)
    else
    {
        bpf_printk("Recieved a packet at Master");
#pragma clang loop unroll(full)
        for (__u32 i = 0; i < MASTER_ARRAY_SIZE; i++)
        {
            bpf_tail_call(ctx, &master_array, i);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";