#include "bpf.h"
#include "bpf_helpers.h"
#include "pxp_constants.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, ROLE_MODE_SIZE);
} role_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MASTER_ARRAY_SIZE);
} master_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, AGENT_ARRAY_SIZE);
} agent_array SEC(".maps");

SEC("xdp")
int xdp_root(struct xdp_md *ctx)
{
    __u32 *fd;
    __u32 key = 0;
    __u32 *role_mode = bpf_map_lookup_elem(&role_array, &key);

    // Tail call to Agent
    if (!role_mode || *role_mode == ROLE_MODE_AGENT) {
        #pragma clang loop unroll(full) 
        for (__u32 i = 0; i < AGENT_ARRAY_SIZE; i++) {
            fd = bpf_map_lookup_elem(&agent_array, &i);
            if (fd) {
                bpf_tail_call(ctx, &role_array, *fd);
            }
        }
    }
    // Tail call to Master
    else {
        #pragma clang loop unroll(full) 
        for (__u32 i = 0; i < MASTER_ARRAY_SIZE; i++) {
            fd = bpf_map_lookup_elem(&master_array, &i);
            if (fd) {
                bpf_tail_call(ctx, &role_array, *fd);
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";