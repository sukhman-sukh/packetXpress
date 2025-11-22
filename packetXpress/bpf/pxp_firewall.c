
#include "bpf.h"
#include "bpf_helpers.h"

SEC("xdp_firewall")
int pxp_firewall(struct xdp_md* ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";