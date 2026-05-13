/*
 * pxp_forwarder.c — XDP final-hop forwarder
 *
 * Sits at master_array[3].  Called after firewall, balancer, and profiler
 * when the packet should leave the gateway.
 *
 * For packets already handled by pxp_balancer (fast path), this stage is
 * never reached because bpf_redirect() in the balancer exits XDP
 * processing immediately.
 *
 * For packets that fell through the balancer (e.g. non-TCP/UDP, or the
 * AF_XDP slow path wasn't configured), we return XDP_PASS so the kernel
 * delivers them to the local socket/stack.
 *
 * The balancer's bpf_redirect() is the real forwarding engine.
 * This program is the graceful "end of pipeline" handler.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pxp_constants.h"
#include "pxp_maps.h"

SEC("xdp_forwarder")
int pxp_forwarder(struct xdp_md *ctx)
{
    /*
     * Packets that reach here were not redirected by the balancer.
     * Allow the kernel network stack to handle them (local delivery,
     * ICMP, ARP, etc.).
     */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
