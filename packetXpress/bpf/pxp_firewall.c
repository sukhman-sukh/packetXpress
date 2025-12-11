#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include "pxp_structs.h"
#include "pxp_constants.h"
#include "pxp_maps.h"

SEC("xdp_firewall")
int pxp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ---- Ethernet ---- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* ---- IPv4 ---- */
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u8 proto = iph->protocol;

    /* we store blocked port at key 0 */
    __u32 key = 0;
    __u16 *blocked_port = bpf_map_lookup_elem(&firewall_dport, &key);

    if (!blocked_port)
    {
        bpf_printk("No blocked port configured");
        goto chain;
    }

    bpf_printk("Blocked port configured: %d", *blocked_port);

    /* ---- TCP ---- */
    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;

        __u16 dport_host = bpf_ntohs(tcph->dest); // Convert to host order for comparison
        bpf_printk("TCP packet: dport=%d, blocked=%d", dport_host, *blocked_port);

        if (dport_host == *blocked_port)
        {
            bpf_printk("DROPPED: TCP dport %d", *blocked_port);
            return XDP_DROP;
        }
        goto chain;
    }

    /* ---- UDP ---- */
    if (proto == IPPROTO_UDP)
    {
        struct udphdr *udph = (void *)iph + iph->ihl * 4;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;

        __u16 dport_host = bpf_ntohs(udph->dest); // Convert to host order for comparison
        bpf_printk("UDP packet: dport=%d, blocked=%d", dport_host, *blocked_port);

        if (dport_host == *blocked_port)
        {
            bpf_printk("DROPPED: UDP dport %d", *blocked_port);
            return XDP_DROP;
        }
        goto chain;
    }

chain:
    /* Continue the master pipeline */
    bpf_tail_call(ctx, &master_array, 1);
    bpf_printk("Firewall → Tail call to next stage failed!");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";