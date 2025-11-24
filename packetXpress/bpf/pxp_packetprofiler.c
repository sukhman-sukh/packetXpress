// bpf/packet_profiler.c
#include <linux/bpf.h> // must be first
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

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB ring buffer */
} events SEC(".maps");

static __always_inline int handle_ipv4(void *data, void *data_end, __u32 cpu, __u32 ifindex)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    struct pxp_packet_event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.src_ip = iph->saddr;
    ev.dst_ip = iph->daddr;
    ev.protocol = iph->protocol;
    ev.ifindex = ifindex;
    ev.cpu = cpu;
    ev.ttl = iph->ttl;

    void *l4 = (void *)iph + iph->ihl * 4;
    if (l4 > data_end)
        return -1;

    if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return -1;
        ev.src_port = bpf_ntohs(uh->source);
        ev.dst_port = bpf_ntohs(uh->dest);
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return -1;
        ev.src_port = bpf_ntohs(th->source);
        ev.dst_port = bpf_ntohs(th->dest);

        /* Read full TCP flags byte (safe) */
        __u8 flags = 0;
        if ((void *)th + 14 <= data_end)
        {
            flags = *(__u8 *)((void *)th + 13); /* offset 13 contains flags */
        }
        ev.tcp_flags = flags;
    }
    else if (iph->protocol == IPPROTO_ICMP)
    {
        struct icmphdr *icmph = l4;
        if ((void *)(icmph + 1) > data_end)
            return -1;
        ev.icmp_type = icmph->type;
        ev.icmp_code = icmph->code;
    }

    /* small debug — keep small in production */
    bpf_printk("pxp %x:%d -> %x:%d proto=%d cpu=%d if=%d",
               ev.src_ip, ev.src_port,
               ev.dst_ip, ev.dst_port,
               ev.protocol, ev.cpu, ev.ifindex);

    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
    return 0;
}

SEC("xdp_packet_profiler")
int pxp_packet_profiler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 ifindex = ctx->ingress_ifindex;
    // bpf_printk("Recieved a packet at %d", cpu);
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    handle_ipv4(data, data_end, cpu, ifindex);

    bpf_tail_call(ctx, &master_array, 3);
    // bpf_printk("Tail call to forwarder failed!");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
