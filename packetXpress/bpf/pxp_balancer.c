/*
 * pxp_balancer.c — XDP L4 reverse proxy fast path
 *
 * Implements the data-plane portion of the L4 DNAT balancer:
 *
 *   Fast path (conntrack hit):
 *     1. Parse Ethernet/IP/TCP-UDP headers
 *     2. Look up rp_flow_ct[5-tuple]
 *     3. On HIT: rewrite dst_ip to backend real_ip, fix checksums, redirect
 *
 *   Slow path (conntrack miss):
 *     4. Redirect to AF_XDP slow-path queue (rp_slowpath XSK map)
 *        Userspace router parses SNI/Host, picks backend via Maglev,
 *        installs conntrack entry, replays the packet.
 *
 *   Checksum update uses RFC 1624 incremental method (Eq. 3):
 *     HC' = ~(~HC + ~m + m')
 *
 *   DNAT is INGRESS-ONLY.  Return traffic (backend → client) goes
 *   directly; the backend node runs an agent BPF (TC egress) that
 *   rewrites src_ip → gateway VIP (not implemented in this file).
 *
 * Map slot: master_array[1]
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "pxp_constants.h"
#include "pxp_maps.h"

/* ── Checksum helpers ────────────────────────────────────────── */

/*
 * csum_fold: fold a 32-bit accumulator into a 16-bit one's complement sum.
 * Required after adding carries from 16-bit chunks.
 */
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

/*
 * csum_update_u32: RFC 1624 Eq.3 incremental IP checksum update.
 *
 *   HC'  = ~( ~HC + ~old + new )
 *
 * Parameters are in network byte order (as stored in the packet).
 * Returns the updated checksum in network byte order.
 */
static __always_inline __u16 csum_update_u32(__u16 old_csum,
                                               __be32 old_val,
                                               __be32 new_val)
{
    __u32 csum = (~old_csum & 0xffff)
               + (~bpf_ntohs((__be16)(old_val >> 16)) & 0xffff)
               + (~bpf_ntohs((__be16)(old_val & 0xffff)) & 0xffff)
               + bpf_ntohs((__be16)(new_val >> 16))
               + bpf_ntohs((__be16)(new_val & 0xffff));
    return csum_fold(csum);
}

/* ── Header parsing ──────────────────────────────────────────── */

struct parsed_pkt {
    struct ethhdr *eth;
    struct iphdr  *ip;
    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
    };
    __u8  proto;
    __u16 src_port;
    __u16 dst_port;
};

static __always_inline int parse_pkt(struct xdp_md *ctx, struct parsed_pkt *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1; /* not IPv4 — pass through */

    /* IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    p->eth  = eth;
    p->ip   = ip;
    p->proto = ip->protocol;

    /* TCP */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        p->tcp      = tcp;
        p->src_port = tcp->source;
        p->dst_port = tcp->dest;
    }
    /* UDP */
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        p->udp      = udp;
        p->src_port = udp->source;
        p->dst_port = udp->dest;
    }
    else {
        return -1; /* not TCP/UDP */
    }
    return 0;
}

/* ── DNAT: rewrite dst_ip and fix checksums ──────────────────── */

static __always_inline void dnat_rewrite(struct parsed_pkt *p,
                                          struct rp_backend *b)
{
    __be32 old_ip = p->ip->daddr;
    __be32 new_ip = b->real_ip;

    /* Update IP checksum (incremental, RFC 1624). */
    p->ip->check = csum_update_u32(p->ip->check, old_ip, new_ip);

    /* Update L4 pseudo-header checksum. */
    if (p->proto == IPPROTO_TCP) {
        p->tcp->check = csum_update_u32(p->tcp->check, old_ip, new_ip);
    } else {
        if (p->udp->check)
            p->udp->check = csum_update_u32(p->udp->check, old_ip, new_ip);
    }

    /* Overwrite dst_ip in the packet. */
    p->ip->daddr = new_ip;

    /* Rewrite destination MAC with the backend's MAC (next-hop or direct). */
    __builtin_memcpy(p->eth->h_dest, b->real_mac, ETH_ALEN);
}

/* ── Main XDP program ────────────────────────────────────────── */

SEC("xdp_balancer")
int pxp_balancer(struct xdp_md *ctx)
{
    struct parsed_pkt pkt = {};
    if (parse_pkt(ctx, &pkt) < 0)
        goto pass_to_profiler; /* non-IP/TCP/UDP: hand off */

    /* Build 5-tuple conntrack key. */
    struct rp_flow_key fk = {
        .src_ip   = pkt.ip->saddr,
        .dst_ip   = pkt.ip->daddr,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port,
        .proto    = pkt.proto,
    };

    /* ── Fast path: conntrack hit ─────────────────────────────── */
    struct rp_ct_val *ct = bpf_map_lookup_elem(&rp_flow_ct, &fk);
    if (ct) {
        ct->last_seen_ns = bpf_ktime_get_ns();

        struct rp_backend *b = bpf_map_lookup_elem(&rp_backends, &ct->backend_idx);
        if (!b)
            goto pass_to_profiler; /* backend vanished, let it fall through */

        dnat_rewrite(&pkt, b);

        /* Redirect out of the egress interface toward the backend. */
        return bpf_redirect(b->ifindex, 0);
    }

    /* ── Slow path: conntrack miss → AF_XDP userspace router ──── */
    __u32 rx_queue = ctx->rx_queue_index;
    int rc = bpf_redirect_map(&rp_slowpath, rx_queue, XDP_PASS);
    if (rc == XDP_REDIRECT)
        return XDP_REDIRECT; /* handed to AF_XDP socket */

    /* AF_XDP not configured (no socket on this queue): fall through. */

pass_to_profiler:
    /* Hand packet to the next stage in the master pipeline. */
    bpf_tail_call(ctx, &master_array, 2); /* 2 = pxp_packet_profiler */
    bpf_printk("pxp_balancer: tail-call to profiler failed");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
