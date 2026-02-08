/*
 * pxp_firewall.c — LBVS-based XDP firewall
 *
 * Implements the Linear Bit-Vector Search (LBVS) classification algorithm
 * from "Securing Linux with a Faster and Scalable Iptables" (Miano et al.)
 *
 * Supports:
 *   - INPUT chain  : DROP / ACCEPT for packets destined to local host
 *   - FORWARD chain: DROP / ACCEPT / FORWARD (redirect) for transit packets
 *   - 5-tuple matching: src_ip, dst_ip, src_port, dst_port, protocol
 *   - Max 64 rules (bitvector = single uint64)
 *   - Wildcard (any) per field
 *   - Early-break when bitvector becomes 0
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include "pxp_constants.h"
#include "pxp_maps.h"


#define MAX_RULES        64

#define FW_ACTION_DROP    0
#define FW_ACTION_ACCEPT  1
#define FW_ACTION_FORWARD 2

#define FW_CHAIN_INPUT    0
#define FW_CHAIN_FORWARD  1

#define FW_FIELD_SRC_IP   0
#define FW_FIELD_DST_IP   1
#define FW_FIELD_SRC_PORT 2
#define FW_FIELD_DST_PORT 3
#define FW_FIELD_PROTO    4


struct fw_fwd_params {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
};

/*
 * Per-field bitvector hash maps.
 * Key  : field value (__u32, network-order for IPs, host-order for ports)
 * Value: bitvector (__u64) — bit i set means rule i could match this value
 *
 * Userspace pre-computes these from the ruleset.  Each entry already
 * includes the wildcard-rule bits (rules with "any" for this field).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_src_ip_bv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_dst_ip_bv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_src_port_bv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_dst_port_bv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_proto_bv SEC(".maps");

/*
 * Wildcard bitvectors — one per field (5 entries).
 * Index 0=src_ip, 1=dst_ip, 2=src_port, 3=dst_port, 4=proto
 * Bit i set means rule i has wildcard ("any") for this field.
 * Used as fallback when a packet value is NOT in the hash map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_wildcard_bv SEC(".maps");

/* Per-rule action: rule index → action (DROP=0, ACCEPT=1, FORWARD=2) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_actions SEC(".maps");

/* Chain mask bitvectors: index 0=INPUT mask, 1=FORWARD mask */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_chain_mask SEC(".maps");

/* Default action per chain: 0=INPUT, 1=FORWARD → action */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_default_action SEC(".maps");

/*
 * Local IPs — used by the Chain Selector.
 * If dst_ip is in this set → packet goes to INPUT chain.
 * Otherwise → FORWARD chain.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_local_ips SEC(".maps");

/* Forward params per rule (for FORWARD+redirect action) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct fw_fwd_params);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_fwd_params_map SEC(".maps");

/*
 * find_first_set_bit — O(log₂ 64) = 6 comparisons.
 * Returns the index (0-63) of the least-significant set bit,
 * which corresponds to the highest-priority matching rule.
 * Returns -1 if the bitvector is 0 (no match).
 */
static __always_inline int find_first_set_bit(__u64 bv)
{
    if (bv == 0)
        return -1;

    int pos = 0;
    if (!(bv & 0x00000000FFFFFFFFULL)) { pos += 32; bv >>= 32; }
    if (!(bv & 0x000000000000FFFFULL)) { pos += 16; bv >>= 16; }
    if (!(bv & 0x00000000000000FFULL)) { pos += 8;  bv >>= 8;  }
    if (!(bv & 0x000000000000000FULL)) { pos += 4;  bv >>= 4;  }
    if (!(bv & 0x0000000000000003ULL)) { pos += 2;  bv >>= 2;  }
    if (!(bv & 0x0000000000000001ULL)) { pos += 1;              }
    return pos;
}

/* --------------- main XDP program --------------- */

SEC("xdp_firewall")
int pxp_firewall(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        goto chain_next;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip   = iph->saddr;
    __u32 dst_ip   = iph->daddr;
    __u32 proto    = (__u32)iph->protocol;
    __u32 src_port = 0;
    __u32 dst_port = 0;

    void *l4 = (void *)iph + (iph->ihl * 4);
    if (l4 + 1 > data_end)
        goto do_classify;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end)
            goto do_classify;
        src_port = (__u32)bpf_ntohs(tcph->source);
        dst_port = (__u32)bpf_ntohs(tcph->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end)
            goto do_classify;
        src_port = (__u32)bpf_ntohs(udph->source);
        dst_port = (__u32)bpf_ntohs(udph->dest);
    }
    /* ICMP: no ports, src_port/dst_port stay 0 */

do_classify:;

    /* ================================================================
     * CHAIN SELECTOR — predict which iptables chain applies.
     *   dst_ip ∈ fw_local_ips → INPUT
     *   otherwise             → FORWARD
     * ================================================================ */
    __u32 chain = FW_CHAIN_FORWARD;
    __u8 *is_local = bpf_map_lookup_elem(&fw_local_ips, &dst_ip);
    if (is_local)
        chain = FW_CHAIN_INPUT;

    /* Get the chain mask (which rules belong to this chain) */
    __u64 *chain_mask_ptr = bpf_map_lookup_elem(&fw_chain_mask, &chain);
    if (!chain_mask_ptr || *chain_mask_ptr == 0)
        goto apply_default;  /* no rules for this chain */

    __u64 chain_bitmask = *chain_mask_ptr;

    /* ================================================================
     * LBVS CLASSIFICATION
     *
     * Start with all bits set, then AND with each field's bitvector.
     * Early-break if result becomes 0 (no possible match).
     * ================================================================ */
    __u64 result = 0xFFFFFFFFFFFFFFFFULL;

    {
        __u64 *bv = bpf_map_lookup_elem(&fw_src_ip_bv, &src_ip);
        if (bv) {
            result &= *bv;
        } else {
            __u32 wk = FW_FIELD_SRC_IP;
            __u64 *wc = bpf_map_lookup_elem(&fw_wildcard_bv, &wk);
            if (wc)
                result &= *wc;
            else
                result = 0;
        }
        if (result == 0) goto apply_default;
    }

    {
        __u64 *bv = bpf_map_lookup_elem(&fw_dst_ip_bv, &dst_ip);
        if (bv) {
            result &= *bv;
        } else {
            __u32 wk = FW_FIELD_DST_IP;
            __u64 *wc = bpf_map_lookup_elem(&fw_wildcard_bv, &wk);
            if (wc)
                result &= *wc;
            else
                result = 0;
        }
        if (result == 0) goto apply_default;
    }

    {
        __u64 *bv = bpf_map_lookup_elem(&fw_src_port_bv, &src_port);
        if (bv) {
            result &= *bv;
        } else {
            __u32 wk = FW_FIELD_SRC_PORT;
            __u64 *wc = bpf_map_lookup_elem(&fw_wildcard_bv, &wk);
            if (wc)
                result &= *wc;
            else
                result = 0;
        }
        if (result == 0) goto apply_default;
    }

    {
        __u64 *bv = bpf_map_lookup_elem(&fw_dst_port_bv, &dst_port);
        if (bv) {
            result &= *bv;
        } else {
            __u32 wk = FW_FIELD_DST_PORT;
            __u64 *wc = bpf_map_lookup_elem(&fw_wildcard_bv, &wk);
            if (wc)
                result &= *wc;
            else
                result = 0;
        }
        if (result == 0) goto apply_default;
    }

    {
        __u64 *bv = bpf_map_lookup_elem(&fw_proto_bv, &proto);
        if (bv) {
            result &= *bv;
        } else {
            __u32 wk = FW_FIELD_PROTO;
            __u64 *wc = bpf_map_lookup_elem(&fw_wildcard_bv, &wk);
            if (wc)
                result &= *wc;
            else
                result = 0;
        }
        if (result == 0) goto apply_default;
    }

    /* Apply chain mask — keep only rules for the selected chain */
    result &= chain_bitmask;
    if (result == 0)
        goto apply_default;

    {
        int rule_idx = find_first_set_bit(result);
        if (rule_idx < 0 || rule_idx >= MAX_RULES)
            goto apply_default;

        __u32 rule_key = (__u32)rule_idx;
        __u32 *action = bpf_map_lookup_elem(&fw_actions, &rule_key);
        if (!action)
            goto apply_default;

        bpf_printk("FW: matched rule %d action=%d chain=%d",
                    rule_idx, *action, chain);

        switch (*action) {
        case FW_ACTION_DROP:
            return XDP_DROP;

        case FW_ACTION_ACCEPT:
            goto chain_next;

        case FW_ACTION_FORWARD: {
            /* Look up redirect parameters */
            struct fw_fwd_params *fwd =
                bpf_map_lookup_elem(&fw_fwd_params_map, &rule_key);
            if (!fwd || fwd->ifindex == 0)
                goto chain_next;

            /* Rewrite MAC headers for the next hop */
            if ((void *)(eth + 1) > data_end)
                goto chain_next;

            __builtin_memcpy(eth->h_dest,   fwd->dst_mac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, fwd->src_mac, ETH_ALEN);

            /* Redirect to target interface */
            return bpf_redirect(fwd->ifindex, 0);
        }

        default:
            goto chain_next;
        }
    }

apply_default:;
    {
        __u32 *def_action = bpf_map_lookup_elem(&fw_default_action, &chain);
        if (def_action && *def_action == FW_ACTION_DROP) {
            bpf_printk("FW: default DROP chain=%d", chain);
            return XDP_DROP;
        }
        /* Default ACCEPT: fall through to next pipeline stage */
    }

chain_next:
    /* Continue the master pipeline (next program = balancer) */
    bpf_tail_call(ctx, &master_array, 1);
    bpf_printk("FW: tail call to next stage failed");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
