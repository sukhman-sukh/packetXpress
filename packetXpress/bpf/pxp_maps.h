#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pxp_constants.h"

#pragma once

/* ──────────────────────────────────────────────────────────────
 * Role / dispatcher maps  (shared by all programs)
 * ────────────────────────────────────────────────────────────── */

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, ROLE_MODE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} role_array SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MASTER_ARRAY_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} master_array SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, AGENT_ARRAY_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} agent_array SEC(".maps");

/* ──────────────────────────────────────────────────────────────
 * Reverse-proxy maps
 *
 * Data-plane fast path (looked up in pxp_balancer):
 *   rp_flow_ct   — LRU per-CPU conntrack: 5-tuple → backend_idx
 *   rp_backends  — backend pool:          backend_idx → {ip, mac, ifindex}
 *
 * Userspace-populated (control plane installs after SNI parse):
 *   rp_slowpath  — XSKMAP for new-flow redirect to AF_XDP slow path
 * ────────────────────────────────────────────────────────────── */

/* 5-tuple key for the conntrack and service-lookup maps. */
struct rp_flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   proto;
    __u8   _pad[3];
};

/* Conntrack value: backend index + timestamp (ns). */
struct rp_ct_val {
    __u32 backend_idx;
    __u64 last_seen_ns;
};

/* Backend descriptor populated by userspace. */
struct rp_backend {
    __be32 real_ip;          /* backend's real IP (DNAT destination) */
    __u8   real_mac[6];      /* backend's MAC (or next-hop MAC) */
    __u32  ifindex;          /* egress interface index */
    __u8   _pad[2];
};

/*
 * LRU per-CPU conntrack map.
 * Key  = rp_flow_key (17 bytes, padded to 20)
 * Value = rp_ct_val
 * 1M entries, per-CPU so no spinlock on the fast path.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key,   struct rp_flow_key);
    __type(value, struct rp_ct_val);
    __uint(max_entries, RP_CT_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rp_flow_ct SEC(".maps");

/*
 * Backend pool.
 * Key  = backend_idx (u32, 0-based)
 * Value = rp_backend
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, struct rp_backend);
    __uint(max_entries, RP_MAX_BACKENDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rp_backends SEC(".maps");

/*
 * AF_XDP socket map for new-flow redirect to the slow-path daemon.
 * Key  = rx_queue_index (u32)
 * Value = AF_XDP socket fd
 */
struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, RP_XSK_MAX_QUEUES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rp_slowpath SEC(".maps");
