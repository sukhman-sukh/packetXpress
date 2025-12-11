#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "pxp_constants.h"

#pragma once

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, ROLE_MODE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} role_array SEC(".maps");
#pragma once
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

// Firewall config map: holds a single TCP destination port to DROP
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} firewall_dport SEC(".maps");
