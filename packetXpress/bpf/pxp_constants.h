#pragma once

/* ── Role dispatcher ── */
#define ROLE_MODE_MASTER 0
#define ROLE_MODE_AGENT  1

#define ROLE_MODE_SIZE    2    /* 0: Master, 1: Agent */
#define MASTER_ARRAY_SIZE 4    /* FW -> LB -> PacketProfiling -> Forwarder */
#define AGENT_ARRAY_SIZE  1    /* ingress agent forwarder */

/* ── Reverse-proxy tuning ── */
#define RP_CT_MAX_ENTRIES   (1 << 20)   /* 1M conntrack entries */
#define RP_MAX_BACKENDS     256         /* max backends across all services */
#define RP_XSK_MAX_QUEUES   64          /* max NIC rx queues */

/* ── IP protocols ── */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
