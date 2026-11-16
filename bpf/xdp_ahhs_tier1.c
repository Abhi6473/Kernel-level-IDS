/* =========================================================================
 * AHHS-IDS: Adaptive Hybrid Hardware-Software Intrusion Detection System
 * Phase 3: Multi-Tier In-Kernel Pipeline (Tier 1 Pre-Filter & Tier 2 Tracker)
 *
 * File: xdp_ahhs_tier1.c
 *
 * Architecture & Tier Breakdown:
 * -------------------------------------------------------------------------
 * - TIER 1 (Stateless Pre-Filter):
 *     Evaluates L2-L4 packet headers against an inline Decision Tree
 *     (tier1_tree.h) in O(1) time without accessing stateful memory maps.
 *     Known benign ports (80, 443, 53, 123) -> PASS immediately.
 *     Known malicious ports (23, 4444, 1337, etc.) -> DROP immediately.
 *     Dynamic / unknown ports -> AMBIGUOUS (escalate to Tier 2).
 *
 * - TIER 2 (Stateful Sliding Window & LRU Flow Tracker):
 *     Tracks dynamic connection states in an LRU hash map (flow_lru_map,
 *     65,536 entries). Fast-paths known malicious flows using ahhs_blocklist.
 *     Accumulates window statistics over 100 packets or 1.0 second.
 *     Upon window completion, extracts 8 log2q3 features into per-CPU scratch
 *     and triggers Tier 3 via bpf_tail_call().
 *
 * - TIER 3 (Chained Quantized In-Kernel Autoencoder - in xdp_ahhs_tier3.c):
 *     4-program tail-call chained neural network (8 -> 16 -> 4 -> 16 -> 8)
 *     computing integer reconstruction error and dynamically blocklisting flows.
 * ========================================================================= */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tier1_tree.h"
#include "ahhs_common.h"

/* -------------------------------------------------------------------------
 * Fallback Macros & Compatibility Definitions
 * ------------------------------------------------------------------------- */
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohl
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif
#ifndef bpf_htonl
#define bpf_htonl(x) __builtin_bswap32(x)
#endif

#define AHHS_ACTION_NON_IPV4   -1
#define AHHS_ACTION_MANAGEMENT -2
#define AHHS_STALE_WINDOW_NS   60000000000ULL /* 60-second idle timeout for inactive flows */

/* -------------------------------------------------------------------------
 * Tier 1 Telemetry Map
 * Per-CPU array tracking decision counts:
 *   0=PASS, 1=DROP, 2=AMBIGUOUS, 3=NON_IPV4
 * ------------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} tier1_stats_map SEC(".maps");

static __always_inline void increment_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&tier1_stats_map, &key);
    if (val) {
        *val += 1;
    }
}

static __always_inline int is_ids_target_port(__u16 port)
{
    if (port == 80 || port == 53 || port == 443 || port == 123 ||
        port == 23 || port == 4444 || port == 1337 || port == 2323 || port == 31337 ||
        port == 8080 || port == 9000 || port == 6000 ||
        (port >= 8000 && port <= 8030)) {
        return 1;
    }
    return 0;
}

/* =========================================================================
 * SECTION 1: TIER 1 - STATELESS WIRE-SPEED PRE-FILTER
 * Parses L2-L4 headers, validates verifier boundaries, and evaluates
 * the static inline decision tree.
 * ========================================================================= */
static __always_inline int tier1_prefilter(
    void *data, void *data_end,
    struct flow_key *key,
    __u32 *pkt_len,
    __u8 *is_syn_out)
{
    /* 1. Layer 2: Ethernet Header Parsing & Verifier Boundary Check */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TIER1_ACTION_PASS;
    }

    __u16 h_proto = eth->h_proto;
    void *l3_hdr = (void *)(eth + 1);

    /* Handle 802.1Q / 802.1ad VLAN tags if present */
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct {
            __u16 h_vlan_TCI;
            __u16 h_vlan_encapsulated_proto;
        } *vlan = l3_hdr;

        if ((void *)(vlan + 1) > data_end) {
            return TIER1_ACTION_PASS;
        }
        h_proto = vlan->h_vlan_encapsulated_proto;
        l3_hdr = (void *)(vlan + 1);
    }

    /* Only inspect IPv4 traffic; pass other protocols (ARP, IPv6) directly */
    if (h_proto != bpf_htons(ETH_P_IP)) {
        return AHHS_ACTION_NON_IPV4;
    }

    /* 2. Layer 3: IPv4 Header Parsing & Bounds Validation */
    struct iphdr *iph = l3_hdr;
    if ((void *)(iph + 1) > data_end) {
        return TIER1_ACTION_PASS;
    }

    __u32 ip_hlen = iph->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr)) {
        return TIER1_ACTION_PASS;
    }

    /* Fragmented packets: non-first fragments do not contain L4 TCP/UDP headers */
    if (iph->frag_off & bpf_htons(0x1FFF)) {
        return TIER1_ACTION_PASS;
    }

    void *l4_hdr = (void *)iph + ip_hlen;
    if (l4_hdr > data_end) {
        return TIER1_ACTION_PASS;
    }

    __u32 src_ip   = bpf_ntohl(iph->saddr);
    __u32 dst_ip   = bpf_ntohl(iph->daddr);
    __u8  protocol = iph->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8  is_syn   = 0;
    if (is_syn_out)
        *is_syn_out = 0;

    /* 3. Layer 4: Transport Header Parsing (TCP / UDP) */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) {
            return TIER1_ACTION_PASS;
        }
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
        is_syn = tcph->syn && !tcph->ack;
        if (is_syn_out)
            *is_syn_out = is_syn;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) {
            return TIER1_ACTION_PASS;
        }
        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);
    } else {
        /* Non-TCP/UDP IP traffic (e.g., ICMP) - pass to host network stack */
        return TIER1_ACTION_PASS;
    }

    /* Populate 5-tuple flow key */
    key->src_ip   = src_ip;
    key->dst_ip   = dst_ip;
    key->src_port = src_port;
    key->dst_port = dst_port;
    key->protocol = protocol;

    /* Management traffic: allow incoming SSH to host management port without triggering IDS */
    if (dst_port == 22) {
        return AHHS_ACTION_MANAGEMENT;
    }

    /* Unlisted ports: route to Tier 2/3 for anomaly inspection rather than silently bypassing */
    if (!is_ids_target_port(dst_port)) {
        return TIER1_ACTION_AMBIGUOUS;
    }

    /* Compute IP-level packet length (excluding 14-byte Ethernet header) */
    *pkt_len = (__u32)(data_end - data);
    if (*pkt_len >= sizeof(struct ethhdr)) {
        *pkt_len -= sizeof(struct ethhdr);
    }

    /* 4. Evaluate Tier 1 Decision Tree (tier1_tree_predict) */
    uint32_t features[5];
    features[0] = src_ip;
    features[1] = dst_ip;
    features[2] = (__u32)src_port;
    features[3] = (__u32)dst_port;
    features[4] = (__u32)protocol;

    return tier1_tree_predict(features, 5);
}

/* =========================================================================
 * SECTION 2: TIER 2 - STATEFUL SLIDING WINDOW & LRU FLOW TRACKER
 * Handles ambiguous flows: checks fast-path blocklist, accumulates window
 * statistics (100 pkts / 1.0s), and dispatches to Tier 3 via tail-call.
 * ========================================================================= */
static __always_inline int tier2_process_window(
    struct xdp_md *ctx,
    const struct flow_key *key,
    __u32 pkt_len,
    __u8 is_syn)
{
    __u64 current_time = bpf_ktime_get_ns();

    /* ----- (a) Fast-Path Blocklist Check ----- */
    __u64 *bl_expiry = bpf_map_lookup_elem(&ahhs_blocklist, key);
    if (bl_expiry) {
        if (*bl_expiry > current_time) {
            /* Still active in blocklist -> Drop immediately */
            ahhs_stat_inc(AHHS_STAT_BLOCKHIT);
            return XDP_DROP;
        }
        /* Expired -> Remove stale entry */
        bpf_map_delete_elem(&ahhs_blocklist, key);
    }

    /* ----- (b) Flow LRU Map Lookup & State Maintenance ----- */
    struct flow_state *flow = bpf_map_lookup_elem(&flow_lru_map, key);

    if (!flow) {
        /* (c) First packet for this flow -> Initialize window state */
        struct flow_state init_state = {0};
        init_state.packet_count  = 1;
        init_state.byte_count    = pkt_len;
        init_state.start_time_ns = current_time;
        init_state.last_seen_ns  = current_time;
        init_state.w_start_ns    = current_time;
        init_state.w_pkts        = 1;
        init_state.w_bytes       = pkt_len;
        init_state.w_len_max     = pkt_len;
        init_state.w_len_sq      = (__u64)pkt_len * (__u64)pkt_len;
        init_state.w_syn         = is_syn;

        bpf_map_update_elem(&flow_lru_map, key, &init_state, BPF_ANY);
        return XDP_PASS;
    }

    /* (d) Existing flow -> Update lifetime & window accumulators */
    __u64 iat = current_time - flow->last_seen_ns;

    flow->packet_count++;
    flow->byte_count += pkt_len;
    flow->last_seen_ns = current_time;

    flow->w_pkts++;
    flow->w_bytes += pkt_len;
    if (pkt_len > flow->w_len_max) {
        flow->w_len_max = pkt_len;
    }
    flow->w_len_sq += (__u64)pkt_len * (__u64)pkt_len;
    if (flow->w_pkts > 1) {
        flow->w_iat_sum_ns += iat;
        if (iat > flow->w_iat_max_ns) {
            flow->w_iat_max_ns = iat;
        }
    }
    if (is_syn) {
        flow->w_syn++;
    }

    /* ----- (e) Window Trigger Evaluation (100 Packets or 1.0s Timeout) ----- */
    if ((flow->w_pkts >= AHHS_WIN_PKTS ||
         (current_time - flow->w_start_ns) > AHHS_WIN_NS) &&
        flow->w_pkts >= AHHS_MIN_PKTS) {

        /* Window is complete: extract 8 fixed-point log2q3 features */
        __u32 zero = 0;
        struct ahhs_scratch *sc = bpf_map_lookup_elem(&ahhs_scratch_map, &zero);
        if (sc) {
            ahhs_extract_features(flow, sc->feat);
            sc->key = *key; /* Preserve 5-tuple so Tier 3 can blocklist if anomalous */

            /* Atomically reset window accumulators for next interval */
            flow->w_pkts       = 0;
            flow->w_bytes      = 0;
            flow->w_len_max    = 0;
            flow->w_len_sq     = 0;
            flow->w_iat_sum_ns = 0;
            flow->w_iat_max_ns = 0;
            flow->w_syn        = 0;
            flow->w_start_ns   = current_time;

            /* Dispatch tail-call into Tier 3 Neural Network (Program 0: Layer 1) */
            bpf_tail_call(ctx, &ahhs_t3_prog_array, AHHS_T3_L1);
            return XDP_PASS;
        }
    }

    /* ----- (f) Stale Window Handling: reset only if connection was completely idle for > 60s ----- */
    if ((current_time - flow->last_seen_ns) > AHHS_STALE_WINDOW_NS &&
        flow->w_pkts < AHHS_MIN_PKTS) {
        flow->w_pkts       = 0;
        flow->w_bytes      = 0;
        flow->w_len_max    = 0;
        flow->w_len_sq     = 0;
        flow->w_iat_sum_ns = 0;
        flow->w_iat_max_ns = 0;
        flow->w_syn        = 0;
        flow->w_start_ns   = current_time;
    }

    return XDP_PASS;
}

/* =========================================================================
 * SECTION 3: ROOT XDP INGRESS ENTRYPOINT - MULTI-TIER PIPELINE DISPATCHER
 * Every packet entering the network interface executes here.
 * ========================================================================= */
SEC("xdp")
int xdp_ahhs_tier1(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct flow_key key = {0};
    __u32 pkt_len = 0;
    __u8 is_syn = 0;

    /* -----------------------------------------------------------------
     * STEP 1: Execute Tier 1 Stateless Pre-Filter (Decision Tree)
     * ----------------------------------------------------------------- */
    int action = tier1_prefilter(data, data_end, &key, &pkt_len, &is_syn);

    if (action == AHHS_ACTION_MANAGEMENT) {
        return XDP_PASS; /* Silent management passthrough: keep SSH alive without polluting IDS telemetry */
    }

    /* Fast-Path Blocklist Check: drop quarantined flows at pipeline ingress */
    __u64 current_time = bpf_ktime_get_ns();
    __u64 *bl_expiry = bpf_map_lookup_elem(&ahhs_blocklist, &key);
    if (bl_expiry) {
        if (*bl_expiry > current_time) {
            ahhs_stat_inc(AHHS_STAT_BLOCKHIT);
            return XDP_DROP;
        }
        bpf_map_delete_elem(&ahhs_blocklist, &key);
    }

    if (action == TIER1_ACTION_DROP) {
        increment_stat(TIER1_ACTION_DROP);
        return XDP_DROP;
    } else if (action == TIER1_ACTION_PASS) {
        increment_stat(TIER1_ACTION_PASS);
        return XDP_PASS;
    } else if (action == AHHS_ACTION_NON_IPV4) {
        increment_stat(3);
        return XDP_PASS;
    }

    /* -----------------------------------------------------------------
     * STEP 2: Ambiguous Flow -> Forward to Tier 2 Stateful Tracker
     * ----------------------------------------------------------------- */
    increment_stat(TIER1_ACTION_AMBIGUOUS);
    return tier2_process_window(ctx, &key, pkt_len, is_syn);
}

SEC("license")
char _license[] = "GPL";
