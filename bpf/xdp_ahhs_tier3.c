/* =========================================================================
 * AHHS-IDS Phase 3: Tier 3 Autoencoder — 4 Chained XDP Programs + Self-Test
 *
 * File: xdp_ahhs_tier3.c
 *
 * Architecture: Each dense layer runs as a separate tail-called XDP program
 * to stay within the BPF verifier's instruction limit. Per-CPU scratch
 * carries intermediate activations across tail calls.
 *
 * Layer pipeline:
 *   L1 (8→16, ReLU) → L2 (16→4, ReLU) → L3 (4→16, ReLU) → L4 (16→8, linear)
 *   L4 computes reconstruction error and decides XDP_DROP vs XDP_PASS.
 *
 * All programs are fail-open: any lookup failure → XDP_PASS + FAILOPEN stat.
 * ========================================================================= */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "ahhs_common.h"

/* -------------------------------------------------------------------------
 * Helper: clamp a signed 32-bit value to signed 8-bit range
 * ------------------------------------------------------------------------- */
static __always_inline __s8 clamp_s8(__s32 v)
{
    if (v < -128) return -128;
    if (v > 127)  return 127;
    return (__s8)v;
}

/* =========================================================================
 * Layer 1: Input quantization + dense 8→16 (ReLU)
 * ========================================================================= */
SEC("xdp")
int ahhs_t3_l1(struct xdp_md *ctx)
{
    /* 1. Lookup per-CPU scratch */
    __u32 zero = 0;
    struct ahhs_scratch *sc = bpf_map_lookup_elem(&ahhs_scratch_map, &zero);
    if (!sc) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 2. Read active model set index */
    __u32 *idx = bpf_map_lookup_elem(&ahhs_nn_index, &zero);
    if (!idx) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }
    __u32 set = *idx & 1;
    sc->set = set;

    /* 3. Lookup model weights for this set */
    struct ahhs_model *model = bpf_map_lookup_elem(&ahhs_model_map, &set);
    if (!model) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 4. Input quantization: x_q[i] = clamp(feat[i] - zp[i], -128, 127) */
    __s8 x_q[AHHS_N_IN];
    #pragma unroll
    for (int i = 0; i < AHHS_N_IN; i++)
        x_q[i] = clamp_s8((__s32)sc->feat[i] - (__s32)model->zp[i]);

    /* 5. Dense layer 1: 8→16, ReLU (lo=0) */
    ahhs_dense_1((const __s8 *)model->w1, model->b1, model->mult[0],
                 x_q, sc->buf_a, 0);

    /* 6. Stat: packet inspected */
    ahhs_stat_inc(AHHS_STAT_INSPECTED);

    /* 7. Tail call to Layer 2 */
    bpf_tail_call(ctx, &ahhs_t3_prog_array, AHHS_T3_L2);

    /* 8. Tail call failed — fail open */
    ahhs_stat_inc(AHHS_STAT_FAILOPEN);
    return XDP_PASS;
}

/* =========================================================================
 * Layer 2: Dense 16→4 (ReLU, encoder bottleneck)
 * ========================================================================= */
SEC("xdp")
int ahhs_t3_l2(struct xdp_md *ctx)
{
    /* 1. Lookup scratch */
    __u32 zero = 0;
    struct ahhs_scratch *sc = bpf_map_lookup_elem(&ahhs_scratch_map, &zero);
    if (!sc) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 2. Lookup model */
    __u32 set = sc->set;
    struct ahhs_model *model = bpf_map_lookup_elem(&ahhs_model_map, &set);
    if (!model) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 3. Dense layer 2: 16→4, ReLU (lo=0) */
    ahhs_dense_2((const __s8 *)model->w2, model->b2, model->mult[1],
                 sc->buf_a, sc->buf_b, 0);

    /* 4. Tail call to Layer 3 */
    bpf_tail_call(ctx, &ahhs_t3_prog_array, AHHS_T3_L3);

    /* 5. Fail open */
    ahhs_stat_inc(AHHS_STAT_FAILOPEN);
    return XDP_PASS;
}

/* =========================================================================
 * Layer 3: Dense 4→16 (ReLU, decoder expansion)
 * ========================================================================= */
SEC("xdp")
int ahhs_t3_l3(struct xdp_md *ctx)
{
    /* 1. Lookup scratch */
    __u32 zero = 0;
    struct ahhs_scratch *sc = bpf_map_lookup_elem(&ahhs_scratch_map, &zero);
    if (!sc) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 2. Lookup model */
    __u32 set = sc->set;
    struct ahhs_model *model = bpf_map_lookup_elem(&ahhs_model_map, &set);
    if (!model) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 3. Dense layer 3: 4→16, ReLU (lo=0) */
    ahhs_dense_3((const __s8 *)model->w3, model->b3, model->mult[2],
                 sc->buf_b, sc->buf_a, 0);

    /* 4. Tail call to Layer 4 */
    bpf_tail_call(ctx, &ahhs_t3_prog_array, AHHS_T3_L4);

    /* 5. Fail open */
    ahhs_stat_inc(AHHS_STAT_FAILOPEN);
    return XDP_PASS;
}

/* =========================================================================
 * Layer 4: Dense 16→8 (linear) + reconstruction error + decision
 * ========================================================================= */
SEC("xdp")
int ahhs_t3_l4(struct xdp_md *ctx)
{
    /* 1. Lookup scratch */
    __u32 zero = 0;
    struct ahhs_scratch *sc = bpf_map_lookup_elem(&ahhs_scratch_map, &zero);
    if (!sc) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 2. Lookup model */
    __u32 set = sc->set;
    struct ahhs_model *model = bpf_map_lookup_elem(&ahhs_model_map, &set);
    if (!model) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 3. Dense layer 4: 16→8, LINEAR (lo=-128, no ReLU clamp) */
    __s8 y[AHHS_N_OUT];
    ahhs_dense_4((const __s8 *)model->w4, model->b4, model->mult[3],
                 sc->buf_a, y, -128);

    /* 4. Reconstruct quantized input on stack for error computation */
    __s8 x_q[AHHS_N_IN];
    #pragma unroll
    for (int i = 0; i < AHHS_N_IN; i++)
        x_q[i] = clamp_s8((__s32)sc->feat[i] - (__s32)model->zp[i]);

    /* 5. Compute squared reconstruction error: err = Σ (x_q[i] - y[i])² */
    __u32 err = 0;
    #pragma unroll
    for (int i = 0; i < AHHS_N_IN; i++) {
        __s32 diff = (__s32)x_q[i] - (__s32)y[i];
        err += (__u32)(diff * diff);
    }

    /* 6. Write debug: last reconstruction error */
    __u32 *dbg = bpf_map_lookup_elem(&ahhs_dbg, &zero);
    if (dbg)
        *dbg = err;

    /* 7. Anomaly decision */
    if (err > model->theta) {
        /* Anomalous: block flow and drop packet */
        ahhs_stat_inc(AHHS_STAT_ANOMALY);
        __u64 expiry = bpf_ktime_get_ns() + AHHS_BLOCK_TTL_NS;
        bpf_map_update_elem(&ahhs_blocklist, &sc->key, &expiry, BPF_ANY);
        return XDP_DROP;
    }

    /* 8. Normal: pass packet */
    ahhs_stat_inc(AHHS_STAT_NORMAL);
    return XDP_PASS;
}

/* =========================================================================
 * Self-Test: Reads 8 bytes from packet payload as test input features,
 * copies to scratch, and tail-calls into the L1 pipeline.
 * ========================================================================= */
SEC("xdp")
int ahhs_t3_selftest(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Bounds check: need 14 (eth) + 8 (feature) bytes */
    if (data + 14 + 8 > data_end)
        return XDP_PASS;

    /* 2. Lookup scratch */
    __u32 zero = 0;
    struct ahhs_scratch *sc = bpf_map_lookup_elem(&ahhs_scratch_map, &zero);
    if (!sc) {
        ahhs_stat_inc(AHHS_STAT_FAILOPEN);
        return XDP_PASS;
    }

    /* 3. Copy 8 bytes at offset 14 into scratch features */
    __u8 *payload = (__u8 *)data + 14;
    #pragma unroll
    for (int i = 0; i < AHHS_N_IN; i++)
        sc->feat[i] = payload[i];

    /* 4. Zero the flow key (self-test has no real flow) */
    __builtin_memset(&sc->key, 0, sizeof(sc->key));

    /* 5. Tail call into Layer 1 */
    bpf_tail_call(ctx, &ahhs_t3_prog_array, AHHS_T3_L1);

    /* 6. Fail open */
    ahhs_stat_inc(AHHS_STAT_FAILOPEN);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
