/* =========================================================================
 * AHHS-IDS Phase 3: Shared Constants, Structs, Maps, and Helpers
 *
 * File: ahhs_common.h
 *
 * Included by both xdp_ahhs_tier1.c (Tier 1/2) and xdp_ahhs_tier3.c
 * (Tier 3 layers). Identical map definitions in each translation unit
 * are merged by `bpftool gen object`.
 *
 * Spec reference: §4 (constants, structs, maps), §3 (features, log2q3),
 *                 §6.1 (requant, dense).
 * ========================================================================= */

#ifndef AHHS_COMMON_H
#define AHHS_COMMON_H

#include <linux/types.h>

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* -------------------------------------------------------------------------
 * §4.1 Constants
 * ------------------------------------------------------------------------- */
#define AHHS_N_IN           8
#define AHHS_N_H1          16
#define AHHS_N_LAT          4
#define AHHS_N_H2          16
#define AHHS_N_OUT          8
#define AHHS_REQUANT_SHIFT  24
#define AHHS_WIN_PKTS      100
#define AHHS_WIN_NS        1000000000ULL     /* 1 s */
#define AHHS_MIN_PKTS        8               /* don't score windows with fewer packets */
#define AHHS_BLOCK_TTL_NS  60000000000ULL    /* 60 s */

enum {
    AHHS_T3_L1 = 0,
    AHHS_T3_L2,
    AHHS_T3_L3,
    AHHS_T3_L4,
    AHHS_T3_N              /* == 4 */
};

/* Tier 3 stats map indices */
enum {
    AHHS_STAT_INSPECTED = 0,
    AHHS_STAT_ANOMALY   = 1,
    AHHS_STAT_NORMAL    = 2,
    AHHS_STAT_FAILOPEN  = 3,
    AHHS_STAT_BLOCKHIT  = 4,
};

/* -------------------------------------------------------------------------
 * §4.2 Structs
 * ------------------------------------------------------------------------- */

/* Flow key: classic 5-tuple with 4-byte alignment padding.
 * Moved here from xdp_ahhs_tier1.c so Tier 3 can share it. */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
};

/* Flow state: original 4 lifetime fields + per-window accumulators.
 * Window accumulators are reset after each Tier 3 inspection. */
struct flow_state {
    /* --- existing lifetime counters (kept in place) --- */
    __u64 packet_count;
    __u64 byte_count;
    __u64 start_time_ns;
    __u64 last_seen_ns;
    /* --- per-window accumulators (new) --- */
    __u64 w_start_ns;
    __u64 w_bytes;
    __u64 w_len_sq;
    __u64 w_iat_sum_ns;
    __u64 w_iat_max_ns;
    __u32 w_pkts;
    __u32 w_len_max;
    __u32 w_syn;
    __u32 _pad;
};

/* Model struct: 592 bytes, no padding, little-endian.
 * Packed with struct.pack("<44i4i2I384b8B", ...) in Python. */
struct ahhs_model {
    __s32 b1[AHHS_N_H1];                           /*  64 */
    __s32 b2[AHHS_N_LAT];                          /*  16 */
    __s32 b3[AHHS_N_H2];                           /*  64 */
    __s32 b4[AHHS_N_OUT];                          /*  32 */
    /* --- subtotal biases: 176 --- */
    __s32 mult[AHHS_T3_N];                         /*  16: requant multipliers */
    __u32 theta;                                    /*   4: anomaly threshold  */
    __u32 version;                                  /*   4                     */
    /* --- subtotal meta: 200 --- */
    __s8  w1[AHHS_N_H1  * AHHS_N_IN];              /* 128: row-major [out][in] */
    __s8  w2[AHHS_N_LAT * AHHS_N_H1];              /*  64 */
    __s8  w3[AHHS_N_H2  * AHHS_N_LAT];             /*  64 */
    __s8  w4[AHHS_N_OUT * AHHS_N_H2];              /* 128 */
    /* --- subtotal weights: 384 --- */
    __u8  zp[AHHS_N_IN];                           /*   8: input zero points */
};
_Static_assert(sizeof(struct ahhs_model) == 592, "ahhs_model layout mismatch");

/* Per-CPU scratch: carries state across tail calls (fixes G2). */
struct ahhs_scratch {
    struct flow_key key;                            /*  16 */
    __u8   feat[AHHS_N_IN];                         /*   8 */
    __s8   buf_a[AHHS_N_H1];                        /*  16 */
    __s8   buf_b[AHHS_N_H1];                        /*  16 */
    __u32  set;                                     /*   4: model set (0 or 1) */
    __u32  _pad;                                    /*   4 */
};

/* -------------------------------------------------------------------------
 * §4.3 Maps — identical definitions included in every .c;
 *             merged by bpftool gen object.
 * ------------------------------------------------------------------------- */

/* BPF-side only: maps and helpers that need bpf_helpers.h. The userspace loader
 * (gcc) includes this header just for struct ahhs_model / constants.
 * Maps are __weak so that `bpftool gen object` can merge identical definitions
 * that appear in both xdp_ahhs_tier1.o and xdp_ahhs_tier3.o (strong duplicates
 * fail with "conflicting non-weak symbol"). */
#ifdef __bpf__

/* Tier 2 LRU map (existing, extended value) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct flow_key);
    __type(value, struct flow_state);
} flow_lru_map SEC(".maps") __weak;

/* Tier 3 tail-call program array — 4 layers (fixes G3) */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, AHHS_T3_N);
    __type(key,   __u32);
    __type(value, __u32);
} ahhs_t3_prog_array SEC(".maps") __weak;

/* Per-CPU scratch for inter-layer data (fixes G2) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct ahhs_scratch);
} ahhs_scratch_map SEC(".maps") __weak;

/* Double-buffered model weights: set 0 = Running, set 1 = Idle */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key,   __u32);
    __type(value, struct ahhs_model);
} ahhs_model_map SEC(".maps") __weak;

/* Active model set index (0 or 1); read ONCE per inference in L1 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} ahhs_nn_index SEC(".maps") __weak;

/* Flow blocklist: anomalous flows are blocked for BLOCK_TTL_NS (fixes G5) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key,   struct flow_key);
    __type(value, __u64);          /* expiry timestamp (ns) */
} ahhs_blocklist SEC(".maps") __weak;

/* Tier 3 telemetry counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key,   __u32);
    __type(value, __u64);
} ahhs_t3_stats SEC(".maps") __weak;

/* Debug map: last reconstruction error for self-test verification */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} ahhs_dbg SEC(".maps") __weak;

/* -------------------------------------------------------------------------
 * Tier 3 stat helper
 * ------------------------------------------------------------------------- */
static __always_inline void ahhs_stat_inc(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&ahhs_t3_stats, &idx);
    if (v)
        *v += 1;
}

#endif /* __bpf__ */

/* -------------------------------------------------------------------------
 * §3  log2q3 — fixed-point log2 with 3 fractional bits, output 0..255.
 *
 * v = min(x + 1, 0xFFFFFFFF)
 * e = ilog2(v)
 * frac = ((v >> (e-3)) if e >= 3 else (v << (3-e))) & 7
 * return (e << 3) | frac
 *
 * Properties: monotonic, log2q3(0)=0, log2q3(2^32-1)=255.
 * ------------------------------------------------------------------------- */
static __always_inline __u32 ahhs_ilog2_u32(__u32 v)
{
    /* v >= 1 guaranteed by caller */
    __u32 r = 0;
    if (v >> 16) { v >>= 16; r += 16; }
    if (v >>  8) { v >>=  8; r +=  8; }
    if (v >>  4) { v >>=  4; r +=  4; }
    if (v >>  2) { v >>=  2; r +=  2; }
    if (v >>  1) {            r +=  1; }
    return r;
}

static __always_inline __u8 ahhs_log2q3(__u32 x)
{
    /* v = min(x + 1, 0xFFFFFFFF): clamp so x+1 cannot overflow */
    __u32 v = (x >= 0xFFFFFFFFU) ? 0xFFFFFFFFU : x + 1;
    __u32 e = ahhs_ilog2_u32(v);
    __u32 frac;
    if (e >= 3)
        frac = (v >> (e - 3)) & 7;
    else
        frac = (v << (3 - e)) & 7;
    return (__u8)((e << 3) | frac);
}

/* -------------------------------------------------------------------------
 * §3  Feature extraction — 8 uint8 features from window accumulators.
 *
 * Called with w_pkts >= AHHS_MIN_PKTS (i.e. >= 8, so n-1 >= 7).
 * All arithmetic is pure integer.
 * ------------------------------------------------------------------------- */
static __always_inline void ahhs_extract_features(const struct flow_state *f,
                                                    __u8 *feat)
{
    __u32 n = f->w_pkts;
    if (n == 0) {
        /* Safety: should never happen given MIN_PKTS guard */
        #pragma unroll
        for (int i = 0; i < AHHS_N_IN; i++)
            feat[i] = 0;
        return;
    }

    /* feat[0]: packets in window */
    feat[0] = ahhs_log2q3(n);

    /* feat[1]: mean packet length = w_bytes / n */
    __u32 mean_len = (__u32)(f->w_bytes / (__u64)n);
    feat[1] = ahhs_log2q3(mean_len);

    /* feat[2]: max packet length */
    feat[2] = ahhs_log2q3(f->w_len_max);

    /* feat[3]: packet length variance = E[X²] - E[X]²
     *   E[X²] = w_len_sq / n    (u64 / u32 → u64)
     *   E[X]² = mean_len²       (u32 * u32 → u64)
     *   var   = max(0, E[X²] - E[X]²)  clamped to u32 for log2q3 */
    {
        __u64 e_x2   = f->w_len_sq / (__u64)n;
        __u64 mean_sq = (__u64)mean_len * (__u64)mean_len;
        __u64 var64   = e_x2 > mean_sq ? (e_x2 - mean_sq) : 0;
        __u32 var32   = var64 > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)var64;
        feat[3] = ahhs_log2q3(var32);
    }

    /* feat[4]: mean inter-arrival time (µs)
     *   = (w_iat_sum_ns / (n-1)) / 1000  */
    if (n > 1) {
        __u64 mean_iat_ns = f->w_iat_sum_ns / (__u64)(n - 1);
        __u32 mean_iat_us = (__u32)(mean_iat_ns / 1000ULL);
        feat[4] = ahhs_log2q3(mean_iat_us);
    } else {
        feat[4] = 0;
    }

    /* feat[5]: max inter-arrival time (µs) */
    {
        __u32 max_iat_us = (__u32)(f->w_iat_max_ns / 1000ULL);
        feat[5] = ahhs_log2q3(max_iat_us);
    }

    /* feat[6]: window bytes (clamp u64 → u32) */
    {
        __u32 wb = f->w_bytes > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)f->w_bytes;
        feat[6] = ahhs_log2q3(wb);
    }

    /* feat[7]: SYN ratio = (w_syn * 255) / n, already 0..255 */
    feat[7] = (__u8)(((__u64)f->w_syn * 255ULL) / (__u64)n);
}

/* -------------------------------------------------------------------------
 * §6.1  Requantization: int32 accumulator → int8
 *
 *   v = (acc * mult + (1 << (SHIFT-1))) >> SHIFT   (arithmetic right shift)
 *   return clamp(v, lo, 127)
 *
 * lo = 0 for ReLU layers (L1-L3), lo = -128 for the linear output (L4).
 * ------------------------------------------------------------------------- */
static __always_inline __s8 ahhs_requant(__s32 acc, __s32 mult, __s32 lo)
{
    __s64 v = ((__s64)acc * (__s64)mult + (1LL << (AHHS_REQUANT_SHIFT - 1)))
              >> AHHS_REQUANT_SHIFT;
    if (v < lo)  v = lo;
    if (v > 127) v = 127;
    return (__s8)v;
}

/* -------------------------------------------------------------------------
 * §6.1  Dense layer macro: out[o] = requant(Σ w[o][i]*x[i] + b[o])
 *
 * W is row-major [OUT][IN], x is [IN], y is [OUT].
 * Both loops are constant-bound and pragma-unrolled.
 * ------------------------------------------------------------------------- */
#define AHHS_DENSE(NAME, IN, OUT)                                             \
static __always_inline void NAME(const __s8 *w, const __s32 *b, __s32 mult,  \
                                 const __s8 *x, __s8 *y, __s32 lo)           \
{                                                                             \
    _Pragma("unroll")                                                         \
    for (int o = 0; o < (OUT); o++) {                                         \
        __s32 acc = b[o];                                                     \
        _Pragma("unroll")                                                     \
        for (int i = 0; i < (IN); i++)                                        \
            acc += (__s32)x[i] * (__s32)w[o * (IN) + i];                      \
        y[o] = ahhs_requant(acc, mult, lo);                                   \
    }                                                                         \
}

/* Instantiate the four dense layers */
AHHS_DENSE(ahhs_dense_1, AHHS_N_IN,  AHHS_N_H1)    /*  8 → 16 */
AHHS_DENSE(ahhs_dense_2, AHHS_N_H1,  AHHS_N_LAT)   /* 16 →  4 */
AHHS_DENSE(ahhs_dense_3, AHHS_N_LAT, AHHS_N_H2)    /*  4 → 16 */
AHHS_DENSE(ahhs_dense_4, AHHS_N_H2,  AHHS_N_OUT)   /* 16 →  8 */

#endif /* AHHS_COMMON_H */

