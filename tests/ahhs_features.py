"""ahhs_features.py - Feature extraction and integer log2 matching C implementation §3.

Bit-identical mirror of ahhs_extract_features and ahhs_log2q3 from ahhs_common.h.
"""

from typing import List, Tuple

# Constants matching §4.1 / §5
AHHS_WIN_PKTS = 100
AHHS_WIN_NS = 1_000_000_000      # 1 second
AHHS_MIN_PKTS = 8                 # matches C AHHS_MIN_PKTS
AHHS_STALE_NS = 10_000_000_000   # 10 seconds


def ilog2_u32(v: int) -> int:
    """Integer log2 of a 32-bit unsigned integer (floor).
    v must be >= 1 (caller guarantees).
    """
    v = int(v) & 0xFFFFFFFF
    if v == 0:
        return 0
    return v.bit_length() - 1


def log2q3(x: int) -> int:
    """Fixed-point log2 with 3 fractional bits, matching C ahhs_log2q3 exactly.

    C formula (ahhs_common.h §3):
        v = min(x + 1, 0xFFFFFFFF)
        e = ilog2(v)
        frac = (v >> (e-3)) & 7  if e >= 3 else (v << (3-e)) & 7
        return (e << 3) | frac

    Domain: [0, 2^32 - 1] -> [0, 255] (uint8).
    Properties: monotonic, log2q3(0) = 0, log2q3(2^32-1) = 255.
    """
    x = int(x) & 0xFFFFFFFF
    # v = min(x + 1, 0xFFFFFFFF)
    if x >= 0xFFFFFFFF:
        v = 0xFFFFFFFF
    else:
        v = x + 1
    e = ilog2_u32(v)
    if e >= 3:
        frac = (v >> (e - 3)) & 7
    else:
        frac = (v << (3 - e)) & 7
    res = (e << 3) | frac
    return min(res, 255)


def extract_features_from_state(
    w_pkts: int,
    w_bytes: int,
    w_len_max: int,
    w_len_sq: int,
    w_iat_sum_ns: int,
    w_iat_max_ns: int,
    w_syn: int,
) -> List[int]:
    """Pure integer mirror of C ahhs_extract_features() from ahhs_common.h.

    Returns 8 uint8 features:
        0: log2q3(n)            - packets in window
        1: log2q3(mean_len)     - mean packet length = w_bytes / n
        2: log2q3(w_len_max)    - max packet length
        3: log2q3(var_len)      - packet length variance, clamped u32
        4: log2q3(mean_iat_us)  - mean IAT in microseconds
        5: log2q3(max_iat_us)   - max IAT in microseconds
        6: log2q3(wb)           - window bytes clamped to u32
        7: (w_syn * 255) / n    - SYN ratio 0..255
    """
    n = int(w_pkts)
    if n == 0:
        return [0] * 8

    # feat[0]: packets in window
    f0 = log2q3(n)

    # feat[1]: mean packet length = w_bytes / n (integer division)
    mean_len = int(w_bytes) // n
    mean_len = mean_len & 0xFFFFFFFF  # u32
    f1 = log2q3(mean_len)

    # feat[2]: max packet length
    f2 = log2q3(int(w_len_max) & 0xFFFFFFFF)

    # feat[3]: packet length variance = E[X^2] - E[X]^2
    #   E[X^2] = w_len_sq / n    (u64 / u32 -> u64)
    #   E[X]^2 = mean_len^2      (u32 * u32 -> u64)
    #   var = max(0, E[X^2] - E[X]^2) clamped to u32
    e_x2 = int(w_len_sq) // n
    mean_sq = mean_len * mean_len
    var64 = e_x2 - mean_sq if e_x2 > mean_sq else 0
    var32 = 0xFFFFFFFF if var64 > 0xFFFFFFFF else int(var64)
    f3 = log2q3(var32)

    # feat[4]: mean inter-arrival time (us)
    #   = (w_iat_sum_ns / (n-1)) / 1000,  0 if n <= 1
    if n > 1:
        mean_iat_ns = int(w_iat_sum_ns) // (n - 1)
        mean_iat_us = mean_iat_ns // 1000
        mean_iat_us = mean_iat_us & 0xFFFFFFFF  # u32
        f4 = log2q3(mean_iat_us)
    else:
        f4 = 0

    # feat[5]: max inter-arrival time (us)
    max_iat_us = int(w_iat_max_ns) // 1000
    max_iat_us = max_iat_us & 0xFFFFFFFF  # u32
    f5 = log2q3(max_iat_us)

    # feat[6]: window bytes clamped u64 -> u32
    wb = int(w_bytes)
    wb = 0xFFFFFFFF if wb > 0xFFFFFFFF else wb
    f6 = log2q3(wb)

    # feat[7]: SYN ratio = (w_syn * 255) / n, already 0..255
    f7 = (int(w_syn) * 255) // n
    f7 = f7 & 0xFF

    return [f0, f1, f2, f3, f4, f5, f6, f7]


def window_features(packets: List[Tuple[int, int, bool]]) -> List[List[int]]:
    """Simulate pipeline flow windowing and feature extraction.

    packets: list of tuples (timestamp_ns, pkt_length, is_syn)
    Returns: list of 8-element uint8 feature vectors emitted on window close.

    Follows §5 window trigger semantics:
      - Trigger when: (w_pkts >= AHHS_WIN_PKTS or (now - w_start_ns) > AHHS_WIN_NS)
                      and w_pkts >= AHHS_MIN_PKTS
      - On trigger: extract features, reset window accumulators
      - If (now - w_start_ns) > AHHS_STALE_NS: hard reset without emission
    """
    windows_out = []

    # Window accumulators
    w_pkts = 0
    w_bytes = 0
    w_len_max = 0
    w_len_sq = 0
    w_iat_sum_ns = 0
    w_iat_max_ns = 0
    w_syn = 0
    w_start_ns = 0
    w_last_ns = 0

    first_packet_of_flow = True
    for ts_ns, length, is_syn in packets:
        # Kernel semantics (xdp_ahhs_tier1.c): the flow's window clock starts at the flow's first
        # packet; after every reset (trigger OR stale) it restarts at the time of the packet that
        # caused the reset -- NOT at the first packet of the following window.
        if first_packet_of_flow:
            w_start_ns = ts_ns
            w_last_ns = ts_ns
            first_packet_of_flow = False
        elif w_pkts == 0:
            w_last_ns = ts_ns            # first packet of a window: no IAT contribution
        else:
            w_iat = max(0, ts_ns - w_last_ns)
            w_iat_sum_ns += w_iat
            if w_iat > w_iat_max_ns:
                w_iat_max_ns = w_iat
            w_last_ns = ts_ns

        w_pkts += 1
        w_bytes += length
        if length > w_len_max:
            w_len_max = length
        w_len_sq += length * length
        if is_syn:
            w_syn += 1

        time_elapsed = ts_ns - w_start_ns
        should_trigger = (
            (w_pkts >= AHHS_WIN_PKTS or time_elapsed > AHHS_WIN_NS)
            and w_pkts >= AHHS_MIN_PKTS
        )

        if should_trigger:
            feat = extract_features_from_state(
                w_pkts, w_bytes, w_len_max, w_len_sq,
                w_iat_sum_ns, w_iat_max_ns, w_syn,
            )
            windows_out.append(feat)
            w_pkts = w_bytes = w_len_max = w_len_sq = 0
            w_iat_sum_ns = w_iat_max_ns = w_syn = 0
            w_start_ns = ts_ns                       # kernel: w_start_ns = current_time
        elif time_elapsed > AHHS_STALE_NS and w_pkts < AHHS_MIN_PKTS:
            w_pkts = w_bytes = w_len_max = w_len_sq = 0
            w_iat_sum_ns = w_iat_max_ns = w_syn = 0
            w_start_ns = ts_ns                       # kernel: hard reset, w_start_ns = current_time

    return windows_out
