"""ref_int_forward.py - Pure integer inference reference (§7.4).

Bit-identical twin of the C integer arithmetic in ahhs_common.h / xdp_ahhs_tier3.c.
Uses NumPy integer types only to prevent floating point operations.

AHHS_REQUANT_SHIFT = 24 (from ahhs_common.h §6.1):
    v = ((s64)acc * (s64)mult + (1LL << (AHHS_REQUANT_SHIFT - 1))) >> AHHS_REQUANT_SHIFT
    clamp(v, lo, 127)
"""

from typing import Dict, Any, Tuple
import numpy as np

# Must match AHHS_REQUANT_SHIFT in ahhs_common.h
SHIFT = 24


def requant(acc: np.ndarray, M: int, lo: int) -> np.ndarray:
    """Requantize int32 accumulator to int8 activation (§6.1).

    Formula from ahhs_common.h ahhs_requant():
        v = ((s64)acc * (s64)mult + (1LL << (SHIFT - 1))) >> SHIFT
        clamp(v, lo, 127)

    where SHIFT = AHHS_REQUANT_SHIFT = 24.

    Args:
        acc: int32 accumulator array
        M: int32 multiplier
        lo: int lower bound (0 for ReLU, -128 for linear)

    Returns:
        np.ndarray with dtype np.int8
    """
    acc = np.asarray(acc, dtype=np.int64)
    M = np.int64(M)
    acc_scaled = acc * M + np.int64(1 << (SHIFT - 1))
    val = acc_scaled >> SHIFT
    clamped = np.clip(val, lo, 127)
    return clamped.astype(np.int8)


def dense(
    x: np.ndarray,
    W: np.ndarray,
    b: np.ndarray,
    M: int,
    lo: int
) -> np.ndarray:
    """Single quantized dense layer (§6.1 / AHHS_DENSE macro).

    Computes:
        acc_j = b_j + sum_i (x_i * W_ji)
        out_j = requant(acc_j, M, lo)

    Args:
        x: input activations, int8 array of shape (N_in,)
        W: weight matrix, int8 array of shape (N_out, N_in)
        b: int32 bias array of shape (N_out,)
        M: int32 multiplier
        lo: int lower bound (0 for ReLU, -128 for linear)

    Returns:
        out: int8 activations of shape (N_out,)
    """
    x_i32 = np.asarray(x, dtype=np.int32)
    W_i32 = np.asarray(W, dtype=np.int32)
    b_i32 = np.asarray(b, dtype=np.int32)

    # Matrix-vector product with int32 accumulator
    acc = b_i32 + np.dot(W_i32, x_i32)
    return requant(acc, M, lo)


def int_forward(
    feat_u8: np.ndarray,
    model: Dict[str, Any]
) -> Tuple[np.ndarray, np.ndarray, int, bool]:
    """Pure integer forward pass through Tier 3 4-layer autoencoder.

    Layer dimensions: 8 -> 16 -> 4 -> 16 -> 8

    Args:
        feat_u8: uint8 feature vector of length 8
        model: dictionary containing:
            'w1': (16, 8) int8
            'b1': (16,) int32
            'M1': int32 multiplier
            'w2': (4, 16) int8
            'b2': (4,) int32
            'M2': int32 multiplier
            'w3': (16, 4) int8
            'b3': (16,) int32
            'M3': int32 multiplier
            'w4': (8, 16) int8
            'b4': (8,) int32
            'M4': int32 multiplier
            'zp': (8,) uint8 input zero-point
            'theta': uint32 anomaly threshold

    Returns:
        x_q: int8 input quantized vector (feat_u8 - zp)
        y: int8 reconstructed vector
        err: uint32 squared reconstruction error (sum of (x_q - y)^2)
        is_anomaly: bool (err > theta)
    """
    feat = np.asarray(feat_u8, dtype=np.int32)
    zp = np.asarray(model['zp'], dtype=np.int32)

    # L1: Input shift to signed int8: x_q = feat - zp (clamped to [-128, 127])
    x_q = np.clip(feat - zp, -128, 127).astype(np.int8)

    # L1: 8 -> 16 (ReLU: lo=0)
    h1 = dense(x_q, model['w1'], model['b1'], model['M1'], lo=0)

    # L2: 16 -> 4 (ReLU: lo=0)
    lat = dense(h1, model['w2'], model['b2'], model['M2'], lo=0)

    # L3: 4 -> 16 (ReLU: lo=0)
    h2 = dense(lat, model['w3'], model['b3'], model['M3'], lo=0)

    # L4: 16 -> 8 (Linear output: lo=-128)
    y = dense(h2, model['w4'], model['b4'], model['M4'], lo=-128)

    # Reconstruction error in pure integer: sum_i (x_q_i - y_i)^2
    diff = x_q.astype(np.int32) - y.astype(np.int32)
    err = int(np.sum(diff * diff))

    theta = int(model['theta'])
    is_anomaly = bool(err > theta)

    return x_q, y, err, is_anomaly
