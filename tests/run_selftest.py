#!/usr/bin/env python3
"""run_selftest.py - Tier 3 Autoencoder Self-Test Harness (§8).

Loops over every vector in golden_tier3.json:
1. Synthesizes a 22-byte packet (14-byte Ethernet header + 8-byte feat_u8).
2. If running on Linux with bpftool and root:
   - Uses `bpftool prog run` on pinned ahhs_t3_selftest.
   - Reads the return code (XDP_PASS=2, XDP_DROP=1).
   - Reads ahhs_dbg[0] (reconstruction error).
3. If running offline / on macOS:
   - Evaluates via ref_int_forward.int_forward() (the bit-identical twin).
4. Verifies 100% agreement on return code and error value against golden_tier3.json.

Usage:
    python3 run_selftest.py [--live] [--golden golden_tier3.json]
"""

import argparse
import json
import os
import re
import subprocess
import struct
import sys

import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..")) if os.path.basename(SCRIPT_DIR) in ("tests", "scripts", "bpf") else SCRIPT_DIR
for p in [ROOT_DIR, os.path.join(ROOT_DIR, "scripts"), os.path.join(ROOT_DIR, "tests"), os.path.join(ROOT_DIR, "bpf"), os.path.join(ROOT_DIR, "models")]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

def find_file(fname):
    candidates = [
        fname,
        os.path.join(ROOT_DIR, fname),
        os.path.join(ROOT_DIR, "models", fname),
        os.path.join(ROOT_DIR, "bpf", fname),
        os.path.join(ROOT_DIR, "scripts", fname),
        os.path.join(ROOT_DIR, "tests", fname),
        os.path.join(ROOT_DIR, "data", fname),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return fname

from ref_int_forward import int_forward


def load_model(bin_path: str = "ahhs_model.bin") -> dict:
    """Parse ahhs_model.bin according to struct ahhs_model layout."""
    actual_path = find_file(bin_path)
    with open(actual_path, "rb") as f:
        data = f.read()
    assert len(data) == 592, f"Expected 592 bytes, got {len(data)}"

    # Unpack matching <44i4iII384b8B
    unpacked = struct.unpack("<44i4iII384b8B", data)
    b1 = np.array(unpacked[0:16], dtype=np.int32)
    b2 = np.array(unpacked[16:20], dtype=np.int32)
    b3 = np.array(unpacked[20:36], dtype=np.int32)
    b4 = np.array(unpacked[36:44], dtype=np.int32)

    M1, M2, M3, M4 = unpacked[44:48]
    theta = unpacked[48]
    version = unpacked[49]

    w1 = np.array(unpacked[50:178], dtype=np.int8).reshape(16, 8)
    w2 = np.array(unpacked[178:242], dtype=np.int8).reshape(4, 16)
    w3 = np.array(unpacked[242:306], dtype=np.int8).reshape(16, 4)
    w4 = np.array(unpacked[306:434], dtype=np.int8).reshape(8, 16)

    zp = np.array(unpacked[434:442], dtype=np.uint8)

    return {
        "b1": b1, "b2": b2, "b3": b3, "b4": b4,
        "M1": M1, "M2": M2, "M3": M3, "M4": M4,
        "theta": theta, "version": version,
        "w1": w1, "w2": w2, "w3": w3, "w4": w4,
        "zp": zp,
    }


def make_packet(feat_u8: list) -> bytes:
    """Synthesize 22-byte packet: 14-byte Ethernet header + 8 feature bytes."""
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    return eth_hdr + bytes(feat_u8)


def _run(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"command failed ({res.returncode}): {' '.join(cmd)}\n{res.stderr.strip()}")
    return res.stdout


def _parse_retval(out: str) -> int:
    """Parse `bpftool prog run` output. Accepts JSON ({"retval": N}) or text ("Return value: N, ...").
    NEVER defaults: an unparsable output must fail the test, not silently look like XDP_PASS."""
    try:
        j = json.loads(out)
        if isinstance(j, dict) and "retval" in j:
            return int(j["retval"])
    except (ValueError, TypeError):
        pass
    m = re.search(r"[Rr]eturn value:\s*(\d+)", out)
    if m:
        return int(m.group(1))
    raise RuntimeError(f"cannot parse retval from bpftool output: {out!r}")


def _parse_u32_value(out: str) -> int:
    """Parse `bpftool -j map lookup ...` (value as int, or list of bytes/hex strings)."""
    j = json.loads(out)
    if isinstance(j, list):                       # some versions wrap in a list
        j = j[0]
    v = j["value"] if isinstance(j, dict) and "value" in j else j
    if isinstance(v, int):
        return v
    if isinstance(v, list):
        bs = [int(x, 16) if isinstance(x, str) else int(x) for x in v]
        return struct.unpack("<I", bytes(bs[:4]))[0]
    raise RuntimeError(f"cannot parse map value from: {out!r}")


def test_live_bpftool(pkt_bytes: bytes) -> tuple:
    """Run packet through pinned self-test via bpftool prog run (needs root + loaded pipeline)."""
    pkt_path = "/tmp/ahhs_selftest_pkt.bin"
    with open(pkt_path, "wb") as f:
        f.write(pkt_bytes)
    out = _run(["bpftool", "-j", "prog", "run", "pinned", "/sys/fs/bpf/ahhs/prog_ahhs_t3_selftest",
                "data_in", pkt_path, "data_out", "/dev/null", "repeat", "1"])
    ret_code = _parse_retval(out)
    dbg = _run(["bpftool", "-j", "map", "lookup", "pinned", "/sys/fs/bpf/ahhs/ahhs_dbg",
                "key", "0", "0", "0", "0"])
    return ret_code, _parse_u32_value(dbg)


def main():
    parser = argparse.ArgumentParser(description="Run Tier 3 Autoencoder Self-Test on Golden Trace")
    parser.add_argument("--golden", default="golden_tier3.json", help="Path to golden trace JSON")
    parser.add_argument("--model", default="ahhs_model.bin", help="Path to model binary")
    parser.add_argument("--live", action="store_true", help="Execute live via bpftool (requires Linux root)")
    args = parser.parse_args()

    print("=" * 65)
    print("AHHS-IDS: Tier 3 In-Kernel Self-Test Harness (§8)")
    print(f"Mode: {'Live (bpftool prog run)' if args.live else 'Offline Reference Verification'}")
    print("=" * 65)

    golden_path = find_file(args.golden)
    if not os.path.exists(golden_path):
        print(f"[-] Golden trace '{args.golden}' not found. Run export_tier3.py first.")
        sys.exit(1)

    with open(golden_path, "r") as f:
        golden = json.load(f)

    model = load_model(args.model)
    print(f"Loaded model from {args.model}: theta = {model['theta']}")
    print(f"Evaluating {len(golden)} golden trace vectors...")

    passed = 0
    failed = 0

    for item in golden:
        idx = item["index"]
        feat = item["feat_u8"]
        expected_err = item["err"]
        expected_anomaly = item["is_anomaly"]
        expected_verdict = 1 if expected_anomaly else 2  # XDP_DROP=1, XDP_PASS=2

        pkt = make_packet(feat)

        if args.live:
            actual_verdict, actual_err = test_live_bpftool(pkt)
        else:
            _, _, actual_err, actual_anomaly = int_forward(np.array(feat, dtype=np.uint8), model)
            actual_verdict = 1 if actual_anomaly else 2

        err_match = (actual_err == expected_err)
        verdict_match = (actual_verdict == expected_verdict)

        if err_match and verdict_match:
            passed += 1
        else:
            failed += 1
            print(f"  [✗ MISMATCH] Vector {idx:3d}: "
                  f"feat={feat} | err: got {actual_err}, expected {expected_err} | "
                  f"verdict: got {actual_verdict}, expected {expected_verdict}")

    print("\n" + "=" * 65)
    print(f"SELF-TEST RESULTS: {passed}/{len(golden)} PASSED ({100.0 * passed / len(golden):.1f}%)")
    print("=" * 65)

    if failed == 0:
        print("[✓] ALL GOLDEN VECTORS MATCHED WITH 100% BIT-PARITY.\n")
        sys.exit(0)
    else:
        print(f"[!] WARNING: {failed} vector(s) failed verification.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
