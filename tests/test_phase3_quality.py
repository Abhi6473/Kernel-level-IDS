#!/usr/bin/env python3
"""test_phase3_quality.py - Regression tests for the defects found in review.
Run after `make export3`:  python3 test_phase3_quality.py   (exit 1 on any failure)
"""
import json, os, sys
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

PASSED = FAILED = 0
def check(name, cond, detail=""):
    global PASSED, FAILED
    if cond: PASSED += 1; print(f"  [✓ PASS] {name}")
    else:    FAILED += 1; print(f"  [✗ FAIL] {name} - {detail}")

from run_selftest import load_model
from ref_int_forward import int_forward
import ahhs_features as F

print("\n== Q1: model/export sanity ==")
m = load_model(find_file("ahhs_model.bin"))
check("zero-points are NOT all zero (benign means)", int(np.sum(m["zp"])) > 0, f"zp={m['zp']}")
check("requant multipliers in (0, 2^31)", all(0 < m[f"M{i}"] < 2**31 for i in range(1, 5)))
summary = json.load(open(find_file("evaluation_summary.json")))
check("theta > 0 and < 520200 (max possible err)", 0 < m["theta"] < 520200, f"theta={m['theta']}")
check("dataset is official CIC-IDS-2017", summary.get("dataset") == "CIC-IDS-2017")

print("\n== Q2: output scale == input scale (fixed 2^-5) ==")
notebook_src = open(find_file("AHHS_CICIDS2017_Exhaustive_Training.ipynb")).read()
check("notebook uses fixed s_io = 1/32", "1.0 / 32.0" in notebook_src)
check("Layer-4 export uses fixed s_io scale", "s_out = s_io" in notebook_src)

print("\n== Q3: CIC-IDS-2017 held-out evaluation ==")
check("Total test windows >= 12,000", summary["total_test_windows"] >= 12000, f"n={summary['total_test_windows']}")
check("Tier 1 accuracy == 100%", summary["tier1_accuracy"] == 1.0, f"acc={summary['tier1_accuracy']}")
check("Tier 3 ROC-AUC >= 0.90", summary["tier3_roc_auc"] >= 0.90, f"AUC={summary['tier3_roc_auc']:.4f}")
check("Detection Rate (TPR @ theta) >= 85%", summary["tier3_tpr_at_theta"] >= 0.85, f"TPR={summary['tier3_tpr_at_theta']*100:.2f}%")
check("PortScan TPR >= 99%", summary["per_attack_detection"]["PortScan"]["tpr"] >= 0.99, f"TPR={summary['per_attack_detection']['PortScan']['tpr']*100:.2f}%")
check("DoS Slowloris TPR >= 70%", summary["per_attack_detection"]["DoS_Slowloris"]["tpr"] >= 0.70, f"TPR={summary['per_attack_detection']['DoS_Slowloris']['tpr']*100:.2f}%")

print("\n== Q4: golden trace quality ==")
g = json.load(open(find_file("golden_tier3.json")))
nd = sum(x["is_anomaly"] for x in g); npass = len(g) - nd
check(">= 200 golden vectors", len(g) >= 200, f"{len(g)}")
check(">= 60 expected-DROP and >= 60 expected-PASS", nd >= 60 and npass >= 60, f"drop={nd} pass={npass}")
check("golden err values reproduce from integer reference",
      all(int_forward(np.array(x["feat_u8"], dtype=np.uint8), m)[2] == x["err"] for x in g))
check("golden anomaly verdicts match err > theta",
      all((x["err"] > m["theta"]) == x["is_anomaly"] for x in g))

print("\n== Q5: Python window simulator == kernel semantics ==")
# 100 packets 1 ms apart -> exactly one window, emitted at packet 100; clock restarts at that packet
pk = [(i * 1_000_000, 100, False) for i in range(100)]
check("100-packet window emitted", len(F.window_features(pk)) == 1)
# 8 packets then a >1 s gap: kernel triggers on the 9th packet (time since w_start > 1 s, w_pkts>=8)
pk = [(i * 1_000_000, 100, False) for i in range(8)] + [(1_500_000_000, 100, False)]
check("timeout window (>=8 pkts, >1 s) emitted", len(F.window_features(pk)) == 1)
# after a trigger the next window's clock starts at the TRIGGER packet time (kernel), not at the next packet
pk = [(i * 1_000_000, 100, False) for i in range(100)]                 # window 1 closes at t=99 ms
pk += [(99_000_000 + 1_100_000_000, 100, False)]                         # 1.1 s after trigger pkt
pk += [(99_000_000 + 1_100_000_000 + (i + 1) * 1_000, 100, False) for i in range(8)]
w = F.window_features(pk)
check("window clock restarts at trigger packet (kernel parity)", len(w) == 2, f"windows={len(w)}")

print("\n== Q6: packet-length parity (IP-level sizes) ==")
t1_src = open(find_file("xdp_ahhs_tier1.c")).read()
check("kernel subtracts Ethernet header (14 bytes) for IP-level pkt_len",
      "sizeof(struct ethhdr)" in t1_src and "pkt_len -= sizeof(struct ethhdr)" in t1_src)

print(f"\nQUALITY TESTS: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
