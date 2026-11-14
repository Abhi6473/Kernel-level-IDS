#!/usr/bin/env python3
"""
AHHS-IDS (Adaptive Hybrid Hardware-Software Intrusion Detection System)
Phase 1: Tier 1 Lightweight Decision Tree Pre-Filter Training & C Transpiler

This script:
1. Generates realistic network traffic data with standard 5-tuple features:
   - src_ip   (32-bit uint)
   - dst_ip   (32-bit uint)
   - src_port (16-bit uint)
   - dst_port (16-bit uint)
   - protocol (8-bit uint: 6=TCP, 17=UDP)
   Traffic includes:
   - Benign: standard services (HTTP 80, HTTPS 443, DNS 53, NTP 123)
   - Malicious: known exploits/backdoors (Telnet 23, Mirai 2323, Metasploit 4444, Backdoors 1337, 31337)
   - Ambiguous: dynamic services / ephemeral microservices (ports 5001-10000) forwarded to Tier 2
2. Trains a shallow scikit-learn DecisionTreeClassifier (max_depth 3-4).
   Keeping the tree shallow guarantees compliance with the eBPF verifier's
   instruction limit and branch complexity constraints.
3. Transpiles the model into an eBPF-compliant C header (`tier1_tree.h`) using
   `emlearn`, stripping any floating-point math to satisfy the eBPF verifier.
"""

import os
import re
import socket
import struct
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
import emlearn

# Restore standard IEEE 754 numerical handling (emlearn alters errstate during import)
np.seterr(all="ignore")

# ---------------------------------------------------------------------------
# Label Definitions
# ---------------------------------------------------------------------------
LABEL_BENIGN    = 0  # High confidence benign -> XDP_PASS
LABEL_MALICIOUS = 1  # High confidence malicious -> XDP_DROP
LABEL_AMBIGUOUS = 2  # Ambiguous / suspicious -> Forward to Tier 2 LRU Tracking

def ip2int(ip_str: str) -> int:
    """Convert dotted-decimal IPv4 string to 32-bit host-order integer."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def generate_5tuple_port_dataset(n_samples: int = 6000):
    """
    Generate representative 5-tuple network traffic across realistic network subnets:
    - Benign: standard web (80, 443), DNS (53), NTP (123)
    - Malicious: known malicious ports/signatures (23, 1337, 2323, 4444, 31337)
    - Ambiguous: non-standard high ports (5001-10000) requiring stateful sliding-window
                 analysis in Tier 2
    """
    np.random.seed(42)
    X = []
    y = []

    subnets = ["192.168.1", "10.0.0", "172.16.1"]

    # 1. Benign Traffic (Web browsing, DNS, NTP)
    n_benign = int(n_samples * 0.4)
    benign_ports = [53, 80, 123, 443]
    for _ in range(n_benign):
        src_sub = np.random.choice(subnets)
        src_ip = ip2int(f"{src_sub}.{np.random.randint(2, 250)}")
        dst_ip = ip2int(f"{np.random.randint(11, 220)}.{np.random.randint(1, 250)}.{np.random.randint(1, 250)}.{np.random.randint(2, 250)}")
        src_port = np.random.randint(1024, 65535)
        dst_port = int(np.random.choice(benign_ports))
        proto = 17 if dst_port in [53, 123] and np.random.rand() > 0.3 else 6
        X.append([src_ip, dst_ip, src_port, dst_port, proto])
        y.append(LABEL_BENIGN)

    # 2. Malicious Traffic (Known exploit ports, shell backdoors, C2 beacons, Mirai)
    n_malicious = int(n_samples * 0.3)
    malicious_ports = [23, 1337, 2323, 4444, 31337]
    for _ in range(n_malicious):
        src_sub = np.random.choice(subnets)
        src_ip = ip2int(f"{src_sub}.{np.random.randint(2, 250)}")
        dst_ip = ip2int(f"{np.random.randint(11, 220)}.{np.random.randint(1, 250)}.{np.random.randint(1, 250)}.{np.random.randint(2, 250)}")
        src_port = np.random.randint(1024, 65535)
        dst_port = int(np.random.choice(malicious_ports))
        proto = 6  # TCP
        X.append([src_ip, dst_ip, src_port, dst_port, proto])
        y.append(LABEL_MALICIOUS)

    # 3. Ambiguous Traffic (Suspicious dynamic services, microservices, non-standard web)
    n_ambiguous = n_samples - n_benign - n_malicious
    for _ in range(n_ambiguous):
        src_sub = np.random.choice(subnets)
        src_ip = ip2int(f"{src_sub}.{np.random.randint(2, 250)}")
        dst_ip = ip2int(f"{np.random.randint(11, 220)}.{np.random.randint(1, 250)}.{np.random.randint(1, 250)}.{np.random.randint(2, 250)}")
        src_port = np.random.randint(1024, 65535)
        dst_port = np.random.randint(5001, 10000)
        proto = int(np.random.choice([6, 17]))
        X.append([src_ip, dst_ip, src_port, dst_port, proto])
        y.append(LABEL_AMBIGUOUS)

    return np.array(X, dtype=np.uint32), np.array(y, dtype=np.int32)

def clean_code_for_ebpf(c_code: str, model_name: str = "tier1_tree") -> str:
    """
    Format emlearn output to strictly adhere to eBPF constraints:
    1. eBPF kernel forbids floating-point instructions/types. We guard
       tier1_tree_predict_proba with `#if !defined(__bpf__) && !defined(__BPF__)`.
    2. Force `static __always_inline` on all evaluation functions so the compiler
       inlines them directly into the XDP entrypoint without external symbols.
    3. Include proper include guards, decision macro definitions, and pragmas.
    """
    # Guard float-based predict_proba for eBPF targets
    idx = c_code.find(f"{model_name}_predict_proba")
    if idx != -1:
        start_line = c_code.rfind("\n", 0, idx)
        c_code_clean = (
            c_code[:start_line]
            + "\n#if !defined(__bpf__) && !defined(__BPF__)\n"
            + c_code[start_line:].strip()
            + "\n#endif /* !__BPF__ */\n"
        )
    else:
        c_code_clean = c_code

    # Guard #include <stdint.h> from BPF target compilation and supply kernel typedefs
    c_code_clean = re.sub(
        r'#include\s+<stdint\.h>',
        '#if defined(__bpf__) || defined(__BPF__)\ntypedef __s32 int32_t;\ntypedef __u32 uint32_t;\n#else\n#include <stdint.h>\n#endif',
        c_code_clean
    )

    # Ensure predict function is static __always_inline
    c_code_clean = re.sub(
        r'int32_t\s+' + re.escape(model_name) + r'_predict\s*\(',
        f'static __always_inline int32_t {model_name}_predict(',
        c_code_clean
    )
    # Ensure helper sub-trees are also static __always_inline
    c_code_clean = re.sub(
        r'static inline int32_t\s+' + re.escape(model_name) + r'_tree_',
        f'static __always_inline int32_t {model_name}_tree_',
        c_code_clean
    )

    header = f"""/* =========================================================================
 * AHHS-IDS: Tier 1 Lightweight Decision Tree (Auto-Generated via emlearn)
 * STRICT eBPF CONSTRAINTS APPLIED:
 * - Pure integer arithmetic (uint32_t features, no floating-point registers)
 * - All evaluation functions qualified with static __always_inline
 * - Shallow depth to guarantee verifier complexity < 1M instructions
 * ========================================================================= */

#ifndef TIER1_TREE_H
#define TIER1_TREE_H

#include <linux/types.h>

/* Tier 1 Actions */
#define TIER1_ACTION_PASS      0  /* Benign packet: immediately XDP_PASS */
#define TIER1_ACTION_DROP      1  /* Malicious packet: immediately XDP_DROP */
#define TIER1_ACTION_AMBIGUOUS 2  /* Ambiguous flow: pass to Tier 2 LRU tracking */

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
"""

    footer = """
#pragma clang diagnostic pop

#endif /* TIER1_TREE_H */
"""
    return header + c_code_clean.strip() + footer

def main():
    print("=" * 65)
    print("AHHS-IDS: Phase 1 Tier 1 Decision Tree Training & Transpilation")
    print("=" * 65)

    # 1. Generate / Prepare Data
    print("[+] Generating 5-tuple network dataset (Benign, Malicious, Ambiguous)...")
    X, y = generate_5tuple_port_dataset(n_samples=6000)
    print(f"    Total samples: {len(X)} | Features: [src_ip, dst_ip, src_port, dst_port, proto]")

    # 2. Train Shallow Decision Tree
    # Max depth between 3 and 4 strictly respects eBPF verifier limits
    tree_depth = 4
    print(f"[+] Training DecisionTreeClassifier (max_depth={tree_depth})...")
    clf = DecisionTreeClassifier(max_depth=tree_depth, random_state=42)
    clf.fit(X, y)

    train_acc = clf.score(X, y)
    print(f"[+] Model Accuracy: {train_acc * 100:.2f}%")
    print(f"    Leaf nodes: {clf.get_n_leaves()} | Tree depth: {clf.get_depth()}")
    print("    Feature importances:")
    feature_names = ["src_ip", "dst_ip", "src_port", "dst_port", "proto"]
    for fname, imp in zip(feature_names, clf.feature_importances_):
        print(f"      - {fname}: {imp * 100:.2f}%")

    # 3. Transpile to C using emlearn
    print("[+] Transpiling Decision Tree to C code using emlearn (method='inline')...")
    model = emlearn.convert(clf, method='inline', dtype='uint32_t')
    raw_c = model.save(name='tier1_tree')

    # 4. Clean and adapt for eBPF kernel execution
    print("[+] Enforcing eBPF kernel constraints (removing float ops, inlining)...")
    ebpf_c_header = clean_code_for_ebpf(raw_c, model_name="tier1_tree")

    output_path = "bpf/tier1_tree.h" if os.path.exists("bpf") else "tier1_tree.h"
    with open(output_path, "w") as f:
        f.write(ebpf_c_header)

    print(f"[✓] Successfully generated eBPF header: {output_path}")
    print("=" * 65)

if __name__ == "__main__":
    main()
