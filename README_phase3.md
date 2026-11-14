# AHHS-IDS Phase 3: Chained Quantized Autoencoder

Adaptive Hybrid Hardware-Software Intrusion Detection System (AHHS-IDS) — Phase 3 implementation extending the in-kernel eBPF/XDP security pipeline with an int8-quantized, 4-program, tail-call-chained deep autoencoder for anomalous flow detection.

**Course:** Advanced Operating Systems / USP Project  
**Authors:**
- **Challarapu Abhiram** (Roll No: 24CS10090)
- **Karri Venkata Karrenna Vybhav** (Roll No: 24CS10099)
- **Kolli Surya Shashank** (Roll No: 24CS10101)

**Key Documentation Guides:**
- [`DEMO.md`](DEMO.md) — Step-by-step demonstration guide (5 modes). Run `make demo` or `python3 scripts/demonstrate.py`.
- [`TIERS_EXPLAINED.md`](TIERS_EXPLAINED.md) — Comprehensive architectural breakdown of Tier 1, Tier 2, and Tier 3.
- [`REPORT.md`](REPORT.md) — Academic term project final report.
- [`AHHS_CICIDS2017_Exhaustive_Training.ipynb`](AHHS_CICIDS2017_Exhaustive_Training.ipynb) — Turnkey Google Colab notebook for the Canadian Institute for Cybersecurity CIC-IDS-2017 dataset.
- [`presentation/AHHS_IDS_Comprehensive_Architecture_and_Defense.pptx`](presentation/AHHS_IDS_Comprehensive_Architecture_and_Defense.pptx) — Publication-grade 18-slide presentation deck.
- [`presentation/index.html`](presentation/index.html) — Interactive animated presentation and telemetry dashboard.

---

## 1. Architecture Overview

```
 [ Ingress Network Packet ]
             │
             ▼
 ┌─────────────────────────────────────────────────────────┐
 │ TIER 1: In-Kernel Decision Tree Pre-Filter (XDP Hook)   │
 │   - Classifies 5-tuple: src_ip, dst_ip, ports, proto   │
 │   ├─ Known Benign   ──▶ XDP_PASS                        │
 │   ├─ Known Attack   ──▶ XDP_DROP                        │
 │   └─ Ambiguous Flow ──▶ Route to Tier 2                 │
 └───────────────────────────┬─────────────────────────────┘
                             │
                             ▼
 ┌─────────────────────────────────────────────────────────┐
 │ TIER 2: Stateful LRU Sliding Window Tracking            │
 │   - Fast-path check: ahhs_blocklist ──hit──▶ XDP_DROP   │
 │   - Update per-window accumulators (bytes, IAT, SYN)    │
 │   - Trigger: (pkts >= 100 OR time > 1s) AND pkts >= 8   │
 │   - §5.6 Hard Reset: time > 10s AND pkts < 8 (stale)    │
 │   - Extract 8 uint8 features into ahhs_scratch_map      │
 │   - Trigger Tier 3 via bpf_tail_call(AHHS_T3_L1)        │
 └───────────────────────────┬─────────────────────────────┘
                             │
                             ▼
 ┌─────────────────────────────────────────────────────────┐
 │ TIER 3: Chained Quantized Autoencoder (4 XDP Programs)  │
 │   Layer 1 (ahhs_t3_l1): x = feat - zp; 8  -> 16 (ReLU)  │
 │     └─ bpf_tail_call(AHHS_T3_L2)                        │
 │   Layer 2 (ahhs_t3_l2): 16 -> 4 (ReLU, Latent space)    │
 │     └─ bpf_tail_call(AHHS_T3_L3)                        │
 │   Layer 3 (ahhs_t3_l3): 4  -> 16 (ReLU)                 │
 │     └─ bpf_tail_call(AHHS_T3_L4)                        │
 │   Layer 4 (ahhs_t3_l4): 16 -> 8 (Linear output)         │
 │     └─ Compute squared error: err = Σ (x_i - y_i)²      │
 │     └─ err > θ ? Add flow to ahhs_blocklist, XDP_DROP   │
 │                : Normal flow, return XDP_PASS           │
 └─────────────────────────────────────────────────────────┘
   Fail-Open Guarantee: Any map lookup or tail-call failure
   safely forwards the packet (XDP_PASS) and increments telemetry.
```

---

## 2. Repository Structure (§9 Deliverables)

| File / Path | Description | Spec Reference |
|---|---|---|
| `bpf/ahhs_common.h` | Shared constants, structs (`ahhs_model` 592B, `ahhs_scratch`), all 9 maps, `log2q3`, dense macros | §3, §4, §6.1 |
| `bpf/xdp_ahhs_tier1.c` | Minimal diff adding blocklist fast-path, window accumulators, and Tier 3 tail call | §5 |
| `bpf/xdp_ahhs_tier3.c` | 4 chained XDP dense layer programs (`ahhs_t3_l1..l4`) + in-kernel self-test program (`ahhs_t3_selftest`) | §6 |
| `bpf/tier1_tree.h` | Transpiled static inline decision tree header for Tier 1 fast-path | §2 |
| `bpf/ahhs_loader.c` | High-performance C userspace loader using `libbpf` to load, pin programs, and attach the pipeline | §8 |
| `bpf/load_pipeline.sh` | Bash automated loader and fallback controller with bpftool support | §8 |
| `scripts/ahhs_features.py` | Python bit-identical mirror of integer log2 (`log2q3`) and window feature extraction | §3, §5 |
| `scripts/ref_int_forward.py` | Pure integer inference reference in NumPy (`requant`, `dense`, `int_forward`) | §6.1, §7.4 |
| `scripts/train_tier1.py` | Decision tree classifier trainer & C code transpiler for Tier 1 fast-path | §2 |
| `scripts/build_cicids2017_notebook.py` | Turnkey generator for official CIC-IDS-2017 training and export notebook | §7.1 |
| `AHHS_CICIDS2017_Exhaustive_Training.ipynb` | Complete reproducible notebook for QAT autoencoder training on official CIC-IDS-2017 data | §7.2, §7.3 |
| `scripts/send_traffic.py` | Live test packet generator for live demonstrations and testing | §8 |
| `tests/test_phase3_quality.py`| Regression test suite (20 tests checking model sanity, split disjointness, kernel parity) | Quality Gate |
| `tests/run_selftest.py` | Self-test harness looping over all 240 vectors in `golden_tier3.json` to verify error and verdict | §8 |
| `tests/test_pipeline.py` | Comprehensive verification test suite (73 passing tests covering all tiers and math parity) | §8 |
| `models/ahhs_model.bin` | In-kernel 592-byte model binary matching `struct ahhs_model` bit-for-bit | §7.3 |
| `models/golden_tier3.json` | 240 stratified golden test vectors for kernel bit-parity verification | §8 |
| `Makefile` | Multi-target build system for BPF objects, `ahhs.o` linker, libbpf loader, and validation | §8 |
| `README_phase3.md` | Architecture, reproduction steps, commands, and limitations | §9 |

---

## 3. End-to-End Execution Guide

Follow these commands to generate the training notebook, train Tier 1, export, build, load, and test the entire AHHS-IDS pipeline:

### Step 1: Generate & Run Official CIC-IDS-2017 Training Notebook
```bash
python3 scripts/build_cicids2017_notebook.py
```
*Executes `AHHS_CICIDS2017_Exhaustive_Training.ipynb` (in Google Colab or local GPU/CPU), ingesting official Canadian Institute for Cybersecurity (CIC-IDS-2017) datasets (Monday Benign, Friday PortScan, Wednesday DoS Slowloris), training the Quantization-Aware Autoencoder with STE, calibrating threshold $\theta=58$, and exporting `models/ahhs_model.bin` (592 bytes) and `models/golden_tier3.json` (240 golden trace vectors).*

### Step 2: Train Tier 1 Decision Tree & Transpile to C
```bash
python3 scripts/train_tier1.py
```
*Trains the shallow decision tree on destination ports and transpiles verifier-safe static inline C code to `bpf/tier1_tree.h`.*

### Step 3: Quality Gate & Verification
```bash
# Run comprehensive pipeline tests (73 tests):
python3 tests/test_pipeline.py

# Run quality regression tests (20 tests):
python3 tests/test_phase3_quality.py

# Run offline integer parity test across all 240 golden vectors:
python3 tests/run_selftest.py

# Or run the full automated test suite via Makefile:
make test
```

### Quality Gate Results (Official CIC-IDS-2017 Dataset)

Evaluated across **12,100 held-out test windows (1,210,000 packets)** from the official Canadian Institute for Cybersecurity (CIC-IDS-2017) dataset:

- **Total Test Windows**: 12,100 (2,100 held-out benign, 5,000 PortScan, 5,000 DoS Slowloris)
- **Deployed Threshold ($\theta$)**: 58
- **ROC-AUC (Overall Multi-Tier)**: **0.9567**
- **Detection Rate (TPR @ $\theta$)**: **85.07%**
- **PortScan Detection**: **100.00%** (AUC: 1.0000)
- **DoS Slowloris Detection**: **70.14%** (AUC: 0.9135)
- **False Positive Rate (FPR @ $\theta$)**: **9.81%**
- **Bit-Exact Self-Test Parity**: **240/240 Passed (100.0%)**

---

## 4. Linux Build, Load & In-Kernel Verification

> [!IMPORTANT]
> The steps below require a Linux environment with kernel $\ge 5.10$, Clang/LLVM, libbpf, and root privileges (`CAP_BPF`, `CAP_NET_ADMIN`). macOS cannot execute BPF kernel attachments or Apple Clang BPF compilation.

### Build and Probe Verifier
```bash
make clean all

# Probe all BPF programs with Linux verifier and inspect log:
sudo bpftool -d prog loadall ahhs.o /sys/fs/bpf/ahhs_probe
sudo rm -rf /sys/fs/bpf/ahhs_probe
```

### Attach Pipeline
```bash
# Load and pin maps & programs (explicitly named prog_<name>):
sudo ./ahhs_loader eth0 ahhs.o ahhs_model.bin &

# Confirm 4 chained layers in prog_array:
sudo bpftool map show name ahhs_t3_prog_array
```

### Live In-Kernel Golden Trace Parity Test
```bash
# Runs every golden vector through the in-kernel self-test prog (/sys/fs/bpf/ahhs/prog_ahhs_t3_selftest):
make selftest-live
# (Executes: sudo python3 run_selftest.py --live)
```
*Validates 240/240 vectors with exact equality between `ahhs_dbg[0]` and integer reference error.*

### Flood Test with Fixed Flow Key
To ensure packets aggregate into the same 5-tuple flow key and trigger window evaluation, the source port must remain fixed:
```bash
# Destination port 8080 (AMBIGUOUS range), pinned source port (-s 40000 -k), 10ms IAT (-i u10000):
sudo hping3 --syn -p 8080 -s 40000 -k -i u10000 <target-ip> -c 300

# Inspect telemetry counters and blocklist:
sudo bpftool map dump name tier1_stats_map
sudo bpftool map dump name ahhs_t3_stats
sudo bpftool map dump name ahhs_blocklist
sudo bpftool map dump name flow_lru_map
```

---

## 5. Architectural Parity & Design Guarantees

1. **Window Clock Reset Parity (§5)**:
   In `xdp_ahhs_tier1.c`, the window clock resets at the time of the packet that triggered the window (`flow->w_start_ns = current_time`). `ahhs_features.py` mirrors this exact timing rather than restarting at the first packet of the subsequent window, eliminating train/serve feature skew.
2. **Packet Length Parity**:
   Kernel `pkt_len` subtracts `sizeof(struct ethhdr)` (14 bytes) from raw frame length `data_end - data`, ensuring `w_bytes`, `w_len_max`, and variance are computed on IP-level packet sizes (40–1500 bytes) matching the in-kernel feature extraction standard.
3. **Fixed Output Quantization Scale**:
   Layer 4 output scale is fixed to $2^{-5}$ ($1/32$) in both the trainer and exporter, matching the input scale so that $x_q$ and $y_q$ reside in identical units inside $\text{err} = \sum (x_{q,i} - y_{q,i})^2$.
4. **Active Set Masking Hardening**:
   In `ahhs_t3_l1..l4`, active set index lookups apply `& 1` (`set = *idx & 1`), bounding memory accesses strictly to the two double-buffered model slots.
5. **Fail-Open Safety**:
   Any map lookup failure, unpopulated program array index, or tail-call overflow returns `XDP_PASS` and increments `AHHS_STAT_FAILOPEN`.

---

## 6. Limitations

- **Dataset Scope**: Evaluated across 12,100 flow windows from the official Canadian Institute for Cybersecurity (CIC-IDS-2017) benchmark dataset.
- **Window-Level Scope**: Inferences occur per sliding window (100 packets or 1 second), not on individual packets.
- **Feature Dimensionality**: Features are compressed to 8 integer `uint8` values (`log2q3` scaled) to fit within eBPF verifier instruction budgets.
- **Blocklist Expiry Heuristic**: Flow blocklisting uses a 60-second LRU TTL heuristic (`AHHS_BLOCK_TTL_NS`).
