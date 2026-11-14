# AHHS-IDS: Adaptive Hybrid Hardware-Software Intrusion Detection System
## Multi-Tier In-Kernel eBPF/XDP Deep Learning Security Architecture

[![Kernel](https://img.shields.io/badge/Linux_Kernel-%E2%89%A55.10-blue.svg)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-orange.svg)](https://ebpf.io)
[![Dataset](https://img.shields.io/badge/Dataset-CIC--IDS--2017-green.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![Bit Parity](https://img.shields.io/badge/Golden_Parity-240%2F240_(100%25)-purple.svg)](models/golden_tier3.json)
[![Detection](https://img.shields.io/badge/Detection_Rate-85.07%25-brightgreen.svg)](models/evaluation_summary.json)

**Course Term Project** — *Advanced Operating Systems / USP Project*  
**Authors:**
- **Challarapu Abhiram** (Roll No: 24CS10090)
- **Karri Venkata Karrenna Vybhav** (Roll No: 24CS10099)
- **Kolli Surya Shashank** (Roll No: 24CS10101)

---

## 1. Executive Summary

**AHHS-IDS** is a high-performance network intrusion detection system executed entirely inside the Linux kernel data path using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)**.

Existing kernel-level IDSes face a severe architectural dilemma:
1. **Static In-Kernel Filters (e.g., bpfilter)**: Execute at wire speed ($10\text{--}12\text{ ns}$), but provide **0% protection against zero-day or behavioral shifts**.
2. **Monolithic Per-Packet ML (e.g., Lucid-XDP)**: Running neural networks on every packet collapses single-core throughput to **$\approx 1.2\text{ Mpps}$** (>95% of packets are dropped at 40 Gbps, causing a self-inflicted DoS).
3. **Hybrid RingBuffer Offload (e.g., Falco, Tetragon)**: Pushing packet events to userspace introduces a **$5\text{ to }50\text{ ms}$ reaction delay**, allowing **over 300,000 attack packets into the host** before a rule can be applied.

AHHS-IDS breaks this deadlock through **hierarchical stateful amortization**:
- **Tier 1 (Stateless Wire-Speed Pre-Filter)**: A branchless C decision tree classifying known ports in **$11.8\text{ ns}$** ($O(1)$) directly at NIC driver ingress, resolving ~90% of traffic.
- **Tier 2 (Stateful LRU Sliding Window)**: An LRU hash map (`flow_lru_map`, 65,536 capacity) tracking connection states and accumulating flow statistics over 100 packets or 1.0 second in **$45\text{ ns}$**.
- **Tier 3 (Deep In-Kernel Quantized Autoencoder)**: A 4-program, tail-call-chained neural network ($8 \to 16 \to 4 \to 16 \to 8$, 428 parameters, 592 bytes) running pure integer $Q_{24}$ arithmetic without floating-point registers. Amortized cost is just **$3.42\text{ ns}$ per packet**.
- **Immediate In-Kernel Quarantine**: Anomalous flows ($\text{err} > \theta$) are inserted into an in-kernel blocklist (`ahhs_blocklist`) with a 60-second TTL in **$< 1\text{ }\mu\text{s}$**, ensuring **0 attack packets breach the host**.

### Key Empirical Results on Official CIC-IDS-2017 Dataset

Trained and evaluated on **12,100 held-out windows (1,210,000 packets)** from the official Canadian Institute for Cybersecurity (**CIC-IDS-2017**) benchmark:

| Metric | Measured Value | Operational Significance |
| :--- | :---: | :--- |
| **Combined Detection Rate (TPR @ $\theta=58$)** | **`85.07%`** | Detected 8,507 of 10,000 held-out attack windows |
| **Friday PortScan Detection Rate** | **`100.00%`** | **5,000 / 5,000** attack windows caught (AUC: 1.0000) |
| **Wednesday DoS Slowloris Detection Rate** | **`70.14%`** | **3,507 / 5,000** attack windows caught (AUC: 0.9135) |
| **Multi-Tier ROC-AUC** | **`0.9567`** | Near-optimal separation across all attack classes |
| **Benign False Positive Rate (FPR)** | **`9.81%`** | Evaluated on unseen Monday benign traffic |
| **Single-Core Line Throughput** | **`60.7 Mpps`** | **$50.6\times$ higher than Monolithic Kernel ML** |
| **Amortized Ingress Latency** | **`16.45 ns`** | Fully sustains 40G/100G wire-speed processing |
| **Attack Exposure Lag** | **$< 1\text{ }\mu\text{s}$** | **0 packets leak** after window evaluation |
| **Kernel Bit-Exact Parity** | **`240 / 240 (100%)`** | Golden trace vectors verified inside Linux 6.8 kernel |
| **In-Kernel Memory Allocation** | **`7.2 MB`** | 100% fits within CPU L3 cache ($<0.1\%$ system RAM) |
| **BPF Verifier Complexity** | **`< 600 insns`** | Safe against 1,000,000 BPF instruction limit |

---

## 2. Architecture & Pipeline Flow

```
                      [ Raw Network Packet Ingress ]
                                     │
                                     ▼
                   ┌───────────────────────────────────┐
                   │    TIER 1: Pre-Filter (Tree)      │
                   │   Matches 5-Tuple at Wire Speed   │
                   └─────────────────┬─────────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
             Known Benign        Known Attack        Ambiguous
            (e.g., Port 80)     (e.g., Port 4444)   (e.g., Port 8080)
                 │                   │                   │
                 ▼                   ▼                   ▼
            [ XDP_PASS ]        [ XDP_DROP ]    ┌──────────────────────┐
                                                │ TIER 2: LRU Window   │
                                                │ flow_lru_map lookup  │
                                                └──────────┬───────────┘
                                                           │
                                        ┌──────────────────┴──────────────────┐
                                        │ Fast Blocklist Match?               │
                                        │ (ahhs_blocklist expiry > ktime)     │
                                        └──────────┬──────────────────────────┘
                                                   │
                                      ┌────────────┴────────────┐
                                      ▼                         ▼
                                   [ YES ]                   [ NO ]
                                      │                         │
                                 [ XDP_DROP ]        Accumulate w_pkts, w_bytes,
                                                     IAT sum/max, length sq.
                                                                │
                                                    Window Full? (100 pkts / 1s)
                                                                │
                                                                ▼
                                                     Extract 8 uint8 features
                                                     Write to ahhs_scratch_map
                                                     Atomically reset window
                                                                │
                                                                ▼
                                                    bpf_tail_call(ahhs_t3_prog_array, 0)
                                                                │
    ┌───────────────────────────────────────────────────────────┴────────────────────────┐
    │                                                                                    │
    │                           TIER 3: CHAINED AUTOENCODER                              │
    │                                                                                    │
    │   [Program 0: ahhs_t3_l1] ──► Dense Layer 1:  8 → 16 (ReLU)                        │
    │                               bpf_tail_call(ahhs_t3_prog_array, 1)                 │
    │                                           │                                        │
    │   [Program 1: ahhs_t3_l2] ──► Dense Layer 2: 16 →  4 (ReLU Bottleneck)             │
    │                               bpf_tail_call(ahhs_t3_prog_array, 2)                 │
    │                                           │                                        │
    │   [Program 2: ahhs_t3_l3] ──► Dense Layer 3:  4 → 16 (ReLU Decoder Expansion)      │
    │                               bpf_tail_call(ahhs_t3_prog_array, 3)                 │
    │                                           │                                        │
    │   [Program 3: ahhs_t3_l4] ──► Dense Layer 4: 16 →  8 (Linear Reconstruction)       │
    │                               Compute err = Σ(x_q[i] - y[i])²                      │
    │                                                                                    │
    │                                        err > θ (58)?                               │
    │                                              │                                     │
    │                            ┌─────────────────┴─────────────────┐                   │
    │                            ▼                                   ▼                   │
    │                         [ YES ]                             [ NO ]                 │
    │               Record AHHS_STAT_ANOMALY             Record AHHS_STAT_NORMAL         │
    │               Add to ahhs_blocklist (TTL: 60s)                 │                   │
    │                            │                                   ▼                   │
    │                            ▼                              [ XDP_PASS ]             │
    │                       [ XDP_DROP ]                                                 │
    └────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Repository Structure

```text
ebpf/
├── Makefile                                 # Build, test & deployment orchestration
├── README.md                                # This deployment and user guide
├── REPORT.md                                # Academic term project final report
├── TIERS_EXPLAINED.md                       # Comprehensive Tier 1, 2, 3 architectural guide
├── AHHS_CICIDS2017_Exhaustive_Training.ipynb# Turnkey Google Colab training notebook
├── vm_setup_and_run.sh                      # Turnkey VM environment provisioning script
│
├── bpf/                                     # Linux Kernel eBPF/XDP C Source & Headers
│   ├── xdp_ahhs_tier1.c                     # Modular Tier 1 Decision Tree & Tier 2 LRU Window Tracker
│   ├── xdp_ahhs_tier3.c                     # Tier 3 4-Program Chained Quantized Autoencoder
│   ├── ahhs_common.h                        # Shared BPF maps, structs (592B model), fixed-point math
│   ├── tier1_tree.h                         # Generated port-based static inline C decision tree
│   ├── ahhs_loader.c                        # Userspace libbpf loader & program array linker
│   └── load_pipeline.sh                     # Automated loader, model injector & fallback controller
│
├── scripts/                                 # Python ML Training, Features & Export Pipelines
│   ├── train_tier1.py                       # Tier 1 decision tree trainer (port-based)
│   ├── build_cicids2017_notebook.py         # Generator script for CIC-IDS-2017 Colab notebook
│   ├── ref_int_forward.py                   # Bit-identical integer reference forward pass
│   ├── ahhs_features.py                     # Fixed-point feature extractor & simulator
│   └── send_traffic.py                      # Live network traffic generator for pipeline testing
│
├── tests/                                   # Automated Quality & Verification Harnesses
│   ├── test_pipeline.py                     # 73-test end-to-end integration suite
│   ├── test_phase3_quality.py               # 20-test CIC-IDS-2017 quality regression suite
│   └── run_selftest.py                      # 240 golden vector bit-exact verification harness
│
├── models/                                  # Model Binaries, Golden Traces & Checkpoints
│   ├── ahhs_model.bin                       # 592-byte in-kernel model binary (CIC-IDS-2017, theta=58)
│   ├── golden_tier3.json                    # 240 bit-exact verification vectors (100% parity)
│   └── evaluation_summary.json              # Official CIC-IDS-2017 metrics (ROC-AUC 0.957, TPR 85.1%)
│
├── data/                                    # Dataset directory (.gitkeep)
│   └── .gitkeep
│
└── docs/                                    # Project guidelines, term paper & evaluation figures
    ├── ahhs_cicids2017_report.png           # 300 DPI publication evaluation dashboard
    ├── Term Paper and Term  Project Guideline.pdf
    └── USP_Project_term_paper.pdf
```

---

## 4. Step-by-Step Deployment & Usage Guide

### Prerequisites & Target Environment

To deploy and run AHHS-IDS directly inside the Linux kernel data path:
- **Operating System**: Linux (Ubuntu 20.04, 22.04, or 24.04 LTS recommended)
- **Kernel Version**: Linux Kernel $\ge 5.10$ with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, and `CONFIG_NET_CLS_ACT=y`
- **Toolchain**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y clang llvm libbpf-dev linux-tools-common \
      linux-tools-$(uname -r) bpftool iproute2 gcc make python3 python3-pip
  ```
- **Privileges**: Root access (`sudo`) or `CAP_BPF` + `CAP_NET_ADMIN` capabilities.

*(Note: On non-Linux systems such as macOS, the full test suite, Python reference math, and verification harnesses run out-of-the-box without root).*

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/Abhi6473/Kernel-level-IDS.git
cd Kernel-level-IDS
```

---

### Step 2: Build the eBPF Programs and Userspace Loader

Compile the Tier 1 pre-filter, Tier 3 chained neural network layers, combined BPF object, and the libbpf loader:

```bash
make clean
make all
```

**What this produces:**
- `bpf/xdp_ahhs_tier1.o`: Compiled Tier 1 decision tree and Tier 2 window tracker.
- `bpf/xdp_ahhs_tier3.o`: Compiled 4-layer chained neural network (`ahhs_t3_l1` .. `ahhs_t3_l4`) and self-test hook.
- `ahhs.o`: Combined linked BPF object generated via `bpftool gen object`.
- `ahhs_loader`: High-performance userspace loader linked with `libbpf`.
- `ahhs_model.bin`: The exact 592-byte in-kernel model binary ($\theta = 58$).

---

### Step 3: Probe the Linux BPF Verifier

Before attaching to network interfaces, verify that the Linux kernel verifier accepts all programs:

```bash
sudo bpftool -d prog loadall ahhs.o /sys/fs/bpf/ahhs_probe
sudo rm -rf /sys/fs/bpf/ahhs_probe
```
*(All 5 programs will load with `< 600` instructions and zero complexity rejections).*

---

### Step 4: Deploy and Attach to a Network Interface

You can load and attach AHHS-IDS using either the libbpf C loader or the automated bash loader script:

#### Option A: Using the Libbpf C Loader (Recommended)
```bash
# Syntax: sudo ./ahhs_loader <interface> <bpf_obj> <model_binary>
sudo ./ahhs_loader eth0 ahhs.o models/ahhs_model.bin &
```

#### Option B: Using the Automated Bash Script
```bash
# Attach to eth0 (or lo for local loopback testing)
sudo bash bpf/load_pipeline.sh eth0 xdpgeneric
```

**What happens during load:**
1. Mounts `/sys/fs/bpf` and creates `/sys/fs/bpf/ahhs`.
2. Loads and pins all 7 BPF maps (`flow_lru_map`, `ahhs_blocklist`, `ahhs_model_map`, `ahhs_nn_index`, etc.).
3. Populates `ahhs_t3_prog_array` with programs 0, 1, 2, and 3 for chained tail-calls.
4. Injects the 592-byte model binary `models/ahhs_model.bin` into `ahhs_model_map[0]`.
5. Sets `ahhs_nn_index = 0` (Active model slot).
6. Attaches `xdp_ahhs_tier1` directly to the interface via XDP hook.

---

### Step 5: Verify Active In-Kernel Telemetry & Maps

Check the status of the pipeline using standard `bpftool` commands or Makefile targets:

```bash
# 1. View all active AHHS maps:
sudo bpftool map list

# 2. Inspect Tier 1 statistics (PASS, DROP, AMBIGUOUS counters):
make dump-stats
# Or directly:
sudo bpftool map dump name tier1_stats_map

# 3. Inspect Tier 3 neural network telemetry (INVOCATIONS, ANOMALIES, NORMAL):
sudo bpftool map dump name ahhs_t3_stats

# 4. View active quarantined flows in blocklist:
sudo bpftool map dump name ahhs_blocklist

# 5. Inspect active connection states in LRU window tracker:
make dump-flows
```

---

### Step 6: Inject Test Traffic into the Pipeline

Send test traffic through the attached interface to observe in-kernel decisions:

```bash
# 1. Send normal HTTP traffic (Port 80 -> Expected: Tier 1 XDP_PASS):
python3 scripts/send_traffic.py --type normal --target 127.0.0.1

# 2. Send a 150-packet burst to dynamic Port 8080 (Triggers 100-packet window & Tier 3 Autoencoder):
python3 scripts/send_traffic.py --type flood --target 127.0.0.1 --src-port 40000

# 3. Inspect Tier 3 telemetry and confirm anomaly drop:
sudo bpftool map dump name ahhs_t3_stats
sudo bpftool map dump name ahhs_blocklist
```

*(Because the flood exceeds $\theta = 58$, Tier 3 marks `ANOMALY`, drops the packet, and writes the flow key `127.0.0.1:40000 -> 8080` to `ahhs_blocklist` with a 60-second TTL. Subsequent packets are dropped immediately in ~12 ns at Tier 1 fast-path).*

---

### Step 7: Live Zero-Downtime Model Hot-Swapping

Update the active neural network parameters without restarting the driver or dropping a single packet:

```bash
# 1. Inspect current active slot (0):
sudo bpftool map dump name ahhs_nn_index

# 2. Toggle active model slot from 0 to 1 atomically:
sudo bpftool map update name ahhs_nn_index key 0 0 0 0 value 1 0 0 0

# 3. Confirm active slot is now 1:
sudo bpftool map dump name ahhs_nn_index
```

---

### Step 8: Run Automated Quality Gates & Self-Tests

Execute the complete automated test suite verifying mathematics, model sanity, and bit-level kernel parity:

```bash
# 1. Run all 93 unit, pipeline, and quality regression tests:
make test

# 2. Run offline integer forward self-test across 240 golden trace vectors:
make selftest

# 3. Run live in-kernel self-test via BPF_PROG_TEST_RUN (requires Linux root):
make selftest-live
```

**Expected output:**
```text
SELF-TEST RESULTS: 240/240 PASSED (100.0%)
[✓] ALL GOLDEN VECTORS MATCHED WITH 100% BIT-PARITY.
```

---

### Step 9: Retrain on Official CIC-IDS-2017 Dataset

To retrain the model or reproduce the full experimental evaluation from scratch:

#### Option A: Google Colab Turnkey Notebook
1. Open Google Colab: [https://colab.research.google.com/](https://colab.research.google.com/)
2. Upload [`AHHS_CICIDS2017_Exhaustive_Training.ipynb`](AHHS_CICIDS2017_Exhaustive_Training.ipynb).
3. Select **Runtime -> Run all**.
4. The notebook downloads official Canadian Institute for Cybersecurity (CIC-IDS-2017) datasets (Monday Benign, Friday PortScan, Wednesday DoS Slowloris), executes Quantization-Aware Training with Straight-Through Estimators (STE), calibrates $\theta = 58$, generates the 300-DPI evaluation dashboard, packs `ahhs_model.bin` (592 bytes), and exports all artifacts into a downloadable ZIP archive.

#### Option B: Regenerate the Notebook Locally
```bash
python3 scripts/build_cicids2017_notebook.py
```

---

### Step 10: Unload and Detach the Pipeline

To cleanly detach the XDP program and unpin all BPF maps from `/sys/fs/bpf`:

```bash
make unload IFACE=eth0
```

---

## 5. Troubleshooting & FAQ

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| `Operation not permitted` | Missing Linux kernel privileges | Prepend `sudo` to loader and `bpftool` commands. |
| `Device or resource busy` | An XDP program is already attached | Detach existing program: `sudo ip link set dev <iface> xdp off`. |
| `Link has no XDP support` | Driver does not support native `xdpdrv` | Pass `xdpgeneric` (SKB mode) to `bpf/load_pipeline.sh <iface> xdpgeneric`. |
| `Cannot find bpftool` | Kernel tools not installed | Install matching package: `sudo apt-get install -y linux-tools-$(uname -r)`. |
| `Verification failed on non-Linux` | Host is macOS / Windows | macOS does not run Linux kernel BPF code; run live XDP commands inside an Ubuntu VM or container. Python tests run on any OS. |
