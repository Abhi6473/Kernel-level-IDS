# AHHS-IDS: Tier-by-Tier Architectural Breakdown & Code Guide
## Adaptive Hybrid Hardware-Software Intrusion Detection System
**Course Term Project** — *Advanced Operating Systems / Systems Engineering*  
**Authors:** Challarapu Abhiram (24CS10090), Karri Venkata Karrenna Vybhav (24CS10099), Kolli Surya Shashank (24CS10101)

---

## Birds-Eye Architectural Overview

AHHS-IDS decomposes the line-rate intrusion detection problem into three distinct tiers executed entirely in the Linux kernel data path using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)**:

```
[ Raw Network Packet Ingress ]
              │
              ▼
┌────────────────────────────────────────┐
│   TIER 1: Stateless Pre-Filter        │  <-- bpf/tier1_tree.h & xdp_ahhs_tier1.c:tier1_prefilter()
│   O(1) Decision Tree on 5-Tuple        │  <-- ~12 ns latency, zero map access, drops known threats
└──────────────────┬─────────────────────┘
                   │
      ┌────────────┼────────────┐
      │            │            │
  Known Benign  Known Attack Ambiguous Traffic (Dynamic / Unknown Ports)
 (Ports 80,443) (Ports 23,4444) │
      │            │            ▼
      ▼            ▼    ┌────────────────────────────────────────┐
 [ XDP_PASS ] [ XDP_DROP ]│ TIER 2: Stateful Sliding Window Tracker │  <-- xdp_ahhs_tier1.c:tier2_process_window()
                        │ LRU Hash Map (flow_lru_map: 65,536)    │  <-- ~45 ns latency, 100 pkts or 1.0s window
                        └──────────────────┬─────────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │ Fast-Path Blocklist Hit?            │  <-- ahhs_blocklist (16,384 entries, 60s TTL)
                        │ (Expiry > bpf_ktime_get_ns())       │
                        └──────────┬──────────────────────────┘
                                   │
                     ┌─────────────┴─────────────┐
                     ▼                           ▼
                  [ YES ]                     [ NO ]
                     │                           │
                [ XDP_DROP ]          Accumulate window metrics
                                      (pkts, bytes, IAT, len², SYN)
                                                 │
                                      Window Full? (100 pkts / 1.0s)
                                                 │
                                                 ▼
                                      Extract 8 log2q3 features
                                      Atomically reset window
                                      bpf_tail_call(ahhs_t3_prog_array, 0)
                                                 │
                                                 ▼
                        ┌────────────────────────────────────────┐
                        │ TIER 3: Deep Quantized Autoencoder     │  <-- bpf/xdp_ahhs_tier3.c
                        │ 4-Program Chained Tail Calls           │  <-- 428 parameters, 592B model binary
                        │ 8 -> 16 -> 4 -> 16 -> 8 (Zero Float)   │  <-- ~1,150 ns latency (amortized to 11.5 ns)
                        └──────────────────┬─────────────────────┘
                                           │
                                    err = Σ(x_q - y)²
                                           │
                             ┌─────────────┴─────────────┐
                             ▼                           ▼
                       err > θ (Anomaly)           err <= θ (Normal)
                             │                           │
                    Record AHHS_STAT_ANOMALY    Record AHHS_STAT_NORMAL
                    Insert into ahhs_blocklist           │
                             │                           ▼
                             ▼                      [ XDP_PASS ]
                        [ XDP_DROP ]
```

---

## 1. TIER 1: Stateless Wire-Speed Pre-Filter

### Purpose
To filter out high-volume known benign and known malicious traffic at wire speed ($O(1)$) without allocating kernel socket buffers (`sk_buff`) and without touching memory maps. Resolves ~90% of raw packet volume in $\approx 12\text{ ns}$.

### Key Files & Functions
- **`bpf/tier1_tree.h`**: Static inline C decision tree generated from Scikit-Learn training. Uses pure integer comparisons.
  - `tier1_tree_predict(uint32_t *features, int n_features)`: Evaluates 5-tuple features (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
- **`bpf/xdp_ahhs_tier1.c` (`tier1_prefilter()`)**:
  - Parses L2 Ethernet header, handles 802.1Q/802.1ad VLAN tags.
  - Verifies IPv4 protocol and checks bounds against `ctx->data_end`.
  - Parses L4 TCP/UDP transport headers, extracts `src_port`, `dst_port`, and `is_syn`.
  - Computes IP-level `pkt_len` by subtracting Ethernet header size.
  - Calls `tier1_tree_predict()`.
- **`scripts/train_tier1.py`**:
  - Generates training dataset with randomized IP subnets (preventing shortcut learning).
  - Trains a shallow `DecisionTreeClassifier` (max depth $\le 4$).
  - Transpiles the tree into BPF-safe C code with `<stdint.h>` include guards.

### Port Classification Rules
| Destination Port | Traffic Description | Tier 1 Action | Verdict |
| :---: | :--- | :---: | :---: |
| **80** | HTTP Web Traffic | `TIER1_ACTION_PASS` (0) | `XDP_PASS` |
| **443** | HTTPS Encrypted Web | `TIER1_ACTION_PASS` (0) | `XDP_PASS` |
| **53** | DNS Name Resolution | `TIER1_ACTION_PASS` (0) | `XDP_PASS` |
| **123** | NTP Network Time Protocol | `TIER1_ACTION_PASS` (0) | `XDP_PASS` |
| **23** | Telnet Brute-Force Probe | `TIER1_ACTION_DROP` (1) | `XDP_DROP` |
| **4444** | Metasploit Default Shell Handler | `TIER1_ACTION_DROP` (1) | `XDP_DROP` |
| **1337** | Elite Backdoor Port | `TIER1_ACTION_DROP` (1) | `XDP_DROP` |
| **2323** | Mirai Botnet Alternative Telnet | `TIER1_ACTION_DROP` (1) | `XDP_DROP` |
| **31337** | Back Orifice Trojan | `TIER1_ACTION_DROP` (1) | `XDP_DROP` |
| **Others / Dynamic** | Port 8080, 9000, ephemeral ports | `TIER1_ACTION_AMBIGUOUS` (2) | Escalate to Tier 2 |

---

## 2. TIER 2: Stateful Sliding Window & LRU Flow Tracker

### Purpose
To track dynamic behavioral characteristics of ambiguous flows over a sliding window (100 packets or 1.0 second), capturing inter-arrival time statistics, packet length distributions, and protocol flags. Executes in $\approx 45\text{ ns}$.

### Key Files & Functions
- **`bpf/ahhs_common.h`**:
  - `struct flow_key` (16 bytes): 5-tuple identifier (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
  - `struct flow_state` (88 bytes): Lifetime counters (`packet_count`, `byte_count`, `last_seen_ns`) and window accumulators (`w_pkts`, `w_bytes`, `w_len_max`, `w_len_sq`, `w_iat_sum_ns`, `w_iat_max_ns`, `w_syn`, `w_start_ns`).
  - `flow_lru_map` (`BPF_MAP_TYPE_LRU_HASH`): 65,536 entries (~6.8 MB). Automatically evicts least recently active flows under heavy load.
  - `ahhs_blocklist` (`BPF_MAP_TYPE_HASH`): 16,384 entries. Stores active quarantine timestamps ($ktime + 60\text{s}$).
  - `ahhs_scratch_map` (`BPF_MAP_TYPE_PERCPU_ARRAY`): 1 entry (32 bytes / CPU). Holds ping-pong activation scratchpad across tail calls.
  - `ahhs_extract_features(flow, feat)`: Computes the 8 fixed-point `log2q3` features directly in kernel C.
- **`bpf/xdp_ahhs_tier1.c` (`tier2_process_window()`)**:
  - Fast-path blocklist check: drops immediately if flow is quarantined.
  - Looks up flow in `flow_lru_map` (creates initial entry if first packet).
  - Updates inter-arrival time `iat = current_time - flow->last_seen_ns`.
  - Accumulates `w_pkts`, `w_bytes`, `w_len_max`, `w_len_sq`, `w_iat_sum_ns`, and `w_syn`.
  - Window trigger: when `w_pkts >= 100` or `(current_time - w_start_ns) > 1.0s`, extracts features into `ahhs_scratch_map`, atomically resets window counters, and triggers `bpf_tail_call(ctx, &ahhs_t3_prog_array, 0)`.
- **`scripts/ahhs_features.py`**:
  - Fixed-point logarithm implementation (`log2q3`).
  - Flow simulator replicating kernel window semantics with 100% fidelity.

### The 8 Extracted Features
| Index | Feature Description | Mathematical Formula | Purpose in Detection |
| :---: | :--- | :--- | :--- |
| `feat[0]` | Packet Count in Window | $\text{log2q3}(n)$ | Detects burst volume and packet flood density. |
| `feat[1]` | Mean Packet Length | $\text{log2q3}(\text{bytes} / n)$ | Differentiates small probe packets from data transfers. |
| `feat[2]` | Maximum Packet Length | $\text{log2q3}(\text{len}_{\max})$ | Identifies large MTU payload pushes. |
| `feat[3]` | Packet Length Variance | $\text{log2q3}(\mathbb{E}[X^2] - (\mathbb{E}[X])^2)$ | Probes have zero variance; HTTP/DNS traffic has high variance. |
| `feat[4]` | Mean Inter-Arrival Time | $\text{log2q3}(\text{IAT}_{\text{sum}} / (n-1))$ in $\mu\text{s}$ | High rate floods show microsecond IAT; normal streams are spaced. |
| `feat[5]` | Maximum Inter-Arrival Time | $\text{log2q3}(\text{IAT}_{\max})$ in $\mu\text{s}$ | Catches burst pauses and slow-rate DoS variations. |
| `feat[6]` | Total Window Bytes | $\text{log2q3}(\text{bytes})$ | Measures total throughput density per window. |
| `feat[7]` | TCP SYN Flag Ratio | $(\text{SYN} \times 255) / n$ | Flags SYN floods (ratio = 255) vs normal ACK/data traffic (ratio $\approx 0$). |

---

## 3. TIER 3: Chained Quantized In-Kernel Autoencoder

### Purpose
To perform deep non-linear anomaly detection on 100-packet flow windows entirely inside the Linux kernel without floating-point arithmetic. Computes reconstruction error in pure integer math, dropping anomalous packets and quarantining offending 5-tuples for 60 seconds.

### Key Files & Functions
- **`bpf/xdp_ahhs_tier3.c`**:
  - `ahhs_t3_l1`: Layer 1 Dense $8 \to 16$ + ReLU. Centers input using zero points: $x_q = \text{clamp}(x - \text{zp}, -128, 127)$. Writes to `buf_a`. Tail-calls Program 1.
  - `ahhs_t3_l2`: Layer 2 Dense $16 \to 4$ + ReLU (Bottleneck representation). Reads `buf_a`, writes to `buf_b`. Tail-calls Program 2.
  - `ahhs_t3_l3`: Layer 3 Dense $4 \to 16$ + ReLU (Decoder expansion). Reads `buf_b`, writes to `buf_a`. Tail-calls Program 3.
  - `ahhs_t3_l4`: Layer 4 Dense $16 \to 8$ (Linear reconstruction $y$). Computes squared reconstruction error:
    $$\text{err} = \sum_{i=0}^7 (x_{q, i} - y_i)^2$$
    If $\text{err} > \theta$: flags `AHHS_STAT_ANOMALY`, writes 5-tuple to `ahhs_blocklist` with 60-second TTL, returns `XDP_DROP`.  
    If $\text{err} \le \theta$: flags `AHHS_STAT_NORMAL`, returns `XDP_PASS`.
  - `ahhs_t3_selftest`: Pinned self-test entrypoint executing 240 golden trace vectors with bit-exact validation.
- **`AHHS_CICIDS2017_Exhaustive_Training.ipynb` & `scripts/build_cicids2017_notebook.py`**:
  - Ingests official Canadian Institute for Cybersecurity (CIC-IDS-2017) datasets.
  - Trains PyTorch Quantization-Aware Training (QAT) autoencoder strictly on Monday benign network traffic.
  - Uses Straight-Through Estimators (STE) and Exponential Moving Averages (EMA) to track quantization scale boundaries.
  - Calibrates $\theta = 58$ on benign validation traffic.
  - Quantizes weights to int8, biases to int16, and packs model into exact 592-byte binary format (`models/ahhs_model.bin`).
  - Generates 240 golden trace vectors (`models/golden_tier3.json`).
- **`scripts/ref_int_forward.py`**:
  - Python bit-exact reference implementation of kernel fixed-point inference.
- **`bpf/ahhs_common.h` (`struct ahhs_model`)**:
  - 592-byte layout: Header (16B), Weights (384B), Biases (88B), Multipliers (16B), Zero-points (8B), Padding (80B).

### Mathematical Formulation of In-Kernel Dense Layer
For each output neuron $o$:
$$\text{acc}_o = b_o + \sum_{i=0}^{\text{IN}-1} W_{o, i} \cdot x_i$$
$$v_o = (\text{acc}_o \times M + 2^{23}) \gg 24$$
$$y_o = \text{clamp}(v_o, \text{lo}, 127)$$
- Layers 1, 2, 3: $\text{lo} = 0$ (implements ReLU).
- Layer 4: $\text{lo} = -128$ (implements linear output reconstruction).
- Input & Output Scale: Fixed to $s_{\text{io}} = 2^{-5} = 1/32$, guaranteeing scale-consistent squared error calculation.

---

## 4. Machine Learning Models & Datasets

| Model Tier | Algorithm | Parameters | Training Dataset | Calibrated Threshold ($\theta$) | Performance |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **Tier 1** | Decision Tree (Depth $\le 4$) | 15 nodes | Real protocol ports (5-tuple classification) | Hard-coded thresholds (38, 890, 4722, 20668) | $100\%$ accuracy on verified ports |
| **Tier 3 (CIC-IDS-2017)** | Bottleneck Autoencoder ($8 \to 16 \to 4 \to 16 \to 8$) | 428 parameters (384 int8 weights + 44 int16 biases) | Official Canadian Institute for Cybersecurity (**CIC-IDS-2017**) 12,100 held-out windows | $\theta = 58$ (calibrated on 95th percentile benign validation windows) | ROC-AUC: **0.957**, Overall TPR: **85.07%**, PortScan: **100.0%**, Slowloris: **70.14%** |
