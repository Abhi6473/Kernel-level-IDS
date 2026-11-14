# AHHS-IDS Live Demonstration & Examination Defense Guide
## How to Demonstrate the In-Kernel Multi-Tier Intrusion Detection System
**Course:** Advanced Operating Systems / USP Project  
**Authors:** Challarapu Abhiram (24CS10090), Karri Venkata Karrenna Vybhav (24CS10099), Kolli Surya Shashank (24CS10101)

---

## Demonstration Quick-Start Menu

| Demonstration Mode | Target Environment | Command / Action | What it Shows |
| :--- | :---: | :--- | :--- |
| **Mode 1: Automated Terminal Demo** | Any OS (macOS/Linux) | `python3 scripts/demonstrate.py` | Full 7-stage automated demonstration across Tier 1, Tier 2, Tier 3, blocklist, hot-swap, and self-test. |
| **Mode 2: Interactive Defense Demo** | Any OS (macOS/Linux) | `python3 scripts/demonstrate.py --interactive` | Pauses at each tier, allowing you to explain the exact mechanics to the professor before proceeding. |
| **Mode 3: Live Visual Web UI** | Web Browser | `open presentation/index.html` | Animated packet flow dots, live sliding window accumulator, autoencoder anomaly flashing, and simulated kernel map counters. |
| **Mode 4: Live Linux Kernel & eBPF VM** | Linux Kernel $\ge 5.10$ | `make && sudo bash bpf/load_pipeline.sh` | Real in-kernel XDP attachment, `bpftool` map telemetry inspection, real raw packet injection, and live zero-downtime hot-swap. |
| **Mode 5: Google Colab Real Dataset Training** | Google Colab | Upload `AHHS_CICIDS2017_Exhaustive_Training.ipynb` | Exhaustive training on official Canadian Institute for Cybersecurity (CIC-IDS-2017) datasets with 300-DPI visual reports. |

---

## Mode 1 & 2: Terminal Demonstration (`scripts/demonstrate.py`)

Run this in your terminal to demonstrate all system tiers in under 2 minutes:

```bash
# Automated run
python3 scripts/demonstrate.py

# Interactive step-by-step mode (press Enter between stages)
python3 scripts/demonstrate.py --interactive
```

### What Happens During the Demonstration:
1. **Stage 1 (Tier 1 Stateless Pre-Filter)**:
   - Evaluates destination ports against `bpf/tier1_tree.h`.
   - Demonstrates wire-speed passing for Port 80 (HTTP), 443 (HTTPS), 53 (DNS), 123 (NTP).
   - Demonstrates wire-speed dropping for Port 23 (Telnet), 4444 (Metasploit), 1337 (Backdoor), 2323 (Mirai).
   - Demonstrates escalation to Tier 2 for Port 8080 and 9000 (Ambiguous).
2. **Stage 2 (Tier 2 Stateful Sliding Window)**:
   - Streams 100 packets for ambiguous flow `10.0.0.5:49152 -> 192.168.1.10:8080`.
   - Displays live accumulators: packet count, byte count, inter-arrival time sum/max, and SYN flag ratio.
   - At packet 100, triggers window completion and extracts the 8 `log2q3` fixed-point features.
   - Shows atomic accumulator reset in flow state.
3. **Stage 3 (Tier 3 In-Kernel Quantized Autoencoder)**:
   - Loads the 592-byte model binary `models/ahhs_model.bin`.
   - Runs the exact integer forward pass ($8 \to 16 \to 4 \to 16 \to 8$).
   - Shows normal benign window producing $\text{err} = 0 \le \theta$ $\to$ `NORMAL TRAFFIC -> XDP_PASS`.
   - Shows attack flood window producing $\text{err} = 36,872 \gg \theta$ $\to$ `ANOMALY DETECTED -> XDP_DROP`.
4. **Stage 4 (Dynamic Fast-Path Blocklisting)**:
   - Shows 5-tuple insertion into `ahhs_blocklist` with 60-second TTL.
   - Simulates subsequent packets 101 to 150: dropped on ingress fast-path in ~12 ns without reaching Tier 2 or Tier 3.
5. **Stage 5 (Zero-Downtime Double-Buffered Hot-Swap)**:
   - Explains Slot 0 (Active) vs Slot 1 (Idle).
   - Demonstrates atomic index switch via `ahhs_nn_index` ($0 \to 1$) without dropping packets or restarting drivers.
6. **Stage 6 (In-Kernel Bit-Exact Golden Trace Self-Test)**:
   - Evaluates all 240 golden test vectors from `models/golden_tier3.json`.
   - Confirms **100.0% bit-exact equivalence** with integer kernel math.
7. **Stage 7 (Live Animated Telemetry Dashboard)**:
   - Provides direct link to open the visual UI in your browser.

---

## Mode 3: Interactive Visual Presentation Dashboard (`presentation/index.html`)

To open the visual presentation tool during your viva or defense:

```bash
# On macOS:
open presentation/index.html

# On Linux:
xdg-open presentation/index.html
```

### Visual Features to Highlight in Demonstration:
- **Packet Ingress Animation**: Real-time colored packet dots traversing the pipeline:
  - Green dots = Benign Port 80/443 traffic $\to$ Exit via `XDP_PASS`.
  - Red dots = Malicious Port 23/4444 traffic $\to$ Terminated immediately via `XDP_DROP`.
  - Amber dots = Dynamic Port 8080 traffic $\to$ Route into Tier 2.
- **Tier 2 Window Progress Bar**: Visualizes the 100-packet buffer accumulating state.
- **Tier 3 Autoencoder Pulse**: Flashes vibrant purple when the 100th packet triggers deep inference.
- **Live Simulated BPF Map Telemetry**: Real-time counters showing `tier1_stats_map`, `flow_lru_map`, and `ahhs_t3_stats`.

---

## Mode 4: Live Linux Kernel & eBPF VM Deployment

If you are demonstrating on a Linux host (Ubuntu 20.04/22.04/24.04 with kernel $\ge 5.10$):

### 1. Build Kernel BPF Bytecode
```bash
make clean
make
```
*Compiles `xdp_ahhs_tier1.o` and `xdp_ahhs_tier3.o` using `clang -target bpf -O2`.*

### 2. Load Pipeline & Pin BPF Maps
```bash
sudo bash bpf/load_pipeline.sh
```
*This automated script:*
- Mounts `/sys/fs/bpf` if not already mounted.
- Loads `xdp_ahhs_tier1.o` and `xdp_ahhs_tier3.o`.
- Populates the tail-call program array `ahhs_t3_prog_array` with programs 0, 1, 2, and 3 (`ahhs_t3_l1` to `ahhs_t3_l4`).
- Injects `models/ahhs_model.bin` (592 bytes) into `ahhs_model_map[0]`.
- Sets active model pointer `ahhs_nn_index` to 0.
- Attaches `xdp_ahhs_tier1` to the target interface (e.g. `lo` or `eth0`).

### 3. Verify Loaded Maps with `bpftool`
```bash
# View all pinned AHHS maps
sudo bpftool map list

# Inspect Tier 1 statistics (PASS, DROP, AMBIGUOUS counters)
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/tier1_stats_map

# Inspect Tier 3 statistics (INVOCATIONS, ANOMALIES, NORMAL)
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/ahhs_t3_stats

# Inspect active model index (should show set 0)
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/ahhs_nn_index
```

### 4. Inject Live Test Traffic (`scripts/send_traffic.py`)
In another terminal, inject traffic to observe kernel classification in real time:

```bash
# Send 150-packet flood to Port 8080 (triggers 100-packet window and Tier 3 autoencoder)
python3 scripts/send_traffic.py --type flood --target 127.0.0.1 --src-port 40000
```

### 5. Confirm In-Kernel Anomaly Drop & Blocklisting
```bash
# Confirm ANOMALY counter incremented in Tier 3
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/ahhs_t3_stats

# Confirm offending 5-tuple was dynamically quarantined in blocklist
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/ahhs_blocklist

# Confirm LRU connection state was tracked and reset
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/flow_lru_map
```

### 6. Demonstrate Live Zero-Downtime Hot-Swap
Toggle active model slot live without dropping a single packet:
```bash
# Flip active model slot from 0 to 1
sudo bpftool map update pinned /sys/fs/bpf/ahhs/ahhs_nn_index key 0 0 0 0 value 1 0 0 0

# Confirm active index is now 1
sudo bpftool map dump pinned /sys/fs/bpf/ahhs/ahhs_nn_index
```

---

## Mode 5: Google Colab Real Dataset Training (`AHHS_CICIDS2017_Exhaustive_Training.ipynb`)

To demonstrate real-world dataset training before your professor:

1. Open Google Colab: [https://colab.research.google.com/](https://colab.research.google.com/)
2. Click **Upload** and select [`AHHS_CICIDS2017_Exhaustive_Training.ipynb`](file:///Users/vaibhavkarri/ebpf/AHHS_CICIDS2017_Exhaustive_Training.ipynb).
3. Select **Runtime -> Run all**.
4. The notebook will automatically:
   - Download the real Canadian Institute for Cybersecurity (**CIC-IDS-2017**) dataset from validated Hugging Face mirrors.
   - Convert 78 bidirectional flow metrics to the 8 in-kernel fixed-point features (`log2q3`).
   - Train the port-based Decision Tree pre-filter.
   - Train the PyTorch Quantization-Aware Training (QAT) autoencoder across 200 epochs.
   - Calibrate $\theta$ at the 99th percentile of benign validation traffic.
   - Export the verified 592-byte in-kernel model binary and golden self-test traces.
   - Generate a publication-quality 300-DPI visual evaluation dashboard.
   - Package all artifacts into a downloadable ZIP file.

---

## Verification Test Commands for Defense

Before your presentation, run these automated verification commands:

```bash
# 1. Run 73 unit & pipeline tests (100% pass)
make test

# 2. Run 20 quality gate & mathematical sanity tests (100% pass)
python3 tests/test_phase3_quality.py

# 3. Run 240 golden trace vectors over CIC-IDS-2017 model (100% bit parity)
make selftest
```
