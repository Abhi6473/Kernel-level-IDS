# AHHS-IDS: Two-Laptop Live Demonstration Guide
## "Attacker vs. Defender" Real-Time In-Kernel Network Defense Showcase
**Course:** Advanced Operating Systems / USP Project  
**Authors:** Challarapu Abhiram (24CS10090), Karri Venkata Karrenna Vybhav (24CS10099), Kolli Surya Shashank (24CS10101)

---

## 1. Overview of the 2-Laptop Setup

This guide allows your team to perform a **live multi-machine defense demonstration** before the examination committee:

```
┌────────────────────────────────┐                 ┌────────────────────────────────┐
│      LAPTOP 2: ATTACKER        │                 │      LAPTOP 1: DEFENDER        │
│    (Operated by Abhiram)       │  Direct CAT6 or │     (Operated by Vybhav)       │
│                                │  Local Switch   │                                │
│   Static IP: 192.168.1.200/24  │ ═══════════════ │   Static IP: 192.168.1.100/24  │
│                                │                 │                                │
│   - scripts/attacker_console.py│                 │   - XDP Ingress Hook Attached  │
│   - Interactive Attack Menu    │                 │   - scripts/detector_dashboard │
│   - Targeted Threat Bursts     │                 │   - Live Map Telemetry (2 Hz)  │
└────────────────────────────────┘                 └────────────────────────────────┘
                                                                   │
                                                                   ▼
                                                           [ PROJECTOR / TV ]
                                                     (Presented by Shashank)
```

- **Laptop 1 (Defender / Target Machine)**: Runs Linux Kernel $\ge 5.10$. AHHS-IDS is attached to the physical interface via XDP. Runs `scripts/detector_dashboard.py` projected on the big screen.
- **Laptop 2 (Attacker / Intrusion Generator)**: Connects to Laptop 1 and runs `scripts/attacker_console.py` to trigger benign traffic, known backdoor probes, port scans, and volumetric SYN floods.

---

## 2. Step 1: Network Configuration

### Option A: Direct Ethernet Cable (Recommended)
Connect an Ethernet cable (CAT5e/6) directly between Laptop 1 and Laptop 2.

**On Laptop 1 (Defender - Ubuntu Linux):**
```bash
# Identify your Ethernet interface (e.g. eth0, enp3s0, or enx...)
ip link

# Assign static IP: 192.168.1.100
sudo ip addr flush dev eth0
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip link set dev eth0 up
```

**On Laptop 2 (Attacker - macOS, Linux, or Windows WSL):**
```bash
# On Linux / WSL:
sudo ip addr flush dev eth0
sudo ip addr add 192.168.1.200/24 dev eth0
sudo ip link set dev eth0 up

# On macOS:
sudo ifconfig en0 192.168.1.200 netmask 255.255.255.0 up
```

**Verify Connectivity:**
On Laptop 2, test the link:
```bash
ping -c 3 192.168.1.100
```
*(You should see < 0.5 ms round-trip time).*

### Option B: Local Wi-Fi / Mobile Hotspot
Connect both laptops to the same Wi-Fi router or phone hotspot. Use `ip addr show` or `ifconfig` to find each laptop's assigned IP (e.g., `192.168.43.100` and `192.168.43.200`).

---

## 3. Step 2: Laptop 1 (Defender) Setup & Startup

Run these commands on **Laptop 1** before the presentation starts:

```bash
# 1. Navigate to the project root
cd /path/to/ebpf

# 2. Compile eBPF C programs (if not already built)
make

# 3. Load the multi-tier pipeline and pin BPF maps
# Replace 'eth0' with your actual interface name
sudo bash bpf/load_pipeline.sh eth0

# 4. Start the live defender dashboard on the projector screen
sudo python3 scripts/detector_dashboard.py --iface eth0
```

The terminal will display the real-time telemetry dashboard:
```
============================================================================
       AHHS-IDS: REAL-TIME IN-KERNEL DEFENDER DASHBOARD (XDP / eBPF)        
       Multi-Tier Hybrid Architecture | Hook: eth0 (Zero-Copy)       
============================================================================
 Active Model: Slot 0 (592 Bytes) | Anomaly Threshold: θ = 58 | Double-Buffer: SYNCHRONIZED

┌── TIER 1: STATELESS WIRE-SPEED PRE-FILTER (bpf/tier1_tree.h) ───────────────┐
│  • PASS (Known Benign Ports: 80, 443, 53, 123) : 0          packets        │
│  • DROP (Known Malicious: 23, 4444, 1337, etc.) : 0          packets        │
│  • AMBIGUOUS (Escalated to Tier 2 Tracking)  : 0          packets        │
│  • NON-IPV4 / ICMP (Stack Passthrough)       : 0          packets        │
└─────────────────────────────────────────────────────────────────────────────┘
┌── TIER 2 & TIER 3: STATEFUL SLIDING WINDOW & IN-KERNEL AUTOENCODER ──────────┐
│  • Tier 2 LRU Window Capacity: 65,536 entries | Trigger: 100 pkts / 1.0s         │
│  • Autoencoder Invocations   : 0          windows evaluated       │
│  • NORMAL Verdicts (err <= θ) : 0          flows (XDP_PASS)        │
│  • ANOMALY DETECTIONS (err > θ) : 0          flows (XDP_DROP)        │
└─────────────────────────────────────────────────────────────────────────────┘
┌── DYNAMIC FAST-PATH BLOCKLIST (ahhs_blocklist: 16,384 Slots, 60s TTL) ───────┐
│  [CLEAR] No active quarantined flows. All ingress channels nominal.         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Step 3: Laptop 2 (Attacker) Setup & Execution

On **Laptop 2**, launch the interactive intrusion console:

```bash
cd /path/to/ebpf
python3 scripts/attacker_console.py --target 192.168.1.100
```

You will see the interactive attack menu:
```
======================================================================
      AHHS-IDS: ATTACK GENERATOR CONSOLE (LAPTOP 2)        
Target Defender IP: 192.168.1.100 | Status: CONNECTED
======================================================================
  1. Send Benign Traffic (Ports 80, 53 -> Expected: Tier 1 PASS)
  2. Send Known Threat Probes (Ports 4444, 23 -> Expected: Tier 1 DROP)
  3. Send Ambiguous Stream (Port 8080, 40 pkts -> Expected: Tier 2 Track)
  4. Send Volumetric Flood (150 pkts -> Triggers Tier 3 & Blocklist)
  5. Verify Quarantine Enforcement (Subsequent pkts -> Fast-path DROP)
  6. Run Sequential Port Scan (Ports 8000-8030)
  7. RUN AUTOMATED 5-MINUTE EXAMINATION SHOWCASE (All Scenarios)
  8. Change Target IP Address
  9. Exit Console
======================================================================
Select attack scenario [1-9]:
```

---

## 5. Step 4: Live Demonstration Dialogue & Choreography

### Phase 1: Tier 1 Stateless Pre-Filtering
- **Abhiram (Laptop 2)**: Selects option `1` (`Send Benign Traffic`). Sends 30 HTTP (Port 80) packets.
- **Vybhav (Laptop 1 Dashboard)**: *"Look at the projector screen: Tier 1 `PASS` counter immediately jumps to 30. This decision took ~12 ns without touching memory maps or allocating `sk_buff`."*
- **Abhiram (Laptop 2)**: Selects option `2` (`Send Known Threat Probes`). Sends 15 Metasploit (Port 4444) packets and 15 Telnet (Port 23) packets.
- **Vybhav (Laptop 1 Dashboard)**: *"Tier 1 `DROP` counter increments to 30. These packets were dropped at wire speed directly in the NIC RX driver ring buffer."*

### Phase 2: Tier 2 Ambiguous Flow Tracking
- **Abhiram (Laptop 2)**: Selects option `3` (`Send Ambiguous Stream`). Sends 40 packets to Port 8080.
- **Vybhav (Laptop 1 Dashboard)**: *"Because Port 8080 is not a standard service, Tier 1 cannot decide statelessly. Tier 1 increments the `AMBIGUOUS` counter to 40. These packets enter Tier 2, where an LRU entry is created in `flow_lru_map`. Because fewer than 100 packets have arrived, the window is still in-flight."*

### Phase 3: Tier 3 In-Kernel Quantized Autoencoder & Dynamic Blocklisting
- **Abhiram (Laptop 2)**: Selects option `4` (`Send Volumetric Flood`). Injects 150 packets to Port 8080 from fixed source port 49152.
- **Vybhav (Laptop 1 Dashboard)**: *"Watch the dashboard closely! As packet 100 arrives, Tier 2 detects a full window, extracts 8 fixed-point `log2q3` features, and calls `bpf_tail_call()` into Tier 3. The 4-program neural network calculates the reconstruction error in pure integer math. Since `err = 36,872` exceeds threshold `θ = 58`, Tier 3 flags an `ANOMALY`. It drops the packet and inserts the 5-tuple into `ahhs_blocklist` with a 60-second TTL."*
- **Abhiram (Laptop 2)**: Selects option `5` (`Verify Quarantine Enforcement`). Tries to send 30 more packets from port 49152.
- **Vybhav (Laptop 1 Dashboard)**: *"Notice that even though the attacker is still sending packets, they are immediately dropped at the Tier 1 ingress fast-path (~12 ns) because of the active blocklist entry. They never reach Tier 2 or Tier 3 again."*

### Phase 4: Zero-Downtime Double-Buffered Hot-Swap
- **Vybhav (Laptop 1)**: Opens a second terminal on Laptop 1 and flips the active model index:
  ```bash
  sudo bpftool map update pinned /sys/fs/bpf/ahhs/ahhs_nn_index key 0 0 0 0 value 1 0 0 0
  ```
- **Shashank (Slides)**: *"On the dashboard, you can see `Active Model: Slot 1`. In an enterprise deployment, when a new model is retrained, we write the 592-byte binary into the idle buffer and atomically flip the index pointer. There is zero packet loss, zero driver detach, and zero downtime."*

---

## 6. Troubleshooting Checklist

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `ping: Destination Host Unreachable` | Static IP mismatch or wrong interface name | Verify with `ip addr show` on both laptops. Ensure both use netmask `/24` (`255.255.255.0`). |
| `Permission denied` loading XDP | eBPF requires root privileges | Prepend `sudo` to `load_pipeline.sh` and `detector_dashboard.py`. |
| `XDP program already attached` | Previous session left program attached | Run `sudo ip link set dev <iface> xdp off`. |
| Packets not reaching dashboard | Local Linux firewall (`ufw` / `iptables`) blocking packets | Run `sudo ufw disable` during the lab demonstration. |
