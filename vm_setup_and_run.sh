#!/usr/bin/env bash
# =========================================================================
# vm_setup_and_run.sh - Automated AHHS-IDS Launcher for defender-vm
# =========================================================================
set -e

# Find the project directory
if [[ -d "/home/ubuntu/ebpf/ebpf" ]]; then
    cd /home/ubuntu/ebpf/ebpf
elif [[ -d "/home/ubuntu/ebpf" ]]; then
    cd /home/ubuntu/ebpf
else
    cd "$(dirname "$0")"
fi

echo "================================================================="
echo "   AHHS-IDS: AUTOMATED VM COMPILATION & DEFENDER STARTUP"
echo "================================================================="

# 1. Clean stale BPF pins and old XDP attachments to prevent "File exists"
echo "[*] Cleaning stale BPF pins and existing XDP attachments..."
sudo pkill -f "ahhs_loader" 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/ahhs /sys/fs/bpf/ahhs_tier3 2>/dev/null || true
sudo ip link set dev enp0s1 xdp off 2>/dev/null || true

# 2. Ensure model binary exists in root
if [[ ! -f "ahhs_model.bin" && -f "models/ahhs_model.bin" ]]; then
    cp models/ahhs_model.bin ahhs_model.bin
    echo "[✓] Copied models/ahhs_model.bin -> ./ahhs_model.bin"
fi

# Ensure pre-generated Tier 1 tree header exists and is up to date
if [[ ! -f "bpf/tier1_tree.h" && -f "/home/ubuntu/ebpf_host/bpf/tier1_tree.h" ]]; then
    cp /home/ubuntu/ebpf_host/bpf/tier1_tree.h bpf/tier1_tree.h
    echo "[✓] Restored bpf/tier1_tree.h from host"
fi
touch bpf/tier1_tree.h

# 3. Apply kernel C fixes to tier1 if needed
python3 -c "
path = 'bpf/xdp_ahhs_tier1.c'
with open(path, 'r') as f:
    s = f.read()
s = s.replace('is_syn = tcph->syn && !tcph->ack;\n        *is_syn_out = is_syn;', '*is_syn = (tcph->syn && !tcph->ack) ? 1 : 0;')
if 'dst_port == 22' not in s:
    s = s.replace('key->protocol = protocol;', 'key->protocol = protocol;\n\n    if (src_port == 22 || dst_port == 22) return TIER1_ACTION_PASS;')
with open(path, 'w') as f:
    f.write(s)
"

# 4. Apply type fixes to tier1_tree.h if needed
python3 -c "
path = 'bpf/tier1_tree.h'
with open(path, 'r') as f:
    s = f.read()
s = s.replace('#if !defined(__bpf__) && !defined(__BPF__)\n#include <stdint.h>\n#endif', '#if defined(__bpf__) || defined(__BPF__)\ntypedef __s32 int32_t;\ntypedef __u32 uint32_t;\n#else\n#include <stdint.h>\n#endif')
with open(path, 'w') as f:
    f.write(s)
"

# 5. Compile eBPF programs and userspace loader
echo "[*] Compiling eBPF objects and ahhs_loader..."
make clean >/dev/null 2>&1 || true
make

# 6. Start the eBPF loader in the background (&)
echo "[*] Attaching 3-tier eBPF pipeline to enp0s1 in the background..."
sudo ./ahhs_loader enp0s1 > /tmp/ahhs_loader.log 2>&1 &
sleep 2

# 7. Verify loader is active
if pgrep -f "ahhs_loader" >/dev/null; then
    echo "[✓] eBPF Pipeline is LIVE in kernel on interface enp0s1!"
else
    echo "[-] Loader output:"
    cat /tmp/ahhs_loader.log
    exit 1
fi

echo "================================================================="
echo "   STARTING REAL-TIME IN-KERNEL DEFENDER DASHBOARD"
echo "================================================================="
sudo python3 scripts/detector_dashboard.py --iface enp0s1 --zero
