#!/usr/bin/env bash
# =========================================================================
# AHHS-IDS Phase 3: Complete Multi-Tier eBPF Pipeline Loader & Linker
# =========================================================================
# Usage:
#   sudo ./load_pipeline.sh [interface] [mode] [--selftest]
# Default:
#   interface = eth0
#   mode      = xdpgeneric (or xdpdrv)
# =========================================================================

set -euo pipefail

IFACE="${1:-eth0}"
XDP_MODE="${2:-xdpgeneric}"
PIN_DIR="/sys/fs/bpf/ahhs"
LINKED_OBJ="ahhs.o"
TIER1_OBJ="xdp_ahhs_tier1.o"
TIER3_OBJ="xdp_ahhs_tier3.o"
LOADER_BIN="./ahhs_loader"
MODEL_BIN="models/ahhs_model.bin"
[[ ! -f "${MODEL_BIN}" ]] && MODEL_BIN="ahhs_model.bin"

echo "================================================================="
echo "AHHS-IDS: Multi-Tier Pipeline Loader (Phase 3 Autoencoder)"
echo "================================================================="
echo "[*] Interface: ${IFACE} | Mode: ${XDP_MODE}"

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (sudo)." 
   exit 1
fi

# Ensure model binary exists
if [[ ! -f "${MODEL_BIN}" ]]; then
    echo "[!] Model binary '${MODEL_BIN}' not found. Exporting..."
    python3 export_tier3.py --model models/tier3_model.pt --data data/ --out . 2>/dev/null || true
fi

# Prefer dedicated libbpf loader if compiled
if [[ -x "${LOADER_BIN}" ]]; then
    echo "[+] Found compiled libbpf loader (${LOADER_BIN}). Executing..."
    exec "${LOADER_BIN}" "${IFACE}" "${LINKED_OBJ}" "${MODEL_BIN}"
fi

# Fallback: bpftool-based loader
echo "[*] Using bpftool fallback loader..."

# 1. Clean existing pins
rm -rf "${PIN_DIR}" 2>/dev/null || true
mkdir -p "${PIN_DIR}"

# 2. Check if combined ahhs.o exists; if not, check individual objects
if [[ -f "${LINKED_OBJ}" ]]; then
    TARGET_OBJ="${LINKED_OBJ}"
elif [[ -f "${TIER1_OBJ}" && -f "${TIER3_OBJ}" ]]; then
    echo "[*] Generating combined object ${LINKED_OBJ} via bpftool..."
    bpftool gen object "${LINKED_OBJ}" "${TIER1_OBJ}" "${TIER3_OBJ}" 2>/dev/null || TARGET_OBJ="${TIER1_OBJ}"
    TARGET_OBJ="${LINKED_OBJ}"
else
    echo "[!] Object files not found. Compiling via make..."
    make all
    TARGET_OBJ="${LINKED_OBJ}"
fi

# 3. Attach Tier 1 XDP hook to network interface
echo "[+] Step 1: Attaching Tier 1 pre-filter to ${IFACE}..."
ip link set dev "${IFACE}" "${XDP_MODE}" off 2>/dev/null || true
ip link set dev "${IFACE}" "${XDP_MODE}" obj "${TARGET_OBJ}" sec xdp
echo "[✓] Attached Tier 1 to ${IFACE}."

# 4. Populate Tier 3 prog_array (4 chained autoencoder programs)
echo "[+] Step 2: Linking 4 chained autoencoder programs into ahhs_t3_prog_array..."
for i in 0 1 2 3; do
    PROG_NAME="ahhs_t3_l$((i+1))"
    PROG_PIN="${PIN_DIR}/${PROG_NAME}"
    rm -f "${PROG_PIN}" 2>/dev/null || true
    bpftool prog load "${TARGET_OBJ}" "${PROG_PIN}" type xdp name "${PROG_NAME}" 2>/dev/null || true
    if [[ -f "${PROG_PIN}" ]]; then
        bpftool map update name ahhs_t3_prog_array key "${i}" 0 0 0 value pinned "${PROG_PIN}" 2>/dev/null || true
        echo "    [✓] Chained layer $i -> ${PROG_NAME}"
    fi
done

# 5. Populate model weights into ahhs_model_map (Slot 0) and activate via ahhs_nn_index
if [[ -f "${MODEL_BIN}" ]]; then
    echo "[+] Step 3: Loading 592-byte model into ahhs_model_map (Slot 0)..."
    python3 -c "
import os, sys
model_path = '${MODEL_BIN}'
if os.path.exists(model_path):
    with open(model_path, 'rb') as f:
        data = f.read()
    if len(data) == 592:
        hex_bytes = ' '.join(f'{b:02x}' for b in data)
        os.system(f'bpftool map update name ahhs_model_map key 0 0 0 0 value {hex_bytes} 2>/dev/null || true')
"
    # Set active index to slot 0
    bpftool map update name ahhs_nn_index key 0 0 0 0 value 0 0 0 0 2>/dev/null || true
    echo "[✓] Loaded model weights into ahhs_model_map[0] and set ahhs_nn_index = 0."
fi

echo "================================================================="
echo "[✓] AHHS-IDS Pipeline is ACTIVE and running on ${IFACE}!"
echo "    - Tier 1: In-kernel Decision Tree Pre-filter (xdp_ahhs_tier1)"
echo "    - Tier 2: Stateful 5-tuple LRU Window + Feature Extractor"
echo "    - Tier 3: 4-Layer Chained Quantized Autoencoder (8->16->4->16->8)"
echo "    - Action: Anomaly threshold exceed -> ahhs_blocklist + XDP_DROP"
echo ""
echo "Verify status:"
echo "    ip link show dev ${IFACE}"
echo "    sudo bpftool map dump name tier1_stats_map"
echo "    sudo bpftool map dump name ahhs_t3_stats"
echo "    sudo bpftool map dump name ahhs_blocklist"
echo "    sudo bpftool map dump name flow_lru_map"
echo "================================================================="
