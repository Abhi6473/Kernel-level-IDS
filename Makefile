# =========================================================================
# AHHS-IDS: Adaptive Hybrid Hardware-Software Intrusion Detection System
# Multi-Tier eBPF Pipeline Makefile (Phase 3: Chained Quantized Autoencoder)
# =========================================================================

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
PYTHON ?= python3
CC ?= gcc

# Target architecture (default to x86, or arm64 / native arch)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Source directories
BPF_DIR ?= bpf
SCRIPTS_DIR ?= scripts
TESTS_DIR ?= tests
MODELS_DIR ?= models
DATA_DIR ?= data

# Source and Object files
XDP_C = $(BPF_DIR)/xdp_ahhs_tier1.c
XDP_OBJ = $(BPF_DIR)/xdp_ahhs_tier1.o
TIER3_C = $(BPF_DIR)/xdp_ahhs_tier3.c
TIER3_OBJ = $(BPF_DIR)/xdp_ahhs_tier3.o
LINKED_OBJ = ahhs.o
LOADER_C = $(BPF_DIR)/ahhs_loader.c
LOADER_BIN = ahhs_loader
TREE_HEADER = $(BPF_DIR)/tier1_tree.h
COMMON_HEADER = $(BPF_DIR)/ahhs_common.h
TRAIN_PY = $(SCRIPTS_DIR)/train_tier1.py

# Network interface for XDP attachment
IFACE ?= eth0
XDP_MODE ?= xdpgeneric # Options: xdpgeneric (SKB mode) or xdpdrv (Native driver mode)

# Compiler flags for BPF target
CFLAGS = -O2 -g -Wall -Wextra -target bpf -D__TARGET_ARCH_$(ARCH) -I$(BPF_DIR) -I. -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu

# Userspace loader flags
LOADER_CFLAGS = -O2 -Wall -I$(BPF_DIR) -I.
LOADER_LDFLAGS = -lbpf -lelf -lz

all: $(LINKED_OBJ) $(LOADER_BIN) ensure-model

ensure-model:
	@if [ ! -f "ahhs_model.bin" ]; then \
		if [ -f "$(MODELS_DIR)/ahhs_model.bin" ]; then \
			cp $(MODELS_DIR)/ahhs_model.bin ahhs_model.bin; \
			echo "==> Copied $(MODELS_DIR)/ahhs_model.bin -> ahhs_model.bin"; \
		fi; \
	fi

# 1. Train Decision Tree and generate tier1_tree.h (preserve existing header if python deps missing)
$(TREE_HEADER):
	@if [ ! -f "$@" ]; then \
		echo "==> Generating $(TREE_HEADER)..."; \
		PYTHONPATH=$(SCRIPTS_DIR):. $(PYTHON) $(TRAIN_PY) 2>/dev/null || { \
			if [ -f "/home/ubuntu/ebpf_host/bpf/tier1_tree.h" ]; then \
				cp /home/ubuntu/ebpf_host/bpf/tier1_tree.h $@; \
				echo "==> Restored $(TREE_HEADER) from host mount"; \
			else \
				echo "==> [ERROR] Cannot build $(TREE_HEADER): missing numpy/scikit-learn and no backup header"; exit 1; \
			fi; \
		}; \
	fi

# 2. Compile Tier 1 eBPF C program to BPF ELF object
$(XDP_OBJ): $(XDP_C) $(TREE_HEADER) $(COMMON_HEADER)
	@echo "==> Compiling Tier 1 eBPF program for target BPF ($(ARCH))..."
	$(CLANG) $(CFLAGS) -c $(XDP_C) -o $@
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 && $(LLVM_STRIP) -g $@ || true
	@echo "==> Successfully built $(XDP_OBJ)"

# 3. Compile Tier 3 eBPF C program (4 Layers + Self-Test)
$(TIER3_OBJ): $(TIER3_C) $(COMMON_HEADER)
	@echo "==> Compiling Tier 3 eBPF program for target BPF ($(ARCH))..."
	$(CLANG) $(CFLAGS) -c $(TIER3_C) -o $@
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 && $(LLVM_STRIP) -g $@ || true
	@echo "==> Successfully built $(TIER3_OBJ)"

# 4. Link Tier 1 and Tier 3 into single BPF object with shared maps (§8)
$(LINKED_OBJ): $(XDP_OBJ) $(TIER3_OBJ)
	@echo "==> Linking $(XDP_OBJ) and $(TIER3_OBJ) into $(LINKED_OBJ) via bpftool..."
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) gen object $@ $(XDP_OBJ) $(TIER3_OBJ) && \
		echo "==> Successfully generated combined BPF object: $(LINKED_OBJ)" || \
		{ rm -f $@; echo "==> [ERROR] bpftool gen object failed"; exit 1; }; \
	else \
		echo "==> [NOTICE] bpftool not available locally; $(LINKED_OBJ) creation requires bpftool on Linux"; \
	fi

# 5. Build userspace libbpf loader (§8)
$(LOADER_BIN): $(LOADER_C) $(COMMON_HEADER)
	@echo "==> Compiling libbpf userspace loader ($(LOADER_BIN))..."
	@if [ "$$(uname)" = "Linux" ]; then \
		$(CC) $(LOADER_CFLAGS) $(LOADER_C) -o $@ $(LOADER_LDFLAGS); \
		echo "==> Successfully built $(LOADER_BIN)"; \
	else \
		echo "==> [NOTICE] ahhs_loader targets Linux libbpf; skip native build on non-Linux host"; \
	fi

# Generate turnkey Google Colab CIC-IDS-2017 training notebook
notebook:
	PYTHONPATH=$(SCRIPTS_DIR):. $(PYTHON) $(SCRIPTS_DIR)/build_cicids2017_notebook.py

# Load pipeline using libbpf loader or bash script
load: $(LINKED_OBJ)
	@echo "==> Loading AHHS-IDS pipeline on $(IFACE)..."
	@if [ -f "./$(LOADER_BIN)" ]; then \
		sudo ./$(LOADER_BIN) $(IFACE) $(LINKED_OBJ) $(MODELS_DIR)/ahhs_model.bin; \
	else \
		sudo ./$(BPF_DIR)/load_pipeline.sh $(IFACE) $(XDP_MODE); \
	fi

# Detach XDP program from interface and unpin maps
unload:
	@echo "==> Detaching XDP program from $(IFACE)..."
	sudo ip link set dev $(IFACE) $(XDP_MODE) off 2>/dev/null || \
	sudo ip link set dev $(IFACE) xdp off 2>/dev/null || true
	@echo "==> Cleaning up pinned BPF objects..."
	sudo rm -rf /sys/fs/bpf/ahhs /sys/fs/bpf/ahhs_tier3 2>/dev/null || true
	@echo "==> AHHS-IDS pipeline unloaded."

# Run Tier 3 self-test over all vectors in golden_tier3.json
selftest:
	@echo "==> Running Tier 3 verification harness over golden_tier3.json..."
	PYTHONPATH=$(SCRIPTS_DIR):$(TESTS_DIR):. $(PYTHON) $(TESTS_DIR)/run_selftest.py

# Live in-kernel self-test with bpftool (requires Linux root)
selftest-live:
	@echo "==> Running live in-kernel self-test via bpftool..."
	sudo PYTHONPATH=$(SCRIPTS_DIR):$(TESTS_DIR):. $(PYTHON) $(TESTS_DIR)/run_selftest.py --live

# Inspect BPF maps using bpftool
dump-stats:
	@echo "==> Dumping Tier 1 Statistics Map..."
	sudo $(BPFTOOL) map dump name tier1_stats_map 2>/dev/null || true
	@echo "==> Dumping Tier 3 Telemetry Map (ahhs_t3_stats)..."
	sudo $(BPFTOOL) map dump name ahhs_t3_stats 2>/dev/null || true
	@echo "==> Dumping Flow Blocklist (ahhs_blocklist)..."
	sudo $(BPFTOOL) map dump name ahhs_blocklist 2>/dev/null || true

dump-flows:
	@echo "==> Dumping Tier 2 LRU Flow Map..."
	sudo $(BPFTOOL) map dump name flow_lru_map 2>/dev/null || true

# Comprehensive test suite
test:
	PYTHONPATH=$(SCRIPTS_DIR):$(TESTS_DIR):. $(PYTHON) $(TESTS_DIR)/test_pipeline.py
	PYTHONPATH=$(SCRIPTS_DIR):$(TESTS_DIR):. $(PYTHON) $(TESTS_DIR)/test_phase3_quality.py

# Clean build artifacts
clean:
	rm -rf $(XDP_OBJ) $(TIER3_OBJ) $(LINKED_OBJ) $(LOADER_BIN)

.PHONY: all load unload dump-stats dump-flows clean notebook selftest selftest-live test
