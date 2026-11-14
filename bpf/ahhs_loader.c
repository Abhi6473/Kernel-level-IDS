/* =========================================================================
 * AHHS-IDS Phase 3: Libbpf Pipeline Loader & Linker (§8)
 *
 * File: ahhs_loader.c
 *
 * This userspace program:
 * 1. Loads the combined eBPF object file (ahhs.o) via libbpf.
 * 2. Populates the Tier 3 tail-call program array (ahhs_t3_prog_array):
 *      [0] -> ahhs_t3_l1
 *      [1] -> ahhs_t3_l2
 *      [2] -> ahhs_t3_l3
 *      [3] -> ahhs_t3_l4
 * 3. Loads the 592-byte trained model binary (ahhs_model.bin) into
 *    both slots of ahhs_model_map (slot 0 = running, slot 1 = idle).
 * 4. Initializes ahhs_nn_index[0] = 0.
 * 5. Pins the maps and programs under /sys/fs/bpf/ahhs/ for introspection.
 * 6. Attaches the Tier 1 pre-filter (xdp_ahhs_tier1) to the network interface.
 * 7. Listens for SIGINT/SIGTERM to cleanly detach and unload.
 *
 * Compilation:
 *   gcc -O2 -Wall ahhs_loader.c -o ahhs_loader -lbpf -lelf -lz
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "ahhs_common.h"

#define PIN_DIR "/sys/fs/bpf/ahhs"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int mkdir_p(const char *path)
{
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [ahhs_obj] [model_bin]\n", argv[0]);
        fprintf(stderr, "  Defaults: ahhs_obj = ahhs.o, model_bin = ahhs_model.bin\n");
        return 1;
    }

    const char *ifname     = argv[1];
    const char *obj_path   = argc > 2 ? argv[2] : "ahhs.o";
    const char *model_path = argc > 3 ? argv[3] : "models/ahhs_model.bin";

    /* Robust fallbacks for BPF object */
    if (access(obj_path, F_OK) != 0) {
        if (access("ahhs.o", F_OK) == 0)
            obj_path = "ahhs.o";
        else if (access("bpf/ahhs.o", F_OK) == 0)
            obj_path = "bpf/ahhs.o";
    }

    /* Robust fallbacks if model not at explicit path */
    if (access(model_path, F_OK) != 0) {
        if (access("models/ahhs_model.bin", F_OK) == 0)
            model_path = "models/ahhs_model.bin";
        else if (access("ahhs_model.bin", F_OK) == 0)
            model_path = "ahhs_model.bin";
        else if (access("../models/ahhs_model.bin", F_OK) == 0)
            model_path = "../models/ahhs_model.bin";
        else if (access("../ahhs_model.bin", F_OK) == 0)
            model_path = "../ahhs_model.bin";
    }

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "[-] Error: Invalid network interface '%s': %s\n",
                ifname, strerror(errno));
        return 1;
    }

    printf("=================================================================\n");
    printf("AHHS-IDS: Multi-Tier Pipeline Loader (§8)\n");
    printf("=================================================================\n");
    printf("[*] Interface: %s (ifindex %d)\n", ifname, ifindex);
    printf("[*] BPF Object: %s\n", obj_path);
    printf("[*] Model Binary: %s\n", model_path);

    /* 1. Open BPF object */
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "[-] Failed to open BPF object '%s'\n", obj_path);
        return 1;
    }

    /* 2. Load BPF object into kernel */
    printf("[+] Step 1: Loading BPF object into kernel...\n");
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[-] Failed to load BPF object: %d (%s)\n",
                err, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    printf("[✓] BPF object successfully loaded into kernel.\n");

    /* 3. Populate Tier 3 prog_array with the 4 layer programs */
    printf("[+] Step 2: Populating Tier 3 program array (ahhs_t3_prog_array)...\n");
    struct bpf_map *prog_map = bpf_object__find_map_by_name(obj, "ahhs_t3_prog_array");
    if (!prog_map) {
        fprintf(stderr, "[-] Map 'ahhs_t3_prog_array' not found in BPF object\n");
        bpf_object__close(obj);
        return 1;
    }
    int prog_map_fd = bpf_map__fd(prog_map);

    const char *prog_names[AHHS_T3_N] = {
        "ahhs_t3_l1",
        "ahhs_t3_l2",
        "ahhs_t3_l3",
        "ahhs_t3_l4"
    };

    for (__u32 i = 0; i < AHHS_T3_N; i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (!prog) {
            fprintf(stderr, "[-] Program '%s' not found\n", prog_names[i]);
            bpf_object__close(obj);
            return 1;
        }
        int prog_fd = bpf_program__fd(prog);
        err = bpf_map_update_elem(prog_map_fd, &i, &prog_fd, BPF_ANY);
        if (err) {
            fprintf(stderr, "[-] Failed to insert %s into prog_array[%u]: %s\n",
                    prog_names[i], i, strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
        printf("    Linked ahhs_t3_prog_array[%u] -> %s (fd %d)\n", i, prog_names[i], prog_fd);
    }
    printf("[✓] Tier 3 tail call linkage complete (4 layers chained).\n");

    /* 4. Load 592-byte model into ahhs_model_map */
    printf("[+] Step 3: Loading model parameters from %s...\n", model_path);
    FILE *mf = fopen(model_path, "rb");
    if (!mf) {
        fprintf(stderr, "[-] Failed to open model binary '%s': %s\n",
                model_path, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct ahhs_model model_data;
    size_t n_read = fread(&model_data, 1, sizeof(model_data), mf);
    fclose(mf);

    if (n_read != sizeof(model_data)) {
        fprintf(stderr, "[-] Model size mismatch: read %zu bytes, expected %zu\n",
                n_read, sizeof(model_data));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *model_map = bpf_object__find_map_by_name(obj, "ahhs_model_map");
    if (!model_map) {
        fprintf(stderr, "[-] Map 'ahhs_model_map' not found\n");
        bpf_object__close(obj);
        return 1;
    }
    int model_map_fd = bpf_map__fd(model_map);

    /* Populate both slots: slot 0 (Running), slot 1 (Idle) */
    __u32 slot0 = 0, slot1 = 1;
    if (bpf_map_update_elem(model_map_fd, &slot0, &model_data, BPF_ANY) ||
        bpf_map_update_elem(model_map_fd, &slot1, &model_data, BPF_ANY)) {
        fprintf(stderr, "[-] Failed to write model into ahhs_model_map: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("[✓] Loaded 592-byte model into slots 0 (Running) & 1 (Idle) (theta=%u)\n",
           model_data.theta);

    /* 5. Set active model set index to 0 */
    struct bpf_map *idx_map = bpf_object__find_map_by_name(obj, "ahhs_nn_index");
    if (idx_map) {
        int idx_fd = bpf_map__fd(idx_map);
        __u32 zero = 0;
        bpf_map_update_elem(idx_fd, &zero, &zero, BPF_ANY);
        printf("[✓] Initialized ahhs_nn_index = 0\n");
    }

    /* 6. Pin maps under /sys/fs/bpf/ahhs */
    system("rm -rf " PIN_DIR " 2>/dev/null || true");
    mkdir_p(PIN_DIR);
    err = bpf_object__pin_maps(obj, PIN_DIR);
    if (err) {
        fprintf(stderr, "[-] Failed to pin maps under %s: %s (stale pins? run 'make unload' first)\n",
                PIN_DIR, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    /* FIX: programs must be pinned too -- run_selftest.py uses prog_ahhs_t3_selftest.
     * Pin each program explicitly by FUNCTION name (all layers share SEC("xdp"), so
     * relying on libbpf's section-derived pin names would collide). */
    {
        struct bpf_program *p;
        char ppath[256];
        bpf_object__for_each_program(p, obj) {
            snprintf(ppath, sizeof(ppath), "%s/prog_%s", PIN_DIR, bpf_program__name(p));
            err = bpf_program__pin(p, ppath);
            if (err) {
                fprintf(stderr, "[-] Failed to pin program %s: %s\n", ppath, strerror(-err));
                bpf_object__close(obj);
                return 1;
            }
        }
    }
    printf("[✓] Pinned maps and programs under %s/\n", PIN_DIR);

    /* 7. Attach Tier 1 XDP hook */
    printf("[+] Step 4: Attaching Tier 1 pre-filter to %s...\n", ifname);
    struct bpf_program *t1_prog = bpf_object__find_program_by_name(obj, "xdp_ahhs_tier1");
    if (!t1_prog) {
        fprintf(stderr, "[-] Program 'xdp_ahhs_tier1' not found\n");
        bpf_object__close(obj);
        return 1;
    }

    int t1_fd = bpf_program__fd(t1_prog);
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE; /* Safe generic XDP mode */
    err = bpf_xdp_attach(ifindex, t1_fd, xdp_flags, NULL);
    if (err) {
        /* Try DRV mode if SKB fails */
        xdp_flags = XDP_FLAGS_DRV_MODE;
        err = bpf_xdp_attach(ifindex, t1_fd, xdp_flags, NULL);
    }

    if (err) {
        fprintf(stderr, "[-] Failed to attach XDP to %s: %d (%s)\n",
                ifname, err, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    printf("[✓] Successfully attached xdp_ahhs_tier1 to %s.\n", ifname);

    printf("=================================================================\n");
    printf("[★] AHHS-IDS 3-Tier Pipeline is LIVE!\n");
    printf("    Tier 1: Decision Tree Pre-filter\n");
    printf("    Tier 2: LRU Sliding Window + Feature Extractor\n");
    printf("    Tier 3: 4-Layer Quantized Autoencoder (8->16->4->16->8)\n");
    printf("Press Ctrl+C to detach and exit...\n");
    printf("=================================================================\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        sleep(1);
    }

    printf("\n[*] Detaching XDP and unpinning...\n");
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    {
        struct bpf_program *p;
        char ppath[256];
        bpf_object__for_each_program(p, obj) {
            snprintf(ppath, sizeof(ppath), "%s/prog_%s", PIN_DIR, bpf_program__name(p));
            bpf_program__unpin(p, ppath);
        }
    }
    bpf_object__unpin_maps(obj, PIN_DIR);
    bpf_object__close(obj);
    printf("[✓] Clean exit. Pipeline detached.\n");

    return 0;
}
