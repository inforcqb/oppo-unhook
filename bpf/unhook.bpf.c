/* SPDX-License-Identifier: GPL-2.0 */
/*
 * unhook.bpf.c — eBPF kprobe: zero out oplus_security_guard hooks
 *
 * Attach: kprobe on __arm64_sys_getpid
 * Action: write 0 to pre/post hook arrays via bpf_probe_write_kernel
 *
 * Build: clang -target bpf -O2 -g -c unhook.bpf.c -o unhook.bpf.o
 */

#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

/* Map: user-space sets target addresses + counts */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, unsigned long);
} config SEC(".maps");

/* bpf_probe_write_kernel helper */
static long (*probe_write_kernel)(void *dst, const void *src, __u32 len)
    = (void *)BPF_FUNC_probe_write_kernel;

SEC("kprobe/__arm64_sys_getpid")
int unhook_kprobe(struct pt_regs *ctx)
{
    unsigned long zero = 0;
    __u32 key;

    /* Read pre_hook config: key=0 → addr, key=1 → count */
    key = 0;
    unsigned long *pre_addr = bpf_map_lookup_elem(&config, &key);
    key = 1;
    unsigned long *pre_cnt  = bpf_map_lookup_elem(&config, &key);

    /* Read post_hook config: key=2 → addr, key=3 → count */
    key = 2;
    unsigned long *post_addr = bpf_map_lookup_elem(&config, &key);
    key = 3;
    unsigned long *post_cnt  = bpf_map_lookup_elem(&config, &key);

    /* Zero pre_hook_array */
    if (pre_addr && pre_cnt && *pre_addr) {
        unsigned long count = *pre_cnt > 64 ? 64 : *pre_cnt;
        for (unsigned long i = 0; i < count; i++) {
            probe_write_kernel((void *)(*pre_addr + i * 16), &zero, 8);
        }
    }

    /* Zero post_hook_array */
    if (post_addr && post_cnt && *post_addr) {
        unsigned long count = *post_cnt > 64 ? 64 : *post_cnt;
        for (unsigned long i = 0; i < count; i++) {
            probe_write_kernel((void *)(*post_addr + i * 16), &zero, 8);
        }
    }

    return 0;
}
