/* SPDX-License-Identifier: GPL-2.0 */
/*
 * unhook.bpf.c — eBPF kprobe: zero oplus_security_guard hook arrays
 *
 * Uses BPF global variables (.rodata) instead of maps to avoid
 * relocation complexity. Addresses are set by the loader before
 * program load by patching values at known offsets.
 *
 * Build: clang -target bpf -O2 -g -c unhook.bpf.c -o unhook.bpf.o
 */

typedef unsigned char  __u8;
typedef unsigned int   __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))

/* BPF helper function IDs */
#define BPF_FUNC_probe_write_kernel 36

static long (*probe_write_kernel)(void *dst, const void *src, __u32 len)
    = (void *)BPF_FUNC_probe_write_kernel;

char _license[] SEC("license") = "GPL";

/*
 * Global configuration (set by loader before BPF_PROG_LOAD).
 * These live in .rodata and are writable by userspace before loading.
 *
 * pre_addr   — address of oplus_pre_hook_array
 * post_addr  — address of oplus_post_hook_array
 * entry_cnt  — number of function pointer entries to zero
 *              (each entry = 16 bytes: 8B func ptr + 8B data ptr)
 */
volatile __u64 pre_addr  = 0;
volatile __u64 post_addr = 0;
volatile __u64 entry_cnt = 8;

SEC("kprobe/__arm64_sys_getpid")
int unhook_kprobe(struct pt_regs *ctx)
{
    __u64 zero = 0;
    __u64 count = entry_cnt;
    __u64 i;

    if (count > 64)
        count = 64;

    /* Zero pre_hook_array function pointers */
    if (pre_addr) {
        for (i = 0; i < count; i++) {
            if (probe_write_kernel((void *)(pre_addr + i * 16),
                                   &zero, sizeof(zero)) != 0)
                break;
        }
    }

    /* Zero post_hook_array function pointers */
    if (post_addr) {
        for (i = 0; i < count; i++) {
            if (probe_write_kernel((void *)(post_addr + i * 16),
                                   &zero, sizeof(zero)) != 0)
                break;
        }
    }

    return 0;
}
