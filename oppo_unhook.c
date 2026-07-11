/*
 * oppo_unhook.c — eBPF OPPO security hook killer (no ELF needed)
 * ===============================================================
 *
 * Generates BPF instructions directly, avoiding ELF/relocation hell.
 *
 * BPF program (pseudo):
 *   R1 = &config (map fd)
 *   R2 = &key
 *   call map_lookup_elem  →  R0 = value_ptr (or NULL)
 *   if R0 == NULL: bail
 *   R1 = *value_ptr (hook addr from map)
 *   R2 = &zero (on stack)
 *   R3 = 8
 *   call probe_write_kernel
 *   exit
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

/* ── BPF instruction encoding helpers ──────────────────────────
 * Uses kernel's struct bpf_insn from <linux/bpf.h>
 */

#define BPF_LD_IMM64(DST, IMM) \
    ((struct bpf_insn){ .code = 0x18, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = (__u32)(IMM) }), \
    ((struct bpf_insn){ .code = 0x00, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (__u32)((IMM) >> 32) })

#define BPF_MOV64_IMM(DST, IMM) \
    ((struct bpf_insn){ .code = 0xb7, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_MOV64_REG(DST, SRC) \
    ((struct bpf_insn){ .code = 0xbf, .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
    ((struct bpf_insn){ .code = 0x63, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0 })

#define BPF_ALU64_IMM(OP, DST, IMM) \
    ((struct bpf_insn){ .code = 0x07, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    ((struct bpf_insn){ .code = 0x05, .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM })

#define BPF_CALL_REL(IMM) \
    ((struct bpf_insn){ .code = 0x85, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_EXIT() \
    ((struct bpf_insn){ .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 })

#define BPF_JMP_A(OFF) \
    ((struct bpf_insn){ .code = 0x05, .dst_reg = 0, .src_reg = 0, .off = OFF, .imm = 0 })

#define BPF_MOV64_IMM(DST, IMM) \
    ((struct bpf_insn){ .code = 0xb7, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

/* BPF registers */
#define BPF_REG_0  0
#define BPF_REG_1  1
#define BPF_REG_2  2
#define BPF_REG_3  3
#define BPF_REG_6  6
#define BPF_REG_7  7
#define BPF_REG_8  8
#define BPF_REG_9  9
#define BPF_REG_10 10

/* BPF helper func IDs */
#define BPF_FUNC_probe_write_kernel 36
#define BPF_FUNC_map_lookup_elem    1

/* ── syscall wrappers ────────────────────────────────────────── */
static int bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr)
{ return syscall(__NR_bpf, cmd, attr, sizeof(*attr)); }

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int gfd, unsigned long fl)
{ return syscall(__NR_perf_event_open, attr, pid, cpu, gfd, fl); }

/* ── helpers ────────────────────────────────────────────────── */
static void die(const char *msg)
{ fprintf(stderr, "[-] %s (errno=%d: %s)\n", msg, errno, strerror(errno)); exit(1); }

static uint64_t kallsyms_find(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char t; char n[128]; uint64_t a;
        if (sscanf(line, "%lx %c %127s", &a, &t, n) != 3) continue;
        if (a == 0) continue;
        if (strstr(n, name)) { fclose(f); return a; }
    }
    fclose(f); return 0;
}

/* ── Build BPF program ─────────────────────────────────────────
 *
 * for (i = 0; i < entry_cnt; i++) {
 *     val = config_map[i]
 *     if (val) bpf_probe_write_kernel((void*)val, &zero, 8);
 * }
 *
 * Config map layout:
 * Key 0-7: target addresses (hook array entries)
 * Max entries: 16, Value: 8 bytes
 */
static int build_bpf(int map_fd, int entry_cnt)
{
    struct bpf_insn prog[] = {
        // R6 = 0 (zero value for writes)
        BPF_MOV64_IMM(BPF_REG_6, 0),
        // Store zero on stack at -8 for probe_write_kernel src
        BPF_STX_MEM(0x18, BPF_REG_10, BPF_REG_6, -8),  // BPF_DW = 0x18
        // R7 = &zero (stack pointer - 8)
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),
        BPF_ALU64_IMM(0, BPF_REG_7, -8),  // 0 = ADD

        // R8 = loop counter (0 to entry_cnt-1)
        BPF_MOV64_IMM(BPF_REG_8, 0),

        // -- loop start --
        // R1 = map_fd (pseudo-map-fd)
        ((struct bpf_insn){ .code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .off = 0, .imm = 0 }),
        ((struct bpf_insn){ .code = 0x00, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = map_fd }),
        // R2 = &counter (stack -16)
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(0, BPF_REG_2, -16),
        // Store counter
        BPF_STX_MEM(0x04, BPF_REG_2, BPF_REG_8, 0),  // BPF_W = 0x04, store at R2+0

        // R2 = &counter (reload, clobbered by STX? no, STX doesn't clobber DST)
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(0, BPF_REG_2, -16),

        // call map_lookup_elem(R1=map, R2=key) → R0
        BPF_CALL_REL(BPF_FUNC_map_lookup_elem),

        // if R0 == NULL: skip
        BPF_JMP_IMM(0x04, BPF_REG_0, 0, 3),  // 0x04 = JNE (jump if R0 != 0), skip 3

        // R1 = *R0 (hook addr)
        // This needs: R1 = *(u64 *)R0
        // BPF_LDX_MEM(BPF_DW, R1, R0, 0) → code 0x79
        ((struct bpf_insn){ .code = 0x79, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_0, .off = 0, .imm = 0 }),

        // R2 = &zero (R7)
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
        // R3 = 8
        BPF_MOV64_IMM(BPF_REG_3, 8),
        // call probe_write_kernel(R1,R2,R3)
        BPF_CALL_REL(BPF_FUNC_probe_write_kernel),

        // R8++ (loop counter)
        BPF_ALU64_IMM(0, BPF_REG_8, 1),

        // if R8 < entry_cnt, goto loop start
        BPF_JMP_IMM(0x0a, BPF_REG_8, entry_cnt, -12),  // 0x0a = JLT (unsigned <)

        // R0 = 0
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT(),
    };

    union bpf_attr attr = {0};
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insns = (unsigned long)prog;
    attr.insn_cnt = sizeof(prog) / sizeof(prog[0]);
    attr.license = (unsigned long)"GPL";
    attr.log_level = 1;
    char logbuf[65536] = {0};
    attr.log_buf = (unsigned long)logbuf;
    attr.log_size = sizeof(logbuf);

    int prog_fd = bpf_sys(BPF_PROG_LOAD, &attr);
    if (prog_fd < 0) {
        fprintf(stderr, "[-] BPF_PROG_LOAD failed: %s\n", strerror(errno));
        fprintf(stderr, "[!] Verifier log:\n%s\n", logbuf);
        return -1;
    }
    printf("[+] BPF program loaded (fd=%d, %zu insns)\n",
           prog_fd, sizeof(prog) / sizeof(prog[0]));
    printf("[+] Verifier: OK\n");
    return prog_fd;
}

/* ── Create config map ───────────────────────────────────────── */
static int create_config_map(uint64_t *addrs, int count)
{
    union bpf_attr attr = {0};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 16;

    int fd = bpf_sys(BPF_MAP_CREATE, &attr);
    if (fd < 0) die("BPF_MAP_CREATE");
    printf("[+] Config map created (fd=%d)\n", fd);

    /* Populate map with hook addresses */
    for (int i = 0; i < count && i < 16; i++) {
        union bpf_attr ua = {0};
        uint32_t key = i;
        ua.map_fd = fd;
        ua.key = (unsigned long)&key;
        ua.value = (unsigned long)&addrs[i];
        ua.flags = BPF_ANY;
        if (bpf_sys(BPF_MAP_UPDATE_ELEM, &ua) < 0) {
            fprintf(stderr, "[-] map update key=%d: %s\n", i, strerror(errno));
        } else {
            printf("  [map] key=%d val=0x%lx\n", i, addrs[i]);
        }
    }

    return fd;
}

/* ── Attach kprobe ───────────────────────────────────────────── */
static int attach_kprobe(int prog_fd, const char *func)
{
    /* Mount debugfs */
    system("mount -t debugfs none /sys/kernel/debug 2>/dev/null");

    /* Create kprobe via debugfs */
    int kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND);
    if (kfd < 0) die("open kprobe_events");

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "-:oppo_unhook\n");
    write(kfd, cmd, strlen(cmd)); /* remove existing */

    snprintf(cmd, sizeof(cmd), "p:oppo_unhook %s\n", func);
    if (write(kfd, cmd, strlen(cmd)) < 0) { close(kfd); die("write kprobe"); }
    close(kfd);
    printf("[+] Kprobe: p:oppo_unhook %s\n", func);

    /* Get event ID */
    int efd = open("/sys/kernel/debug/tracing/events/kprobes/oppo_unhook/id", O_RDONLY);
    if (efd < 0) die("open event id");
    char buf[16] = {0};
    read(efd, buf, sizeof(buf) - 1);
    close(efd);
    int eid = atoi(buf);

    /* perf_event_open */
    struct perf_event_attr attr = {0};
    attr.type = 2; /* PERF_TYPE_TRACEPOINT */
    attr.size = sizeof(attr);
    attr.config = eid;
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    int evfd = perf_open(&attr, -1, 0, -1, 0);
    if (evfd < 0) die("perf_event_open");

    if (ioctl(evfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) die("PERF_EVENT_IOC_SET_BPF");
    if (ioctl(evfd, PERF_EVENT_IOC_ENABLE) < 0) die("PERF_EVENT_IOC_ENABLE");
    printf("[+] Kprobe attached (event_fd=%d)\n", evfd);
    return evfd;
}

/* ── main ───────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    printf("\n============================================\n");
    printf("  oppo_unhook — eBPF Hook Killer v3.0\n");
    printf("============================================\n\n");

    if (getuid() != 0) die("Must run as root");

    /* Step 1: Get hook addresses */
    printf("[*] Finding hook addresses...\n");

    /* Set kptr_restrict to 0 for visibility */
    int kfd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
    if (kfd >= 0) { write(kfd, "0\n", 2); close(kfd); }

    uint64_t pre_addr  = kallsyms_find("oplus_pre_hook_array");
    uint64_t post_addr = kallsyms_find("oplus_post_hook_array");

    if (!pre_addr && !post_addr) die("Cannot find hook arrays");

    printf("[+] pre_hook_array:  0x%lx\n", pre_addr);
    printf("[+] post_hook_array: 0x%lx\n", post_addr);

    /*
     * Hook array entry: struct { void *func; void *data; } = 16 bytes.
     * pre_hook at 0x...010, post_hook at 0x...040 → 48 bytes gap = 3 entries in pre.
     */
    int pre_entries  = pre_addr  ? ((post_addr - pre_addr) / 16) : 0;
    int post_entries = post_addr ? 8 : 0;  /* assume up to 8 entries */
    printf("[*] Estimated: %d pre-hook entries, %d post-hook entries\n",
           pre_entries, post_entries);

    /* Build target list: one map entry per hook function pointer */
    uint64_t targets[16] = {0};
    int idx = 0;
    for (int i = 0; i < pre_entries && idx < 8; i++)
        targets[idx++] = pre_addr + i * 16;  /* point to func ptr slot */
    for (int i = 0; i < post_entries && idx < 16; i++)
        targets[idx++] = post_addr + i * 16;

    printf("[*] %d targets to zero\n", idx);

    /* Step 2: Create config map and populate */
    int map_fd = create_config_map(targets, idx);

    /* Step 3: Build and load BPF program */
    printf("\n[*] Building BPF program...\n");
    int prog_fd = build_bpf(map_fd, idx);
    if (prog_fd < 0) die("BPF build failed");

    /* Step 4: Attach kprobe */
    printf("\n[*] Attaching kprobe...\n");
    int evfd = attach_kprobe(prog_fd, "__arm64_sys_getpid");

    /* Step 5: Trigger */
    printf("\n[*] Triggering BPF program (calling getpid)...\n");
    pid_t pid = getpid();
    printf("[+] getpid() = %d → BPF fired!\n", pid);

    /* Step 6: Verify */
    printf("\n=== DONE ===\n");
    printf("[*] Check: dmesg | grep -i rootcheck\n");
    printf("[*] If ROOTCHECK messages STOPPED → hooks disabled!\n");
    printf("[*] Now: /data/local/tmp/ksud.so insmod /data/local/tmp/kernelsu.ko\n");

    /* Keep attached for a few seconds */
    printf("\n[*] Kprobe live. Waiting 5s for verification...\n");
    sleep(5);

    /* Cleanup */
    ioctl(evfd, PERF_EVENT_IOC_DISABLE, 0);
    close(evfd);
    close(prog_fd);
    close(map_fd);

    /* Remove kprobe */
    kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND);
    if (kfd >= 0) { write(kfd, "-:oppo_unhook\n", 14); close(kfd); }

    printf("[*] Clean. Next: insmod kernelsu.ko\n");
    return 0;
}
