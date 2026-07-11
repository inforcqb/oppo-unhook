/* Minimal BPF helpers for kernel 5.15 */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* BPF helper function IDs */
#define BPF_FUNC_probe_write_kernel  36  /* added in 5.8 */
#define BPF_FUNC_trace_printk        6   /* debugging */

/* BPF map types */
#define BPF_MAP_TYPE_ARRAY 2

/* BPF program types */
#define BPF_PROG_TYPE_KPROBE 7
#define BPF_PROG_TYPE_TRACING 26

/* BPF flags */
#define BPF_F_CURRENT_CPU   0xffffffffULL
#define BPF_F_ALLOW_OVERRIDE (1ULL << 0)

/* BPF attach types for perf_event */
#define PERF_EVENT_IOC_SET_BPF  _IOW('$', 40, __u32)
#define PERF_EVENT_IOC_ENABLE   _IO ('$', 0)
#define PERF_EVENT_IOC_DISABLE  _IO ('$', 1)

/* clang __attribute__ shortcuts */
#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

/* helper macro for kprobe entry */
#define SEC(name) __section(name)

#endif /* __BPF_HELPERS_H */
