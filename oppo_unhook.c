/*
 * oppo_unhook.c — eBPF-based OPPO security hook disabler
 * =================================================================
 *
 * 1. Finds oplus_security_guard hook array addresses via kallsyms
 * 2. Loads the BPF kprobe program (unhook.bpf.o)
 * 3. Populates BPF config map with target addresses
 * 4. Attaches kprobe to __arm64_sys_getpid
 * 5. Triggers by calling getpid() → BPF writes zeros to hook arrays
 * 6. Verifies hooks disabled by checking dmesg or ROOTCHECK log
 *
 * Requires: root, CONFIG_BPF=y, CONFIG_KPROBES=y
 * Usage: oppo_unhook [unhook.bpf.o path] [--dry-run]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

/* ── BPF syscall wrapper ────────────────────────────────────── */
static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* ── perf_event_open syscall ────────────────────────────────── */
static inline int perf_event_open(struct perf_event_attr *attr,
                                   pid_t pid, int cpu, int group_fd,
                                   unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* ── helpers ────────────────────────────────────────────────── */
static void die(const char *msg)
{
    fprintf(stderr, "[-] %s (errno=%d: %s)\n", msg, errno, strerror(errno));
    exit(1);
}

static uint64_t kallsyms_find(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char symtype, symname[128];
        uint64_t addr = 0;
        if (sscanf(line, "%lx %c %127s", &addr, &symtype, symname) != 3)
            continue;
        if (addr == 0) continue;
        if (strstr(symname, name)) { fclose(f); return addr; }
    }
    fclose(f);
    return 0;
}

/* ── Minimal ELF parser for loading BPF objects ──────────────── */
struct bpf_elf_ctx {
    const char *data;
    size_t size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;
    const char *shstrtab;
    int prog_fd;
    int map_fd;
};

static int bpf_elf_load(const char *path, struct bpf_elf_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->prog_fd = -1;
    ctx->map_fd = -1;

    /* Read entire file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    fstat(fd, &st);
    ctx->size = st.st_size;
    ctx->data = malloc(ctx->size);
    if (!ctx->data) { close(fd); return -1; }
    read(fd, (void *)ctx->data, ctx->size);
    close(fd);

    ctx->ehdr = (Elf64_Ehdr *)ctx->data;
    if (memcmp(ctx->ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[-] Not an ELF file\n"); return -1;
    }

    /* Section headers */
    ctx->shdrs = (Elf64_Shdr *)(ctx->data + ctx->ehdr->e_shoff);
    Elf64_Shdr *shstr = &ctx->shdrs[ctx->ehdr->e_shstrndx];
    ctx->shstrtab = ctx->data + shstr->sh_offset;

    return 0;
}

static const char *shname(struct bpf_elf_ctx *ctx, int idx)
{
    return ctx->shstrtab + ctx->shdrs[idx].sh_name;
}

static void *shdata(struct bpf_elf_ctx *ctx, int idx)
{
    return (void *)(ctx->data + ctx->shdrs[idx].sh_offset);
}

/* Load BPF programs and maps from ELF */
static int bpf_elf_load_all(struct bpf_elf_ctx *ctx)
{
    for (int i = 1; i < ctx->ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &ctx->shdrs[i];
        const char *name = shname(ctx, i);

        /* Skip non-program sections */
        if (sh->sh_type != SHT_PROGBITS) continue;

        /* Load BPF programs */
        if (strncmp(name, "kprobe/", 7) == 0 ||
            strncmp(name, "kretprobe/", 10) == 0 ||
            strcmp(name, "license") == 0) {
            continue; /* handled below */
        }

        /* Load maps */
        if (strcmp(name, ".maps") == 0) {
            /* Find map definitions */
            for (int j = 1; j < ctx->ehdr->e_shnum; j++) {
                if (strcmp(shname(ctx, j), "maps") == 0) {
                    /* Map data section */
                    Elf64_Shdr *ms = &ctx->shdrs[j];
                    void *mdata = shdata(ctx, j);
                    size_t msize = ms->sh_size;

                    /* Parse BTF map definitions — simplified:
                     * Just create an ARRAY map with 4 entries */
                    union bpf_attr attr = {0};
                    attr.map_type = BPF_MAP_TYPE_ARRAY;
                    attr.key_size = 4;
                    attr.value_size = 8;
                    attr.max_entries = 4;
                    strcpy(attr.map_name, "config");

                    ctx->map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
                    if (ctx->map_fd < 0) {
                        fprintf(stderr, "[-] map create: %d (%s)\n", errno, strerror(errno));
                        return -1;
                    }
                    printf("[+] Created config map (fd=%d)\n", ctx->map_fd);

                    (void)mdata; (void)msize;
                    break;
                }
            }
        }
    }

    /* Load kprobe program */
    for (int i = 1; i < ctx->ehdr->e_shnum; i++) {
        const char *name = shname(ctx, i);
        if (strncmp(name, "kprobe/", 7) == 0 ||
            strncmp(name, "kretprobe/", 10) == 0) {

            void *insns = shdata(ctx, i);
            size_t insn_cnt = ctx->shdrs[i].sh_size / 8;

            /* Find corresponding .rel section for map relocations */
            for (int j = 1; j < ctx->ehdr->e_shnum; j++) {
                char relname[64];
                snprintf(relname, sizeof(relname), ".rel%s", name);
                if (strcmp(shname(ctx, j), relname) == 0) {
                    /* Fix up map_fd references */
                    Elf64_Rel *rels = shdata(ctx, j);
                    size_t nrel = ctx->shdrs[j].sh_size / sizeof(Elf64_Rel);
                    for (size_t r = 0; r < nrel; r++) {
                        uint32_t *insn = (uint32_t *)((char *)insns + rels[r].r_offset);
                        /* BPF_LD_IMM64: patch src_reg with map_fd */
                        if ((insn[0] & 0xFF) == 0x18) {  /* BPF_LD | BPF_IMM | BPF_DW */
                            insn[0] = (insn[0] & 0xFFFF) | (ctx->map_fd << 16);
                        }
                    }
                }
            }

            /* Fix license section relocation */
            for (int j = 1; j < ctx->ehdr->e_shnum; j++) {
                if (strcmp(shname(ctx, j), "license") == 0) {
                    char lic_rel[64];
                    snprintf(lic_rel, sizeof(lic_rel), ".rel%s", name);
                    /* If there's a relocation for license, patch it */
                    /* For simplicity, skip — GPL license is handled by kernel */
                }
            }

            union bpf_attr attr = {0};
            attr.prog_type = BPF_PROG_TYPE_KPROBE;
            attr.insns = (unsigned long)insns;
            attr.insn_cnt = insn_cnt;
            attr.license = (unsigned long)"GPL";
            attr.log_level = 1;
            attr.log_buf = (unsigned long)malloc(65536);
            attr.log_size = 65536;
            memset((void *)(unsigned long)attr.log_buf, 0, 65536);

            ctx->prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
            if (ctx->prog_fd < 0) {
                fprintf(stderr, "[-] BPF_PROG_LOAD failed: %d (%s)\n",
                        errno, strerror(errno));
                fprintf(stderr, "[!] Verifier log:\n%s\n",
                        (char *)(unsigned long)attr.log_buf);
                free((void *)(unsigned long)attr.log_buf);
                return -1;
            }
            free((void *)(unsigned long)attr.log_buf);
            printf("[+] BPF program loaded (fd=%d, %zu insns)\n",
                   ctx->prog_fd, insn_cnt);

            return 0; /* Only load first program for now */
        }
    }

    fprintf(stderr, "[-] No kprobe program found in ELF\n");
    return -1;
}

/* Attach kprobe to a kernel function */
static int kprobe_attach(int prog_fd, const char *func_name)
{
    /* Create perf event for kprobe */
    struct perf_event_attr attr = {0};
    attr.type = 7; /* PERF_TYPE_TRACEPOINT for kprobe */
    attr.size = sizeof(attr);
    attr.config = 0;  /* will be set by debugfs */
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    /* kprobe via debugfs: write to /sys/kernel/debug/tracing/kprobe_events,
     * then open the resulting event.
     * 
     * Simpler alternative: use PERF_TYPE_TRACEPOINT with kprobe events
     * via /sys/kernel/debug/tracing/events/kprobes/<name>/id
     */

    /* Method: write kprobe event, then perf_event_open the event */
    int kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND);
    if (kfd < 0) {
        fprintf(stderr, "[-] Cannot open kprobe_events (debugfs mounted?)\n");
        fprintf(stderr, "    Try: mount -t debugfs none /sys/kernel/debug\n");
        return -1;
    }

    char cmd[256];
    /* Remove existing kprobe if any */
    snprintf(cmd, sizeof(cmd), "-:unhook_kprobe\n");
    write(kfd, cmd, strlen(cmd));

    /* Add new kprobe */
    snprintf(cmd, sizeof(cmd), "p:unhook_kprobe %s\n", func_name);
    if (write(kfd, cmd, strlen(cmd)) < 0) {
        fprintf(stderr, "[-] Failed to create kprobe: %s\n", strerror(errno));
        close(kfd);
        return -1;
    }
    close(kfd);
    printf("[+] Kprobe created: p:unhook_kprobe %s\n", func_name);

    /* Now open the event via perf_event_open */
    /* First, get event ID */
    int eid_fd = open("/sys/kernel/debug/tracing/events/kprobes/unhook_kprobe/id", O_RDONLY);
    if (eid_fd < 0) {
        fprintf(stderr, "[-] Cannot read event ID: %s\n", strerror(errno));
        return -1;
    }
    char eid_buf[16] = {0};
    read(eid_fd, eid_buf, sizeof(eid_buf) - 1);
    close(eid_fd);
    int eid = atoi(eid_buf);

    attr.type = 2; /* PERF_TYPE_TRACEPOINT */
    attr.config = eid;

    int evt_fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (evt_fd < 0) {
        fprintf(stderr, "[-] perf_event_open failed: %s\n", strerror(errno));
        return -1;
    }

    /* Attach BPF program to event */
    if (ioctl(evt_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
        fprintf(stderr, "[-] PERF_EVENT_IOC_SET_BPF failed: %s\n", strerror(errno));
        close(evt_fd);
        return -1;
    }

    if (ioctl(evt_fd, PERF_EVENT_IOC_ENABLE) < 0) {
        fprintf(stderr, "[-] PERF_EVENT_IOC_ENABLE failed: %s\n", strerror(errno));
        close(evt_fd);
        return -1;
    }

    printf("[+] Kprobe attached (event_fd=%d, event_id=%d)\n", evt_fd, eid);
    return evt_fd;
}

/* Write config values to BPF map */
static int config_map_set(int map_fd, uint32_t key, uint64_t value)
{
    union bpf_attr attr = {0};
    attr.map_fd = map_fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)&value;
    attr.flags = BPF_ANY;

    if (bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
        fprintf(stderr, "[-] map update key=%u: %s\n", key, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── main ───────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    const char *bpf_path = "/data/local/tmp/unhook.bpf.o";
    const char *kprobe_fn = "__arm64_sys_getpid";
    int dry_run = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "--dry-run") == 0) dry_run = 1;
        else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: oppo_unhook [BPF_OBJ_PATH] [--dry-run]\n");
            printf("  BPF_OBJ_PATH  path to unhook.bpf.o (default: /data/local/tmp/unhook.bpf.o)\n");
            printf("  --dry-run     test only, don't write hooks\n");
            return 0;
        } else bpf_path = argv[1];
    }
    if (argc > 2 && strcmp(argv[2], "--dry-run") == 0) dry_run = 1;

    printf("\n============================================\n");
    printf("  oppo_unhook — eBPF Hook Disabler v2.0\n");
    printf("  CVE-2026-43499 integration + eBPF write\n");
    printf("============================================\n\n");

    if (getuid() != 0) die("Must run as root");

    /* Step 1: Find hook array addresses */
    printf("[*] Finding hook array addresses...\n");
    uint64_t pre_addr = kallsyms_find("oplus_pre_hook_array");
    uint64_t post_addr = kallsyms_find("oplus_post_hook_array");

    if (!pre_addr && !post_addr) {
        printf("[-] Hook arrays not visible in kallsyms.\n");
        printf("[*] Trying /sys/module sections...\n");

        /* Fallback: read module section bases */
        char buf[32];
        int fd = open("/sys/module/oplus_security_guard/sections/.data", O_RDONLY);
        if (fd >= 0) {
            memset(buf, 0, sizeof(buf));
            read(fd, buf, sizeof(buf) - 1);
            close(fd);
            uint64_t data_base = strtoull(buf, NULL, 16);
            printf("[*] Module .data base: 0x%lx\n", data_base);
        }
        die("Cannot find hook addresses. Please provide them manually.");
    }

    printf("[+] pre_hook_array:  0x%lx\n", pre_addr);
    printf("[+] post_hook_array: 0x%lx\n", post_addr);

    if (dry_run) {
        printf("[*] Dry run complete. Addresses found.\n");
        printf("[*] Run without --dry-run to disable hooks.\n");
        return 0;
    }

    /* Step 2: Check debugfs is mounted */
    if (access("/sys/kernel/debug/tracing/kprobe_events", W_OK) != 0) {
        printf("[*] Mounting debugfs...\n");
        system("mount -t debugfs none /sys/kernel/debug 2>/dev/null");
        if (access("/sys/kernel/debug/tracing/kprobe_events", W_OK) != 0) {
            die("Cannot access debugfs. Is CONFIG_DEBUG_FS=y?");
        }
    }

    /* Step 3: Load BPF program */
    printf("\n[*] Loading BPF program: %s\n", bpf_path);
    if (access(bpf_path, R_OK) != 0) {
        die("BPF object file not found");
    }

    struct bpf_elf_ctx ctx;
    if (bpf_elf_load(bpf_path, &ctx) != 0) {
        die("Failed to parse BPF ELF");
    }

    if (bpf_elf_load_all(&ctx) != 0) {
        die("Failed to load BPF program");
    }

    /* Step 4: Configure BPF map with hook addresses */
    printf("\n[*] Configuring target addresses...\n");
    config_map_set(ctx.map_fd, 0, pre_addr);   /* key=0: pre hook addr */
    config_map_set(ctx.map_fd, 1, 32);          /* key=1: pre hook count */
    config_map_set(ctx.map_fd, 2, post_addr);   /* key=2: post hook addr */
    config_map_set(ctx.map_fd, 3, 32);          /* key=3: post hook count */
    printf("[+] Config map populated\n");

    /* Step 5: Attach kprobe */
    printf("\n[*] Attaching kprobe to %s...\n", kprobe_fn);
    int evt_fd = kprobe_attach(ctx.prog_fd, kprobe_fn);
    if (evt_fd < 0) {
        /* Cleanup */
        close(ctx.prog_fd);
        close(ctx.map_fd);
        die("Failed to attach kprobe");
    }

    /* Step 6: Trigger the kprobe by calling getpid() */
    printf("\n[*] Triggering kprobe (calling getpid)...\n");
    pid_t pid = getpid();
    printf("[+] getpid() = %d → BPF program should have fired\n", pid);

    /* Step 7: Verify */
    printf("\n[*] Checking results:\n");
    printf("[*] Run: dmesg | grep -i rootcheck\n");
    printf("[*] If no new ROOTCHECK messages → hooks DISABLED ✓\n");
    printf("[*] Now try: /data/local/tmp/ksud.so insmod /data/local/tmp/kernelsu.ko\n");

    /* Keep kprobe attached (for verification) */
    printf("\n[*] Kprobe is live. Press Enter to detach...\n");
    getchar();

    /* Cleanup */
    ioctl(evt_fd, PERF_EVENT_IOC_DISABLE);
    close(evt_fd);
    close(ctx.prog_fd);
    close(ctx.map_fd);

    /* Remove kprobe */
    int kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND);
    if (kfd >= 0) {
        write(kfd, "-:unhook_kprobe\n", 16);
        close(kfd);
    }

    printf("[*] Kprobe detached. Done.\n");
    return 0;
}
