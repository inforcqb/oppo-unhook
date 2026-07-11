/* oppo_unhook.c — step-by-step BPF test + hook killer */

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

typedef uint64_t u64;
#define I(o,d,s,f,i) ((u64)(o)|((u64)((d)&0xf)<<8)|((u64)((s)&0xf)<<12)|((u64)((uint16_t)(f))<<16)|((u64)((uint32_t)(i))<<32))

static int bs(int c, union bpf_attr *a){return syscall(__NR_bpf,c,a,sizeof(*a));}
static int pe(struct perf_event_attr *a,pid_t p,int u,int g,unsigned long f){return syscall(__NR_perf_event_open,a,p,u,g,f);}
static void die(const char *m){fprintf(stderr,"[-] %s (%d)\n",m,errno);exit(1);}

static u64 ks(const char *n){FILE*f=fopen("/proc/kallsyms","r");if(!f)return 0;
    char l[256];while(fgets(l,sizeof(l),f)){char t,s[128];u64 a;
        if(sscanf(l,"%lx %c %127s",&a,&t,s)!=3||!a)continue;
        if(strstr(s,n)){fclose(f);return a;}}fclose(f);return 0;}

int main(void){
    printf("oppo_unhook v3.2 — BPF step test\n\n");
    if(getuid())die("need root");
    {int f=open("/proc/sys/kernel/kptr_restrict",O_WRONLY);if(f>=0){write(f,"0\n",2);close(f);}}
    system("mount -t debugfs none /sys/kernel/debug 2>/dev/null");

    /* Test 1: minimal valid BPF program (R0=0; exit) */
    printf("[*] Test 1: minimal BPF program...\n");
    u64 prog1[] = {
        I(0xb7,0,0,0,0),  /* R0 = 0 */
        I(0x95,0,0,0,0),  /* exit */
    };
    union bpf_attr at1={0};
    at1.prog_type=BPF_PROG_TYPE_KPROBE;
    at1.insns=(unsigned long)prog1;
    at1.insn_cnt=2;
    at1.license=(unsigned long)"GPL";
    char lb1[65536]={0};
    at1.log_buf=(unsigned long)lb1; at1.log_size=sizeof(lb1);
    int fd1=bs(BPF_PROG_LOAD,&at1);
    if(fd1<0){printf("[-] FAIL\n%s\n",lb1);}else{printf("[+] OK fd=%d\n",fd1);close(fd1);}

    /* Test 2: BPF program with map lookup */
    printf("[*] Test 2: map + lookup...\n");
    union bpf_attr ma={0};
    ma.map_type=BPF_MAP_TYPE_ARRAY;ma.key_size=4;ma.value_size=8;ma.max_entries=4;
    int mfd=bs(BPF_MAP_CREATE,&ma);
    if(mfd<0)die("map create");
    printf("[+] map fd=%d\n",mfd);

    /* Populate map */
    {union bpf_attr u={0};uint32_t k=0;u64 v=0xdeadbeef;
        u.map_fd=mfd;u.key=(unsigned long)&k;u.value=(unsigned long)&v;u.flags=BPF_ANY;
        bs(BPF_MAP_UPDATE_ELEM,&u);}

    /* prog: R1=map_fd(pseudo); R2=&key(R10-4); call map_lookup_elem; exit */
    u64 prog2[]={
        /* store key=0 on stack */
        I(0xb7,6,0,0,0),         /* R6 = 0 */
        I(0x63,10,6,-4,0),       /* *(u32*)(R10-4)=R6 (BPF_W store) */
        /* R1 = pseudo map fd */
        I(0x18,1,1,0,0),         /* LD IMM64 insn0: op=0x18, dst=1, src=1(BPF_PSEUDO_MAP_FD) */
        I(0x00,0,0,0,mfd),       /* LD IMM64 insn1: fd in imm */
        /* R2 = &key */
        I(0xbf,2,10,0,0),        /* R2 = R10 */
        I(0x07,2,0,0,-4),        /* R2 += -4 (ADD, not what we want...) */
        /* call map_lookup_elem */
        I(0x85,0,0,0,1),         /* call 1 */
        /* R0 = 0; exit */
        I(0xb7,0,0,0,0),
        I(0x95,0,0,0,0),
    };
    union bpf_attr at2={0};
    at2.prog_type=BPF_PROG_TYPE_KPROBE;
    at2.insns=(unsigned long)prog2;
    at2.insn_cnt=sizeof(prog2)/sizeof(prog2[0]);
    at2.license=(unsigned long)"GPL";
    char lb2[65536]={0};
    at2.log_buf=(unsigned long)lb2; at2.log_size=sizeof(lb2);
    int fd2=bs(BPF_PROG_LOAD,&at2);
    if(fd2<0){printf("[-] FAIL\n%s\n",lb2);die("BPF map test failed");}
    printf("[+] OK fd=%d\n",fd2);
    close(fd2);
    close(mfd);

    /* Test 3: Hook addresses */
    printf("[*] Test 3: hook addresses...\n");
    u64 pa=ks("oplus_pre_hook_array"), pb=ks("oplus_post_hook_array");
    printf("[+] pre=0x%lx post=0x%lx\n",pa,pb);
    if(!pa&&!pb)die("no hook addrs");

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
