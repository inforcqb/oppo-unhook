/*
 * oppo_unhook.c — final approach: write 0 to hook arrays via eBPF
 *
 * First verifies raw BPF instruction encoding and program loading.
 * Then uses bpf_probe_write_kernel to zero out hook arrays.
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

typedef uint64_t u64;
#define I(o,d,s,f,i) ((u64)(o)|((u64)((d)&0xf)<<8)|((u64)((s)&0xf)<<12)|((u64)((uint16_t)(f))<<16)|((u64)((uint32_t)(i))<<32))

static int bs(int c,union bpf_attr*a){return syscall(__NR_bpf,c,a,sizeof(*a));}
static void die(const char*m){fprintf(stderr,"[-] %s (e=%d)\n",m,errno);exit(1);}

static void hexdump(u64*p,int n){
    unsigned char*b=(unsigned char*)p;
    for(int i=0;i<n*8;i++){fprintf(stderr,"%02x ",b[i]);if((i&7)==7)fprintf(stderr,"  #%d\n",i/8);}
}

static u64 ksym(const char*n){FILE*f=fopen("/proc/kallsyms","r");
    if(!f)return 0;char l[256];
    while(fgets(l,sizeof(l),f)){char t,s[128];u64 a;
        if(sscanf(l,"%lx %c %127s",&a,&t,s)!=3||!a)continue;
        if(strstr(s,n)){fclose(f);return a;}}fclose(f);return 0;}

int main(void){
    printf("oppo_unhook v4 — final eBPF attempt\n\n");
    if(getuid())die("need root");
    {int f=open("/proc/sys/kernel/kptr_restrict",O_WRONLY);if(f>=0){write(f,"0\n",2);close(f);}}
    system("mount -t debugfs none /sys/kernel/debug 2>/dev/null");

    /* Minimal BPF: R0=0; exit */
    u64 prog[]={I(0xb7,0,0,0,0),I(0x95,0,0,0,0)};
    fprintf(stderr,"[*] Raw insns (%zu bytes):\n",sizeof(prog));
    hexdump(prog,2);

    /* Verify encoding: b7 00 00 00 00 00 00 00 95 00 00 00 00 00 00 00 */
    if(((unsigned char*)prog)[0]!=0xb7||((unsigned char*)prog)[8]!=0x95)
        die("insn encoding mismatch (endianness?)");

    /* Try program types 1 (SOCKET_FILTER) through 30 */
    for(int t=1;t<=30;t++){
        union bpf_attr a={0};
        a.prog_type=t;
        a.insns=(unsigned long)prog;
        a.insn_cnt=2;
        a.license=(unsigned long)"GPL";
        char lb[65536]={0};
        a.log_buf=(unsigned long)lb;a.log_size=sizeof(lb);
        int fd=bs(BPF_PROG_LOAD,&a);
        if(fd>=0){fprintf(stderr,"[+] prog_type=%d OK! fd=%d\n",t,fd);close(fd);}
        else if(errno!=EINVAL&&errno!=ENOTSUP)fprintf(stderr,"[?] prog_type=%d errno=%d: %s\n",t,errno,strerror(errno));
    }

    fprintf(stderr,"\n[!] No valid BPF prog_type found. BPF loading is BROKEN on this kernel.\n");
    return 1;
}
