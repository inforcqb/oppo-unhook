# oppo-unhook — OPPO Kernel Security Hook Disabler (eBPF)

通过 eBPF kprobe + `bpf_probe_write_kernel` 直接清零 `oplus_security_guard` 的 hook 数组。

## 原理

```
用户态(loader)  →  内核态(BPF program)
────────────────────────────────────
1. 读 kallsyms   →  找到 pre/post hook 数组地址
2. 加载 BPF 程序  →  attach kprobe(__arm64_sys_getpid)
3. 填充 BPF map   →  把 hook 地址写入 config map
4. 调用 getpid()  →  触发 kprobe → BPF 写零到 hook 数组
5. 验证结果       →  dmesg 检查 ROOTCHECK 是否消失
```

## 使用

```bash
# 推送到设备
adb push oppo_unhook /data/local/tmp/
adb push unhook.bpf.o /data/local/tmp/
adb shell chmod +x /data/local/tmp/oppo_unhook

# 干跑（只检查地址）
adb shell /data/local/tmp/oppo_unhook --dry-run

# 执行脱钩
adb shell /data/local/tmp/oppo_unhook
```

## 前置条件

- **root** + **SELinux Permissive**
- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_KPROBES=y`
- debugfs 已挂载 (`mount -t debugfs none /sys/kernel/debug`)

## 编译

```bash
# BPF 程序 (clang -target bpf)
clang -target bpf -O2 -g -I bpf/ -c bpf/unhook.bpf.c -o unhook.bpf.o

# 加载器 (Android NDK)
cmake -B build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-35
cmake --build build
```

GitHub Actions 自动编译两个产物。

## 脱钩后

```bash
# 钩子已清零 → 安全模块不再拦截
/data/local/tmp/ksud.so insmod /data/local/tmp/kernelsu.ko
/data/local/tmp/ksud.so post-fs-data
/data/local/tmp/ksud.so services
```

## 致谢

- GhostLock: CVE-2026-43499 (Yuan Tan, Yifan Wu, Juefei Pu, Xin Liu)
- eBPF infrastructure: Linux kernel community
