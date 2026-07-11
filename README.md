# oppo_unhook — OPPO Kernel Security Hook Disabler

基于 **CVE-2026-43499 (GhostLock)** 的 OPPO 设备内核安全钩子禁用工具。

## 目标

- **设备**: OPPO PJA110 / OP5943L1 及类似机型
- **内核**: Linux 5.15.180-android13 (arm64, PREEMPT)
- **漏洞**: futex PI proxy-lock rollback 导致的 UAF（影响 2.6.39 ~ 6.18.x）

## 原理

1. 利用 futex PI 死锁链触发 `rt_mutex_start_proxy_lock()` 的 EDEADLK 回滚
2. 回滚中 `remove_waiter()` 错误地操作 `current` 而非 `waiter->task`
3. 导致 waiter 线程的 `pi_blocked_on` 残留指向已释放的内核栈 `rt_mutex_waiter`
4. 通过内核栈喷射，在释放位置植入伪造的 `rt_mutex_waiter` 结构
5. PI 链遍历通过残留指针跟踪到伪造结构，实现受控内核写
6. 向 `oplus_pre_hook_array` / `oplus_post_hook_array` 写入 0，禁用安全钩子

## 使用方法

```bash
# 1. 下载编译产物（GitHub Actions Artifacts）
# 2. 推送到设备并运行
adb push oppo_unhook /data/local/tmp/
adb shell chmod +x /data/local/tmp/oppo_unhook

# 3. 自动模式（从 kallsyms 读取钩子地址）
adb shell /data/local/tmp/oppo_unhook

# 4. 手动指定地址
adb shell /data/local/tmp/oppo_unhook \
    --target-prea 0xffffffd77xxxxxxx \
    --target-posta 0xffffffd77xxxxxxx

# 5. 干跑模式（仅测试漏洞是否存在，不写钩子）
adb shell /data/local/tmp/oppo_unhook --dry-run
```

## 前置条件

- **必须 root**: 需要读取 `/proc/kallsyms` 获取钩子地址
- **必须 SELinux Permissive**: 需要执行 futex 系统调用
- **推荐**: 先冻结用户态安全守护进程（qsguard, oplus_gaia 等）

## 编译

```bash
# 本地编译（需要 Android NDK 27）
cmake -B build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-26 \
    -DANDROID_STL=none
cmake --build build
```

GitHub Actions 自动编译：push 到 main 分支即可。

## 后续步骤

钩子禁用后，加载 KernelSU：

```bash
# 提取并加载 KSU 内核模块
/data/local/tmp/ksud.so debug extract-binary \
    android13-5.15_kernelsu.ko /data/local/tmp/kernelsu.ko
/data/local/tmp/ksud.so insmod /data/local/tmp/kernelsu.ko

# 完成用户态设置
/data/local/tmp/ksud.so post-fs-data
/data/local/tmp/ksud.so services
```

## 免责声明

此工具仅用于安全研究和学习目的。不当使用可能导致设备变砖、数据丢失。
使用者自行承担所有风险。

## 致谢

- CVE-2026-43499 发现者: Yuan Tan, Yifan Wu, Juefei Pu, Xin Liu
- PoC: [MobiusM/CVE-2026-43499](https://github.com/MobiusM/CVE-2026-43499)
- GhostLock 分析: Nebula Security
