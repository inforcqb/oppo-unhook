# oppo-unhook: OPPO Kernel Security Hook Disabler
# ================================================
# Uses eBPF kprobe + bpf_probe_write_kernel to zero out
# oplus_security_guard hook arrays.
#
# Build targets:
#   oppo_unhook    — userspace loader
#   unhook.bpf.o   — BPF kernel program

cmake_minimum_required(VERSION 3.22)
project(oppo_unhook C)

# ── BPF program ────────────────────────────────────────────────
# Compiled with clang -target bpf (separate from Android NDK build)

set(BPF_SRC  "${CMAKE_SOURCE_DIR}/bpf/unhook.bpf.c")
set(BPF_INC  "${CMAKE_SOURCE_DIR}/bpf")
set(BPF_OUT  "${CMAKE_BINARY_DIR}/unhook.bpf.o")

# ── Userspace loader ──────────────────────────────────────────
set(LOADER_SRC "${CMAKE_SOURCE_DIR}/oppo_unhook.c")

add_executable(oppo_unhook ${LOADER_SRC})
target_include_directories(oppo_unhook PRIVATE ${BPF_INC})
target_compile_options(oppo_unhook PRIVATE
    -O2 -Wall -Wextra
    -fno-stack-protector
)

# Note: BPF program compilation is handled by GitHub Actions workflow,
# not CMake (because it needs clang with bpf target, not Android NDK).
# The workflow:
#   1. Build unhook.bpf.o with system clang -target bpf
#   2. Build oppo_unhook with Android NDK
#   3. Package both as artifact
