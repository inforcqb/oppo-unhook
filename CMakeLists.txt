# oppo-unhook: OPPO Kernel Security Hook Disabler
# Based on CVE-2026-43499 (GhostLock) — futex PI UAF
#
# Target: Linux 5.15.180, arm64 (OPPO PJA110, Android 16)

cmake_minimum_required(VERSION 3.22)
project(oppo_unhook C)
set(CMAKE_C_STANDARD 11)

add_executable(oppo_unhook oppo_unhook.c)
target_compile_options(oppo_unhook PRIVATE
    -O1 -Wall -Wextra
    -fno-stack-protector -fno-sanitize=all
    -Wno-unused-function -Wno-unused-variable
)

add_executable(oracle_test oracle_test.c)
target_compile_options(oracle_test PRIVATE
    -O1 -Wall -Wextra
    -fno-stack-protector -fno-sanitize=all
    -Wno-unused-function -Wno-unused-variable
)
