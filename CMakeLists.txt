# OPPO PJA110 Kernel Security Hook Disabler
# Based on CVE-2026-43499 (GhostLock) — futex PI UAF
#
# Target: Linux 5.15.180-android13 (Oppo PJA110 / OP5943L1)
# Goal: Zero out oplus_security_guard pre/post hook arrays to allow KSU loading

cmake_minimum_required(VERSION 3.22)

project(oppo_unhook C)

set(CMAKE_C_STANDARD 11)

# ── GitHub Actions NDK ───────────────────────────────────────
if(DEFINED ENV{ANDROID_NDK_HOME})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake"
        CACHE PATH "" FORCE)
else()
    set(CMAKE_TOOLCHAIN_FILE "${ANDROID_NDK}/build/cmake/android.toolchain.cmake"
        CACHE PATH "" FORCE)
endif()

set(ANDROID_ABI      "arm64-v8a"  CACHE STRING "" FORCE)
set(ANDROID_PLATFORM "android-26" CACHE STRING "" FORCE)
set(ANDROID_STL      "none"       CACHE STRING "" FORCE)

add_executable(oppo_unhook
    oppo_unhook.c
)

target_compile_options(oppo_unhook PRIVATE
    -O1 -Wall -Wextra
    -fno-stack-protector
    -fno-sanitize=all
)

target_link_options(oppo_unhook PRIVATE
    -static
    -Wl,--no-rosegment
)
