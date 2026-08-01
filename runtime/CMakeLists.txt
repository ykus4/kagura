# =============================================================================
# kagura runtime
#
# Source lists are grouped by the platform a file can actually COMPILE on, not
# by the directory it lives in.  The previous WIN32 / NOT WIN32 split meant
# every android/*.c was fed to the compiler on macOS and every ios/*.c on
# Linux, where their `#ifdef __ANDROID__` / `#ifdef __APPLE__` guards reduce
# them to empty translation units - an ISO C constraint violation (C11 6.9p1)
# that only survives because compilers are lenient about it by default.
#
# Lists are written out explicitly rather than globbed so that adding a file
# is a visible diff and lands it in a deliberate group.
# =============================================================================

# ---- Portable: compiles and is useful on every target ------------------------
set(KAGURA_RUNTIME_SOURCES
  core/aes.c
  core/zero_buf.c
  core/vm_interpreter.c

  # Symbols the passes emit unconditionally, so they must exist everywhere.
  #
  # core/blob_integrity.c in particular used to sit in the `if(NOT WIN32)`
  # block despite including only <stdint.h> and having no POSIX dependency at
  # all.  lib/Transforms/Data/StringEncryptionAES.cpp emits
  # kagura_check_blob_integrity on every platform, so -kagura-str-aes simply
  # could not link on Windows.
  core/blob_integrity.c
  core/bb_check.c
  core/telemetry.c
  core/random.c

  # Response policy: one owner for both exported names, all platforms.
  core/tamper_response.c
  core/soft_response.c

  # Shared helpers (see the header comment in each).
  core/hash.c
  core/pathprobe.c
  core/procfs.c
  core/imagelist.c

  # Thin wrapper over core/imagelist.c.
  anti_debug/loaded_library_scan.c

  # Game / anti-cheat helpers with no OS dependency.
  game/game_values.c
  game/state_integrity.c
  game/behavior_log.c
  game/integrity_report.c
)

add_library(kagura_runtime STATIC ${KAGURA_RUNTIME_SOURCES})

# ---- POSIX: Apple and Android/Linux, but not Windows -------------------------
# dlfcn.h, unistd.h, sys/* and the Mach / ELF loader interfaces.
if(NOT WIN32)
  target_sources(kagura_runtime PRIVATE
    core/device_key.c
    core/crash_symbolication.c

    anti_debug/anti_debug.c
    anti_debug/breakpoint_detection.c
    anti_debug/hook_detection.c
    anti_debug/emulator_detection.c
    anti_debug/symbol_interposition.c
    anti_debug/anti_dump.c

    game/il2cpp_protection.c
    game/ue4_protection.c
  )
endif()

# ---- Apple: iOS / macOS ------------------------------------------------------
if(APPLE)
  target_sources(kagura_runtime PRIVATE
    ios/jailbreak_detection.c
    ios/ios_integrity.c
    ios/ios_jailbreak_advanced.c
    ios/ios_platform.c
    ios/macho_integrity.c
    ios/fishhook_countermeasure.c
    ios/testflight_detect.c
    ios/swift_protection.c
    ios/objc_name_remap.c
    ios/device_attest.c
  )
endif()

# ---- Android / Linux ---------------------------------------------------------
# Several of these are additionally gated on __ANDROID__ internally and reduce
# to stubs on desktop Linux; that is intentional, they still compile there.
if(ANDROID OR (UNIX AND NOT APPLE))
  target_sources(kagura_runtime PRIVATE
    android/android_root_advanced.c
    android/jni_hook_detection.c
    android/play_integrity.c
    android/safetynet_compat.c
    android/art_environment.c
    android/load_order.c
    android/apk_integrity.c
    android/elf_integrity.c
    android/split_apk.c
    android/direct_syscall.c
    android/proc_inspection.c
    android/seccomp_checks.c
  )
endif()

# ---- Windows -----------------------------------------------------------------
#
# NOTE: lib/Transforms/AntiAnalysis/AntiDebug.cpp emits calls to
# kagura_check_tracer_pid, kagura_check_inline_hooks, kagura_check_got_hooks,
# kagura_check_sw_breakpoints, kagura_check_hw_breakpoints and
# kagura_check_emulator on every target, but all six live in anti_debug/*.c,
# which is POSIX-only.  -kagura-anti-debug therefore cannot link on Windows.
# Fixing it needs Windows implementations of those six checks, which is a
# design question (what does "inline hook detection" mean here?) rather than a
# build-system one, so it is left as a known gap.
if(WIN32)
  target_sources(kagura_runtime PRIVATE
    windows/anti_debug.c
    windows/integrity.c
    windows/device_key.c
    windows/etw_detection.c
  )
  target_link_libraries(kagura_runtime PRIVATE
    ws2_32      # WinSock2  (anti_debug: Frida port check)
    imagehlp    # MapFileAndCheckSum (integrity: PE checksum)
    bcrypt      # BCryptGenRandom (core/random.c)
  )
endif()

target_include_directories(kagura_runtime PUBLIC
  ${CMAKE_SOURCE_DIR}/include
)

set_target_properties(kagura_runtime PROPERTIES
  C_STANDARD 11
  POSITION_INDEPENDENT_CODE ON
)

# ---- Warnings ----------------------------------------------------------------
# -Wmissing-prototypes is the load-bearing one: it is what keeps every
# cross-TU symbol declared in runtime/internal.h and stops the hand-written
# `extern` declarations from creeping back.  -Wstrict-prototypes catches the
# K&R `()` spellings that silently accept any argument list.
#
# Deliberately no -Werror: CI builds this with several compilers and SDK
# versions, and a warning that only one of them emits should not break the
# build for everyone.
if(MSVC)
  target_compile_options(kagura_runtime PRIVATE /W4)
else()
  target_compile_options(kagura_runtime PRIVATE
    -Wall -Wextra -Wmissing-prototypes -Wstrict-prototypes)
endif()
