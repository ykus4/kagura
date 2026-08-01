# ---- Platform-independent core sources ---------------------------------------
# Only files that compile cleanly on all platforms (no POSIX-only headers).
set(KAGURA_RUNTIME_CORE_SOURCES
  core/aes.c
  core/zero_buf.c
  core/vm_interpreter.c
  core/bb_check.c
  core/telemetry.c
  core/random.c
  core/tamper_response.c
  core/soft_response.c
  core/hash.c
  core/pathprobe.c
  core/procfs.c
  core/imagelist.c
)

add_library(kagura_runtime STATIC ${KAGURA_RUNTIME_CORE_SOURCES})

if(NOT WIN32)
  # POSIX-only core files (dlfcn.h, unistd.h, sys/* headers)
  target_sources(kagura_runtime PRIVATE
    core/device_key.c
    core/blob_integrity.c
    core/crash_symbolication.c

    # ---- Anti-debug / anti-analysis ------------------------------------------
    anti_debug/anti_debug.c
    anti_debug/breakpoint_detection.c
    anti_debug/hook_detection.c
    anti_debug/emulator_detection.c
    anti_debug/loaded_library_scan.c
    anti_debug/symbol_interposition.c
    anti_debug/anti_dump.c

    # ---- Android + Linux: integrity, attestation, syscall / proc hardening ---
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

    # ---- iOS / macOS: integrity, jailbreak detection -------------------------
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

    # ---- Game / anti-cheat ---------------------------------------------------
    game/il2cpp_protection.c
    game/ue4_protection.c
    game/game_values.c
    game/state_integrity.c
    game/behavior_log.c
    game/integrity_report.c
  )
endif()

# ---- A.1: Windows runtime stubs --------------------------------------------
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
