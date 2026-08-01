# kagura-android-ndk.cmake
# Android NDK CMake integration for the kagura LLVM obfuscator.
#
# ─────────────────────────────────────────────────────────────────────────────
# Quick-start
# ─────────────────────────────────────────────────────────────────────────────
#
# 1. In your app/build.gradle point CMake at this file and set the plugin path:
#
#      android {
#        defaultConfig {
#          externalNativeBuild {
#            cmake {
#              arguments "-DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.so",
#                        "-DKAGURA_PROFILE=BALANCED"
#            }
#          }
#        }
#        externalNativeBuild {
#          cmake { path "CMakeLists.txt" }
#        }
#      }
#
# 2. In your native CMakeLists.txt:
#
#      cmake_minimum_required(VERSION 3.22)
#      project(mygame)
#
#      include(path/to/kagura-android-ndk.cmake)
#
#      kagura_android_config()          # validate env, set default flags
#
#      add_library(mynativelib SHARED src/native.cpp)
#      kagura_android_target(mynativelib)
#
# ─────────────────────────────────────────────────────────────────────────────
# CMake cache variables (override via -D on the cmake command line or in
# build.gradle's arguments block)
# ─────────────────────────────────────────────────────────────────────────────
#
#   KAGURA_PLUGIN_PATH   Path to KaguraObfuscator.{dylib,so,dll}
#                        (auto-discovered under <kagura>/build/lib/Transforms,
#                         or taken from the environment variable of the same name)
#   KAGURA_PROFILE       Obfuscation profile: FAST | BALANCED | STRONG | CUSTOM,
#                        or a path to your own JSON policy file
#                        (default: BALANCED)
#   KAGURA_RUNTIME_DIR   The kagura runtime/ directory (default: auto-detected)
#
#   Fine-grained pass toggles. Each one that is set is applied AFTER the
#   profile and overrides it; -kagura-config is then omitted so the
#   kagura-config pass cannot clobber the override:
#     KAGURA_ENABLE_STR        String encryption
#     KAGURA_ENABLE_FLA        CFG flattening
#     KAGURA_ENABLE_BCF        Bogus control flow
#     KAGURA_ENABLE_SUB        Instruction substitution
#     KAGURA_ENABLE_CO         Constant obfuscation (MBA)
#     KAGURA_ENABLE_JNI        JNI dynamic registration    (default ON)
#     KAGURA_ENABLE_ANTIDEBUG  Anti-debug / Anti-Frida
#     KAGURA_ENABLE_IL2CPP     IL2CPP runtime protection   (default OFF)
#     KAGURA_BCF_PROB          Bogus CF probability [0-100]
#     KAGURA_BCF_ITER          Bogus CF iterations
#     KAGURA_SUB_ITER          Substitution iterations
#     KAGURA_SEED              PRNG seed (0 = system entropy)
#     KAGURA_METRICS           Emit obfuscation metrics      (default OFF)
#
# The pass set for each profile is NOT defined in this file. It is read from
# integration/profiles/<profile>.json via integration/cmake/KaguraProfile.cmake,
# the single source of truth shared by every kagura integration.

cmake_minimum_required(VERSION 3.22)

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/KaguraProfile.cmake")

# ─────────────────────────────────────────────────────────────────────────────
# Internal: resolve this file's directory so helper paths work regardless
# of where the including CMakeLists.txt lives.
# ─────────────────────────────────────────────────────────────────────────────

get_filename_component(_KAGURA_NDK_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(_KAGURA_NDK_DIR "${_KAGURA_NDK_DIR}" ABSOLUTE)

# Auto-detect the runtime source directory (two levels up from integration/android/)
if(NOT DEFINED KAGURA_RUNTIME_DIR)
  get_filename_component(_KAGURA_ROOT "${_KAGURA_NDK_DIR}/../.." ABSOLUTE)
  set(KAGURA_RUNTIME_DIR "${_KAGURA_ROOT}/runtime"
      CACHE PATH "Directory containing kagura runtime C sources")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Profile selection
# ─────────────────────────────────────────────────────────────────────────────
#
# FAST / BALANCED / STRONG resolve to integration/profiles/<name>.json.
# CUSTOM means "no profile — use the KAGURA_ENABLE_* variables only".
# Any other value is treated as a path to your own JSON policy file.

set(KAGURA_PROFILE "BALANCED" CACHE STRING
    "Obfuscation profile: FAST | BALANCED | STRONG | CUSTOM | <path to .json>")
set_property(CACHE KAGURA_PROFILE PROPERTY STRINGS FAST BALANCED STRONG CUSTOM)

# ─────────────────────────────────────────────────────────────────────────────
# Fine-grained pass options
#
# Only KAGURA_ENABLE_JNI, KAGURA_ENABLE_IL2CPP and KAGURA_METRICS get defaults:
# they are Android-specific and appear in no shared profile. The rest are
# intentionally left undefined so the profile decides; define one on the
# command line to override the profile for that pass.
# ─────────────────────────────────────────────────────────────────────────────

option(KAGURA_ENABLE_JNI       "JNI dynamic registration"       ON)
option(KAGURA_ENABLE_IL2CPP    "IL2CPP runtime protection"      OFF)
option(KAGURA_METRICS          "Print obfuscation metrics"      OFF)

# ─────────────────────────────────────────────────────────────────────────────
# Internal: build the compile-options list from the current flag variables.
# Result is stored in OUT_VAR as a CMake list (semicolon-separated).
# ─────────────────────────────────────────────────────────────────────────────

function(_kagura_ndk_build_flags OUT_VAR)
  if(NOT KAGURA_PLUGIN_PATH OR NOT EXISTS "${KAGURA_PLUGIN_PATH}")
    message(WARNING
      "[kagura] Plugin not found at ${KAGURA_PLUGIN_PATH} — obfuscation disabled")
    set(${OUT_VAR} "" PARENT_SCOPE)
    return()
  endif()

  # Explicit overrides. Android-only passes are never part of a shared
  # profile, so they always come through here.
  set(_overrides "")
  if(KAGURA_ENABLE_JNI)
    list(APPEND _overrides "-kagura-jni")
  endif()
  if(KAGURA_METRICS)
    list(APPEND _overrides "-kagura-metrics")
  endif()
  foreach(_pair
      "KAGURA_ENABLE_STR;-kagura-str"
      "KAGURA_ENABLE_FLA;-kagura-fla"
      "KAGURA_ENABLE_BCF;-kagura-bcf"
      "KAGURA_ENABLE_SUB;-kagura-sub"
      "KAGURA_ENABLE_CO;-kagura-co"
      "KAGURA_ENABLE_ANTIDEBUG;-kagura-anti-debug")
    list(GET _pair 0 _var)
    list(GET _pair 1 _flag)
    if(DEFINED ${_var})
      if(${_var})
        list(APPEND _overrides "${_flag}")
      endif()
    endif()
  endforeach()
  foreach(_pair
      "KAGURA_BCF_PROB;-kagura-bcf-prob"
      "KAGURA_BCF_ITER;-kagura-bcf-iter"
      "KAGURA_SUB_ITER;-kagura-sub-iter"
      "KAGURA_SEED;-kagura-seed")
    list(GET _pair 0 _var)
    list(GET _pair 1 _flag)
    if(DEFINED ${_var})
      list(APPEND _overrides "${_flag}=${${_var}}")
    endif()
  endforeach()

  # CUSTOM = no profile; the overrides are the whole configuration.
  set(_profile "${KAGURA_PROFILE}")
  if(_profile STREQUAL "CUSTOM")
    set(_profile "")
  endif()

  kagura_profile_flags("${_profile}" _pass_flags OVERRIDES ${_overrides})

  set(_flags "SHELL:-fpass-plugin=${KAGURA_PLUGIN_PATH}")
  foreach(_flag IN LISTS _pass_flags)
    list(APPEND _flags "SHELL:-mllvm ${_flag}")
  endforeach()

  set(${OUT_VAR} "${_flags}" PARENT_SCOPE)
endfunction()

# ─────────────────────────────────────────────────────────────────────────────
# Internal: emit ABI-specific compile options onto TARGET_NAME.
# Called from kagura_android_target() after the main flag set.
# ─────────────────────────────────────────────────────────────────────────────

function(_kagura_ndk_abi_flags TARGET_NAME)
  if(NOT ANDROID_ABI)
    return()
  endif()

  if(ANDROID_ABI STREQUAL "armeabi-v7a")
    # Thumb-2 interworking — ensure the compiler stays in Thumb mode for
    # the smaller code size that partially offsets BCF overhead.
    target_compile_options(${TARGET_NAME} PRIVATE
      -mthumb
      -mfpu=neon
    )
    # BCF adds opaque predicates that stress the branch predictor; cap the
    # iteration count at 1 for 32-bit ARM to limit size regression.
    if(KAGURA_ENABLE_BCF AND KAGURA_BCF_ITER GREATER 1)
      message(STATUS
        "[kagura] armeabi-v7a: capping BCF iterations at 1 to limit code size")
      target_compile_options(${TARGET_NAME} PRIVATE
        "SHELL:-mllvm -kagura-bcf-iter=1"
      )
    endif()

  elseif(ANDROID_ABI STREQUAL "arm64-v8a")
    # SVE / NEON hint so the compiler can vectorise helper code in the
    # runtime after inlining.  No kagura-specific cap needed on arm64.
    target_compile_options(${TARGET_NAME} PRIVATE
      -march=armv8-a
    )

  elseif(ANDROID_ABI STREQUAL "x86_64")
    # x86-64 Android (emulator, Chrome OS, some tablets).
    # CFG flattening adds indirect-branch overhead on x86; keep BCF off by
    # default for this ABI unless the caller explicitly opted in.
    if(KAGURA_ENABLE_BCF AND NOT _KAGURA_BCF_X86_64_OVERRIDE)
      message(STATUS
        "[kagura] x86_64: BCF enabled — consider KAGURA_BCF_PROB <= 20 "
        "to limit branch-misprediction overhead on this ABI")
    endif()

  elseif(ANDROID_ABI STREQUAL "x86")
    # 32-bit x86 (legacy emulator).  Disable BCF entirely; the indirect-
    # call overhead is severe and the ABI is rarely targeted in production.
    if(KAGURA_ENABLE_BCF)
      message(WARNING
        "[kagura] x86 ABI: BCF not recommended — code size/perf impact is "
        "disproportionate.  Set KAGURA_ENABLE_BCF=OFF to suppress this warning.")
    endif()
  endif()
endfunction()

# ═════════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# kagura_android_config()
#
# Validates the build environment and applies the selected KAGURA_PROFILE to
# the individual KAGURA_ENABLE_* flags.  Call once near the top of your root
# CMakeLists.txt, before any kagura_android_target() calls.
#
# Performs the following checks:
#   1. Warns if KAGURA_PLUGIN_PATH is not set or the file does not exist.
#   2. Checks the LLVM version embedded in the plugin filename/directory.
#   3. Applies profile presets to the KAGURA_ENABLE_* cache variables.
# ─────────────────────────────────────────────────────────────────────────────

function(kagura_android_config)
  # ---- Plugin path validation ----
  # The plugin runs inside the *host* clang, so the host extension is what
  # matters: .dylib on macOS, .so on Linux, .dll on Windows. Probe all three
  # rather than branching on the Android target.
  kagura_find_plugin(_kp HINTS "${_KAGURA_NDK_DIR}/../../build/lib/Transforms")
  if(_kp)
    set(KAGURA_PLUGIN_PATH "${_kp}"
        CACHE FILEPATH "Path to KaguraObfuscator plugin" FORCE)
    message(STATUS "[kagura] Plugin: ${_kp}")
  else()
    message(WARNING
      "[kagura] Plugin not found under ${_KAGURA_NDK_DIR}/../../build/lib/Transforms\n"
      "  Build the plugin first:  cmake --build <kagura-build-dir>\n"
      "  Then set -DKAGURA_PLUGIN_PATH=<path to KaguraObfuscator.{dylib,so,dll}>")
  endif()

  # ---- LLVM version check ----
  # The plugin filename conventionally encodes the LLVM version, e.g.:
  #   KaguraObfuscator-llvm17.so
  # If found, verify it matches the NDK's clang major version.
  if(DEFINED CMAKE_C_COMPILER)
    execute_process(
      COMMAND "${CMAKE_C_COMPILER}" --version
      OUTPUT_VARIABLE _cc_ver OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(_cc_ver MATCHES "clang version ([0-9]+)")
      set(_clang_major "${CMAKE_MATCH_1}")
      if(KAGURA_PLUGIN_PATH MATCHES "llvm([0-9]+)")
        set(_plugin_llvm "${CMAKE_MATCH_1}")
        if(NOT _clang_major STREQUAL _plugin_llvm)
          message(WARNING
            "[kagura] LLVM version mismatch: clang=${_clang_major}, "
            "plugin built for LLVM ${_plugin_llvm}.  "
            "The plugin may crash or silently miscompile.")
        else()
          message(STATUS "[kagura] LLVM version: ${_clang_major} (matched)")
        endif()
      endif()
    endif()
  endif()

  # ---- Resolve the profile ----
  # Nothing about which passes a profile enables lives here: the pass set is
  # read from integration/profiles/<profile>.json at flag-build time. This
  # only validates the selection and reports it.

  if(KAGURA_PROFILE STREQUAL "CUSTOM")
    message(STATUS
      "[kagura] Profile: CUSTOM  (using individual KAGURA_ENABLE_* variables)")
  else()
    kagura_profile_resolve("${KAGURA_PROFILE}" _profile_json)
    if(_profile_json)
      message(STATUS "[kagura] Profile: ${KAGURA_PROFILE}  (${_profile_json})")
    else()
      message(WARNING
        "[kagura] Unknown profile '${KAGURA_PROFILE}'. "
        "Falling back to BALANCED.  Valid values: FAST BALANCED STRONG CUSTOM "
        "or a path to a JSON policy file")
      set(KAGURA_PROFILE "BALANCED" CACHE STRING "" FORCE)
    endif()
  endif()
endfunction()

# ─────────────────────────────────────────────────────────────────────────────
# kagura_android_target(target_name)
#
# Applies the kagura LLVM pass plugin and all configured flags to the given
# CMake target.  Also links kagura_runtime if the target has been built via
# kagura_android_runtime_target().
#
# Must be called after add_library() / add_executable() for target_name.
# kagura_android_config() should be called before the first invocation of
# this function.
# ─────────────────────────────────────────────────────────────────────────────

function(kagura_android_target TARGET_NAME)
  if(NOT TARGET ${TARGET_NAME})
    message(FATAL_ERROR
      "[kagura] kagura_android_target: '${TARGET_NAME}' is not a CMake target. "
      "Call add_library() or add_executable() first.")
  endif()

  # Build the compile-options list.
  _kagura_ndk_build_flags(_KAGURA_FLAGS)

  if(_KAGURA_FLAGS)
    target_compile_options(${TARGET_NAME} PRIVATE ${_KAGURA_FLAGS})
    message(STATUS "[kagura] Obfuscation applied to target: ${TARGET_NAME}")
  endif()

  # ABI-specific overrides / warnings.
  _kagura_ndk_abi_flags(${TARGET_NAME})

  # Link the runtime if it has been registered via kagura_android_runtime_target().
  if(TARGET kagura_runtime)
    target_link_libraries(${TARGET_NAME} PRIVATE kagura_runtime)
    message(STATUS "[kagura] Linked kagura_runtime to target: ${TARGET_NAME}")
  endif()

  # Pass the IL2CPP protection flag when the runtime target includes
  # il2cpp_protection.c and the profile requests it.
  if(KAGURA_ENABLE_IL2CPP AND TARGET kagura_runtime)
    target_compile_definitions(${TARGET_NAME} PRIVATE KAGURA_IL2CPP_PROTECTION=1)
  endif()
endfunction()

# ─────────────────────────────────────────────────────────────────────────────
# kagura_android_runtime_target(target_name)
#
# Builds the kagura_runtime static library from the runtime C sources and
# registers it under the canonical name "kagura_runtime" so that
# kagura_android_target() can automatically link it.
#
# Parameters:
#   target_name   Name for the runtime static library target.  Pass
#                 "kagura_runtime" to use the conventional name; any other
#                 name creates an ALIAS so both names work.
#
# Example:
#   kagura_android_runtime_target(kagura_runtime)
#   kagura_android_target(mynativelib)   # auto-links kagura_runtime
# ─────────────────────────────────────────────────────────────────────────────

function(kagura_android_runtime_target TARGET_NAME)
  if(TARGET kagura_runtime)
    message(STATUS
      "[kagura] kagura_runtime already defined — skipping second registration")
    return()
  endif()

  if(NOT EXISTS "${KAGURA_RUNTIME_DIR}")
    message(WARNING
      "[kagura] Runtime source directory not found: ${KAGURA_RUNTIME_DIR}\n"
      "  Set -DKAGURA_RUNTIME_DIR=<path> to the kagura runtime/ directory "
      "(the one containing core/, anti_debug/, android/, game/)")
    return()
  endif()

  # Collect runtime sources by DIRECTORY, never by file name: runtime/ is
  # reorganised from time to time and an explicit file list here silently
  # went stale once already (it still named the pre-reorg runtime/aes.c,
  # runtime/anti_debug.c, runtime/jailbreak_detection.c paths).
  #
  # runtime/ios/ and runtime/windows/ are excluded — they are Darwin- and
  # Win32-specific and do not build for Android.
  file(GLOB _runtime_sources CONFIGURE_DEPENDS
    "${KAGURA_RUNTIME_DIR}/core/*.c"
    "${KAGURA_RUNTIME_DIR}/anti_debug/*.c"
    "${KAGURA_RUNTIME_DIR}/android/*.c"
  )

  # The anti-cheat helpers (IL2CPP, UE4, protected values) are only needed by
  # game builds and pull in more code, so they stay opt-in.
  if(KAGURA_ENABLE_IL2CPP)
    file(GLOB _game_sources CONFIGURE_DEPENDS "${KAGURA_RUNTIME_DIR}/game/*.c")
    if(_game_sources)
      list(APPEND _runtime_sources ${_game_sources})
    else()
      message(WARNING
        "[kagura] KAGURA_ENABLE_IL2CPP=ON but no sources found in "
        "${KAGURA_RUNTIME_DIR}/game/")
    endif()
  endif()

  if(NOT _runtime_sources)
    message(WARNING
      "[kagura] No runtime sources found under ${KAGURA_RUNTIME_DIR} — "
      "has the runtime layout changed?")
    return()
  endif()

  add_library(${TARGET_NAME} STATIC ${_runtime_sources})

  # Export headers from the project's include directory.
  get_filename_component(_kagura_include
    "${KAGURA_RUNTIME_DIR}/../include" ABSOLUTE)
  if(EXISTS "${_kagura_include}")
    target_include_directories(${TARGET_NAME} PUBLIC "${_kagura_include}")
  endif()

  set_target_properties(${TARGET_NAME} PROPERTIES
    C_STANDARD              11
    C_STANDARD_REQUIRED     ON
    POSITION_INDEPENDENT_CODE ON
  )

  target_compile_options(${TARGET_NAME} PRIVATE
    -Wall -Wextra -Wno-unused-parameter
  )

  # Create the canonical alias if the caller chose a different name.
  if(NOT TARGET_NAME STREQUAL "kagura_runtime")
    add_library(kagura_runtime ALIAS ${TARGET_NAME})
  endif()

  message(STATUS "[kagura] Runtime target '${TARGET_NAME}' configured")
  message(STATUS "[kagura] Runtime sources: ${_runtime_sources}")
endfunction()
