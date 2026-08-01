# kagura-toolchain.cmake
#
# Generic CMake toolchain file for kagura obfuscation.
# Works with any CMake project (Cocos2d-x, Godot GDNative, custom engines).
#
# Usage
# -----
# Pass this file as the toolchain:
#
#   cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/kagura/integration/cmake/kagura-toolchain.cmake \
#         -DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.dylib \
#         -B build -S .
#
# If you already have a toolchain file (e.g. Android NDK toolchain), chain
# them by setting KAGURA_CHAIN_TOOLCHAIN:
#
#   cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/kagura/integration/cmake/kagura-toolchain.cmake \
#         -DKAGURA_CHAIN_TOOLCHAIN=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.so \
#         -B build -S .
#
# ── Required variables ────────────────────────────────────────────────────────
#   KAGURA_PLUGIN_PATH    Path to KaguraObfuscator.dylib / .so / .dll
#                         (auto-discovered from ../../build/lib/Transforms,
#                          or from the KAGURA_PLUGIN_PATH environment variable)
#
# ── Optional variables ────────────────────────────────────────────────────────
#   KAGURA_RUNTIME_LIB    Path to libkagura_runtime.a
#   KAGURA_CHAIN_TOOLCHAIN  Another toolchain file to include first
#   KAGURA_PROFILE        Obfuscation profile: FAST | BALANCED | STRONG | OFF,
#                         or an absolute path to your own JSON policy file
#                         (default: BALANCED)
#   KAGURA_EXTRA_PASSES   Extra "-kagura-*" flags appended after the profile,
#                         e.g. "-kagura-objc;-kagura-vm"
#   KAGURA_SEED           PRNG seed override (0 = entropy)
#   KAGURA_BCF_PROB       Bogus CF probability override [0-100]
#
# ── Profiles ──────────────────────────────────────────────────────────────────
# The FAST / BALANCED / STRONG pass sets are NOT defined here. They live in
# integration/profiles/{fast,balanced,strong}.json — the single source of
# truth shared by every kagura integration — and are expanded at configure
# time by integration/cmake/KaguraProfile.cmake.
#
#   OFF       no obfuscation (toolchain still chains correctly)
# ─────────────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.20)

include("${CMAKE_CURRENT_LIST_DIR}/KaguraProfile.cmake")

# ── Chain an existing toolchain ───────────────────────────────────────────────
if(KAGURA_CHAIN_TOOLCHAIN AND NOT _KAGURA_CHAINED)
  set(_KAGURA_CHAINED TRUE)
  include("${KAGURA_CHAIN_TOOLCHAIN}")
endif()

# ── Skip if obfuscation is disabled ──────────────────────────────────────────
if(NOT DEFINED KAGURA_PROFILE)
  set(KAGURA_PROFILE "BALANCED")
endif()

if(KAGURA_PROFILE STREQUAL "OFF")
  return()
endif()

# ── Locate plugin ─────────────────────────────────────────────────────────────
# Handles .dylib (Apple), .so (Linux/Android) and .dll (Windows), and honours
# both the CMake variable and the KAGURA_PLUGIN_PATH environment variable.
kagura_find_plugin(_KAGURA_FOUND_PLUGIN)
if(_KAGURA_FOUND_PLUGIN)
  set(KAGURA_PLUGIN_PATH "${_KAGURA_FOUND_PLUGIN}")
endif()

if(NOT KAGURA_PLUGIN_PATH OR NOT EXISTS "${KAGURA_PLUGIN_PATH}")
  message(WARNING
    "[kagura] Plugin not found — obfuscation disabled.\n"
    "  Set -DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.{dylib,so,dll}")
  return()
endif()

# ── Build flag list from the shared profile ───────────────────────────────────
# The pass list comes from integration/profiles/<profile>.json; nothing about
# which passes a profile enables is duplicated here.

set(_KAGURA_OVERRIDES "")
if(KAGURA_EXTRA_PASSES)
  list(APPEND _KAGURA_OVERRIDES ${KAGURA_EXTRA_PASSES})
endif()
if(DEFINED KAGURA_BCF_PROB)
  list(APPEND _KAGURA_OVERRIDES "-kagura-bcf-prob=${KAGURA_BCF_PROB}")
endif()
if(DEFINED KAGURA_SEED)
  list(APPEND _KAGURA_OVERRIDES "-kagura-seed=${KAGURA_SEED}")
endif()

kagura_profile_flags("${KAGURA_PROFILE}" _KAGURA_PASS_FLAGS
                     OVERRIDES ${_KAGURA_OVERRIDES})

if(NOT _KAGURA_PASS_FLAGS)
  message(WARNING
    "[kagura] Unknown KAGURA_PROFILE '${KAGURA_PROFILE}' and no overrides — "
    "falling back to BALANCED")
  kagura_profile_flags("BALANCED" _KAGURA_PASS_FLAGS)
endif()

set(_KAGURA_FLAGS "-fpass-plugin=${KAGURA_PLUGIN_PATH}")
foreach(_flag IN LISTS _KAGURA_PASS_FLAGS)
  string(APPEND _KAGURA_FLAGS " -mllvm ${_flag}")
endforeach()

# ── Inject into compiler flags ────────────────────────────────────────────────
# Use INIT variables so they take effect before project() sees them,
# and use CACHE so they propagate to sub-projects.
set(CMAKE_C_FLAGS_INIT   "${CMAKE_C_FLAGS_INIT}   ${_KAGURA_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_CXX_FLAGS_INIT} ${_KAGURA_FLAGS}")

# ── Runtime library ───────────────────────────────────────────────────────────
if(NOT KAGURA_RUNTIME_LIB)
  foreach(_candidate
      "${CMAKE_CURRENT_LIST_DIR}/../../build/runtime/libkagura_runtime.a"
  )
    if(EXISTS "${_candidate}")
      set(KAGURA_RUNTIME_LIB "${_candidate}")
      break()
    endif()
  endforeach()
endif()

if(KAGURA_RUNTIME_LIB AND EXISTS "${KAGURA_RUNTIME_LIB}")
  set(CMAKE_EXE_LINKER_FLAGS_INIT
      "${CMAKE_EXE_LINKER_FLAGS_INIT} ${KAGURA_RUNTIME_LIB}")
  set(CMAKE_SHARED_LINKER_FLAGS_INIT
      "${CMAKE_SHARED_LINKER_FLAGS_INIT} ${KAGURA_RUNTIME_LIB}")
else()
  message(WARNING
    "[kagura] libkagura_runtime.a not found. "
    "Set -DKAGURA_RUNTIME_LIB=/path/to/libkagura_runtime.a")
endif()

message(STATUS "[kagura] Toolchain: profile=${KAGURA_PROFILE}")
message(STATUS "[kagura]   Plugin : ${KAGURA_PLUGIN_PATH}")
message(STATUS "[kagura]   Runtime: ${KAGURA_RUNTIME_LIB}")
