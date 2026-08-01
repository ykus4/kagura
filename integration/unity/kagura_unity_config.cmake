# kagura_unity_config.cmake
#
# CMake helper for Unity IL2CPP builds.
#
# Unity's IL2CPP backend generates a CMakeLists.txt and invokes cmake/ninja
# internally.  This file can be included from that generated CMakeLists.txt
# (or from the Gradle externalNativeBuild CMake arguments) to inject kagura
# obfuscation flags into every C/C++ compile command.
#
# Usage — from CMake command line or Gradle:
#   cmake -DCMAKE_TOOLCHAIN_FILE=path/to/android.toolchain.cmake \
#         -DKAGURA_CMAKE_DIR=/path/to/kagura/integration/cmake \
#         -C /path/to/kagura/integration/unity/kagura_unity_config.cmake \
#         ...
#
# Or include from the generated CMakeLists.txt:
#   include("/path/to/kagura/integration/unity/kagura_unity_config.cmake")
#
# ── Required variables ────────────────────────────────────────────────────────
#   KAGURA_PLUGIN_PATH   Path to KaguraObfuscator.dylib / .so / .dll
#                        (auto-discovered if unset)
#   KAGURA_RUNTIME_LIB   Path to libkagura_runtime.a
#
# ── Optional variables ────────────────────────────────────────────────────────
#   KAGURA_PROFILE            FAST | BALANCED | STRONG, or a path to your own
#                             JSON policy file (default: BALANCED)
#   KAGURA_EXTRA_PASSES       Extra "-kagura-*" flags appended after the profile
#
#   Per-pass overrides — no defaults, so an unset one means "the profile
#   decides". Setting one appends it after the profile and drops
#   -kagura-config so the kagura-config pass cannot clobber it:
#     KAGURA_ENABLE_STR / _FLA / _BCF / _SUB / _CO / _IBR / _BBR / _BBS /
#     _DCI / _SV / _ANTI_DEBUG / _TAMPER / _GENC / _VM
#     KAGURA_BCF_PROB, KAGURA_SEED
#
# The pass set for each profile is NOT defined here. It comes from
# integration/profiles/<profile>.json via integration/cmake/KaguraProfile.cmake,
# the single source of truth shared by every kagura integration.
# ─────────────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.20)

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/KaguraProfile.cmake")

# ── Locate plugin if not set ──────────────────────────────────────────────────
# Probes .dylib / .so / .dll: IL2CPP cross-builds run the plugin in the host
# clang, so the host's library extension is what matters.
kagura_find_plugin(_KAGURA_FOUND_PLUGIN
  HINTS
    "${CMAKE_CURRENT_LIST_DIR}/../../build/lib/Transforms"
    "${CMAKE_SOURCE_DIR}/../kagura/build/lib/Transforms"
)
if(_KAGURA_FOUND_PLUGIN)
  set(KAGURA_PLUGIN_PATH "${_KAGURA_FOUND_PLUGIN}"
      CACHE FILEPATH "Path to KaguraObfuscator plugin" FORCE)
endif()

if(NOT KAGURA_PLUGIN_PATH OR NOT EXISTS "${KAGURA_PLUGIN_PATH}")
  message(WARNING "[kagura] Plugin not found — obfuscation disabled. "
                  "Set KAGURA_PLUGIN_PATH to KaguraObfuscator.dylib/.so")
  return()
endif()

# ── Locate runtime lib ────────────────────────────────────────────────────────
if(NOT KAGURA_RUNTIME_LIB)
  find_file(KAGURA_RUNTIME_LIB
    NAMES libkagura_runtime.a
    HINTS
      "${CMAKE_CURRENT_LIST_DIR}/../../build/runtime"
      "${CMAKE_SOURCE_DIR}/../kagura/build/runtime"
    DOC "Path to libkagura_runtime.a"
  )
endif()

# ── Profile + overrides ───────────────────────────────────────────────────────
# No option()/set() defaults for the per-pass switches: a default would
# silently override the profile for every Unity project.

if(NOT DEFINED KAGURA_PROFILE)
  set(KAGURA_PROFILE "BALANCED" CACHE STRING
      "kagura: FAST | BALANCED | STRONG, or a path to a JSON policy file")
endif()

set(_KAGURA_OVERRIDES "")
if(KAGURA_EXTRA_PASSES)
  list(APPEND _KAGURA_OVERRIDES ${KAGURA_EXTRA_PASSES})
endif()
foreach(_pair
    "KAGURA_ENABLE_STR;-kagura-str"
    "KAGURA_ENABLE_FLA;-kagura-fla"
    "KAGURA_ENABLE_BCF;-kagura-bcf"
    "KAGURA_ENABLE_SUB;-kagura-sub"
    "KAGURA_ENABLE_CO;-kagura-co"
    "KAGURA_ENABLE_IBR;-kagura-ibr"
    "KAGURA_ENABLE_BBR;-kagura-bbr"
    "KAGURA_ENABLE_BBS;-kagura-bbs"
    "KAGURA_ENABLE_DCI;-kagura-dci"
    "KAGURA_ENABLE_SV;-kagura-sv"
    "KAGURA_ENABLE_ANTI_DEBUG;-kagura-anti-debug"
    "KAGURA_ENABLE_TAMPER;-kagura-tamper"
    "KAGURA_ENABLE_GENC;-kagura-genc"
    "KAGURA_ENABLE_VM;-kagura-vm")
  list(GET _pair 0 _var)
  list(GET _pair 1 _flag)
  if(DEFINED ${_var})
    if(${_var})
      list(APPEND _KAGURA_OVERRIDES "${_flag}")
    endif()
  endif()
endforeach()
if(DEFINED KAGURA_BCF_PROB)
  list(APPEND _KAGURA_OVERRIDES "-kagura-bcf-prob=${KAGURA_BCF_PROB}")
endif()
if(DEFINED KAGURA_SEED)
  list(APPEND _KAGURA_OVERRIDES "-kagura-seed=${KAGURA_SEED}")
endif()

kagura_profile_flags("${KAGURA_PROFILE}" _KAGURA_PASS_FLAGS
                     OVERRIDES ${_KAGURA_OVERRIDES})

# ── Build flag string ─────────────────────────────────────────────────────────
set(_KAGURA_FLAGS "-fpass-plugin=${KAGURA_PLUGIN_PATH}")
foreach(_flag IN LISTS _KAGURA_PASS_FLAGS)
  string(APPEND _KAGURA_FLAGS " -mllvm ${_flag}")
endforeach()

# ── Inject into global compile options ────────────────────────────────────────
# These apply to every target defined after this include().
add_compile_options("SHELL:${_KAGURA_FLAGS}")

# ── Link runtime library ──────────────────────────────────────────────────────
if(KAGURA_RUNTIME_LIB AND EXISTS "${KAGURA_RUNTIME_LIB}")
  # Create an imported static library target so targets can link it by name.
  if(NOT TARGET kagura_runtime)
    add_library(kagura_runtime STATIC IMPORTED GLOBAL)
    set_target_properties(kagura_runtime PROPERTIES
      IMPORTED_LOCATION "${KAGURA_RUNTIME_LIB}"
    )
  endif()
  # Append to CMAKE_EXE_LINKER_FLAGS so IL2CPP's final link step picks it up.
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} ${KAGURA_RUNTIME_LIB}")
  set(CMAKE_SHARED_LINKER_FLAGS
      "${CMAKE_SHARED_LINKER_FLAGS} ${KAGURA_RUNTIME_LIB}")
else()
  message(WARNING "[kagura] Runtime lib not found — passes requiring runtime "
                  "support (AES, VM, AntiDebug, AntiTamper) will fail to link. "
                  "Set KAGURA_RUNTIME_LIB.")
endif()

message(STATUS "[kagura] Unity IL2CPP obfuscation enabled")
message(STATUS "[kagura]   Profile: ${KAGURA_PROFILE}")
message(STATUS "[kagura]   Plugin : ${KAGURA_PLUGIN_PATH}")
message(STATUS "[kagura]   Runtime: ${KAGURA_RUNTIME_LIB}")
message(STATUS "[kagura]   Flags  : ${_KAGURA_FLAGS}")
