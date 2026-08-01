# kagura-cmake.cmake
# CMake snippet for Android NDK projects.
#
# Usage — in your app's CMakeLists.txt:
#
#   include(${CMAKE_SOURCE_DIR}/../kagura/integration/android/kagura-cmake.cmake)
#   kagura_target(my_native_lib)
#
# Or to apply globally:
#
#   include(${CMAKE_SOURCE_DIR}/../kagura/integration/android/kagura-cmake.cmake)
#   kagura_apply_global()
#
# This is the lightweight entry point. For ABI-specific tuning, LLVM version
# checking and a runtime static-library target, use kagura-android-ndk.cmake
# instead.
#
# The pass set for each profile is NOT defined here — it is read from
# integration/profiles/<profile>.json via integration/cmake/KaguraProfile.cmake,
# the single source of truth shared by every kagura integration.

cmake_minimum_required(VERSION 3.19) # string(JSON ...) in KaguraProfile.cmake

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/KaguraProfile.cmake")

# ── Locate the plugin ──────────────────────────────────────────────────────────
# Probes .dylib / .so / .dll and honours the KAGURA_PLUGIN_PATH CMake variable
# and environment variable. A cross build (NDK hosted on macOS) loads the
# *host* plugin, so the host extension is what matters here.

kagura_find_plugin(_KAGURA_FOUND_PLUGIN)
if(_KAGURA_FOUND_PLUGIN)
  set(KAGURA_PLUGIN_PATH "${_KAGURA_FOUND_PLUGIN}"
      CACHE FILEPATH "Path to KaguraObfuscator.{dylib,so,dll}" FORCE)
endif()

# ── Configuration variables (override on the cmake command line) ───────────────

set(KAGURA_PROFILE "BALANCED" CACHE STRING
    "Obfuscation profile: FAST | BALANCED | STRONG, or a path to a JSON policy")
set_property(CACHE KAGURA_PROFILE PROPERTY STRINGS FAST BALANCED STRONG)

# Per-pass overrides. Each is a tri-state: leave it undefined to let the
# profile decide. Setting one switches to the explicit-flag path (see below).
option(KAGURA_ENABLE_JNI "JNI dynamic registration (Android-only; in no profile)" ON)
option(KAGURA_METRICS    "Print obfuscation metrics"                             OFF)

# KAGURA_ENABLE_STR / _FLA / _BCF / _SUB / _CO / _ANTIDEBUG and
# KAGURA_BCF_PROB / _BCF_ITER / _SUB_ITER / _SEED are honoured if defined,
# but are deliberately NOT given defaults here: a default would silently
# override the profile.

# ── Build flag list ────────────────────────────────────────────────────────────

function(_kagura_build_flags OUT_VAR)
  if(NOT KAGURA_PLUGIN_PATH OR NOT EXISTS "${KAGURA_PLUGIN_PATH}")
    message(WARNING
      "[kagura] Plugin not found — obfuscation disabled. "
      "Set -DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.{dylib,so,dll}")
    set(${OUT_VAR} "" PARENT_SCOPE)
    return()
  endif()

  # Collect explicit overrides.
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

  kagura_profile_flags("${KAGURA_PROFILE}" _pass_flags OVERRIDES ${_overrides})

  # Build flags as SHELL: strings so CMake passes "-mllvm <flag>" as a pair.
  set(_flags "SHELL:-fpass-plugin=${KAGURA_PLUGIN_PATH}")
  foreach(_flag IN LISTS _pass_flags)
    list(APPEND _flags "SHELL:-mllvm ${_flag}")
  endforeach()

  set(${OUT_VAR} "${_flags}" PARENT_SCOPE)
endfunction()

# ── Public API ─────────────────────────────────────────────────────────────────

# Apply kagura flags to a specific target
function(kagura_target TARGET_NAME)
  _kagura_build_flags(_KAGURA_FLAGS)
  if(_KAGURA_FLAGS)
    # _KAGURA_FLAGS is already a CMake list (semicolon-separated)
    target_compile_options(${TARGET_NAME} PRIVATE ${_KAGURA_FLAGS})
    message(STATUS "[kagura] Obfuscation applied to target: ${TARGET_NAME}")
  endif()
endfunction()

# Apply kagura flags to all subsequent targets in this CMakeLists.txt
function(kagura_apply_global)
  _kagura_build_flags(_KAGURA_FLAGS)
  if(_KAGURA_FLAGS)
    add_compile_options(${_KAGURA_FLAGS})
    message(STATUS "[kagura] Obfuscation applied globally")
  endif()
endfunction()
