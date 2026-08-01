# KaguraProfile.cmake
#
# Shared profile → flag expansion for every CMake-based kagura integration
# (integration/cmake, integration/android, integration/unity).
#
# The FAST / BALANCED / STRONG pass sets live in exactly one place —
# integration/profiles/*.json — and are read from there at configure time.
# Nothing in this file hard-codes which passes a profile enables.
#
# ── Public API ────────────────────────────────────────────────────────────────
#
#   kagura_profile_resolve(<PROFILE> <OUT_PATH>)
#       Resolves FAST|BALANCED|STRONG (case-insensitive) to the absolute path
#       of the matching integration/profiles/*.json. Anything else — including
#       an absolute path to your own policy file — is passed through.
#
#   kagura_profile_pass_flags(<JSON_PATH> <OUT_LIST>)
#       Expands a policy file into the equivalent bare "-kagura-*" flag list
#       (no -mllvm prefixes). Used as the explicit-flag fallback so a build
#       stays correct even if -kagura-config is not honoured.
#
#   kagura_profile_flags(<PROFILE> <OUT_LIST> [OVERRIDES <flag>...])
#       The one call most integrations want. Returns the bare "-kagura-*"
#       list to pass to the compiler, each element still needing an -mllvm.
#
#       With no OVERRIDES it emits "-kagura-config=<json>" *and* the expanded
#       flag list; both describe the same configuration, so the result is the
#       same whether or not the kagura-config pass takes effect.
#
#       With OVERRIDES it emits the expanded list plus the overrides and
#       *omits* -kagura-config, because the kagura-config pass assigns to the
#       cl::opt globals at pass-run time and would otherwise clobber them.
#
# ─────────────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.19) # string(JSON ...)

# Captured at include() time: CMAKE_CURRENT_LIST_DIR inside a function body
# refers to the caller's listfile, not to this one.
set(_KAGURA_INTEGRATION_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}")

set(KAGURA_PROFILE_DIR "${_KAGURA_INTEGRATION_CMAKE_DIR}/../profiles"
    CACHE PATH "Directory holding the shared kagura profile JSON files")

function(kagura_profile_resolve PROFILE OUT_PATH)
  string(TOLOWER "${PROFILE}" _lower)

  if(_lower STREQUAL "fast" OR _lower STREQUAL "balanced" OR _lower STREQUAL "strong")
    get_filename_component(_path "${KAGURA_PROFILE_DIR}/${_lower}.json" ABSOLUTE)
  else()
    # Treat as a path to a user-supplied policy file.
    get_filename_component(_path "${PROFILE}" ABSOLUTE)
  endif()

  if(NOT EXISTS "${_path}")
    message(WARNING "[kagura] profile '${PROFILE}' not found at ${_path}")
    set(${OUT_PATH} "" PARENT_SCOPE)
    return()
  endif()

  set(${OUT_PATH} "${_path}" PARENT_SCOPE)
endfunction()

function(kagura_profile_pass_flags JSON_PATH OUT_LIST)
  set(_flags "")

  if(NOT EXISTS "${JSON_PATH}")
    set(${OUT_LIST} "" PARENT_SCOPE)
    return()
  endif()

  file(READ "${JSON_PATH}" _json)

  # ---- "passes": { "<key>": true|false, ... } ------------------------------
  # JSON key -> CLI flag is a plain underscore-to-dash rewrite
  # (str_aes -> -kagura-str-aes, anti_debug -> -kagura-anti-debug, ...).
  string(JSON _passes ERROR_VARIABLE _err GET "${_json}" "passes")
  if(NOT _err)
    string(JSON _n LENGTH "${_passes}")
    if(_n GREATER 0)
      math(EXPR _last "${_n} - 1")
      foreach(_i RANGE ${_last})
        string(JSON _key MEMBER "${_passes}" ${_i})
        string(JSON _val GET "${_passes}" "${_key}")
        if(_val)
          string(REPLACE "_" "-" _cli "${_key}")
          list(APPEND _flags "-kagura-${_cli}")
        endif()
      endforeach()
    endif()
  endif()

  # ---- "tuning": { "<key>": <int>, ... } -----------------------------------
  string(JSON _tuning ERROR_VARIABLE _err GET "${_json}" "tuning")
  if(NOT _err)
    string(JSON _n LENGTH "${_tuning}")
    if(_n GREATER 0)
      math(EXPR _last "${_n} - 1")
      foreach(_i RANGE ${_last})
        string(JSON _key MEMBER "${_tuning}" ${_i})
        string(JSON _val GET "${_tuning}" "${_key}")
        string(REPLACE "_" "-" _cli "${_key}")
        list(APPEND _flags "-kagura-${_cli}=${_val}")
      endforeach()
    endif()
  endif()

  set(${OUT_LIST} "${_flags}" PARENT_SCOPE)
endfunction()

function(kagura_profile_flags PROFILE OUT_LIST)
  cmake_parse_arguments(_kp "" "" "OVERRIDES" ${ARGN})

  kagura_profile_resolve("${PROFILE}" _json)
  if(NOT _json)
    # No profile: the caller's own overrides are all we have.
    set(${OUT_LIST} "${_kp_OVERRIDES}" PARENT_SCOPE)
    return()
  endif()

  kagura_profile_pass_flags("${_json}" _expanded)

  if(_kp_OVERRIDES)
    # kagura-config runs as a module pass and overwrites the cl::opt globals,
    # so it would undo the overrides. Use the expanded flags only.
    set(_result ${_expanded} ${_kp_OVERRIDES})
  else()
    set(_result "-kagura-config=${_json}" ${_expanded})
  endif()

  set(${OUT_LIST} "${_result}" PARENT_SCOPE)
endfunction()

# ── Plugin discovery ──────────────────────────────────────────────────────────
#
#   kagura_find_plugin(<OUT_PATH> [HINTS <dir>...])
#       Locates KaguraObfuscator.{dylib,so,dll}. Honours the KAGURA_PLUGIN_PATH
#       CMake variable and the KAGURA_PLUGIN_PATH environment variable first.
#
function(kagura_find_plugin OUT_PATH)
  cmake_parse_arguments(_kf "" "" "HINTS" ${ARGN})

  foreach(_explicit "${KAGURA_PLUGIN_PATH}" "$ENV{KAGURA_PLUGIN_PATH}")
    if(_explicit AND EXISTS "${_explicit}")
      set(${OUT_PATH} "${_explicit}" PARENT_SCOPE)
      return()
    endif()
  endforeach()

  set(_dirs
    ${_kf_HINTS}
    "${_KAGURA_INTEGRATION_CMAKE_DIR}/../../build/lib/Transforms"
  )

  # .dylib on Apple, .so on Linux/Android, .dll on Windows. Probe all three:
  # a cross build (e.g. Android NDK on macOS) loads the *host* plugin.
  foreach(_dir IN LISTS _dirs)
    foreach(_ext dylib so dll)
      if(EXISTS "${_dir}/KaguraObfuscator.${_ext}")
        get_filename_component(_p "${_dir}/KaguraObfuscator.${_ext}" ABSOLUTE)
        set(${OUT_PATH} "${_p}" PARENT_SCOPE)
        return()
      endif()
    endforeach()
  endforeach()

  set(${OUT_PATH} "" PARENT_SCOPE)
endfunction()
