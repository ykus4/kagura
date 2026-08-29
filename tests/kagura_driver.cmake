# kagura_driver.cmake — "run this kagura pipeline over this IR", in either
# plugin linkage mode.  Included by the -P runner scripts in this directory.
#
# There are two ways to reach the passes, and the suite has to work with both:
#
#   Loadable module  (-DPLUGIN=<KaguraObfuscator.so|dylib|dll>)
#       opt --load-pass-plugin=<plugin> -passes=<pipeline>,verify
#
#   Static plugin    (-DKAGURA_OPT=<kagura-opt>)
#       kagura-opt -kagura-<name> ...
#       Used where LLVM cannot build loadable modules (the MSVC Windows
#       tarball sets LLVM_ENABLE_PLUGINS=OFF) and wherever
#       KAGURA_FORCE_STATIC_PLUGIN is on.  `opt --load-pass-plugin` cannot
#       dlopen a static archive, so the pipeline string is translated into one
#       -kagura-<name> flag per pass and kagura-opt assembles the pipeline
#       itself.
#
# Every runner in this directory used to be written against the first form
# only.  tests/CMakeLists.txt therefore returned early for static builds after
# registering four smoke tests — and the one CI job that runs ctest on Linux is
# a static-plugin job, so on Linux the link, pass, regression and integration
# suites (72 of the 73 tests) never ran at all.
#
# kagura-opt has no `-passes=...,verify` equivalent: it builds a default
# pipeline and appends the enabled kagura passes.  Rather than drop the
# verifier on that path — it is what catches the malformed IR that otherwise
# only surfaces as a clang crash during instruction selection — the verifier is
# run as a separate stock-opt invocation over the transformed module.  This
# stays even though kagura-opt now appends a VerifierPass of its own: the test
# is the place the assertion has to be visible, and it must hold against a
# kagura-opt that predates that change.

# Applies PIPELINE (an opt -passes= string) to INPUT, writing OUTPUT.
# Textual .ll output is selected from the OUTPUT extension.
# Sets ${OUT_RESULT} to 0 on success and ${OUT_MESSAGE} to a diagnostic
# otherwise.
function(kagura_apply_passes INPUT OUTPUT PIPELINE OUT_RESULT OUT_MESSAGE)
  set(_extra "")
  if(OUTPUT MATCHES "\\.ll$")
    set(_extra -S)
  endif()
  # -DSEED pins the module PRNG.  Several passes decide per block or per loop
  # whether to fire, so any assertion about what they emitted is a coin flip
  # under an entropy seed.  Both drivers accept the same flag.
  if(DEFINED SEED AND NOT SEED STREQUAL "")
    list(APPEND _extra "-kagura-seed=${SEED}")
  endif()
  # -DEXTRA_FLAGS is a ';'-list of further -kagura-* options.  Both drivers
  # register the same cl::opts, so a caller can turn a per-block probability up
  # to 100 and stop depending on which blocks a particular seed happens to pick.
  if(DEFINED EXTRA_FLAGS AND NOT EXTRA_FLAGS STREQUAL "")
    list(APPEND _extra ${EXTRA_FLAGS})
  endif()

  if(DEFINED KAGURA_OPT AND NOT KAGURA_OPT STREQUAL "")
    # `function(kagura-fla,kagura-sub)` -> `-kagura-fla -kagura-sub`.  Nesting
    # and ordering are dropped deliberately: in this mode Plugin.cpp decides
    # both, from the same table opt's pipeline parser reads.
    string(REGEX MATCHALL "kagura-[a-z0-9-]+" _names "${PIPELINE}")
    list(REMOVE_DUPLICATES _names)
    set(_flags "")
    foreach(_name IN LISTS _names)
      list(APPEND _flags "-${_name}")
    endforeach()
    if(NOT _flags)
      set(${OUT_RESULT} 1 PARENT_SCOPE)
      set(${OUT_MESSAGE}
          "kagura_apply_passes: no kagura pass name in pipeline '${PIPELINE}'"
          PARENT_SCOPE)
      return()
    endif()

    execute_process(
      COMMAND ${KAGURA_OPT} ${_flags} ${_extra} ${INPUT} -o ${OUTPUT}
      RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
      set(${OUT_RESULT} ${_rc} PARENT_SCOPE)
      set(${OUT_MESSAGE} "kagura-opt ${_flags} failed:\n${_out}${_err}" PARENT_SCOPE)
      return()
    endif()

    execute_process(
      COMMAND ${OPT} -passes=verify -disable-output ${OUTPUT}
      RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
      set(${OUT_RESULT} ${_rc} PARENT_SCOPE)
      set(${OUT_MESSAGE}
          "kagura-opt ${_flags} produced IR that fails the verifier:\n${_out}${_err}"
          PARENT_SCOPE)
      return()
    endif()
  else()
    execute_process(
      COMMAND ${OPT} --load-pass-plugin=${PLUGIN} -passes=${PIPELINE},verify
              ${_extra} ${INPUT} -o ${OUTPUT}
      RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
      set(${OUT_RESULT} ${_rc} PARENT_SCOPE)
      set(${OUT_MESSAGE} "opt -passes=${PIPELINE},verify failed:\n${_out}${_err}"
          PARENT_SCOPE)
      return()
    endif()
  endif()

  set(${OUT_RESULT} 0 PARENT_SCOPE)
  set(${OUT_MESSAGE} "" PARENT_SCOPE)
endfunction()

# Fails with a clear message rather than "PLUGIN-NOTFOUND" further downstream.
function(kagura_require_driver SCRIPT_NAME)
  if(NOT DEFINED OPT OR OPT STREQUAL "")
    message(FATAL_ERROR "${SCRIPT_NAME}: -DOPT is required")
  endif()
  if((NOT DEFINED PLUGIN OR PLUGIN STREQUAL "") AND
     (NOT DEFINED KAGURA_OPT OR KAGURA_OPT STREQUAL ""))
    message(FATAL_ERROR
      "${SCRIPT_NAME}: exactly one of -DPLUGIN (loadable module) or "
      "-DKAGURA_OPT (static plugin build) is required")
  endif()
endfunction()
