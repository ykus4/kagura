# run_link_test.cmake — apply one kagura pass and LINK the result.
#
# Every other test in this suite stops at the IR level, so a pass that emits a
# call to a runtime function the runtime does not define still passes them.
# Three passes shipped in that state — kagura-anti-debug, kagura-bbcheck and
# kagura-telemetry each referenced an undefined symbol and nothing caught it.
# This driver goes all the way to a linked executable.
#
# Three stages, deliberately not `clang -fpass-plugin=... -mllvm -kagura-foo`:
# that combination depends on the plugin's cl::opt being registered before
# clang parses -mllvm, which does not hold on every LLVM version. It works on
# 22 and fails on 17 through 21 with "Unknown command line argument". The rest
# of this suite already avoids it for the same reason (see the comment in
# tests/CMakeLists.txt), and the pipeline is passed to opt by name instead.
#
#   1. clang -emit-llvm  — source to bitcode
#   2. opt --load-pass-plugin -passes=<pipeline>
#   3. clang <bitcode> <runtime> — link an executable
#
# Required -D parameters:
#   CLANG     — clang driver
#   OPT       — opt binary from the same LLVM
#   PLUGIN    — path to the loadable pass plugin
#   RUNTIME   — path to libkagura_runtime.a
#   PIPELINE  — pass pipeline for opt, e.g. "kagura-str" or "function(kagura-fla)"
#   LABEL     — name used in temp files and diagnostics
#   SOURCES   — ';'-separated list of C subjects to build

foreach(_var CLANG OPT PLUGIN RUNTIME PIPELINE LABEL SOURCES)
  if(NOT DEFINED ${_var})
    message(FATAL_ERROR "run_link_test.cmake: -D${_var} is required")
  endif()
endforeach()

set(_failures "")

foreach(_src IN LISTS SOURCES)
  get_filename_component(_stem "${_src}" NAME_WE)
  set(_prefix "${CMAKE_CURRENT_BINARY_DIR}/linktest_${LABEL}_${_stem}")
  set(_bc  "${_prefix}.bc")
  set(_obf "${_prefix}.obf.bc")
  set(_exe "${_prefix}.exe")

  # 1. Source -> bitcode.
  execute_process(
    COMMAND ${CLANG} -O1 -emit-llvm -c ${_src} -o ${_bc}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    string(APPEND _failures "\n--- ${LABEL}/${_stem}: clang -emit-llvm failed ---\n${_out}${_err}")
    continue()
  endif()

  # 2. Run the pass, and verify what it produced.
  execute_process(
    COMMAND ${OPT} --load-pass-plugin=${PLUGIN} -passes=${PIPELINE},verify
            ${_bc} -o ${_obf}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    string(APPEND _failures "\n--- ${LABEL}/${_stem}: opt -passes=${PIPELINE} failed ---\n${_out}${_err}")
    continue()
  endif()

  # 3. Link. This is the step the suite never had.
  execute_process(
    COMMAND ${CLANG} ${_obf} ${RUNTIME} -o ${_exe}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    string(APPEND _failures "\n--- ${LABEL}/${_stem}: link failed ---\n${_out}${_err}")
  endif()

  file(REMOVE ${_bc} ${_obf} ${_exe})
endforeach()

if(NOT _failures STREQUAL "")
  message(FATAL_ERROR
    "Pass ${LABEL} did not survive compile -> obfuscate -> link.\n"
    "A link failure here usually means the pass emits a call to a kagura_* "
    "runtime function that runtime/ does not define, or that is defined only "
    "under a platform #ifdef the pass does not honour."
    "${_failures}")
endif()
