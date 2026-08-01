# run_link_test.cmake — compile a subject with one kagura pass and LINK it.
#
# Every other test in this suite stops at the IR level (opt + FileCheck), so a
# pass that emits a call to a runtime function the runtime does not define
# still passes them.  Three passes shipped in that state — kagura-anti-debug,
# kagura-bbcheck and kagura-telemetry each referenced an undefined symbol and
# nothing caught it.  This driver closes that gap by going all the way to a
# linked executable.
#
# Required -D parameters:
#   CLANG    — clang driver
#   PLUGIN   — path to the loadable pass plugin
#   RUNTIME  — path to libkagura_runtime.a
#   FLAG     — the -kagura-* flag under test, without the leading dash
#   SOURCES  — ';'-separated list of C subjects to build

foreach(_var CLANG PLUGIN RUNTIME FLAG SOURCES)
  if(NOT DEFINED ${_var})
    message(FATAL_ERROR "run_link_test.cmake: -D${_var} is required")
  endif()
endforeach()

set(_failures "")

foreach(_src IN LISTS SOURCES)
  get_filename_component(_stem "${_src}" NAME_WE)
  set(_exe "${CMAKE_CURRENT_BINARY_DIR}/linktest_${FLAG}_${_stem}")

  execute_process(
    COMMAND ${CLANG}
            -fpass-plugin=${PLUGIN}
            -mllvm -${FLAG}
            -O1
            ${_src}
            ${RUNTIME}
            -o ${_exe}
    RESULT_VARIABLE _rc
    OUTPUT_VARIABLE _out
    ERROR_VARIABLE  _err
  )

  if(NOT _rc EQUAL 0)
    string(APPEND _failures
      "\n--- ${FLAG} on ${_stem} (exit ${_rc}) ---\n${_out}${_err}")
  else()
    file(REMOVE ${_exe})
  endif()
endforeach()

if(NOT _failures STREQUAL "")
  message(FATAL_ERROR
    "Pass -${FLAG} produced a module that does not link.\n"
    "This usually means the pass emits a call to a kagura_* runtime function "
    "that runtime/ does not define, or that is defined only under a platform "
    "#ifdef the pass does not honour."
    "${_failures}")
endif()
