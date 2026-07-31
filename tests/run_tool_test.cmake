# run_tool_test.cmake — kagura-opt smoke test runner
# Usage: cmake -DKAGURA_OPT=... -DFLAG=... -DINPUT=... [-DEXPECT=...] -P run_tool_test.cmake
#
# Used by static-plugin builds (Windows/MSVC, or KAGURA_FORCE_STATIC_PLUGIN),
# where `opt --load-pass-plugin` is unavailable and the passes are reached
# through kagura-opt instead.  Runs one pass over an .ll file and checks the
# transformed IR for an expected marker.

cmake_minimum_required(VERSION 3.20)

string(RANDOM LENGTH 8 ALPHABET abcdefghijklmnopqrstuvwxyz RAND_SUFFIX)
set(OUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/kagura_tool_${RAND_SUFFIX}.ll")

execute_process(
  COMMAND ${KAGURA_OPT} -${FLAG} -S ${INPUT} -o ${OUT_FILE}
  RESULT_VARIABLE TOOL_RESULT
  ERROR_VARIABLE TOOL_ERROR
)

if(NOT TOOL_RESULT EQUAL 0)
  message(FATAL_ERROR "kagura-opt -${FLAG} failed:\n${TOOL_ERROR}")
endif()

if(NOT EXISTS ${OUT_FILE})
  message(FATAL_ERROR "kagura-opt -${FLAG} produced no output file")
endif()

file(READ ${OUT_FILE} OUT_IR)
file(REMOVE ${OUT_FILE})

if(OUT_IR STREQUAL "")
  message(FATAL_ERROR "kagura-opt -${FLAG} produced empty IR")
endif()

# EXPECT is optional: some passes have no single stable textual marker, and for
# those reaching a non-empty module without crashing is the assertion.
if(DEFINED EXPECT AND NOT EXPECT STREQUAL "")
  string(FIND "${OUT_IR}" "${EXPECT}" FOUND_AT)
  if(FOUND_AT EQUAL -1)
    message(FATAL_ERROR
      "kagura-opt -${FLAG}: expected marker not found in output IR: ${EXPECT}")
  endif()
endif()
