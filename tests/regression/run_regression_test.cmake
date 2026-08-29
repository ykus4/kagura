# run_regression_test.cmake — replay one corpus entry through its pass set.
#
# The corpus is a set of inputs that once crashed a pass.  The test used to be
# a bare `opt -passes=${PASS_PIPELINE} -disable-output`, which asserts nothing
# beyond "opt did not die": no verifier (unlike run_pass_test.cmake and
# run_link_test.cmake, both of which explain why that matters), and no check
# that the pass did anything at all.  Half of this corpus exists because a pass
# emitted *invalid IR* rather than because it segfaulted — phi_heavy_fla and
# fsplit_phi_successor both crashed the backend later, not opt — so a run
# without the verifier could not have caught the bug it was added for.
#
# kagura_apply_passes() runs the verifier in both linkage modes, and EXPECT
# (from the .meta file) pins the transform the entry is about.
#
# Parameters (-D):
#   OPT        — opt binary (runs the verifier)
#   PLUGIN     — loadable pass plugin, OR
#   KAGURA_OPT — kagura-opt, in a static-plugin build
#   PASSES     — opt -passes= pipeline from the .meta file
#   INPUT      — corpus .ll file
#   OUTPUT     — where to write the transformed IR
#   EXPECT     — (optional) regex the transformed IR must match
#   SEED       — pin the module PRNG

cmake_minimum_required(VERSION 3.20)

include(${CMAKE_CURRENT_LIST_DIR}/../kagura_driver.cmake)
kagura_require_driver(run_regression_test.cmake)

foreach(_var PASSES INPUT OUTPUT)
  if(NOT DEFINED ${_var})
    message(FATAL_ERROR "run_regression_test.cmake: -D${_var} is required")
  endif()
endforeach()

kagura_apply_passes(${INPUT} ${OUTPUT} "${PASSES}" _rc _err)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR
    "Regression corpus entry ${INPUT} failed under '${PASSES}':\n${_err}")
endif()

if(DEFINED EXPECT AND NOT EXPECT STREQUAL "")
  file(READ ${OUTPUT} _IR)
  if(NOT _IR MATCHES "${EXPECT}")
    message(FATAL_ERROR
      "Regression corpus entry ${INPUT}: '${PASSES}' produced no match for "
      "EXPECT=${EXPECT}.\n"
      "The entry ran without crashing, which is all this test used to check, "
      "but the transform it is a regression test for did not happen.")
  endif()
endif()

file(REMOVE ${OUTPUT})
