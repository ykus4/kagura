# Regression corpus — replay each known-crash .ll file through the
# relevant pass and verify it does NOT crash, that the result passes the IR
# verifier, and (where the entry declares one) that the transform still
# happens.
#
# Each corpus entry is named <name>.ll and has a companion <name>.meta file
# with:
#   PASS=<pass-name>       (e.g. "function(kagura-fla)")
#   DESCRIPTION=<text>
#   EXPECT=<regex>         (optional) — matched against the transformed IR
#
# EXPECT exists because "opt exited 0" is a weak assertion: a pass that
# declines every function in the entry satisfies it, and several of these
# entries are about a pass *handling* a shape rather than skipping it.

cmake_minimum_required(VERSION 3.20)

# This is the one suite that cannot run in a static-plugin build.  Every other
# suite reaches the passes through kagura-opt there, but kagura-opt has no
# "just my passes" mode: it always builds a default -O pipeline and injects the
# kagura passes at OptimizerLast.  The corpus is hand-written IR shaped for one
# specific pass, and -O2 folds it away before that pass sees it — phi_heavy_fla
# collapses to a single basic block, so kagura-fla has nothing to flatten.
# -O0 is not an escape hatch either: Plugin.cpp only installs the
# -kagura-o0-protect subset on the O0 pipeline, so the pass under test does not
# run at all there.  Replaying the corpus under either condition would assert
# "opt did not crash on a module unrelated to the bug", so it is skipped
# instead, visibly.  The linux-loadable CI job runs the corpus for real.
if(KAGURA_PLUGIN_STATIC)
  message(STATUS "[kagura] Regression corpus skipped: kagura-opt runs a default "
                 "-O pipeline first, which folds the corpus inputs away.")
  add_test(NAME regression-corpus-skipped-static-plugin
    COMMAND ${CMAKE_COMMAND} -E echo
      "SKIPPED: the regression corpus needs a loadable module; kagura-opt "
      "optimises the hand-written corpus IR away before the pass under test runs."
  )
  set_tests_properties(regression-corpus-skipped-static-plugin PROPERTIES
    SKIP_REGULAR_EXPRESSION "SKIPPED:"
  )
  return()
endif()

set(CORPUS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/corpus)

# Auto-discover all .ll files in corpus/
file(GLOB CORPUS_FILES "${CORPUS_DIR}/*.ll")

foreach(LL_FILE ${CORPUS_FILES})
  get_filename_component(BASE ${LL_FILE} NAME_WE)
  set(META_FILE "${CORPUS_DIR}/${BASE}.meta")

  # Default pass if no meta file
  set(PASS_PIPELINE "function(kagura-fla,kagura-sub,kagura-bcf)")
  set(EXPECT_IR "")
  if(EXISTS ${META_FILE})
    file(STRINGS ${META_FILE} META_LINES)
    foreach(LINE ${META_LINES})
      if(LINE MATCHES "^PASS=(.+)$")
        set(PASS_PIPELINE "${CMAKE_MATCH_1}")
      elseif(LINE MATCHES "^EXPECT=(.+)$")
        set(EXPECT_IR "${CMAKE_MATCH_1}")
      endif()
    endforeach()
  endif()

  add_test(NAME regression_${BASE}
    COMMAND ${CMAKE_COMMAND}
      -DOPT=${LLVM_BIN}/opt
      ${KAGURA_PASS_DRIVER}
      -DPASSES=${PASS_PIPELINE}
      -DINPUT=${LL_FILE}
      -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/artifacts/${BASE}.obf.ll
      -DEXPECT=${EXPECT_IR}
      -DSEED=32
      -P ${CMAKE_CURRENT_SOURCE_DIR}/run_regression_test.cmake
  )
  set_tests_properties(regression_${BASE} PROPERTIES
    TIMEOUT 30
    LABELS "regression"
  )
endforeach()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/artifacts)
