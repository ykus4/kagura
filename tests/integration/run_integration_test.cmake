# run_integration_test.cmake
# Called by CTest for each integration test.
#
# Three-stage pipeline:
#   1. clang -O2 -emit-llvm → .ll (baseline AND source for obfuscation)
#   2. the kagura pipeline → obfuscated .ll
#   3. clang obfuscated.ll -o binary, then run and compare output
#
# Stage 2 goes through kagura_apply_passes() rather than a hard-coded
# `opt --load-pass-plugin`, so these tests also run in a static-plugin build —
# where the passes are reached through kagura-opt.  They used not to: the whole
# suite was skipped there, and the only CI job that runs ctest on Linux is a
# static-plugin job.
#
# In the loadable-module mode kagura_apply_passes() uses opt
# --load-pass-plugin (not -fpass-plugin + -mllvm) because opt pre-scans argv
# for --load-pass-plugin before ParseCommandLineOptions, so plugin cl::opt
# flags are registered before the rest of argv is parsed.
#
# Parameters (passed via -D):
#   CLANG      — path to clang
#   OPT        — path to opt (runs the IR verifier in both modes)
#   PLUGIN     — path to libKaguraObfuscator, OR
#   KAGURA_OPT — path to kagura-opt, in a static-plugin build
#   PASSES     — opt -passes= pipeline (e.g. "function(kagura-fla)")
#   SOURCE     — path to the C source file
#   EXPECTED   — expected stdout of the baseline binary.  May be empty, but
#                only for a subject whose output is not worth pinning by hand.
#   TEST_NAME  — unique name for per-test temp files
#   SEED       — value for -kagura-seed
#   RUNTIME    — (optional) kagura runtime library to link, for passes that emit
#                calls into it
#   REQUIRE_IR — a literal marker the obfuscated IR must contain, or the token
#                :changed: (see below).  Required, not optional.
#
# Why REQUIRE_IR is mandatory
# ---------------------------
# "Obfuscated output matches baseline" is satisfied by a pass that transforms
# nothing, and eleven of these twelve tests were in exactly that state: their
# subjects were `static` helpers over literal arguments, so -O2 inlined and
# constant-folded them into a printf of four literals before opt ever ran.  The
# subjects now use externally visible `noinline` helpers over argc-derived
# values, and REQUIRE_IR pins the evidence that the pass fired.
#
# The marker is matched literally, not as a regex, for the same reason
# run_tool_test.cmake does: as a regex `%co.` also matches `%cond`, and a
# marker that matches untransformed IR is no marker at all.
#
# BasicBlockReordering is the one pass whose entire effect is block layout, so
# it has no name of its own to look for; REQUIRE_IR=:changed: asserts instead
# that the obfuscated IR differs from the baseline IR, which for that pass is
# exactly the same statement.
#
# SEED is pinned because three of the passes under test decide per block or per
# loop whether to fire (BogusControlFlow 30 %, DeadCodeInsertion 40 %,
# LoopTransform 80/60/40 %).  With an entropy seed, "the marker is present"
# would be a coin flip rather than an assertion.

cmake_minimum_required(VERSION 3.14)

include(${CMAKE_CURRENT_LIST_DIR}/../kagura_driver.cmake)
kagura_require_driver(run_integration_test.cmake)

if(NOT DEFINED REQUIRE_IR OR REQUIRE_IR STREQUAL "")
  message(FATAL_ERROR
    "run_integration_test.cmake: -DREQUIRE_IR is required for ${TEST_NAME}.\n"
    "Without it a pass that declines to transform anything still matches the "
    "baseline output and the test passes vacuously.")
endif()

# ---- Artefact paths ----------------------------------------------------------
#
# Under the build tree, not the system temp directory. Fixed /tmp names are
# shared by every build tree on the machine, so two trees running ctest collide,
# and any state the OS attaches to one of those paths outlives the build: on
# macOS a system security verdict cached against
# /tmp/kagura_int_vm_correctness_obf SIGKILLs the binary and deletes it on
# sight, which reads as "the obfuscated binary crashed" for every future run in
# every build tree. The identical binary written anywhere else runs fine.
if(DEFINED WORKDIR AND NOT WORKDIR STREQUAL "")
  set(_TMPDIR "${WORKDIR}")
  file(MAKE_DIRECTORY "${_TMPDIR}")
elseif(WIN32 OR CMAKE_HOST_WIN32 OR "$ENV{TEMP}" MATCHES "\\\\")
  set(_TMPDIR "$ENV{TEMP}")
else()
  set(_TMPDIR "/tmp")
endif()
set(BASELINE_IR  "${_TMPDIR}/${TEST_NAME}_base.ll")
set(OBF_IR       "${_TMPDIR}/${TEST_NAME}_obf.ll")
set(BASELINE_BIN "${_TMPDIR}/${TEST_NAME}_base")
set(OBF_BIN      "${_TMPDIR}/${TEST_NAME}_obf")

# ---- Compile baseline binary ------------------------------------------------
execute_process(
  COMMAND ${CLANG} -O2 ${SOURCE} -o ${BASELINE_BIN}
  RESULT_VARIABLE R ERROR_VARIABLE E
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "Baseline compile failed:\n${E}")
endif()

# ---- Run baseline -----------------------------------------------------------
execute_process(
  COMMAND ${BASELINE_BIN}
  OUTPUT_VARIABLE BASELINE_OUTPUT
  RESULT_VARIABLE R TIMEOUT 10
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "Baseline run failed (exit ${R})")
endif()

# ---- Check the baseline against the documented expectation -------------------
#
# EXPECTED was a documented parameter that the body never read: every call site
# passes a real literal ("55\n89\n144\n" and friends) and none of them was ever
# compared to anything.  Only baseline-vs-obfuscated was checked, so a
# toolchain regression that moved both binaries the same way was invisible.
if(DEFINED EXPECTED AND NOT EXPECTED STREQUAL "")
  if(NOT BASELINE_OUTPUT STREQUAL EXPECTED)
    message(FATAL_ERROR
      "Baseline output does not match the expected output for ${TEST_NAME}.\n"
      "Expected:\n${EXPECTED}\n"
      "Got:\n${BASELINE_OUTPUT}\n"
      "The obfuscated binary is compared against this baseline, so both would "
      "have to be wrong in the same way for the rest of this test to notice."
    )
  endif()
endif()

# ---- Emit IR for obfuscation ------------------------------------------------
execute_process(
  COMMAND ${CLANG} -O2 -emit-llvm -S -o ${BASELINE_IR} ${SOURCE}
  RESULT_VARIABLE R ERROR_VARIABLE E
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "IR emit failed:\n${E}")
endif()

# ---- Obfuscate ---------------------------------------------------------------
kagura_apply_passes(${BASELINE_IR} ${OBF_IR} "${PASSES}" R E)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "Obfuscation failed (${PASSES}):\n${E}")
endif()

# ---- Check the pass actually did something -----------------------------------
file(READ ${OBF_IR} _OBF_IR_TEXT)
if(REQUIRE_IR STREQUAL ":changed:")
  file(READ ${BASELINE_IR} _BASE_IR_TEXT)
  # `; ModuleID = <path>` names the input file, so it always differs between
  # these two for reasons that have nothing to do with the pass.  Drop that one
  # line and nothing else — note that CMake's REGEX REPLACE re-anchors `^`
  # after every match, so "^[^\n]*\n" would strip every line of both files and
  # make them trivially equal.
  string(REGEX REPLACE "; ModuleID = '[^']*'" "" _OBF_BODY  "${_OBF_IR_TEXT}")
  string(REGEX REPLACE "; ModuleID = '[^']*'" "" _BASE_BODY "${_BASE_IR_TEXT}")
  if(_OBF_BODY STREQUAL _BASE_BODY)
    message(FATAL_ERROR
      "Pass(es) ${PASSES} left the module byte-for-byte unchanged.\n"
      "The output comparison below would have passed vacuously."
    )
  endif()
else()
  string(FIND "${_OBF_IR_TEXT}" "${REQUIRE_IR}" _MARKER_AT)
  if(_MARKER_AT EQUAL -1)
    message(FATAL_ERROR
      "Pass(es) ${PASSES} produced no '${REQUIRE_IR}' in ${OBF_IR}.\n"
      "The output comparison below would have passed vacuously."
    )
  endif()
endif()

# ---- Compile obfuscated IR to binary ----------------------------------------
if(DEFINED RUNTIME AND NOT RUNTIME STREQUAL "")
  set(_LINK_EXTRA ${RUNTIME})
else()
  set(_LINK_EXTRA "")
endif()
execute_process(
  COMMAND ${CLANG} ${OBF_IR} ${_LINK_EXTRA} -o ${OBF_BIN}
  RESULT_VARIABLE R ERROR_VARIABLE E
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "Obfuscated IR link failed:\n${E}")
endif()

# ---- Run obfuscated binary --------------------------------------------------
execute_process(
  COMMAND ${OBF_BIN}
  OUTPUT_VARIABLE OBF_OUTPUT
  RESULT_VARIABLE R TIMEOUT 10
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "Obfuscated run failed (exit ${R})")
endif()

# ---- Compare output ---------------------------------------------------------
if(NOT BASELINE_OUTPUT STREQUAL OBF_OUTPUT)
  message(FATAL_ERROR
    "Output mismatch for pass(es) ${PASSES}!\n"
    "Expected (baseline):\n${BASELINE_OUTPUT}\n"
    "Got (obfuscated):\n${OBF_OUTPUT}\n"
  )
endif()

message(STATUS "PASS: ${PASSES} — output matches baseline")
