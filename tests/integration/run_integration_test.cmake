# run_integration_test.cmake
# Called by CTest for each integration test.
#
# Three-stage pipeline:
#   1. clang -O2 -emit-llvm → .ll (baseline AND source for obfuscation)
#   2. opt --load-pass-plugin -passes=PASSES → obfuscated .ll
#   3. clang obfuscated.ll -o binary, then run and compare output
#
# Using opt --load-pass-plugin (not -fpass-plugin + -mllvm) because opt
# pre-scans argv for --load-pass-plugin before ParseCommandLineOptions, so
# plugin cl::opt flags are registered before the rest of argv is parsed.
#
# Parameters (passed via -D):
#   CLANG     — path to clang
#   OPT       — path to opt
#   PLUGIN    — path to libKaguraObfuscator
#   PASSES    — opt -passes= pipeline (e.g. "function(kagura-fla)")
#   SOURCE    — path to the C source file
#   EXPECTED  — expected stdout string
#   TEST_NAME — unique name for per-test temp files
#   RUNTIME   — (optional) kagura runtime library to link, for passes that emit
#               calls into it
#   REQUIRE_IR— (optional) regex the obfuscated IR must match.  Without it a
#               pass that silently declines to transform anything passes this
#               test, which is how the VM pass shipped hanging on every input.

cmake_minimum_required(VERSION 3.14)

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

# ---- Emit IR for obfuscation ------------------------------------------------
execute_process(
  COMMAND ${CLANG} -O2 -emit-llvm -S -o ${BASELINE_IR} ${SOURCE}
  RESULT_VARIABLE R ERROR_VARIABLE E
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "IR emit failed:\n${E}")
endif()

# ---- Obfuscate with opt -----------------------------------------------------
execute_process(
  COMMAND ${OPT} --load-pass-plugin=${PLUGIN} -passes=${PASSES}
          -S -o ${OBF_IR} ${BASELINE_IR}
  RESULT_VARIABLE R ERROR_VARIABLE E
)
if(NOT R EQUAL 0)
  message(FATAL_ERROR "opt obfuscation failed (${PASSES}):\n${E}")
endif()

# ---- Check the pass actually did something -----------------------------------
if(DEFINED REQUIRE_IR AND NOT REQUIRE_IR STREQUAL "")
  file(READ ${OBF_IR} _OBF_IR_TEXT)
  if(NOT _OBF_IR_TEXT MATCHES "${REQUIRE_IR}")
    message(FATAL_ERROR
      "Pass(es) ${PASSES} produced no match for '${REQUIRE_IR}' in ${OBF_IR}.\n"
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
