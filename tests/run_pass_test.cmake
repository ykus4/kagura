# run_pass_test.cmake — Two-stage pass test runner
#
# Usage:
#   cmake -DCLANG=... -DOPT=... -DPLUGIN=... -DPASSES=... -DSOURCE=... \
#         -P run_pass_test.cmake
#
#   1. Compile the C source to LLVM IR with clang.
#   2. Run opt with the pass plugin and the requested passes, then the IR
#      verifier.
#
# The verifier matters: two passes shipped emitting IR that fails it — one
# crashing clang in instruction selection, the other segfaulting it — and this
# runner did not notice, because it only checked opt's exit status while opt
# verifies nothing by default.
#
# The IR is built at two optimisation levels. Most of the interesting cases
# involve PHI nodes, which barely exist until mem2reg has run, so a pass that
# mishandles them looks fine on -O0 IR.

cmake_minimum_required(VERSION 3.20)

foreach(_var CLANG OPT PLUGIN PASSES SOURCE)
  if(NOT DEFINED ${_var})
    message(FATAL_ERROR "run_pass_test.cmake: -D${_var} is required")
  endif()
endforeach()

string(RANDOM LENGTH 8 ALPHABET abcdefghijklmnopqrstuvwxyz RAND_SUFFIX)

foreach(_optlevel -O0 -O2)
  set(IR_FILE  "${CMAKE_CURRENT_BINARY_DIR}/kagura_test_${RAND_SUFFIX}${_optlevel}.ll")
  set(OUT_FILE "${IR_FILE}.out.ll")

  # Step 1: C -> LLVM IR
  execute_process(
    COMMAND ${CLANG} ${_optlevel} -emit-llvm -S -o ${IR_FILE} ${SOURCE}
    RESULT_VARIABLE CLANG_RESULT
    ERROR_VARIABLE  CLANG_ERROR
  )
  if(NOT CLANG_RESULT EQUAL 0)
    message(FATAL_ERROR "clang ${_optlevel} failed:\n${CLANG_ERROR}")
  endif()

  # Step 2: opt with the pass plugin, then verify the result.
  #
  # Writing to a real file rather than /dev/null keeps this working on
  # Windows, and appending "verify" makes malformed output a test failure
  # instead of something the backend discovers later.
  execute_process(
    COMMAND ${OPT} --load-pass-plugin=${PLUGIN} -passes=${PASSES},verify
            -S -o ${OUT_FILE} ${IR_FILE}
    RESULT_VARIABLE OPT_RESULT
    ERROR_VARIABLE  OPT_ERROR
  )

  file(REMOVE ${IR_FILE} ${OUT_FILE})

  if(NOT OPT_RESULT EQUAL 0)
    message(FATAL_ERROR
      "opt failed on ${_optlevel} IR with passes '${PASSES}':\n${OPT_ERROR}")
  endif()
endforeach()
