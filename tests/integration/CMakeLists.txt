# Integration tests — compile a realistic "app" through kagura passes
# and verify semantic correctness (output matches baseline) and binary size.
#
# Each integration test:
#   1. Compiles the test subject WITHOUT kagura → baseline binary
#   2. Compiles the same source to IR, obfuscates it, then links the obfuscated
#      bitcode into an obfuscated binary
#   3. Runs both; compares stdout output
#
# In a loadable-module build step 2 uses opt --load-pass-plugin (rather than
# -fpass-plugin + -mllvm) because opt pre-scans argv for --load-pass-plugin
# before calling ParseCommandLineOptions, so the plugin's cl::opt options are
# already registered when the rest of argv is parsed.  With -fpass-plugin the
# plugin is loaded late (during pipeline construction), after LLVM option
# parsing, so any -mllvm flags referencing kagura cl::opts arrive too early and
# are rejected as unknown on all LLVM versions.  In a static-plugin build the
# same step goes through kagura-opt; see tests/kagura_driver.cmake.

cmake_minimum_required(VERSION 3.20)

set(INT_INPUTS ${CMAKE_CURRENT_SOURCE_DIR}/subjects)

# Pinned so a failure is reproducible, and so the passes that fire
# probabilistically do so deterministically — a REQUIRE_IR marker that is only
# present four times out of five is a flaky test, not an assertion.
#
# Where the probability is a tuning parameter (BCF, DCI) the test turns it up
# to 100 instead, which does not depend on the PRNG stream at all; see
# bcf_correctness below.  LoopTransform's 80/60/40 % are hard-coded, so
# lt_correctness still leans on this seed.
set(KAGURA_INT_SEED 32)

# PASSES is an opt -passes= pipeline string, e.g. "function(kagura-fla)" or
# "kagura-str,function(kagura-fla,kagura-co)".
#
# REQUIRE_IR is a required argument, not an optional one.  "Output matches
# baseline" is satisfied by a pass that transforms nothing, so every test needs
# a marker that only its pass can produce; see the header of
# run_integration_test.cmake for the ":changed:" form and for why the marker is
# matched literally rather than as a regex.
#
#   ARGV5  RUNTIME — link the kagura runtime, for passes that emit calls into
#          it (the VM interpreter, for instance).
#   ARGV6  EXTRA_FLAGS — further -kagura-* options, as a ';'-list.
macro(kagura_add_integration_test TEST_NAME PASSES SOURCE_FILE EXPECTED_OUTPUT REQUIRE_IR)
  set(_runtime "")
  set(_extra_flags "")
  if(${ARGC} GREATER 5)
    set(_runtime "${ARGV5}")
  endif()
  if(${ARGC} GREATER 6)
    set(_extra_flags "${ARGV6}")
  endif()
  add_test(NAME integration_${TEST_NAME}
    COMMAND ${CMAKE_COMMAND}
      -DCLANG=${LLVM_BIN}/clang
      -DOPT=${LLVM_BIN}/opt
      ${KAGURA_PASS_DRIVER}
      -DPASSES=${PASSES}
      -DSOURCE=${INT_INPUTS}/${SOURCE_FILE}
      -DEXPECTED=${EXPECTED_OUTPUT}
      -DTEST_NAME=${TEST_NAME}
      -DREQUIRE_IR=${REQUIRE_IR}
      -DSEED=${KAGURA_INT_SEED}
      "-DEXTRA_FLAGS=${_extra_flags}"
      -DRUNTIME=${_runtime}
      -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/artifacts
      -P ${CMAKE_CURRENT_SOURCE_DIR}/run_integration_test.cmake
  )
  set_tests_properties(integration_${TEST_NAME} PROPERTIES
    TIMEOUT 60
  )
endmacro()

# ---- Core CFG obfuscation ---------------------------------------------------
kagura_add_integration_test(fla_correctness
  "function(kagura-fla)"
  fibonacci.c
  "55\n89\n144\n"
  "kagura.sw")          # the flattening dispatcher's state switch

# -kagura-bcf-prob=100 rather than a seed chosen because it happens to make the
# 30 %-per-block draw come up: which blocks fire is then a property of the pass,
# not of the PRNG stream, and stays true when an unrelated change shifts that
# stream.  It also means every block is covered rather than a third of them.
kagura_add_integration_test(bcf_correctness
  "function(kagura-bcf)"
  fibonacci.c
  "55\n89\n144\n"
  "bcf.bogus"           # the never-taken clone of an original block
  ""
  "-kagura-bcf-prob=100")

kagura_add_integration_test(sub_correctness
  "function(kagura-sub)"
  arithmetic_smoke.c
  "42\n100\n0\n-1\n"
  "sub.")               # sub.add / sub.mul / ... — one per rewritten operator

# The marker is the flattening dispatcher, not a bogus-CF block: BogusControlFlow
# fires per block with a probability, and once FLA has rewritten the CFG the set
# of blocks it is offered — and therefore whether the fixed seed makes it fire —
# depends on the order the driver runs the three passes in.  That order is opt's
# pipeline string here and Plugin.cpp's fixed order under kagura-opt, so a
# bcf.bogus marker holds in one linkage mode and not the other.  BCF on its own
# is covered by bcf_correctness above.
kagura_add_integration_test(fla_bcf_sub_combined
  "function(kagura-fla,kagura-bcf,kagura-sub)"
  fibonacci.c
  "55\n89\n144\n"
  "kagura.sw")

# ---- Data obfuscation -------------------------------------------------------
kagura_add_integration_test(str_encrypt_correctness
  "kagura-str"
  string_smoke.c
  "hello world\nkagura obfuscator\n"
  "@kagura_enc_")       # the ciphertext global that replaces the literal

kagura_add_integration_test(co_correctness
  "function(kagura-co)"
  arithmetic_smoke.c
  "42\n100\n0\n-1\n"
  "co.")                # co.xr1 / co.add / co.notv / co.mr — one per identity

# ---- CFG fragmentation ------------------------------------------------------
# BasicBlockReordering only changes block layout, so it has no marker of its
# own; ":changed:" asserts the obfuscated IR differs from the baseline IR.
#
# arithmetic_smoke.c rather than fibonacci.c: after -O2, fib() has exactly two
# non-entry blocks, and permuting two blocks whose relative order the printer
# then re-derives leaves a one-line diff in a `; preds =` comment.  The
# four-way branch in arith_case() gives the shuffle something to shuffle.
kagura_add_integration_test(bbr_correctness
  "function(kagura-bbr)"
  arithmetic_smoke.c
  "42\n100\n0\n-1\n"
  ":changed:")

kagura_add_integration_test(bbs_correctness
  "function(kagura-bbs)"
  arithmetic_smoke.c
  "42\n100\n0\n-1\n"
  ".split")             # the suffix llvm::SplitBlock gives the tail block

kagura_add_integration_test(dci_correctness
  "function(kagura-dci)"
  fibonacci.c
  "55\n89\n144\n"
  "dci.slot"            # the alloca the junk block's dead stores target
  ""
  "-kagura-dci-prob=100")

# ---- All-pass combination ---------------------------------------------------
kagura_add_integration_test(all_passes_correctness
  "kagura-str,function(kagura-fla,kagura-bcf,kagura-sub,kagura-co,kagura-bbr,kagura-bbs,kagura-dci)"
  fibonacci.c
  "55\n89\n144\n"
  "kagura.sw")

# ---- Loop transform ---------------------------------------------------------
kagura_add_integration_test(lt_correctness
  "function(kagura-lt)"
  loop_smoke.c
  "45\n550\n"
  "lt.")                # lt.bogus / lt.dead / lt.combined — one per effect

# ---- Code virtualisation ----------------------------------------------------
#
# This is the one pass whose output is executed by an interpreter rather than by
# the CPU, so nothing short of running the binary catches a bytecode/interpreter
# disagreement.  Until this test existed, -kagura-vm produced a binary that hung
# before its first line of output on every input, and no test noticed.
#
# EXPECTED is empty here on purpose: the subject prints seven lines of derived
# values that are not worth restating by hand, and the pass-vs-baseline
# comparison is the point of the test.
kagura_add_integration_test(vm_correctness
  "function(kagura-vm)"
  vm_smoke.c
  ""
  "kagura_vm_execute"
  $<TARGET_FILE:kagura_runtime>)
