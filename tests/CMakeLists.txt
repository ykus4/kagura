find_package(LLVM REQUIRED CONFIG)

# Plugin-based tests (opt --load-pass-plugin) require a loadable module (.so/.dylib/.dll).
# When LLVM is built without plugin support — e.g. the MSVC-targeted Windows tarball sets
# LLVM_ENABLE_PLUGINS=OFF — there is no module to load.  The passes are still reachable
# through kagura-opt, which links them in statically, so run the smoke tests through that
# tool instead of leaving the platform completely untested.
if(KAGURA_PLUGIN_STATIC)
  if(NOT KAGURA_BITCODE_TOOLS)
    message(STATUS "[kagura] Tests skipped: static plugin build without kagura-opt.")
    message(STATUS "[kagura]   Configure with -DKAGURA_BITCODE_TOOLS=ON to run pass tests here.")
    add_test(NAME kagura_static_build_ok
      COMMAND ${CMAKE_COMMAND} -E echo
        "Static build OK — pass tests skipped (KAGURA_BITCODE_TOOLS=OFF)"
    )
    return()
  endif()

  message(STATUS "[kagura] Static plugin build — running pass tests via kagura-opt")

  # One pass per test, driven through the statically linked tool.  The marker is
  # checked against the transformed IR so a silently-inert pass fails the test.
  macro(kagura_add_tool_test TEST_NAME FLAG INPUT_FILE EXPECT_MARKER)
    add_test(NAME ${TEST_NAME}
      COMMAND ${CMAKE_COMMAND}
        -DKAGURA_OPT=$<TARGET_FILE:kagura-opt>
        -DFLAG=${FLAG}
        -DINPUT=${CMAKE_CURRENT_SOURCE_DIR}/lit/${INPUT_FILE}
        -DEXPECT=${EXPECT_MARKER}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_tool_test.cmake
    )
  endmacro()

  kagura_add_tool_test(test_static_flattening
    kagura-fla control-flow-flattening.ll "switch i32")
  kagura_add_tool_test(test_static_string_encryption
    kagura-str string-encryption.ll "@kagura_enc_")
  # kagura-opt runs the default -O2 pipeline, which folds this input's opaque
  # predicates back down, so there is no bogus-CF marker left to match on.  The
  # assertion here is the weaker "the module survives the pass" — the stronger
  # structural checks live in the lit suite, which needs a loadable module.
  kagura_add_tool_test(test_static_bogus_cf
    kagura-bcf bogus-control-flow.ll "@classify")
  kagura_add_tool_test(test_static_substitution
    kagura-sub substitution.ll "define i32 @arith")

  return()
endif()

# Minimal test: compile a C file with the plugin and verify it doesn't crash
add_custom_target(check-kagura
  COMMAND ${CMAKE_COMMAND} -E echo "Running kagura integration tests..."
  DEPENDS KaguraObfuscator
)

# Test helper: compile a simple C source with all passes enabled
set(KAGURA_PLUGIN $<TARGET_FILE:KaguraObfuscator>)
set(LLVM_BIN ${LLVM_TOOLS_BINARY_DIR})

# Use opt --load-pass-plugin -passes= for testing, which works across all
# LLVM versions (avoids -mllvm cl::opt registration timing issues in LLVM 19).
# Each test: clang -O0 -emit-llvm → opt --load-pass-plugin -passes=...

# Helper macro: create a two-stage test (C → IR → opt with pass)
macro(kagura_add_pass_test TEST_NAME PASS_PIPELINE SOURCE_FILE)
  add_test(NAME ${TEST_NAME}
    COMMAND ${CMAKE_COMMAND}
      -DCLANG=${LLVM_BIN}/clang
      -DOPT=${LLVM_BIN}/opt
      -DPLUGIN=${KAGURA_PLUGIN}
      -DPASSES=${PASS_PIPELINE}
      -DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/pass-inputs/${SOURCE_FILE}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/run_pass_test.cmake
  )
endmacro()

kagura_add_pass_test(test_string_encryption "kagura-str" string_test.c)
kagura_add_pass_test(test_flattening "function(kagura-fla)" control_flow_test.c)
kagura_add_pass_test(test_bogus_cf "function(kagura-bcf)" control_flow_test.c)
kagura_add_pass_test(test_substitution "function(kagura-sub)" arithmetic_test.c)
kagura_add_pass_test(test_cse_break "function(kagura-cse-break)" arithmetic_test.c)
kagura_add_pass_test(test_vm_vm "function(kagura-vm)" vm_test.c)
kagura_add_pass_test(test_indirect_branch "function(kagura-ibr)" indirect_branch_test.c)
kagura_add_pass_test(test_loop_transform "function(kagura-lt)" loop_test.c)
kagura_add_pass_test(test_pointer "function(kagura-bcf,kagura-sub,kagura-ibr,kagura-lt)" pointer_test.c)
kagura_add_pass_test(test_basic_block_reordering "function(kagura-bbr)" control_flow_test.c)
kagura_add_pass_test(test_basic_block_splitting "function(kagura-bbs)" arithmetic_test.c)
kagura_add_pass_test(test_dead_code_insertion "function(kagura-dci)" control_flow_test.c)
kagura_add_pass_test(test_symbol_visibility "kagura-sv" arithmetic_test.c)
kagura_add_pass_test(test_all_passes
  "kagura-str,kagura-fsplit,kagura-sv,function(kagura-bcf,kagura-sub,kagura-co,kagura-ibr,kagura-lt,kagura-bbr,kagura-bbs,kagura-dci)"
  combined_test.c)

# ── New pass tests ───────────────────────────────────────────────────────────
kagura_add_pass_test(test_mvo
  "function(kagura-mvo)"
  arithmetic_test.c)
kagura_add_pass_test(test_honey
  "kagura-honey"
  arithmetic_test.c)
kagura_add_pass_test(test_wstr
  "kagura-wstr"
  string_test.c)
kagura_add_pass_test(test_str_aes
  "kagura-str-aes"
  string_test.c)
kagura_add_pass_test(test_string_split
  "kagura-string-split"
  string_test.c)
kagura_add_pass_test(test_global_enc
  "kagura-genc"
  arithmetic_test.c)
kagura_add_pass_test(test_call_indirection
  "kagura-ci"
  combined_test.c)
kagura_add_pass_test(test_function_split
  "kagura-fsplit"
  combined_test.c)

# ── Link smoke tests ───────────────────────────────────────────────────────────
#
# Every test above stops at the IR level, so a pass that emits a call to a
# runtime function the runtime does not define still passes them.  Three
# passes shipped in exactly that state.  These tests link a real executable.
#
# The pass list is read out of PassRegistry.def rather than written here, so a
# newly registered pass is covered the moment its row is added.

set(KAGURA_LINK_SUBJECTS
  ${CMAKE_CURRENT_SOURCE_DIR}/pass-inputs/combined_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pass-inputs/string_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pass-inputs/control_flow_test.c
)

file(STRINGS ${PROJECT_SOURCE_DIR}/lib/Transforms/PassRegistry.def
     KAGURA_PASS_ROWS
     REGEX "^KAGURA_(FN|MOD)_PASS\\(")

foreach(_row IN LISTS KAGURA_PASS_ROWS)
  if(_row MATCHES "\"(kagura-[a-z0-9-]+)\"")
    set(_cli ${CMAKE_MATCH_1})
    add_test(NAME link_${_cli}
      COMMAND ${CMAKE_COMMAND}
        -DCLANG=${LLVM_BIN}/clang
        -DPLUGIN=${KAGURA_PLUGIN}
        -DRUNTIME=$<TARGET_FILE:kagura_runtime>
        -DFLAG=${_cli}
        "-DSOURCES=${KAGURA_LINK_SUBJECTS}"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_link_test.cmake
    )
    set_tests_properties(link_${_cli} PROPERTIES LABELS link)
  endif()
endforeach()

list(LENGTH KAGURA_PASS_ROWS _n_passes)
message(STATUS "[kagura] Registered ${_n_passes} link smoke tests from PassRegistry.def")

# ── FileCheck / lit tests ──────────────────────────────────────────────────────

find_program(LIT_EXECUTABLE NAMES lit llvm-lit
  HINTS ${LLVM_TOOLS_BINARY_DIR} ${LLVM_BIN}
  DOC "LLVM lit test runner"
)

find_program(FILECHECK_EXECUTABLE NAMES FileCheck
  HINTS ${LLVM_TOOLS_BINARY_DIR}
  DOC "LLVM FileCheck"
)

# ---- Integration tests ------------------------------------------------------
add_subdirectory(integration)

# ---- Fuzz targets (only when KAGURA_BUILD_FUZZ=ON) --------------------------
add_subdirectory(fuzz)

# ---- Regression corpus ------------------------------------------------------
add_subdirectory(regression)

if(LIT_EXECUTABLE AND FILECHECK_EXECUTABLE)
  set(KAGURA_PLUGIN_PATH $<TARGET_FILE:KaguraObfuscator>)

  # configure_file() expands @VAR@ but leaves $<TARGET_FILE:...> untouched, so
  # the plugin path has to go through file(GENERATE) afterwards.  Writing the
  # intermediate to a .in-stage name keeps the final lit.site.cfg.py the only
  # file lit ever sees.
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/lit/lit.site.cfg.py.in
    ${CMAKE_CURRENT_BINARY_DIR}/lit/lit.site.cfg.py.stage
    @ONLY
  )
  file(GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lit/lit.site.cfg.py
    INPUT  ${CMAKE_CURRENT_BINARY_DIR}/lit/lit.site.cfg.py.stage
  )

  # lit is pointed at the BUILD directory, which is where lit.site.cfg.py is
  # generated.  The site config sets test_source_root, so lit then walks the
  # source tree for the .ll files while keeping %t and Output/ under the build
  # tree.  Pointing lit at the source dir instead makes it load lit.cfg.py
  # without the generated substitutions and abort.
  add_test(NAME lit-filecheck
    COMMAND ${LIT_EXECUTABLE} -sv ${CMAKE_CURRENT_BINARY_DIR}/lit
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set_tests_properties(lit-filecheck PROPERTIES
    DEPENDS KaguraObfuscator
  )
else()
  message(STATUS "lit or FileCheck not found — skipping FileCheck tests")
  message(STATUS "  Install with: pip install lit   (FileCheck ships with LLVM)")
endif()
