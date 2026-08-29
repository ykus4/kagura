find_package(LLVM REQUIRED CONFIG)

set(LLVM_BIN ${LLVM_TOOLS_BINARY_DIR})

# ── How the tests reach the passes ────────────────────────────────────────────
#
# Plugin-based tests (opt --load-pass-plugin) require a loadable module
# (.so/.dylib/.dll).  When LLVM is built without plugin support — e.g. the
# MSVC-targeted Windows tarball sets LLVM_ENABLE_PLUGINS=OFF — there is no
# module to load.  The passes are still reachable through kagura-opt, which
# links them in statically.
#
# This file used to `return()` right after registering four kagura-opt smoke
# tests in that case.  The only CI job that runs ctest on Linux configures with
# KAGURA_FORCE_STATIC_PLUGIN=ON, so on Linux that early return dropped all 30
# link tests, 22 pass tests, 8 regression tests, 12 integration tests and the
# whole lit suite — 4 tests registered instead of 73, on a project that
# advertises iOS/Android/macOS/Windows/Linux/Wasm.
#
# Everything below is therefore written against KAGURA_PASS_DRIVER, which names
# whichever driver this build has; tests/kagura_driver.cmake translates an opt
# pipeline string into kagura-opt flags when needed.  Only the lit suite, whose
# RUN lines spell out `-load-pass-plugin`, is genuinely loadable-module-only,
# and it is registered as a skipped ctest entry rather than silently omitted.
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

  message(STATUS "[kagura] Static plugin build — pass tests run through kagura-opt")
  set(KAGURA_PASS_DRIVER -DKAGURA_OPT=$<TARGET_FILE:kagura-opt>)
else()
  set(KAGURA_PASS_DRIVER -DPLUGIN=$<TARGET_FILE:KaguraObfuscator>)
endif()

# ── kagura-opt CLI smoke tests (static builds only) ───────────────────────────
#
# These cover something no other test does: kagura-opt's own `-kagura-<flag>`
# command line, which is the supported entry point on platforms with no
# loadable module.  The marker is checked against the transformed IR so a
# silently-inert pass fails the test.
if(KAGURA_PLUGIN_STATIC)
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
endif()

# Minimal test: compile a C file with the plugin and verify it doesn't crash
add_custom_target(check-kagura
  COMMAND ${CMAKE_COMMAND} -E echo "Running kagura integration tests..."
  DEPENDS KaguraObfuscator
)

# NOTE on build ordering: none of the add_test() calls below can express "build
# KaguraObfuscator first".  CTest's DEPENDS property orders tests by *test
# name*; it was used here with a target name, which CTest ignores without a
# warning, so it read as a build dependency and provided none.  `cmake --build`
# before `ctest` is the contract, as in every CI job.

# Use opt --load-pass-plugin -passes= for testing, which works across all
# LLVM versions (avoids -mllvm cl::opt registration timing issues in LLVM 19).
# Each test: clang -O0/-O2 -emit-llvm → the pass driver → verify

# Helper macro: create a two-stage test (C → IR → passes)
macro(kagura_add_pass_test TEST_NAME PASS_PIPELINE SOURCE_FILE)
  add_test(NAME ${TEST_NAME}
    COMMAND ${CMAKE_COMMAND}
      -DCLANG=${LLVM_BIN}/clang
      -DOPT=${LLVM_BIN}/opt
      ${KAGURA_PASS_DRIVER}
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

# The system libraries runtime/CMakeLists.txt links PRIVATE.
#
# For a static library CMake records those in INTERFACE_LINK_LIBRARIES wrapped
# in $<LINK_ONLY:>, so a consumer going through Kagura::kagura_runtime gets
# them. This driver invokes clang with the archive path directly, which is the
# point — it checks that the emitted calls resolve — so nothing propagates and
# the system libraries have to be named here. Without them link_kagura-bbcheck
# fails on Windows with an unresolved __imp_MapFileAndCheckSumA, which is
# imagehlp, not anything kagura emitted.
if(WIN32)
  set(KAGURA_LINK_SYSLIBS -lws2_32 -limagehlp -lbcrypt)
else()
  set(KAGURA_LINK_SYSLIBS "")
endif()

# Passes whose emitted runtime calls have no Windows implementation.
#
# runtime/CMakeLists.txt documents the anti-debug half of this: AntiDebug.cpp
# emits six kagura_check_* symbols that live in POSIX-only translation units,
# and giving Windows real implementations is a design question rather than a
# build-system one. CallIndirection is the same shape — it emits
# kagura_rtld_default_handle, and the thunk resolution underneath is dlsym.
#
# Registered as WILL_FAIL rather than skipped, deliberately. A skip is how
# these stayed invisible: the only Windows ctest run registered four tests
# until this file stopped returning early. WILL_FAIL keeps them running, and
# turns red the moment somebody implements the missing side — at which point
# the entry below is what needs deleting.
set(KAGURA_WIN32_LINK_GAPS kagura-anti-debug kagura-ci)

# Function-level passes must be wrapped in function(...) for opt; module-level
# passes are named directly. The registry already records which is which, so
# read the macro name alongside the CLI name rather than maintaining a list.
file(STRINGS ${PROJECT_SOURCE_DIR}/include/kagura/PassRegistry.def
     KAGURA_PASS_ROWS
     REGEX "^KAGURA_(FN|MOD)_PASS\\(")

foreach(_row IN LISTS KAGURA_PASS_ROWS)
  if(_row MATCHES "^KAGURA_(FN|MOD)_PASS\\([^\"]*\"(kagura-[a-z0-9-]+)\"")
    set(_kind ${CMAKE_MATCH_1})
    set(_cli  ${CMAKE_MATCH_2})
    if(_kind STREQUAL "FN")
      set(_pipeline "function(${_cli})")
    else()
      set(_pipeline "${_cli}")
    endif()
    add_test(NAME link_${_cli}
      COMMAND ${CMAKE_COMMAND}
        -DCLANG=${LLVM_BIN}/clang
        -DOPT=${LLVM_BIN}/opt
        ${KAGURA_PASS_DRIVER}
        -DRUNTIME=$<TARGET_FILE:kagura_runtime>
        -DPIPELINE=${_pipeline}
        -DLABEL=${_cli}
        "-DSOURCES=${KAGURA_LINK_SUBJECTS}"
        "-DSYSLIBS=${KAGURA_LINK_SYSLIBS}"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_link_test.cmake
    )
    set_tests_properties(link_${_cli} PROPERTIES LABELS link)
    if(WIN32 AND _cli IN_LIST KAGURA_WIN32_LINK_GAPS)
      set_tests_properties(link_${_cli} PROPERTIES WILL_FAIL TRUE)
    endif()
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

# Belongs in cmake/KaguraOptions.cmake with the rest of the user-facing
# options; it is declared here only because the file that consumes it is the
# one that can skip.
#
# Two CI jobs used to guard against a silently-skipped lit suite by grepping
# `ctest -N` output for the test name, and one job (assertions) installed lit
# and then never checked, so a pip failure would have dropped all 32 lit tests
# from the only build with assertions compiled in. One option replaces both
# greps: turn the skip into a configure error wherever the suite is expected.
#
# It deliberately does not apply to static-plugin builds: there the suite is
# skipped for a structural reason (the RUN lines need a loadable module), not
# because a tool is missing.
option(KAGURA_REQUIRE_LIT
       "Fail configuration if lit or FileCheck is missing instead of silently \
skipping the FileCheck suite" OFF)

# ---- Integration tests ------------------------------------------------------
add_subdirectory(integration)

# ---- Fuzz targets (only when KAGURA_BUILD_FUZZ=ON) --------------------------
add_subdirectory(fuzz)

# ---- Regression corpus ------------------------------------------------------
add_subdirectory(regression)

if(KAGURA_PLUGIN_STATIC)
  # Visibly skipped, not silently absent: every RUN line in tests/lit spells
  # out `-load-pass-plugin=%kagura_plugin`, and opt cannot dlopen the static
  # archive this build produces.  Registering the skip means `ctest` reports it
  # rather than the suite just not being in the list.
  add_test(NAME lit-filecheck-skipped-static-plugin
    COMMAND ${CMAKE_COMMAND} -E echo
      "SKIPPED: the lit suite drives opt --load-pass-plugin, which needs a "
      "loadable module; this build links the passes into kagura-opt instead."
  )
  set_tests_properties(lit-filecheck-skipped-static-plugin PROPERTIES
    SKIP_REGULAR_EXPRESSION "SKIPPED:"
  )
elseif(LIT_EXECUTABLE AND FILECHECK_EXECUTABLE)
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
elseif(KAGURA_REQUIRE_LIT)
  message(FATAL_ERROR
    "KAGURA_REQUIRE_LIT=ON but the FileCheck suite cannot be registered:\n"
    "  lit:       ${LIT_EXECUTABLE}\n"
    "  FileCheck: ${FILECHECK_EXECUTABLE}\n"
    "Install with: pip install lit   (FileCheck ships with LLVM)")
else()
  message(STATUS "lit or FileCheck not found — skipping FileCheck tests")
  message(STATUS "  Install with: pip install lit   (FileCheck ships with LLVM)")
endif()

# ── lit vacuity guard ─────────────────────────────────────────────────────────
#
# A FileCheck test whose CHECK lines are all satisfied by its own *input*
# asserts nothing.  Two of them were: basic-block-reordering.ll checked for
# `switch i32` / `ret i32` and loop-transform.ll for `br i1`, all of which the
# input already contained, so `opt -passes=verify` alone passed both — and BBR
# had no other structural test at all.
#
# This runs exactly that experiment over every tests/lit/*.ll and fails if any
# of them survives it.  It needs FileCheck but not the plugin, so it is
# registered in static-plugin builds too.
if(FILECHECK_EXECUTABLE)
  add_test(NAME lit-vacuity-guard
    COMMAND ${CMAKE_COMMAND}
      -DOPT=${LLVM_BIN}/opt
      -DFILECHECK=${FILECHECK_EXECUTABLE}
      -DLIT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/lit
      -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/vacuity
      -P ${CMAKE_CURRENT_SOURCE_DIR}/check_lit_vacuity.cmake
  )
endif()
