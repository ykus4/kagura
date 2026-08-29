# check_lit_vacuity.cmake — fail when a FileCheck test asserts nothing.
#
# A lit test whose CHECK lines are all satisfied by its own input is green
# whatever the pass does — including doing nothing, and including not being
# registered at all.  Two of them were in that state:
#
#   opt -passes=verify -S tests/lit/basic-block-reordering.ll \
#     | FileCheck tests/lit/basic-block-reordering.ll      # PASSED
#
# because the input already contained the `switch i32` and `ret i32` the file
# checked for, and that file was BasicBlockReordering's only structural test.
# loop-transform.ll checked for `br i1`, which its input also already had.
#
# The guard is that same experiment, run for every tests/lit/*.ll and for every
# check prefix the file's RUN lines use: pipe the *untransformed* file through
# FileCheck, and fail if FileCheck is satisfied.
#
# Parameters (-D):
#   OPT       — opt binary (only `-passes=verify`, so no plugin is needed)
#   FILECHECK — FileCheck binary
#   LIT_DIR   — tests/lit source directory
#   WORKDIR   — scratch directory for the verify-only IR

cmake_minimum_required(VERSION 3.20)

foreach(_var OPT FILECHECK LIT_DIR WORKDIR)
  if(NOT DEFINED ${_var})
    message(FATAL_ERROR "check_lit_vacuity.cmake: -D${_var} is required")
  endif()
endforeach()

# Checks that are vacuous by design: each asserts that a pass declines to
# transform the input, so untransformed input is precisely what it expects.
# Entries are either a file name (the whole file is a negative test) or
# "<file>:<PREFIX>" (only that one check prefix is negative — these files also
# carry a positive prefix that this guard does police).
set(ALLOWED_VACUOUS
  vm-obfuscation-unsupported.ll         # the VM must decline shapes it cannot lower
  wasm-pass-filter.ll                   # passes that must not run on a wasm triple
  config-policy.ll:PLAIN                # no policy file / -kagura-str=false
  config-profile-preset.ll:FAST         # FAST leaves anti-tamper off
  dwarf-control.ll:KEEP                 # -kagura-dwarf=keep must not strip
  loop-transform-phi-order.ll:LATCHSTEP # a latch-defined step must not be split
  # These two are checked against files that are not the pass's output at all —
  # a captured stderr and a "the build still succeeded" module — so the
  # experiment this guard runs does not describe them.
  config-strict.ll:NODIAG               # a tolerated key must produce no diagnostic
  config-strict.ll:BUILT                # an unknown key must still let the build finish
)

file(MAKE_DIRECTORY "${WORKDIR}")
file(GLOB LIT_FILES "${LIT_DIR}/*.ll")

set(_vacuous "")
set(_checked 0)

foreach(_ll IN LISTS LIT_FILES)
  get_filename_component(_name "${_ll}" NAME)
  if(_name IN_LIST ALLOWED_VACUOUS)
    continue()
  endif()

  file(READ "${_ll}" _text)

  # A `not diff` RUN line is a differential assertion: the file compares the
  # pass's output against the same module printed with only `-passes=verify` in
  # the pipeline, and fails if they match.  That is this guard's own experiment,
  # spelled out inside the test, and it is strictly stronger than any CHECK
  # line — so the accompanying CHECK block is free to be a
  # "nothing was lost" list that untransformed input would also satisfy.
  if(_text MATCHES "RUN:[^\n]*not[ \t]+diff")
    math(EXPR _checked "${_checked} + 1")
    continue()
  endif()

  # Collect every prefix the RUN lines actually check under, so a file that
  # only uses --check-prefix=SPLIT is still covered.
  set(_prefixes "")
  if(_text MATCHES "\n[ \t]*;[ \t]*CHECK[-:]")
    list(APPEND _prefixes CHECK)
  endif()
  string(REGEX MATCHALL "--?check-prefix(es)?=[A-Za-z0-9_,-]+" _pfx_args "${_text}")
  foreach(_arg IN LISTS _pfx_args)
    string(REGEX REPLACE "^--?check-prefix(es)?=" "" _arg "${_arg}")
    string(REPLACE "," ";" _arg "${_arg}")
    list(APPEND _prefixes ${_arg})
  endforeach()
  list(REMOVE_DUPLICATES _prefixes)
  if(NOT _prefixes)
    # deterministic-output.ll drives `diff` from its RUN lines rather than
    # FileCheck, which is a real assertion; a file that *does* pipe into
    # FileCheck and has no directive for it is not.
    if(_text MATCHES "%FileCheck|FileCheck ")
      list(APPEND _vacuous "${_name} (pipes into FileCheck with no CHECK directive)")
    endif()
    continue()
  endif()

  # `opt -passes=verify` is the identity transform: whatever comes out is what
  # the test would see if its pass did nothing.
  set(_verified "${WORKDIR}/${_name}")
  execute_process(
    COMMAND ${OPT} -passes=verify -S "${_ll}" -o "${_verified}"
    RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_QUIET)
  if(NOT _rc EQUAL 0)
    # The file is not a self-contained module (a lit substitution builds it, or
    # it is deliberately malformed).  It cannot be vacuous in the sense above.
    continue()
  endif()

  math(EXPR _checked "${_checked} + 1")
  foreach(_prefix IN LISTS _prefixes)
    if("${_name}:${_prefix}" IN_LIST ALLOWED_VACUOUS)
      continue()
    endif()
    execute_process(
      COMMAND ${FILECHECK} "${_ll}" --check-prefix=${_prefix}
              --input-file=${_verified}
      RESULT_VARIABLE _fc_rc OUTPUT_QUIET ERROR_QUIET)
    if(_fc_rc EQUAL 0)
      list(APPEND _vacuous "${_name} (prefix ${_prefix})")
    endif()
  endforeach()
endforeach()

if(_vacuous)
  string(REPLACE ";" "\n  " _list "${_vacuous}")
  message(FATAL_ERROR
    "These FileCheck tests pass against their own untransformed input, so they "
    "assert nothing about the pass they name:\n  ${_list}\n"
    "Reproduce with:\n"
    "  ${OPT} -passes=verify -S <file> | ${FILECHECK} <file>\n"
    "Fix by checking for something only the transform produces, or — if the "
    "test is a deliberate 'the pass must decline this input' test — add it to "
    "ALLOWED_VACUOUS in tests/check_lit_vacuity.cmake.")
endif()

message(STATUS "lit vacuity guard: ${_checked} FileCheck tests, none vacuous")
