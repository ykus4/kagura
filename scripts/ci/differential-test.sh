#!/usr/bin/env bash
# differential-test.sh — 4.7.6: Differential testing
#
# Compiles each test input twice — once plain and once with the full kagura
# obfuscation pipeline — executes both binaries, and asserts that their
# stdout output is identical.  A mismatch means obfuscation changed runtime
# behaviour.
#
# Usage:
#   ./scripts/ci/differential-test.sh [plugin_path] [test_dir]
#
# Defaults:
#   plugin_path  = ./build/lib/Transforms/KaguraObfuscator.{dylib,so}
#   test_dir     = ./tests/inputs
#
# Environment overrides:
#   KAGURA_CLANG   path to clang
#   KAGURA_OPT     path to opt
#   KAGURA_SEED    PRNG seed (default: 42)
#   KAGURA_PASSES  obfuscation pipeline (default: standard set, see below)
#
# Exit codes:
#   0  — all tests passed (obfuscated output matches plain output)
#   1  — at least one test failed
#   2  — usage / tool error

set -euo pipefail

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OS="$(uname -s)"
if [[ "${OS}" == "Darwin" ]]; then
    PLUGIN="${1:-${REPO_ROOT}/build/lib/Transforms/KaguraObfuscator.dylib}"
else
    PLUGIN="${1:-${REPO_ROOT}/build/lib/Transforms/KaguraObfuscator.so}"
fi
TEST_DIR="${2:-${REPO_ROOT}/tests/pass-inputs}"
SEED="${KAGURA_SEED:-42}"

# Standard obfuscation pipeline used for differential testing.
# Passes that require runtime support (str-aes, vm, anti-tamper) are excluded
# because the test binaries are not linked against kagura_runtime.
#
# kagura-co is a *function* pass. Naming it in the module position made opt
# reject the whole pipeline, so every subject reported "SKIP (opt error)" — and
# the script still exited 0, because only FAIL_COUNT gated the exit status. This
# suite has therefore never actually compared a single binary, while
# CONTRIBUTING.md and the PR template both ask contributors to run it and
# confirm no regressions.
DEFAULT_PASSES="kagura-str,kagura-genc,kagura-fsplit,kagura-sv,function(kagura-co,kagura-bcf,kagura-sub,kagura-ibr,kagura-lt,kagura-bbr,kagura-bbs,kagura-dci,kagura-mvo)"
PASSES="${KAGURA_PASSES:-${DEFAULT_PASSES}}"

# --------------------------------------------------------------------------
# Tool resolution
# --------------------------------------------------------------------------
CLANG="${KAGURA_CLANG:-}"
OPT="${KAGURA_OPT:-}"

if [[ -z "${CLANG}" ]] && [[ "${OS}" == "Darwin" ]]; then
    BREW_LLVM="$(brew --prefix llvm 2>/dev/null || true)"
    if [[ -n "${BREW_LLVM}" && -x "${BREW_LLVM}/bin/clang" ]]; then
        CLANG="${BREW_LLVM}/bin/clang"
        OPT="${BREW_LLVM}/bin/opt"
    fi
fi
CLANG="${CLANG:-$(command -v clang 2>/dev/null || true)}"
OPT="${OPT:-$(command -v opt 2>/dev/null || true)}"

die() { echo "ERROR: $*" >&2; exit 2; }

# timeout(1) is GNU coreutils and does not exist on macOS, where this project's
# CI primarily runs. The script called it unconditionally, so every subject
# failed at "SKIP (plain run error)" with status 127 from the missing command.
#
# Prefer the real thing (Linux, or brew coreutils as gtimeout) and otherwise
# poll a background job, because an obfuscated binary that hangs is one of the
# regressions this script exists to catch — running without any limit would
# turn that regression into a stuck CI job.
TIMEOUT_CMD=""
for _c in timeout gtimeout; do
    if command -v "${_c}" >/dev/null 2>&1; then TIMEOUT_CMD="${_c}"; break; fi
done

# run_limited <seconds> <outfile> <command...>  — 124 on timeout, else the
# command's own status.
run_limited() {
    local secs="$1" out="$2"
    shift 2

    if [[ -n "${TIMEOUT_CMD}" ]]; then
        "${TIMEOUT_CMD}" "${secs}" "$@" > "${out}" 2>&1
        return $?
    fi

    "$@" > "${out}" 2>&1 &
    local pid=$! waited=0
    while kill -0 "${pid}" 2>/dev/null; do
        if (( waited >= secs )); then
            kill -9 "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
            return 124
        fi
        sleep 1
        (( waited++ )) || true
    done
    wait "${pid}"
}

[[ -x "${CLANG}" ]] || die "clang not found. Set KAGURA_CLANG."
[[ -x "${OPT}"   ]] || die "opt not found. Set KAGURA_OPT."
[[ -f "${PLUGIN}" ]] || die "kagura plugin not found at: ${PLUGIN}  (build first: cd build && cmake --build .)"
[[ -d "${TEST_DIR}" ]] || die "test directory not found: ${TEST_DIR}"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

run_test() {
    local src="$1"
    local name
    name="$(basename "${src}" .c)"
    local tmp="${TMPDIR_WORK}/${name}"

    echo -n "[diff-test] ${name} ... "

    # Stage 1: compile to IR (unoptimised, no kagura)
    local ir="${tmp}.ll"
    if ! "${CLANG}" -O1 -S -emit-llvm -o "${ir}" "${src}" 2>/dev/null; then
        echo "SKIP (compile error)"
        (( SKIP_COUNT++ )) || true
        return
    fi

    # Stage 2: compile plain binary
    local plain_bin="${tmp}.plain"
    if ! "${CLANG}" -O1 -o "${plain_bin}" "${src}" 2>/dev/null; then
        echo "SKIP (link error)"
        (( SKIP_COUNT++ )) || true
        return
    fi

    # Stage 3: apply obfuscation passes via opt
    local obf_ir="${tmp}.obf.ll"
    local obf_flags=(
        "-kagura-str" "-kagura-co" "-kagura-genc" "-kagura-fsplit" "-kagura-sv"
        "-kagura-bcf" "-kagura-sub" "-kagura-ibr" "-kagura-lt"
        "-kagura-bbr" "-kagura-bbs" "-kagura-dci" "-kagura-mvo"
        "-kagura-seed=${SEED}"
    )
    # Do not discard opt's diagnostics. A malformed -passes string is a bug in
    # this script, not a property of the subject, and swallowing the message is
    # how the pipeline stayed broken.
    local opt_err="${tmp}.opt.err"
    if ! "${OPT}" \
        -load-pass-plugin="${PLUGIN}" \
        -passes="${PASSES}" \
        "${obf_flags[@]}" \
        -S -o "${obf_ir}" "${ir}" 2>"${opt_err}"; then
        echo "SKIP (opt error)"
        sed 's/^/    /' "${opt_err}" >&2
        (( SKIP_COUNT++ )) || true
        return
    fi

    # Stage 4: compile obfuscated IR to binary
    local obf_bin="${tmp}.obf"
    if ! "${CLANG}" -O0 -o "${obf_bin}" "${obf_ir}" 2>/dev/null; then
        echo "SKIP (obf link error)"
        (( SKIP_COUNT++ )) || true
        return
    fi

    # Stage 5: run both and capture output
    local plain_out="${tmp}.plain.out"
    local obf_out="${tmp}.obf.out"

    if ! run_limited 10 "${plain_out}" "${plain_bin}"; then
        echo "SKIP (plain run error)"
        (( SKIP_COUNT++ )) || true
        return
    fi
    if ! run_limited 10 "${obf_out}" "${obf_bin}"; then
        echo "FAIL (obfuscated binary crashed or timed out)"
        (( FAIL_COUNT++ )) || true
        return
    fi

    # Stage 6: compare
    if diff -q "${plain_out}" "${obf_out}" > /dev/null 2>&1; then
        echo "PASS"
        (( PASS_COUNT++ )) || true
    else
        echo "FAIL (output mismatch)"
        echo "  --- plain ---"
        head -20 "${plain_out}" | sed 's/^/    /'
        echo "  --- obfuscated ---"
        head -20 "${obf_out}" | sed 's/^/    /'
        echo "  --- diff ---"
        diff "${plain_out}" "${obf_out}" | head -30 | sed 's/^/    /' || true
        (( FAIL_COUNT++ )) || true
    fi
}

# --------------------------------------------------------------------------
# Run tests
# --------------------------------------------------------------------------
echo "======================================================================"
echo " Kagura differential test — seed=${SEED}"
echo " Plugin:   ${PLUGIN}"
echo " Test dir: ${TEST_DIR}"
echo " Passes:   ${PASSES}"
echo "======================================================================"
echo ""

for src in "${TEST_DIR}"/*.c; do
    run_test "${src}"
done

echo ""
echo "======================================================================"
printf " Results: %d passed, %d failed, %d skipped\n" \
    "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}"
echo "======================================================================"

# "Nothing ran" is a failure, not a pass. Gating only on FAIL_COUNT is what let
# a broken -passes string report success for every subject.
if [[ ${PASS_COUNT} -eq 0 ]]; then
    echo "ERROR: no subject was actually compared — see the skip reasons above." >&2
    exit 1
fi

[[ ${FAIL_COUNT} -eq 0 ]]
