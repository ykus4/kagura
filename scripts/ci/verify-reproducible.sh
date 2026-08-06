#!/usr/bin/env bash
# verify-reproducible.sh — 4.1.12: Reproducible build / deterministic output
#
# Compiles a test file twice with a fixed -kagura-seed and asserts that the
# two LLVM IR outputs are identical.  If any pass produces non-deterministic
# output the diff will be non-empty and the script exits with status 1.
#
# Usage:
#   ./scripts/ci/verify-reproducible.sh [plugin_path] [input_c_file] [seed]
#
# Defaults:
#   plugin_path  = ./build/lib/KaguraObfuscator.dylib  (macOS)
#                  ./build/lib/KaguraObfuscator.so      (Linux)
#   input_c_file = tests/inputs/combined_test.c
#   seed         = 12345
#
# Exit codes:
#   0  — both builds produced identical IR (reproducible)
#   1  — IR differs (non-deterministic output detected)
#   2  — usage error or missing tools

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
INPUT="${2:-${REPO_ROOT}/tests/pass-inputs/combined_test.c}"
SEED="${3:-12345}"

# --------------------------------------------------------------------------
# Tool resolution
# --------------------------------------------------------------------------
CLANG="${KAGURA_CLANG:-$(command -v clang 2>/dev/null || true)}"
OPT="${KAGURA_OPT:-$(command -v opt 2>/dev/null || true)}"

# Prefer Homebrew LLVM on macOS
if [[ -z "${CLANG}" ]] || [[ "${OS}" == "Darwin" ]]; then
    BREW_LLVM="$(brew --prefix llvm 2>/dev/null || true)"
    if [[ -n "${BREW_LLVM}" ]]; then
        CLANG="${BREW_LLVM}/bin/clang"
        OPT="${BREW_LLVM}/bin/opt"
    fi
fi

if [[ -z "${CLANG}" || ! -x "${CLANG}" ]]; then
    echo "ERROR: clang not found. Set KAGURA_CLANG or install LLVM." >&2
    exit 2
fi
if [[ -z "${OPT}" || ! -x "${OPT}" ]]; then
    echo "ERROR: opt not found. Set KAGURA_OPT or install LLVM." >&2
    exit 2
fi
if [[ ! -f "${PLUGIN}" ]]; then
    echo "ERROR: kagura plugin not found at: ${PLUGIN}" >&2
    echo "       Build the project first: cd build && cmake --build ." >&2
    exit 2
fi
if [[ ! -f "${INPUT}" ]]; then
    echo "ERROR: input file not found: ${INPUT}" >&2
    exit 2
fi

# --------------------------------------------------------------------------
# Obfuscation flags (safe subset: passes that do not require pre-demoted PHIs)
# These passes are stable at O0 IR and stress-test the PRNG seed determinism.
# --------------------------------------------------------------------------
KAGURA_FLAGS=(
    "-kagura-str"
    "-kagura-bbs"
    "-kagura-bbr"
    "-kagura-dci"
    "-kagura-seed=${SEED}"
)

TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

IR_BASE="${TMPDIR_WORK}/input.ll"
IR_OUT1="${TMPDIR_WORK}/out1.ll"
IR_OUT2="${TMPDIR_WORK}/out2.ll"

# --------------------------------------------------------------------------
# Step 1: Compile to LLVM IR (unoptimised, no kagura yet)
# --------------------------------------------------------------------------
echo "[kagura-repro] Compiling input to IR..."
"${CLANG}" -O0 -S -emit-llvm -o "${IR_BASE}" "${INPUT}"

# --------------------------------------------------------------------------
# Step 2: Run kagura twice with the same seed
# --------------------------------------------------------------------------
run_kagura() {
    local out="$1"
    # kagura-str / kagura-str-aes are module passes.
    # kagura-bbr / kagura-bbs / kagura-dci are function passes — wrap with
    # function(...) so opt's pipeline parser sees them as function passes.
    "${OPT}" \
        -load-pass-plugin="${PLUGIN}" \
        -passes="kagura-str,function(kagura-bbr,kagura-bbs,kagura-dci)" \
        "${KAGURA_FLAGS[@]}" \
        -S -o "${out}" "${IR_BASE}"
}

echo "[kagura-repro] Build 1 (seed=${SEED})..."
run_kagura "${IR_OUT1}"

echo "[kagura-repro] Build 2 (seed=${SEED})..."
run_kagura "${IR_OUT2}"

# --------------------------------------------------------------------------
# Step 3: Compare
# --------------------------------------------------------------------------
echo "[kagura-repro] Comparing outputs..."
if diff -u "${IR_OUT1}" "${IR_OUT2}" > /dev/null 2>&1; then
    echo "[kagura-repro] PASS: Both builds produced identical IR."
    echo "               Plugin:  ${PLUGIN}"
    echo "               Input:   ${INPUT}"
    echo "               Seed:    ${SEED}"
    exit 0
else
    echo "[kagura-repro] FAIL: IR outputs differ — non-deterministic output detected."
    echo "               Plugin:  ${PLUGIN}"
    echo "               Input:   ${INPUT}"
    echo "               Seed:    ${SEED}"
    echo ""
    echo "--- Diff (first 80 lines) ---"
    diff -u "${IR_OUT1}" "${IR_OUT2}" | head -80 || true
    exit 1
fi
