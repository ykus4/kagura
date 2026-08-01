#!/usr/bin/env bash
#
# One-shot build for the kagura plugin, runtime, kagura-opt and the test suite.
#
# Usage:
#   bash build.sh [BUILD_DIR] [extra cmake args...]
#
# Environment:
#   LLVM_PREFIX   LLVM installation prefix. Auto-detected if unset:
#                 `llvm-config --prefix`, then `brew --prefix llvm`,
#                 then a few well-known locations.
#   JOBS          Parallel build jobs (default: all logical CPUs).
#
# Examples:
#   bash build.sh
#   bash build.sh build-debug -DCMAKE_BUILD_TYPE=Debug
#   LLVM_PREFIX=/usr/lib/llvm-19 bash build.sh

set -euo pipefail

# ---- Build directory (first positional arg), remaining args go to cmake ------
BUILD_DIR="build"
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
  BUILD_DIR="$1"
  shift
fi

# ---- Locate LLVM -------------------------------------------------------------
if [ -z "${LLVM_PREFIX:-}" ]; then
  for candidate_cmd in llvm-config llvm-config-22 llvm-config-21 llvm-config-19 llvm-config-18 llvm-config-17; do
    if command -v "$candidate_cmd" > /dev/null 2>&1; then
      LLVM_PREFIX="$("$candidate_cmd" --prefix)"
      break
    fi
  done
fi

if [ -z "${LLVM_PREFIX:-}" ] && command -v brew > /dev/null 2>&1; then
  LLVM_PREFIX="$(brew --prefix llvm 2>/dev/null || true)"
fi

if [ -z "${LLVM_PREFIX:-}" ]; then
  for candidate_dir in \
    /opt/homebrew/opt/llvm \
    /usr/local/opt/llvm \
    /usr/lib/llvm-22 /usr/lib/llvm-21 /usr/lib/llvm-19 /usr/lib/llvm-18 /usr/lib/llvm-17 \
    /usr/local /usr
  do
    if [ -d "$candidate_dir/lib/cmake/llvm" ]; then
      LLVM_PREFIX="$candidate_dir"
      break
    fi
  done
fi

if [ -z "${LLVM_PREFIX:-}" ] || [ ! -d "$LLVM_PREFIX/lib/cmake/llvm" ]; then
  echo "error: could not find an LLVM installation." >&2
  echo "       Set LLVM_PREFIX to a prefix containing lib/cmake/llvm, e.g." >&2
  echo "         macOS: LLVM_PREFIX=\$(brew --prefix llvm) bash build.sh" >&2
  echo "         Linux: LLVM_PREFIX=/usr/lib/llvm-19 bash build.sh" >&2
  exit 1
fi

# ---- Parallelism (macOS has no nproc, Linux has no sysctl -n hw.logicalcpu) --
if [ -z "${JOBS:-}" ]; then
  if command -v nproc > /dev/null 2>&1; then
    JOBS="$(nproc)"
  elif command -v sysctl > /dev/null 2>&1; then
    JOBS="$(sysctl -n hw.logicalcpu)"
  else
    JOBS=4
  fi
fi

# ---- Plugin file extension for the closing message ---------------------------
case "$(uname -s)" in
  Darwin)          PLUGIN_EXT="dylib" ;;
  MINGW*|MSYS*|CYGWIN*) PLUGIN_EXT="dll" ;;
  *)               PLUGIN_EXT="so" ;;
esac

echo "LLVM prefix : $LLVM_PREFIX"
echo "Build dir   : $BUILD_DIR"
echo "Jobs        : $JOBS"
echo ""

# KAGURA_BITCODE_TOOLS=ON is what actually produces kagura-opt; without it the
# documented one-shot build never builds the tool the docs tell you to run.
cmake -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_PREFIX_PATH="$LLVM_PREFIX" \
  -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm" \
  -DCMAKE_C_COMPILER="$LLVM_PREFIX/bin/clang" \
  -DCMAKE_CXX_COMPILER="$LLVM_PREFIX/bin/clang++" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DKAGURA_BITCODE_TOOLS=ON \
  -DKAGURA_BUILD_TESTS=ON \
  "$@" \
  .

cmake --build "$BUILD_DIR" -j"$JOBS"

PLUGIN="$BUILD_DIR/lib/Transforms/KaguraObfuscator.$PLUGIN_EXT"

echo ""
echo "Plugin: $PLUGIN"
if [ -x "$BUILD_DIR/bin/kagura-opt" ]; then
  echo "Tool  : $BUILD_DIR/bin/kagura-opt"
fi
echo ""
echo "Usage:"
echo "  clang -fpass-plugin=$PLUGIN \\"
echo "        -mllvm -kagura-config=integration/profiles/balanced.json \\"
echo "        -O1 your_file.c -o your_file"
echo ""
echo "Tests:"
echo "  cd $BUILD_DIR && ctest --output-on-failure"
