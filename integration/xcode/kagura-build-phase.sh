#!/usr/bin/env bash
# kagura-build-phase.sh
# Xcode "Run Script" build phase — validates the kagura plugin is present
# and prints the active obfuscation configuration to the build log.
#
# Add this as a Run Script phase BEFORE the Compile Sources phase:
#   Shell: /bin/bash
#   Script: ${KAGURA_ROOT}/integration/xcode/kagura-build-phase.sh
#
# Everything it reports comes from kagura-flags.sh, so the log always matches
# what is actually passed to clang.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KAGURA_ROOT="${KAGURA_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
export KAGURA_ROOT

echo "════════════════════════════════════════"
echo "  kagura obfuscation configuration"
echo "════════════════════════════════════════"
echo "  kagura root : $KAGURA_ROOT"
echo "  Profile     : ${KAGURA_PROFILE:-balanced}"

FLAGS="$("$SCRIPT_DIR/kagura-flags.sh" || true)"

if [ -z "$FLAGS" ] || [[ "$FLAGS" != -fpass-plugin=* ]]; then
  echo "  ⚠️  Plugin not found — obfuscation DISABLED"
  echo "  Build kagura first: cd $KAGURA_ROOT && bash build.sh"
  echo "════════════════════════════════════════"
  exit 0
fi

echo "  Plugin      : ${FLAGS%% *}"
echo "  Passes      :"
# Print one "-mllvm <flag>" pair per line for a readable build log.
printf '%s\n' "$FLAGS" | tr ' ' '\n' | grep -v '^-mllvm$' | grep '^-kagura' \
  | sed 's/^/                /'
echo "════════════════════════════════════════"
