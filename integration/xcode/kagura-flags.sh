#!/usr/bin/env bash
# kagura-flags.sh
# Emits the clang flags for kagura obfuscation based on KAGURA_* env vars.
# Called from Xcode via OTHER_CFLAGS = $(shell ...).
#
# Can also be sourced directly:
#   export $(cat kagura.xcconfig | grep ^KAGURA | xargs)
#   FLAGS=$(./kagura-flags.sh)
#
# The pass set for a profile is NOT defined here — it comes from
# ../profiles/{fast,balanced,strong}.json, the single source of truth shared
# by every kagura integration. Per-pass KAGURA_ENABLE_* overrides still work;
# see "Overrides" below.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KAGURA_ROOT="${KAGURA_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PROFILE_DIR="${KAGURA_PROFILE_DIR:-$KAGURA_ROOT/integration/profiles}"

# ── Plugin discovery ──────────────────────────────────────────────────────────
# .dylib on Apple, .so on Linux, .dll on Windows — probe all three so the same
# script works when Xcode drives a cross build or a shared checkout.

PLUGIN="${KAGURA_PLUGIN_PATH:-}"
if [ -z "$PLUGIN" ] || [ ! -f "$PLUGIN" ]; then
  PLUGIN=""
  for dir in \
    "${KAGURA_PLUGIN_DIR:-}" \
    "$KAGURA_ROOT/build/lib/Transforms" \
    "$KAGURA_ROOT/build/Release/lib/Transforms"
  do
    [ -n "$dir" ] || continue
    for ext in dylib so dll; do
      if [ -f "$dir/KaguraObfuscator.$ext" ]; then
        PLUGIN="$dir/KaguraObfuscator.$ext"
        break 2
      fi
    done
  done
fi

if [ -z "$PLUGIN" ] || [ ! -f "$PLUGIN" ]; then
  echo "# kagura: plugin not found under $KAGURA_ROOT/build/lib/Transforms" >&2
  echo "# kagura: set KAGURA_PLUGIN_PATH to KaguraObfuscator.{dylib,so,dll}" >&2
  exit 0
fi

FLAGS="-fpass-plugin=$PLUGIN"

add_flag() {
  FLAGS="$FLAGS -mllvm $1"
}

# ── Profile ───────────────────────────────────────────────────────────────────
# KAGURA_PROFILE: fast | balanced | strong | off, or a path to a JSON policy.
# KAGURA_CONFIG:  explicit path to a JSON policy (wins over KAGURA_PROFILE).

PROFILE="${KAGURA_PROFILE:-balanced}"
CONFIG="${KAGURA_CONFIG:-}"

if [ -z "$CONFIG" ]; then
  case "$(printf '%s' "$PROFILE" | tr '[:upper:]' '[:lower:]')" in
    off)                  CONFIG="" ;;
    fast|balanced|strong) CONFIG="$PROFILE_DIR/$(printf '%s' "$PROFILE" | tr '[:upper:]' '[:lower:]').json" ;;
    *)                    CONFIG="$PROFILE" ;;
  esac
fi

if [ -n "$CONFIG" ] && [ ! -f "$CONFIG" ]; then
  echo "# kagura: profile '$PROFILE' not found at $CONFIG" >&2
  CONFIG=""
fi

# Expand the profile JSON into the equivalent explicit flags. This is the
# fallback path: it keeps the build correct even if -kagura-config is not
# honoured, and it is what makes per-pass overrides possible.
#
# JSON key -> CLI flag is a plain underscore-to-dash rewrite
# (str_aes -> -kagura-str-aes, anti_debug -> -kagura-anti-debug, ...).
expand_profile() {
  python3 - "$1" <<'PY' 2>/dev/null || true
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
out = []
for key, val in doc.get("passes", {}).items():
    if val is True:
        out.append("-kagura-" + key.replace("_", "-"))
for key, val in doc.get("tuning", {}).items():
    out.append("-kagura-%s=%s" % (key.replace("_", "-"), val))
print("\n".join(out))
PY
}

PROFILE_FLAGS=""
if [ -n "$CONFIG" ]; then
  PROFILE_FLAGS="$(expand_profile "$CONFIG")"
  if [ -z "$PROFILE_FLAGS" ]; then
    echo "# kagura: could not expand $CONFIG (python3 missing?) — relying on -kagura-config" >&2
  fi
fi

# ── Overrides ─────────────────────────────────────────────────────────────────
# Any KAGURA_ENABLE_* / tuning variable that is actually set in the environment
# is an override. When there is at least one, -kagura-config is dropped: the
# kagura-config pass assigns to the cl::opt globals at pass-run time and would
# otherwise clobber the override.

OVERRIDES=""
add_override() { OVERRIDES="$OVERRIDES $1"; }

[ "${KAGURA_ENABLE_STR:-}"     = "1" ] && add_override "-kagura-str"
[ "${KAGURA_ENABLE_FLA:-}"     = "1" ] && add_override "-kagura-fla"
[ "${KAGURA_ENABLE_BCF:-}"     = "1" ] && add_override "-kagura-bcf"
[ "${KAGURA_ENABLE_SUB:-}"     = "1" ] && add_override "-kagura-sub"
[ "${KAGURA_ENABLE_CO:-}"      = "1" ] && add_override "-kagura-co"
[ "${KAGURA_ENABLE_OBJC:-}"    = "1" ] && add_override "-kagura-objc"
[ "${KAGURA_ENABLE_ANTIDEB:-}" = "1" ] && add_override "-kagura-anti-debug"
[ "${KAGURA_ENABLE_METRICS:-}" = "1" ] && add_override "-kagura-metrics"

[ -n "${KAGURA_BCF_PROB:-}" ] && add_override "-kagura-bcf-prob=${KAGURA_BCF_PROB}"
[ -n "${KAGURA_BCF_ITER:-}" ] && add_override "-kagura-bcf-iter=${KAGURA_BCF_ITER}"
[ -n "${KAGURA_SUB_ITER:-}" ] && add_override "-kagura-sub-iter=${KAGURA_SUB_ITER}"
[ -n "${KAGURA_SEED:-}" ]     && add_override "-kagura-seed=${KAGURA_SEED}"

# ── Emit ──────────────────────────────────────────────────────────────────────

if [ -n "$CONFIG" ] && [ -z "$OVERRIDES" ]; then
  add_flag "-kagura-config=$CONFIG"
fi

for f in $PROFILE_FLAGS; do
  # An override for the same knob comes later on the command line and wins.
  add_flag "$f"
done

for f in $OVERRIDES; do
  add_flag "$f"
done

if [ -z "$PROFILE_FLAGS" ] && [ -z "$OVERRIDES" ] && [ -z "$CONFIG" ]; then
  echo "# kagura: no profile and no overrides — plugin loaded but no passes enabled" >&2
fi

echo "$FLAGS"
