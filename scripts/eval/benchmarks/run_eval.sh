#!/usr/bin/env bash
# run_eval.sh — Kagura paper evaluation pipeline
#
# Configurations (all verified correct after bug fixes):
#   plain    — no obfuscation
#   balanced — STR + BCF + FLA + SUB + CO
#   strong   — STR + BCF + FLA + SUB + CO + MVO + IBR + BBS + BBR
#
# Evaluations:
#   1. Correctness (7/7 self-test)
#   2. Binary size & instruction count overhead (arm64 native)
#   3. Attacker cost model (analyst-hours estimate)
#   4. Symbolic execution resistance (angr, x86_64 Linux ELF)
#
# Usage: bash run_eval.sh [/path/to/kagura_root]
set -euo pipefail

KAGURA="${1:-$(cd "$(dirname "$0")/../../.." && pwd)}"
BENCH="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$BENCH/../results"
PLUGIN="$KAGURA/build/lib/Transforms/KaguraObfuscator.dylib"
CLANG="/opt/homebrew/opt/llvm/bin/clang"
OBJDUMP="/opt/homebrew/opt/llvm/bin/llvm-objdump"
PYTHON="$KAGURA/.venv/bin/python3"
COST_MODEL="$KAGURA/scripts/eval/attacker_cost_model.py"
ANGR_EVAL="$KAGURA/tests/symbolic_exec/run_angr_eval.py"
FUNC_SRC="$BENCH/eval_functions.c"
MAIN_SRC="$BENCH/eval_main.c"

ZIG_LIBC="/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/libc"
ZIG_I="-nostdinc -isystem $ZIG_LIBC/musl/include -isystem $ZIG_LIBC/include/generic-musl -isystem $ZIG_LIBC/include/x86_64-linux-musl -isystem $ZIG_LIBC/include/any-linux-any"

mkdir -p "$RESULTS"
[ -f "$PLUGIN" ] || { echo "[ERROR] Plugin not found: $PLUGIN"; exit 1; }

echo "========================================================"
echo "  kagura paper evaluation — $(date '+%Y-%m-%d %H:%M')"
echo "========================================================"

# ── Helpers ───────────────────────────────────────────────────────────────

binary_size() {
    local s; s=$(stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 0)
    printf '%s' "${s%%$'\n'*}"
}

instruction_count() {
    local n; n=$("$OBJDUMP" -d "$1" 2>/dev/null | grep -cE '[0-9a-f]{8}:' || true)
    printf '%s' "${n:-0}"
}

# Build arm64: compile func with passes, link with plain main
build_native() {
    local out="$1" obj="${1}.o"; shift
    "$CLANG" -O1 "$@" -c "$FUNC_SRC" -o "$obj"
    "$CLANG" -O1 "$MAIN_SRC" "$obj" -o "$out"
    rm -f "$obj"
}

# Build x86_64 ELF for angr
build_elf() {
    local out="$1" fobj="${1}_f.o" mobj="${1}_m.o"; shift
    # shellcheck disable=SC2086
    "$CLANG" -O1 -target x86_64-linux-musl $ZIG_I \
        "$@" -c "$FUNC_SRC" -o "$fobj"
    "$CLANG" -O1 -target x86_64-linux-musl $ZIG_I \
        -c "$MAIN_SRC" -o "$mobj"
    zig cc -target x86_64-linux-musl "$fobj" "$mobj" -o "$out"
    rm -f "$fobj" "$mobj"
}

# ── Pass configurations ───────────────────────────────────────────────────

# arm64 native: full pass set
BAL_FLAGS=(-fpass-plugin="$PLUGIN"
    -mllvm -kagura-str -mllvm -kagura-bcf
    -mllvm -kagura-fla -mllvm -kagura-sub -mllvm -kagura-co)
STR_FLAGS=(-fpass-plugin="$PLUGIN"
    -mllvm -kagura-str -mllvm -kagura-bcf
    -mllvm -kagura-fla -mllvm -kagura-sub -mllvm -kagura-co
    -mllvm -kagura-mvo -mllvm -kagura-ibr
    -mllvm -kagura-bbs -mllvm -kagura-bbr)

# x86_64 ELF: FLA works with -nostdinc + generic-musl includes.
# MVO excluded: BCF+FLA+MVO triggers intermittent X86MCInstLower crash in LLVM 22
# cross-compilation (upstream LLVM bug; native arm64 is unaffected).
# Balanced: STR+BCF+FLA+SUB+CO  / Strong: +IBR+BBS+BBR (no MVO)
BAL_ELF_FLAGS=(-fpass-plugin="$PLUGIN"
    -mllvm -kagura-str -mllvm -kagura-bcf
    -mllvm -kagura-fla -mllvm -kagura-sub -mllvm -kagura-co)
STR_ELF_FLAGS=(-fpass-plugin="$PLUGIN"
    -mllvm -kagura-str -mllvm -kagura-bcf
    -mllvm -kagura-fla -mllvm -kagura-sub -mllvm -kagura-co
    -mllvm -kagura-ibr
    -mllvm -kagura-bbs -mllvm -kagura-bbr)

# ── Build ─────────────────────────────────────────────────────────────────

echo ""
echo "[1/4] Building binaries..."

# plain — no obfuscation flags
"$CLANG" -O1 -c "$FUNC_SRC" -o "$RESULTS/game_plain_f.o"
"$CLANG" -O1 "$MAIN_SRC" "$RESULTS/game_plain_f.o" -o "$RESULTS/game_plain"
rm -f "$RESULTS/game_plain_f.o"

# shellcheck disable=SC2086
"$CLANG" -O1 -target x86_64-linux-musl $ZIG_I -c "$FUNC_SRC" -o "$RESULTS/game_plain_ef.o"
"$CLANG" -O1 -target x86_64-linux-musl $ZIG_I -c "$MAIN_SRC"  -o "$RESULTS/game_plain_em.o"
zig cc -target x86_64-linux-musl "$RESULTS/game_plain_ef.o" "$RESULTS/game_plain_em.o" -o "$RESULTS/game_plain_elf"
rm -f "$RESULTS/game_plain_ef.o" "$RESULTS/game_plain_em.o"
echo "  plain        OK"

build_native "$RESULTS/game_balanced"     "${BAL_FLAGS[@]}"
build_elf    "$RESULTS/game_balanced_elf" "${BAL_ELF_FLAGS[@]}"
echo "  balanced     OK  (native: STR+BCF+FLA+SUB+CO / elf: same)"

build_native "$RESULTS/game_strong"       "${STR_FLAGS[@]}"
build_elf    "$RESULTS/game_strong_elf"   "${STR_ELF_FLAGS[@]}"
echo "  strong       OK  (native: STR+BCF+FLA+SUB+CO+MVO+IBR+BBS+BBR / elf: no-MVO)"

# ── Correctness ───────────────────────────────────────────────────────────

echo ""
echo "[2/4] Correctness (native arm64)..."
ALL_OK=true
for cfg in plain balanced strong; do
    result=$("$RESULTS/game_${cfg}" 2>&1)
    ok=$("$RESULTS/game_${cfg}" >/dev/null 2>&1 && echo "PASS" || echo "FAIL")
    echo "  $cfg: $result [$ok]"
    [ "$ok" = "PASS" ] || ALL_OK=false
done
$ALL_OK || { echo "[WARN] Some correctness tests failed — metrics may be unreliable"; }

# ── Overhead metrics ──────────────────────────────────────────────────────

echo ""
echo "[3/4] Collecting metrics..."

PS=$(binary_size "$RESULTS/game_plain")
BS=$(binary_size "$RESULTS/game_balanced")
SS=$(binary_size "$RESULTS/game_strong")
PI=$(instruction_count "$RESULTS/game_plain")
BI=$(instruction_count "$RESULTS/game_balanced")
SI=$(instruction_count "$RESULTS/game_strong")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  OVERHEAD (arm64 native)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  %-12s %10s %14s %8s\n" Config BinBytes Instructions SizeOH
printf "  %-12s %10s %14s %8s\n" ------- -------- ------------ ------
printf "  %-12s %10d %14d %8s\n" plain "$PS" "$PI" "1.00x"
python3 -c "
p,b,s,pi,bi,si = $PS,$BS,$SS,$PI,$BI,$SI
print(f'  {\"balanced\":<12} {b:>10} {bi:>14} {b/p:>7.2f}x')
print(f'  {\"strong\":<12}  {s:>10} {si:>14} {s/p:>7.2f}x')
"
echo ""

# ── Attacker cost model ───────────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ATTACKER COST MODEL (representative function: bb=8, complexity=10)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "  [plain — no passes]"
"$PYTHON" "$COST_MODEL" --passes "" --bb-count 8 --complexity 10 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'    base: {d[\"base_cost_hours\"]}h  total: {d[\"total_cost_hours\"]}h  multiplier: {d[\"cost_multiplier\"]}x  verdict: {d[\"verdict\"]}')"

echo "  [balanced — str,bcf,fla,sub,co]"
"$PYTHON" "$COST_MODEL" --passes str,bcf,fla,sub,co --bb-count 8 --complexity 10 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'    total: {d[\"total_cost_hours\"]}h  multiplier: {d[\"cost_multiplier\"]}x  verdict: {d[\"verdict\"]}')"

echo "  [strong — str,bcf,fla,sub,co,mvo,ibr,bbs,bbr]"
"$PYTHON" "$COST_MODEL" --passes str,bcf,fla,sub,co,mvo,ibr,bbs,bbr --bb-count 8 --complexity 10 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'    total: {d[\"total_cost_hours\"]}h  multiplier: {d[\"cost_multiplier\"]}x  verdict: {d[\"verdict\"]}')"
echo ""

# ── Angr symbolic execution ───────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SYMBOLIC EXECUTION (angr, x86_64 ELF, timeout=30s)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for cfg in plain balanced strong; do
    echo "  [$cfg — eval_verify_score]"
    "$PYTHON" "$ANGR_EVAL" \
        --binary "$RESULTS/game_${cfg}_elf" \
        --timeout 30 --entry eval_verify_score 2>/dev/null | \
    python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'error' in d and not d.get('instr_count'):
    print(f'    error: {d[\"error\"]}')
else:
    to = d.get('timed_out', False)
    print(f'    instr={d.get(\"instr_count\",0)}  branches={d.get(\"branch_count\",0)}  paths={d.get(\"paths_explored\",0)}  time={d.get(\"time_elapsed\",0):.1f}s  verdict={d.get(\"verdict\",\"?\")}')
" || echo "    [failed]"
done
echo ""

# ── Save JSON ─────────────────────────────────────────────────────────────

echo "[4/4] Saving results/eval_summary.json ..."
"$PYTHON" - "$RESULTS" "$COST_MODEL" "$ANGR_EVAL" \
    "$PS" "$BS" "$SS" "$PI" "$BI" "$SI" <<'PYEOF'
import json, subprocess, sys
results_dir, cost_bin, angr_bin = sys.argv[1], sys.argv[2], sys.argv[3]
ps,bs,ss,pi,bi,si = [int(x) for x in sys.argv[4:10]]
PYTHON = sys.executable

def cost(passes, bb=8, cx=10):
    args = [PYTHON, cost_bin, "--bb-count", str(bb), "--complexity", str(cx)]
    if passes: args += ["--passes", passes]
    try: return json.loads(subprocess.check_output(args, stderr=subprocess.DEVNULL))
    except: return {}

def angr(cfg):
    args = [PYTHON, angr_bin, "--binary", f"{results_dir}/game_{cfg}_elf",
            "--timeout","30","--entry","eval_verify_score"]
    try: return json.loads(subprocess.check_output(args, stderr=subprocess.DEVNULL))
    except Exception as e: return {"error": str(e)}

out = {
    "plain":    {"size":ps,"instructions":pi,"size_oh":1.0,"instr_oh":1.0,
                 "passes":[],"cost":cost(""),"angr":angr("plain")},
    "balanced": {"size":bs,"instructions":bi,"size_oh":round(bs/max(ps,1),2),
                 "instr_oh":round(bi/max(pi,1),2),
                 "passes":["str","bcf","fla","sub","co"],
                 "cost":cost("str,bcf,fla,sub,co"),"angr":angr("balanced")},
    "strong":   {"size":ss,"instructions":si,"size_oh":round(ss/max(ps,1),2),
                 "instr_oh":round(si/max(pi,1),2),
                 "passes":["str","bcf","fla","sub","co","mvo","ibr","bbs","bbr"],
                 "cost":cost("str,bcf,fla,sub,co,mvo,ibr,bbs,bbr"),"angr":angr("strong")},
}
path = f"{results_dir}/eval_summary.json"
with open(path,"w") as f: json.dump(out,f,indent=2)
print(f"  Saved: {path}")
PYEOF

echo ""
echo "========================================================"
echo "  DONE"
echo "========================================================"
