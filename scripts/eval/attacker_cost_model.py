#!/usr/bin/env python3
"""
attacker_cost_model.py — Kagura attacker cost modeling tool.

4.8.3: Estimates the manual reverse-engineering effort (in analyst-hours)
required to understand a function protected by a given kagura pass combination.

Model:
    base_cost = f(function_size, cyclomatic_complexity)
    For each active pass, multiply by the pass's cost_multiplier.

    total_cost = base_cost * prod(multiplier for each active pass)

Cost multipliers (empirical estimates from red-team exercises and published
obfuscation literature):

    FLA  (control flow flattening):   ×10-30   (CFG becomes unreadable)
    BCF  (bogus control flow):        ×3-5     (false branches to analyze)
    SUB  (instruction substitution):  ×2-4     (obfuscated arithmetic)
    VM   (virtualization):            ×50-500  (custom ISA to reverse)
    STR  (string encryption):         ×1.5-3   (no plaintext strings)
    CO   (constant obfuscation/MBA):  ×2-4     (algebra to unravel)
    IBR  (indirect branching):        ×3-8     (target dispatch analysis)
    MVO  (memory value obfuscation):  ×2-5     (XOR noise on values)
    BBR  (basic block reordering):    ×1.2-2   (layout disorientation)
    BBS  (basic block splitting):     ×1.5-3   (inflated node count)
    DCI  (dead code insertion):       ×2-4     (false paths to prune)

Usage:
    python3 attacker_cost_model.py --binary /tmp/fib_obf --passes fla,bcf,sub
    python3 attacker_cost_model.py --profile STRONG

Output:
    {
      "binary": "/tmp/fib_obf",
      "active_passes": ["fla", "bcf", "sub"],
      "estimated_bb_count": 42,
      "base_cost_hours": 1.2,
      "total_cost_hours": 432.0,
      "cost_multiplier": 360.0,
      "confidence": "medium",
      "verdict": "HIGH_COST"
    }
"""

import argparse
import json
import os
import subprocess
import sys
from typing import List, Optional

# ---- Pass cost multipliers (geometric mean of range) ----------------------

PASS_MULTIPLIERS = {
    "fla":  17.3,   # FLA: ×10-30
    "bcf":   3.9,   # BCF: ×3-5
    "sub":   2.8,   # SUB: ×2-4
    "vm":  158.1,   # VM:  ×50-500
    "str":   2.1,   # STR: ×1.5-3
    "co":    2.8,   # CO:  ×2-4
    "ibr":   4.9,   # IBR: ×3-8
    "mvo":   3.2,   # MVO: ×2-5
    "bbr":   1.5,   # BBR: ×1.2-2
    "bbs":   2.1,   # BBS: ×1.5-3
    "dci":   2.8,   # DCI: ×2-4
    "pe":    2.5,   # PE:  pointer encryption
    "bbcheck": 1.8, # BBCheck: integrity guard overhead
}

PROFILES = {
    "FAST":     ["str", "sub"],
    "BALANCED": ["str", "sub", "bcf", "ibr", "bbr"],
    "STRONG":   ["str", "sub", "bcf", "fla", "ibr", "bbr", "bbs", "dci", "co"],
}

# ---- Binary analysis -------------------------------------------------------

def count_basic_blocks(binary: str) -> Optional[int]:
    """Estimate basic block count using objdump call count heuristic."""
    try:
        out = subprocess.check_output(
            ["objdump", "-d", binary], stderr=subprocess.DEVNULL,
            text=True, timeout=10
        )
        # Count lines that look like branch instructions (rough heuristic)
        branches = sum(1 for line in out.splitlines()
                       if any(op in line for op in
                              ["\tret", "\tjmp", "\tjne", "\tje ", "\tjle",
                               "\tb\t", "\tbl\t", "\tret\t"]))
        return max(branches, 1)
    except Exception:
        return None


# ---- Model -----------------------------------------------------------------

def estimate_cost(passes: List[str], bb_count: int, complexity: int) -> dict:
    # Base cost: 5 minutes per basic block, scaled by cyclomatic complexity
    base_hours = (bb_count * 5.0 / 60.0) * max(1, complexity / 10.0)

    multiplier = 1.0
    for p in passes:
        m = PASS_MULTIPLIERS.get(p.lower(), 1.0)
        multiplier *= m

    total_hours = base_hours * multiplier

    if total_hours > 500:
        verdict = "VERY_HIGH_COST"
    elif total_hours > 100:
        verdict = "HIGH_COST"
    elif total_hours > 20:
        verdict = "MEDIUM_COST"
    else:
        verdict = "LOW_COST"

    confidence = "high" if len(passes) >= 2 else "low"

    return {
        "active_passes": passes,
        "estimated_bb_count": bb_count,
        "base_cost_hours": round(base_hours, 2),
        "cost_multiplier": round(multiplier, 1),
        "total_cost_hours": round(total_hours, 1),
        "confidence": confidence,
        "verdict": verdict,
    }


# ---- CLI -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="kagura attacker cost model — estimate analyst effort"
    )
    parser.add_argument("--binary", help="Binary to analyze (optional)")
    parser.add_argument("--passes", default=None, help="Comma-separated pass list (e.g. fla,bcf,sub); empty string = no passes")
    parser.add_argument("--profile", choices=list(PROFILES.keys()),
                        help="Use a predefined protection profile")
    parser.add_argument("--bb-count", type=int, default=0,
                        help="Override basic block count")
    parser.add_argument("--complexity", type=int, default=10,
                        help="Estimated cyclomatic complexity")
    args = parser.parse_args()

    if args.profile:
        passes = PROFILES[args.profile]
    elif args.passes is not None:
        # Accept explicit empty string for "no passes" (plain baseline)
        passes = [p.strip() for p in args.passes.split(",") if p.strip()]
    else:
        passes = PROFILES["BALANCED"]

    bb_count = args.bb_count
    if not bb_count and args.binary:
        bb_count = count_basic_blocks(args.binary) or 20
    elif not bb_count:
        bb_count = 20  # default estimate

    result = estimate_cost(passes, bb_count, args.complexity)
    if args.binary:
        result["binary"] = args.binary
    if args.profile:
        result["profile"] = args.profile

    print(json.dumps(result, indent=2))

    # Exit 1 if cost is low (protection insufficient)
    if result["verdict"] == "LOW_COST":
        sys.exit(1)


if __name__ == "__main__":
    main()
