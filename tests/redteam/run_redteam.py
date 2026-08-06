#!/usr/bin/env python3
"""
run_redteam.py — Red-team evaluation orchestrator.

4.8.8: Runs all kagura resistance evaluations against a binary and produces
a unified report.

Usage:
    python3 run_redteam.py --binary /tmp/fib_obf \
        [--passes fla,bcf,sub] [--report report.json]
"""

import argparse
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))

def run_script(script: str, args: list) -> dict:
    cmd = [sys.executable, script] + args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      text=True, timeout=120)
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        try:
            return json.loads(e.output)
        except Exception:
            return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def score_verdict(verdict: str) -> int:
    return {
        "RESISTANT": 100,
        "PARTIAL": 50,
        "VULNERABLE": 0,
        "HIGH_COST": 85,
        "VERY_HIGH_COST": 100,
        "MEDIUM_COST": 50,
        "LOW_COST": 10,
        "UNKNOWN": 0,
    }.get(verdict, 0)


def main():
    parser = argparse.ArgumentParser(description="kagura red-team evaluator")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--passes", default="fla,bcf,sub",
                        help="Comma-separated kagura pass list for cost model")
    parser.add_argument("--report", default=None,
                        help="Output JSON report path")
    parser.add_argument("--angr-timeout", type=int, default=30)
    args = parser.parse_args()

    evaluations = {}

    # 1. angr symbolic execution
    print("[1/3] Running angr symbolic execution evaluation...")
    angr_script = os.path.join(ROOT_DIR, "tests/symbolic_exec/run_angr_eval.py")
    if os.path.exists(angr_script):
        ev = run_script(angr_script, [
            "--binary", args.binary,
            "--timeout", str(args.angr_timeout),
        ])
        evaluations["angr"] = ev
        print(f"  angr verdict: {ev.get('verdict', 'ERROR')}")

    # 2. Attacker cost model
    print("[2/3] Running attacker cost model...")
    cost_script = os.path.join(ROOT_DIR, "scripts/eval/attacker_cost_model.py")
    if os.path.exists(cost_script):
        ev = run_script(cost_script, [
            "--binary", args.binary,
            "--passes", args.passes,
        ])
        evaluations["cost_model"] = ev
        print(f"  cost model verdict: {ev.get('verdict', 'ERROR')} "
              f"({ev.get('total_cost_hours', '?')}h)")

    # 3. Frida resistance (static check: count exported symbols)
    print("[3/3] Checking export surface (proxy for Frida resistance)...")
    try:
        out = subprocess.check_output(
            ["nm", "-gU", args.binary], stderr=subprocess.DEVNULL, text=True
        )
        export_count = len([l for l in out.splitlines() if " T " in l])
        frida_verdict = "RESISTANT" if export_count < 10 else (
            "PARTIAL" if export_count < 50 else "VULNERABLE"
        )
        evaluations["symbol_surface"] = {
            "exported_symbols": export_count,
            "verdict": frida_verdict,
        }
        print(f"  symbol surface: {export_count} exports → {frida_verdict}")
    except Exception as e:
        evaluations["symbol_surface"] = {"error": str(e)}

    # Aggregate score
    verdicts = [v.get("verdict", "UNKNOWN") for v in evaluations.values()]
    scores   = [score_verdict(v) for v in verdicts]
    overall_score = int(sum(scores) / max(len(scores), 1))

    if overall_score >= 80:
        overall_verdict = "RESISTANT"
    elif overall_score >= 50:
        overall_verdict = "PARTIAL"
    else:
        overall_verdict = "VULNERABLE"

    report = {
        "binary": args.binary,
        "evaluations": evaluations,
        "overall_verdict": overall_verdict,
        "score": overall_score,
    }

    print(f"\nOverall verdict: {overall_verdict} (score={overall_score}/100)")

    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to: {args.report}")
    else:
        print(json.dumps(report, indent=2))

    if overall_verdict == "VULNERABLE":
        sys.exit(1)


if __name__ == "__main__":
    main()
