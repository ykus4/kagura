# Red-Team Evaluation Tooling

This directory contains tooling for red-team assessments of kagura-protected
binaries.  Use this to verify that kagura's protections are effective before
shipping.

## Overview

A red-team evaluation consists of:

1. **Static analysis** — can a decompiler recover meaningful code?
2. **Dynamic analysis** — can a debugger/Frida extract secrets at runtime?
3. **Symbolic execution** — can angr/Triton solve obfuscated branches?
4. **Cost modeling** — what's the estimated manual reverse-engineering time?

## Quick start

```bash
# Build test subject with STRONG protection
clang -O2 \
  -fpass-plugin=../../build/lib/Transforms/KaguraObfuscator.dylib \
  -mllvm -kagura-fla -mllvm -kagura-bcf -mllvm -kagura-sub \
  -mllvm -kagura-str -mllvm -kagura-co -mllvm -kagura-ibr \
  -o /tmp/kagura_rt_subject \
  subjects/redteam_subject.c

# Run all evaluations
python3 run_redteam.py --binary /tmp/kagura_rt_subject --report report.json
```

## Tools

| Tool | Description |
|:-----|:------------|
| `run_redteam.py` | Orchestrates all evaluations and produces a unified report |
| `../symbolic_exec/run_angr_eval.py` | angr symbolic execution eval |
| `../decompiler_eval/run_ghidra_eval.py` | Ghidra decompilation quality eval |
| `../frida_resistance/probes/` | Frida instrumentation resistance probes |
| `../../scripts/eval/attacker_cost_model.py` | Attacker effort cost model |

## Report format

```json
{
  "binary": "/tmp/kagura_rt_subject",
  "evaluations": {
    "angr": { "verdict": "RESISTANT", "paths_explored": 200, "timed_out": true },
    "ghidra": { "verdict": "RESISTANT", "comprehensibility_score": 8 },
    "cost_model": { "verdict": "HIGH_COST", "total_cost_hours": 240.0 }
  },
  "overall_verdict": "RESISTANT",
  "score": 95
}
```

## Interpreting results

| Score | Verdict | Recommendation |
|:-----:|:--------|:---------------|
| 80-100 | RESISTANT | Ship with confidence |
| 50-79  | PARTIAL   | Add stronger passes (FLA, VM) |
| < 50   | VULNERABLE | Do not ship; review protection policy |
