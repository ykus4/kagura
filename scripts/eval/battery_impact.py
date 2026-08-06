#!/usr/bin/env python3
"""
battery_impact.py — Kagura battery impact estimator.

4.7.8: Estimates the CPU-time overhead added by kagura runtime operations
(string decryption, anti-debug polling, checksum evaluation) and translates
that to an approximate battery-drain percentage for a typical mobile workload.

Model
-----
  runtime_overhead_ms = sum(op_cost_ms * calls_per_second * measurement_seconds)

  The battery model uses a simple linear relationship:
    cpu_percent  = runtime_overhead_ms / (measurement_seconds * 1000) * 100
    battery_pct  ≈ cpu_percent * drain_rate_per_cpu_pct

  Default drain_rate_per_cpu_pct = 0.01  (1 % battery per 1 % CPU per hour)
  based on published Android/iOS power profiles.

Usage
-----
  # Measure a real binary (runs it and samples /proc/pid/stat or `powermetrics`)
  python3 battery_impact.py --binary /tmp/kagura_subject [--duration 10]

  # Estimate from pass list only (no binary needed)
  python3 battery_impact.py --passes fla,str,bcf [--calls-per-sec 100]

  # Output
  {
    "binary":              "/tmp/kagura_subject",
    "active_passes":       ["fla", "str", "bcf"],
    "measurement_seconds": 10,
    "cpu_overhead_pct":    0.42,
    "battery_drain_pct_per_hour": 0.0042,
    "verdict":             "NEGLIGIBLE",
    "details":             {...}
  }

Verdicts
--------
  NEGLIGIBLE  cpu_overhead < 1 %
  LOW         cpu_overhead 1-5 %
  MEDIUM      cpu_overhead 5-15 %
  HIGH        cpu_overhead > 15 %
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from typing import Dict, List, Optional

# ---- Per-pass runtime overhead model (CPU-ms per 1000 calls) ---------------
#
# Empirical estimates from microbenchmarks on Cortex-A78 and Apple M1:
#
#   str / str-aes:  AES-128-CTR decrypt ~200 bytes → ~0.05 ms per call
#   co:             MBA expression eval → ~0.01 ms per call
#   bbcheck:        FNV-1a over ~20 opcodes → ~0.002 ms per call
#   anti-debug:     ptrace() probe → ~0.1 ms per call (syscall)
#   pac:            pacia/autia (ARM hardware) → ~0.001 ms per call
#   pe:             XOR + branch → ~0.001 ms per call
#   fla, bcf, sub:  compile-time transforms, zero runtime overhead
#   mvo, ibr, bbr:  compile-time transforms, zero runtime overhead

PASS_RUNTIME_MS_PER_1K_CALLS: Dict[str, float] = {
    "str":      50.0,   # AES decryption
    "str-aes":  50.0,
    "wstr":     55.0,
    "co":       10.0,   # MBA evaluation
    "bbcheck":   2.0,   # checksum guard
    "anti-debug": 100.0,  # syscall probe
    "pac":       1.0,   # hardware PAC
    "pe":        1.0,   # pointer XOR
    "telemetry": 20.0,  # event logging
    # Transform-only passes (no runtime cost):
    "fla":  0.0,
    "bcf":  0.0,
    "sub":  0.0,
    "ibr":  0.0,
    "bbr":  0.0,
    "bbs":  0.0,
    "dci":  0.0,
    "mvo":  0.0,
    "vm":   5.0,   # VM dispatch overhead per interpreted block
    "genc": 5.0,   # global decrypt at startup (amortized)
    "elt":  1.0,   # table lookup + XOR
    "ci":   2.0,   # indirect call dispatch
}

# Battery drain rate: approx % battery per % CPU per hour (mid-range device)
DRAIN_RATE_PER_CPU_PCT = 0.01


# ---- Binary measurement (Linux: /proc, macOS: top sampling) ----------------

def _measure_linux(binary: str, duration: int) -> Optional[float]:
    """Return average CPU % over `duration` seconds by sampling /proc."""
    try:
        proc = subprocess.Popen(
            [binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        pid = proc.pid
        samples = []
        t_end = time.monotonic() + duration
        prev_cpu = None
        prev_wall = None
        while time.monotonic() < t_end:
            stat_path = f"/proc/{pid}/stat"
            if not os.path.exists(stat_path):
                break
            with open(stat_path) as f:
                fields = f.read().split()
            utime = int(fields[13])
            stime = int(fields[14])
            total_cpu = utime + stime
            wall = time.monotonic()
            if prev_cpu is not None:
                delta_cpu = (total_cpu - prev_cpu) / 100.0   # seconds
                delta_wall = wall - prev_wall
                samples.append(delta_cpu / delta_wall * 100.0)
            prev_cpu = total_cpu
            prev_wall = wall
            time.sleep(0.5)
        proc.terminate()
        proc.wait(timeout=5)
        return sum(samples) / len(samples) if samples else None
    except Exception:
        return None


def _measure_macos(binary: str, duration: int) -> Optional[float]:
    """Sample CPU usage via `top -l N -pid PID` on macOS."""
    try:
        proc = subprocess.Popen(
            [binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        pid = proc.pid
        # top -l <samples> -s 1 -pid <pid> -stats cpu
        top_out = subprocess.check_output(
            ["top", "-l", str(duration), "-s", "1",
             "-pid", str(pid), "-stats", "cpu"],
            timeout=duration + 5, text=True, stderr=subprocess.DEVNULL
        )
        cpu_vals = []
        for line in top_out.splitlines():
            parts = line.strip().split()
            if parts and parts[0].isdigit():
                try:
                    cpu_vals.append(float(parts[-1].rstrip("%")))
                except ValueError:
                    pass
        proc.terminate()
        proc.wait(timeout=5)
        return sum(cpu_vals) / len(cpu_vals) if cpu_vals else None
    except Exception:
        return None


def measure_cpu_overhead(binary: str, duration: int) -> Optional[float]:
    if platform.system() == "Linux":
        return _measure_linux(binary, duration)
    elif platform.system() == "Darwin":
        return _measure_macos(binary, duration)
    return None


# ---- Model-based estimate ---------------------------------------------------

def estimate_from_passes(
    passes: List[str],
    calls_per_sec: int = 100,
    duration_s: int = 10,
) -> dict:
    details: Dict[str, float] = {}
    total_overhead_ms = 0.0
    for p in passes:
        cost_ms_per_1k = PASS_RUNTIME_MS_PER_1K_CALLS.get(p.lower(), 0.0)
        if cost_ms_per_1k == 0.0:
            continue
        overhead_ms = cost_ms_per_1k * (calls_per_sec / 1000.0) * duration_s
        details[p] = round(overhead_ms, 3)
        total_overhead_ms += overhead_ms

    cpu_pct = total_overhead_ms / (duration_s * 1000.0) * 100.0
    battery_pct_per_h = cpu_pct * DRAIN_RATE_PER_CPU_PCT

    if cpu_pct < 1.0:
        verdict = "NEGLIGIBLE"
    elif cpu_pct < 5.0:
        verdict = "LOW"
    elif cpu_pct < 15.0:
        verdict = "MEDIUM"
    else:
        verdict = "HIGH"

    return {
        "active_passes": passes,
        "calls_per_sec": calls_per_sec,
        "measurement_seconds": duration_s,
        "total_overhead_ms": round(total_overhead_ms, 2),
        "cpu_overhead_pct": round(cpu_pct, 4),
        "battery_drain_pct_per_hour": round(battery_pct_per_h, 6),
        "verdict": verdict,
        "details_ms_per_pass": details,
    }


# ---- CLI -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="kagura battery impact estimator"
    )
    parser.add_argument("--binary", help="Binary to measure (optional)")
    parser.add_argument("--passes",
                        help="Comma-separated pass list (e.g. str,bbcheck)")
    parser.add_argument("--calls-per-sec", type=int, default=100,
                        help="Estimated runtime invocations per second")
    parser.add_argument("--duration", type=int, default=10,
                        help="Measurement / estimation window in seconds")
    args = parser.parse_args()

    passes = ([p.strip() for p in args.passes.split(",") if p.strip()]
              if args.passes else list(PASS_RUNTIME_MS_PER_1K_CALLS.keys()))

    result = estimate_from_passes(passes, args.calls_per_sec, args.duration)

    if args.binary:
        result["binary"] = args.binary
        measured = measure_cpu_overhead(args.binary, args.duration)
        if measured is not None:
            result["measured_cpu_pct"] = round(measured, 4)
            result["battery_drain_pct_per_hour_measured"] = round(
                measured * DRAIN_RATE_PER_CPU_PCT, 6
            )

    print(json.dumps(result, indent=2))

    if result["verdict"] == "HIGH":
        sys.exit(1)


if __name__ == "__main__":
    main()
