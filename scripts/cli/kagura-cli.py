#!/usr/bin/env python3
"""
kagura-cli.py — Kagura configuration generator and audit log viewer.

Usage:
  kagura-cli.py config-gen [--profile PROFILE] [--passes PASS,...] \
                            [--protect PATTERN,...] [--deny PATTERN,...] \
                            [--allow PATTERN,...] [-o OUTPUT.json]

  kagura-cli.py audit-view [--log AUDIT.json] [--module FILTER] [--sort-passes]

  kagura-cli.py symmap-view [--map SYMBOLS.json] [--filter PATTERN]

Sub-commands
------------
config-gen    Generate a kagura.json policy file (4.6.1 Config DSL).
audit-view    Pretty-print / filter the audit log produced by -kagura-audit.
symmap-view   Pretty-print / filter the symbol map produced by -kagura-symmap.
"""

import argparse
import json
import sys
import os
from datetime import datetime

# ── Profiles ──────────────────────────────────────────────────────────────────

PROFILES = {
    "FAST": {
        "passes": ["str", "sv"],
        "description": "Minimal overhead — string encryption + symbol hiding only.",
    },
    "BALANCED": {
        "passes": ["str", "str-aes", "sv", "fla", "bcf", "bbs", "bbr"],
        "description": "Good protection with acceptable build-time overhead.",
    },
    "STRONG": {
        "passes": [
            "str", "str-aes", "wstr", "sv", "fla", "bcf", "bbs", "bbr",
            "dci", "co", "ibr", "ci", "genc", "mvo", "lt",
        ],
        "description": "Maximum protection — significant build-time increase.",
    },
}

ALL_PASSES = [
    "fla", "bcf", "sub", "str", "str-aes", "wstr", "anti-debug",
    "objc", "jni", "co", "vm", "bbr", "dci", "fsplit", "bbs",
    "sv", "ibr", "lt", "tamper", "ci", "pac", "genc", "mvo", "pe", "honey",
]

# ── Sub-command: config-gen ───────────────────────────────────────────────────

def cmd_config_gen(args):
    cfg = {}

    if args.profile:
        p = args.profile.upper()
        if p not in PROFILES:
            print(f"Unknown profile '{p}'. Choose from: {', '.join(PROFILES)}", file=sys.stderr)
            sys.exit(1)
        cfg["profile"] = p
        cfg["passes"] = {pass_: True for pass_ in PROFILES[p]["passes"]}
    else:
        cfg["profile"] = "CUSTOM"

    if args.passes:
        explicit = [x.strip().lstrip("-") for x in args.passes.split(",")]
        for pass_ in explicit:
            if pass_ not in ALL_PASSES:
                print(f"Warning: unknown pass '{pass_}'", file=sys.stderr)
        if "passes" not in cfg:
            cfg["passes"] = {}
        for pass_ in explicit:
            cfg["passes"][pass_] = True

    if args.protect:
        cfg["protect"] = [p.strip() for p in args.protect.split(",")]
    if args.deny:
        cfg["deny"] = [p.strip() for p in args.deny.split(",")]
    if args.allow:
        cfg["allow"] = [p.strip() for p in args.allow.split(",")]
    if args.build_id:
        cfg["build_id"] = args.build_id
    if args.seed:
        cfg["seed"] = int(args.seed)
    if args.audit:
        cfg["audit"] = True
        if args.audit_out:
            cfg["audit_out"] = args.audit_out
    if args.symmap:
        cfg["symmap"] = True
        if args.symmap_out:
            cfg["symmap_out"] = args.symmap_out
    if args.dwarf:
        cfg["dwarf"] = args.dwarf

    cfg["_generated"] = datetime.utcnow().isoformat() + "Z"

    text = json.dumps(cfg, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text + "\n")
        print(f"Config written to {args.output}")
    else:
        print(text)

# ── Sub-command: audit-view ───────────────────────────────────────────────────

def cmd_audit_view(args):
    log_path = args.log or "kagura_audit.json"
    if not os.path.exists(log_path):
        print(f"Audit log not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    records = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Parse error: {e}", file=sys.stderr)

    if args.module_filter:
        records = [r for r in records if args.module_filter in r.get("module", "")]

    total_funcs = 0
    for rec in records:
        ts = datetime.utcfromtimestamp(rec.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
        module = rec.get("module", "<unknown>")
        build_id = rec.get("build_id", "")
        funcs = rec.get("functions", [])
        total_funcs += len(funcs)
        print(f"\n{'='*60}")
        print(f"Module   : {module}")
        print(f"Time     : {ts} UTC")
        if build_id:
            print(f"Build ID : {build_id}")
        print(f"Functions: {len(funcs)}")

        if args.sort_passes:
            from collections import Counter
            all_passes = [p for fn in funcs for p in fn.get("passes", [])]
            pass_counts = Counter(all_passes)
            print(f"Passes   : {dict(pass_counts.most_common())}")
        else:
            for fn in funcs:
                passes = ", ".join(fn.get("passes", []))
                print(f"  {fn.get('name', '?')} → [{passes}]")

    print(f"\nTotal: {total_funcs} protected function(s) across {len(records)} module(s)")

# ── Sub-command: symmap-view ──────────────────────────────────────────────────

def cmd_symmap_view(args):
    map_path = args.map or "kagura_symbols.json"
    if not os.path.exists(map_path):
        print(f"Symbol map not found: {map_path}", file=sys.stderr)
        sys.exit(1)

    with open(map_path) as f:
        data = json.load(f)

    symbols = data.get("symbols", data) if isinstance(data, dict) else data
    if isinstance(symbols, dict):
        symbols = [{"original": k, "obfuscated": v} for k, v in symbols.items()]

    if args.filter:
        symbols = [s for s in symbols
                   if args.filter in s.get("original", "") or
                      args.filter in s.get("obfuscated", "")]

    print(f"{'Original':<50} {'Obfuscated'}")
    print("-" * 80)
    for s in symbols:
        orig = s.get("original", "?")
        obfs = s.get("obfuscated", "?")
        print(f"{orig:<50} {obfs}")
    print(f"\nTotal: {len(symbols)} symbol(s)")

# ── Argument parsing ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kagura CLI — config generator and report viewer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # config-gen
    cg = sub.add_parser("config-gen", help="Generate kagura.json policy file")
    cg.add_argument("--profile", help="Preset profile: FAST | BALANCED | STRONG")
    cg.add_argument("--passes",  help="Comma-separated list of passes to enable")
    cg.add_argument("--protect", help="Comma-separated force-protect patterns")
    cg.add_argument("--deny",    help="Comma-separated denylist patterns")
    cg.add_argument("--allow",   help="Comma-separated allowlist patterns")
    cg.add_argument("--build-id", dest="build_id", help="Build ID string")
    cg.add_argument("--seed",    help="PRNG seed (integer)")
    cg.add_argument("--audit",   action="store_true", help="Enable audit log")
    cg.add_argument("--audit-out", dest="audit_out", help="Audit log output path")
    cg.add_argument("--symmap",  action="store_true", help="Enable symbol map")
    cg.add_argument("--symmap-out", dest="symmap_out", help="Symbol map output path")
    cg.add_argument("--dwarf",   choices=["keep","strip","obfuscate"], help="DWARF mode")
    cg.add_argument("-o", "--output", help="Output path (default: stdout)")

    # audit-view
    av = sub.add_parser("audit-view", help="View kagura audit log")
    av.add_argument("--log",    help="Audit log path (default: kagura_audit.json)")
    av.add_argument("--module", dest="module_filter", help="Filter by module name")
    av.add_argument("--sort-passes", action="store_true", help="Show pass frequency")

    # symmap-view
    sv = sub.add_parser("symmap-view", help="View kagura symbol map")
    sv.add_argument("--map",    help="Symbol map path (default: kagura_symbols.json)")
    sv.add_argument("--filter", help="Filter by name substring")

    args = parser.parse_args()

    if args.command == "config-gen":
        cmd_config_gen(args)
    elif args.command == "audit-view":
        cmd_audit_view(args)
    elif args.command == "symmap-view":
        cmd_symmap_view(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
