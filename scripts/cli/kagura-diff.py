#!/usr/bin/env python3
"""kagura-diff — section / symbol / string diff between two binaries.

Shows what kagura's passes actually changed by comparing two builds of the
same target (typically: baseline vs. obfuscated). Useful for:

  - Verifying that strings were encrypted (string count delta)
  - Confirming symbol-visibility passes hid the expected symbols
  - Measuring section growth attributable to FLA / BCF
  - Audit logs ("the release build has 0 plaintext API_KEY refs")

Usage:
    kagura-diff baseline.dylib obfuscated.dylib [--strings N] [--html report.html]

By default, prints a side-by-side text table. Pass `--html report.html` to
emit a self-contained HTML report.

Dependencies:
    `strings` (POSIX) and either `llvm-nm` / `nm` and `llvm-size` / `size`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Sequence


def _which(*candidates: str) -> str:
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
    raise RuntimeError(f"none of {candidates} found on PATH")


def _run(cmd: Sequence[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)


@dataclass
class BinaryInfo:
    path: str
    size_bytes: int
    sections: dict          # name -> size
    symbols: set            # all defined symbols
    exported_symbols: set   # subset that are dynamically exported
    strings: list           # printable string list


def collect(path: Path, min_string_len: int = 4) -> BinaryInfo:
    nm   = _which("llvm-nm", "nm")
    size = _which("llvm-size", "size")
    strings_tool = _which("strings")

    size_bytes = path.stat().st_size

    # Section sizes — try GNU-style first, then macOS `size -m`
    sections: dict[str, int] = {}
    try:
        raw = _run([size, "-A", str(path)])
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                sections[parts[0]] = int(parts[1])
    except subprocess.CalledProcessError:
        # macOS `size` rejects -A; use `size -m` and parse "Section X: N" lines
        raw = _run([size, "-m", str(path)])
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Section "):
                name, _, rest = line.partition(":")
                try:
                    sections[name.split()[1]] = int(rest.strip().split()[0])
                except (IndexError, ValueError):
                    pass

    # Symbols
    symbols: set[str] = set()
    exported: set[str] = set()
    try:
        for line in _run([nm, "--defined-only", str(path)]).splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[-1]
            type_ = parts[-2] if len(parts) > 1 else "?"
            symbols.add(name)
            # Uppercase type letter == external (exported)
            if type_.isupper():
                exported.add(name)
    except subprocess.CalledProcessError:
        pass

    # Strings
    strings_list = _run([strings_tool, "-n", str(min_string_len), str(path)]).splitlines()

    return BinaryInfo(
        path=str(path), size_bytes=size_bytes,
        sections=sections, symbols=symbols,
        exported_symbols=exported, strings=strings_list,
    )


def text_report(a: BinaryInfo, b: BinaryInfo) -> str:
    def row(label: str, va, vb, delta=None):
        d = f"  ({delta:+.1f}%)" if delta is not None else ""
        return f"  {label:<28} {va:>14}  {vb:>14}{d}"

    def pct(va: int, vb: int) -> float:
        return 0.0 if va == 0 else (vb - va) / va * 100

    out = []
    out.append(f"kagura-diff: {a.path}  vs  {b.path}")
    out.append("=" * 78)
    out.append(row("file size (bytes)", a.size_bytes, b.size_bytes,
                   pct(a.size_bytes, b.size_bytes)))

    out.append("")
    out.append("  Sections:")
    all_sections = sorted(set(a.sections) | set(b.sections))
    for s in all_sections:
        va = a.sections.get(s, 0)
        vb = b.sections.get(s, 0)
        if va == vb == 0:
            continue
        out.append(row(s, va, vb, pct(va, vb) if va else None))

    out.append("")
    out.append(row("total symbols",   len(a.symbols),         len(b.symbols)))
    out.append(row("exported symbols", len(a.exported_symbols), len(b.exported_symbols)))
    out.append(row("strings (>=4 chars)", len(a.strings), len(b.strings),
                   pct(len(a.strings), len(b.strings))))

    only_a = a.symbols - b.symbols
    only_b = b.symbols - a.symbols
    out.append("")
    out.append(f"  symbols only in baseline: {len(only_a)}")
    out.append(f"  symbols only in obfuscated: {len(only_b)}")
    if only_a and len(only_a) <= 20:
        out.append("    (baseline-only): " + ", ".join(sorted(only_a)[:20]))
    if only_b and len(only_b) <= 20:
        out.append("    (obfuscated-only): " + ", ".join(sorted(only_b)[:20]))

    return "\n".join(out)


def html_report(a: BinaryInfo, b: BinaryInfo) -> str:
    template = """<!doctype html><html><head><meta charset='utf-8'>
<title>kagura-diff report</title>
<style>
body{font-family:-apple-system,Segoe UI,sans-serif;max-width:960px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #ddd;padding:.4em .8em;text-align:right}
th:first-child,td:first-child{text-align:left}
th{background:#f4f4f4}
tr.grow{background:#fff5f5}tr.shrink{background:#f0f8f0}
pre{background:#f8f8f8;padding:.5em;overflow:auto;max-height:300px}
h2{border-bottom:1px solid #eee;padding-bottom:.2em;margin-top:2em}
</style></head><body>
<h1>kagura-diff report</h1>
<p><b>baseline:</b> <code>{a_path}</code><br>
<b>obfuscated:</b> <code>{b_path}</code></p>
{body}
</body></html>"""

    def pct(va: int, vb: int) -> float:
        return 0.0 if va == 0 else (vb - va) / va * 100

    body = ["<h2>Overview</h2><table>",
            "<tr><th>Metric</th><th>baseline</th><th>obfuscated</th><th>delta</th></tr>"]
    rows = [
        ("File size (bytes)", a.size_bytes, b.size_bytes),
        ("Total symbols", len(a.symbols), len(b.symbols)),
        ("Exported symbols", len(a.exported_symbols), len(b.exported_symbols)),
        ("Strings (>=4 chars)", len(a.strings), len(b.strings)),
    ]
    for label, va, vb in rows:
        d = pct(va, vb)
        cls = "grow" if d > 1 else ("shrink" if d < -1 else "")
        body.append(f"<tr class='{cls}'><td>{label}</td><td>{va}</td>"
                    f"<td>{vb}</td><td>{d:+.1f}%</td></tr>")
    body.append("</table>")

    body.append("<h2>Sections</h2><table>"
                "<tr><th>Section</th><th>baseline</th><th>obfuscated</th>"
                "<th>delta</th></tr>")
    for s in sorted(set(a.sections) | set(b.sections)):
        va = a.sections.get(s, 0)
        vb = b.sections.get(s, 0)
        if va == vb == 0:
            continue
        d = pct(va, vb) if va else 0
        cls = "grow" if d > 1 else ("shrink" if d < -1 else "")
        body.append(f"<tr class='{cls}'><td>{s}</td><td>{va}</td>"
                    f"<td>{vb}</td><td>{d:+.1f}%</td></tr>")
    body.append("</table>")

    only_a = sorted(a.symbols - b.symbols)
    only_b = sorted(b.symbols - a.symbols)
    body.append(f"<h2>Symbols only in baseline ({len(only_a)})</h2>")
    body.append("<pre>" + "\n".join(only_a[:200]) + "</pre>")
    body.append(f"<h2>Symbols only in obfuscated ({len(only_b)})</h2>")
    body.append("<pre>" + "\n".join(only_b[:200]) + "</pre>")

    return template.format(a_path=a.path, b_path=b.path, body="\n".join(body))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("baseline", type=Path)
    p.add_argument("obfuscated", type=Path)
    p.add_argument("--strings", type=int, default=4,
                   help="Minimum string length (default: 4)")
    p.add_argument("--html", type=Path, help="Write an HTML report to this path")
    p.add_argument("--json", type=Path, help="Write a JSON dump to this path")
    args = p.parse_args()

    for path in (args.baseline, args.obfuscated):
        if not path.exists():
            print(f"error: {path}: not found", file=sys.stderr)
            return 2

    a = collect(args.baseline, args.strings)
    b = collect(args.obfuscated, args.strings)

    print(text_report(a, b))

    if args.html:
        args.html.write_text(html_report(a, b))
        print(f"\n[kagura-diff] HTML report → {args.html}")

    if args.json:
        dump = {
            "baseline":   {**asdict(a), "symbols": sorted(a.symbols),
                           "exported_symbols": sorted(a.exported_symbols)},
            "obfuscated": {**asdict(b), "symbols": sorted(b.symbols),
                           "exported_symbols": sorted(b.exported_symbols)},
        }
        args.json.write_text(json.dumps(dump, indent=2))
        print(f"[kagura-diff] JSON dump  → {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
