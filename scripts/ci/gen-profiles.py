#!/usr/bin/env python3
"""Generate integration/profiles/*.json from lib/Transforms/Profiles.def.

The profile -> pass-set mapping has one definition, Profiles.def, which
ConfigLoader.cpp compiles into the plugin. The JSON files under
integration/profiles/ are what the CMake, Xcode, Gradle, Unity and Unreal
integrations point -kagura-config at, so they have to say the same thing.
They did not: the JSON enabled sv / anti_debug / tamper and the compiled
preset did not, which made `{"profile": "BALANCED"}` and the shipped
balanced.json produce materially different binaries.

Usage:
    gen-profiles.py            # write the JSON files
    gen-profiles.py --check    # exit 1 if they are out of date (CI)
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "include" / "kagura" / "PassRegistry.def"
PROFILES = REPO / "lib" / "Transforms" / "Profiles.def"
OUT_DIR = REPO / "integration" / "profiles"

MARKER = "generated from lib/Transforms/Profiles.def by scripts/ci/gen-profiles.py"

# KAGURA_MOD_PASS(STR, "kagura-str", "...", StringEncryptionPass())
# KAGURA_TUNING(BCFProb, "kagura-bcf-prob", uint32_t, 30, "...")
ROW_FLAG_CLI = re.compile(
    r'^KAGURA_(?:FN_PASS|MOD_PASS|TUNING)\(\s*(\w+)\s*,\s*"(kagura-[a-z0-9-]+)"'
)

# KAGURA_PROFILE_PASS(BALANCED, STR, true)
PROFILE_ROW = re.compile(
    r"^KAGURA_PROFILE_(PASS|TUNING)\(\s*(\w+)\s*,\s*(\w+)\s*,\s*([A-Za-z0-9_]+)\s*\)"
)


def json_key_for(cli: str) -> str:
    """"kagura-str-aes" -> "str_aes". Mirrors jsonKeyFor() in ConfigLoader.cpp."""
    return cli[len("kagura-"):].replace("-", "_")


def read_flag_keys() -> dict[str, str]:
    """Map the kagura::opt symbol of every registry row to its JSON policy key."""
    keys: dict[str, str] = {}
    for line in REGISTRY.read_text().splitlines():
        m = ROW_FLAG_CLI.match(line)
        if m:
            keys[m.group(1)] = json_key_for(m.group(2))
    if not keys:
        sys.exit(f"error: no rows parsed out of {REGISTRY}")
    return keys


def read_profiles(flag_keys: dict[str, str]) -> dict[str, dict]:
    """Parse Profiles.def into {PROFILE: {"passes": {...}, "tuning": {...}}}.

    Insertion order is preserved so the generated JSON reads in the same order
    as the table, which keeps the diff of a table edit legible.
    """
    profiles: dict[str, dict] = {}
    for line in PROFILES.read_text().splitlines():
        m = PROFILE_ROW.match(line)
        if not m:
            continue
        kind, profile, flag, raw = m.groups()
        if flag not in flag_keys:
            sys.exit(
                f"error: {PROFILES.name} references {flag}, which has no row in "
                f"{REGISTRY.name}"
            )
        entry = profiles.setdefault(profile, {"passes": {}, "tuning": {}})
        if kind == "PASS":
            if raw not in ("true", "false"):
                sys.exit(f"error: pass row for {profile}/{flag} is not a bool: {raw}")
            entry["passes"][flag_keys[flag]] = raw == "true"
        else:
            entry["tuning"][flag_keys[flag]] = int(raw)
    if not profiles:
        sys.exit(f"error: no profile rows parsed out of {PROFILES}")
    return profiles


def render(profile: str, entry: dict) -> str:
    """Render one profile, enabled passes first and a blank line before the rest.

    The disabled entries are not noise: a reader has to be able to tell "this
    profile leaves fla off on purpose" from "nobody thought about fla".
    """
    enabled = {k: v for k, v in entry["passes"].items() if v}
    disabled = {k: v for k, v in entry["passes"].items() if not v}

    def body(d: dict, indent: str) -> list[str]:
        items = list(d.items())
        return [
            f"{indent}{json.dumps(k)}: {json.dumps(v)}"
            + ("," if i < len(items) - 1 else "")
            for i, (k, v) in enumerate(items)
        ]

    lines = [
        "{",
        f'  "_generated": "DO NOT EDIT — {MARKER}",',
        f'  "profile": {json.dumps(profile)},',
        '  "passes": {',
    ]
    pass_lines = body(enabled, "    ")
    if disabled:
        if pass_lines:
            pass_lines[-1] += ","
            pass_lines.append("")
        pass_lines += body(disabled, "    ")
    lines += pass_lines
    lines += ["  },", '  "tuning": {']
    lines += body(entry["tuning"], "    ")
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if any file is out of date",
    )
    args = ap.parse_args()

    flag_keys = read_flag_keys()
    profiles = read_profiles(flag_keys)

    stale = []
    for profile, entry in profiles.items():
        path = OUT_DIR / f"{profile.lower()}.json"
        want = render(profile, entry)

        # Reject a table that produces invalid JSON before it reaches a build.
        json.loads(want)

        have = path.read_text() if path.exists() else ""
        if have == want:
            continue
        if args.check:
            stale.append((path, have, want))
        else:
            path.write_text(want)
            print(f"wrote {path.relative_to(REPO)}")

    if stale:
        for path, have, want in stale:
            rel = path.relative_to(REPO)
            print(f"error: {rel} is out of date", file=sys.stderr)
            sys.stderr.writelines(
                difflib.unified_diff(
                    have.splitlines(keepends=True),
                    want.splitlines(keepends=True),
                    fromfile=f"{rel} (on disk)",
                    tofile=f"{rel} (from Profiles.def)",
                )
            )
        print(
            "\nRun scripts/ci/gen-profiles.py to regenerate.",
            file=sys.stderr,
        )
        return 1

    if args.check:
        print(f"{len(profiles)} profiles up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
