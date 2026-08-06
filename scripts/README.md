# scripts/

Three groups, split by who runs them. They used to sit in one flat directory,
where a tool you ship to customers looked exactly like a research estimator and
a repo self-check.

## `cli/` — tools you run against your own build

Nothing here reads the kagura source tree; they take a binary, a config, or a
customer list and produce an artefact. These are the parts of kagura an
integrator uses day to day.

| Script | What it does |
|:-------|:-------------|
| `kagura-cli.py` | Generate a JSON policy file; read back an audit log |
| `kagura-diff.py` | Section / symbol / string diff between two builds of the same target |
| `kagura-strip.py` | Post-build hygiene: strip LC_UUID, build IDs and other residual metadata the IR passes cannot reach |
| `variant_generator.py` | Per-customer / per-app config + key material, so one leaked key does not unlock every build |
| `license_manager.py` | Generate, validate and revoke time-limited license tokens |
| `review-risk-assessment.sh` | Scan a binary for patterns that trip App Store / Google Play automated review |

## `eval/` — measurement and research

Estimators and benchmarks. Their output is a number to reason about, not an
artefact to ship, and none of them gates a build.

| Script | What it does |
|:-------|:-------------|
| `attacker_cost_model.py` | Estimated analyst-hours to understand a function under a given pass set |
| `battery_impact.py` | CPU-time overhead of the runtime's periodic work, translated to battery cost |
| `benchmarks/` | Size / speed / integrity benchmark subjects and `run_eval.sh` |

## `ci/` — checks on this repository

Run these before opening a PR; CI runs them too.

| Script | What it does |
|:-------|:-------------|
| `differential-test.sh` | Compiles each `tests/pass-inputs/` subject plain and obfuscated, runs both, asserts identical stdout |
| `verify-reproducible.sh` | Compiles twice with a fixed `-kagura-seed` and asserts byte-identical IR |
| `gen-profiles.py` | Regenerates `integration/profiles/*.json` from `lib/Transforms/Profiles.def`; `--check` fails if they are stale |

`differential-test.sh` and `verify-reproducible.sh` need a built plugin
(`bash build.sh` first) and take the plugin path as `$1` if it is not at
`build/lib/Transforms/`.
