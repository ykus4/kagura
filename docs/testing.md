# Testing & Evaluation

## Unit / regression tests

```bash
cd build && ctest --output-on-failure
```

Lit-based FileCheck tests live under `tests/`. See
`tests/regression/README.md` and `tests/pass-inputs/README.md` for the test
matrix.

## Reproducible build verification

Verify that a fixed seed produces byte-identical IR across two builds:

```bash
./scripts/ci/verify-reproducible.sh
# [kagura-repro] PASS: Both builds produced identical IR.
```

## Differential testing

Verify that obfuscated binaries produce the same output as plain binaries:

```bash
./scripts/ci/differential-test.sh
# [diff-test] arithmetic_test ... PASS
# [diff-test] combined_test   ... PASS
# Results: 8 passed, 0 failed, 0 skipped
```

## App Store / Google Play review risk assessment

Scan a compiled binary for patterns that may trigger store-review rejection
(non-PIE, plaintext API keys, debug symbols leaking selectors, …):

```bash
./scripts/cli/review-risk-assessment.sh path/to/MyApp.dylib --platform ios
# [HIGH    ] [SEC-PIE] ...
# [INFO    ] [ENC-DECL] No obvious encryption keyword references found.
# RESULT: No critical or high review risks detected.
```

## Security evaluation harnesses

```bash
# Symbolic execution resistance (angr)
cd tests/symbolic_exec && python3 run_angr_eval.py \
    --binary /tmp/my_binary --timeout 30

# Decompiler resistance (Ghidra)
cd tests/decompiler_eval && python3 run_ghidra_eval.py \
    --binary /tmp/my_binary --ghidra /path/to/ghidra

# Frida instrumentation resistance (probes F1-F8)
cd tests/frida_resistance && for s in probes/F*.js; do
    frida -l "$s" -f /tmp/my_binary
done

# Full red-team report
cd tests/redteam && python3 run_redteam.py \
    --binary /tmp/my_binary --report report.json
```

Each subdirectory has its own README — see
[`tests/symbolic_exec/README.md`](https://github.com/ykus4/kagura/tree/main/tests/symbolic_exec),
[`tests/decompiler_eval/README.md`](https://github.com/ykus4/kagura/tree/main/tests/decompiler_eval),
[`tests/frida_resistance/README.md`](https://github.com/ykus4/kagura/tree/main/tests/frida_resistance),
[`tests/redteam/README.md`](https://github.com/ykus4/kagura/tree/main/tests/redteam).

## Additional analysis tools

| Script | Purpose |
|:-------|:--------|
| `scripts/cli/kagura-cli.py` | Config generator, audit log viewer, symbol map analyzer |
| `scripts/cli/kagura-diff.py` | Section / symbol / string diff between baseline and obfuscated binary (text or HTML report) |
| `scripts/cli/kagura-strip.py` | Post-build hygiene — zero out `LC_UUID` (Mach-O) / `.note.gnu.build-id` (ELF) so binaries don't leak rebuild fingerprints |
| `scripts/cli/variant_generator.py` | Per-customer / per-app variant generation with custom keys |
| `scripts/eval/attacker_cost_model.py` | Estimate attacker reverse-engineering cost (analyst-hours) |
| `scripts/eval/battery_impact.py` | Model battery / CPU impact of runtime passes |
| `scripts/cli/license_manager.py` | Generate, validate, and revoke time-limited license tokens |

### `kagura-diff` — what passes actually changed

Compare a baseline binary to an obfuscated one and show section growth,
symbol counts, and string-count delta. Useful for validating that a release
build really did strip plaintext API keys, hide non-public symbols, etc.

```bash
scripts/cli/kagura-diff.py baseline.dylib obfuscated.dylib
scripts/cli/kagura-diff.py baseline.dylib obfuscated.dylib --html report.html
```

### `kagura-strip` — scrub residual build metadata

The IR-level passes can't reach metadata the linker writes after them
(`LC_UUID`, `.note.gnu.build-id`, embedded build paths). Run `kagura-strip`
after `strip` to remove those:

```bash
# macOS / iOS
strip MyApp.dylib                       # remove debug symbols first
scripts/cli/kagura-strip.py MyApp.dylib     # zero out LC_UUID

# Linux / Android
llvm-strip MyApp.so
scripts/cli/kagura-strip.py MyApp.so        # remove .note.gnu.build-id + .comment
```
