## Summary

<!-- One or two sentences on what changed and why. -->

## Type of change

- [ ] New pass / new runtime check
- [ ] Bug fix
- [ ] Performance improvement
- [ ] Build / CI / tooling
- [ ] Documentation only
- [ ] Refactor (no behaviour change)

## Test plan

- [ ] `ctest --output-on-failure` passes locally
- [ ] FileCheck lit test added (for new passes / IR transformations)
- [ ] `./scripts/ci/differential-test.sh` shows no regression
- [ ] `mkdocs build --strict` passes (for docs-touching changes)

## Risk

<!-- What could break? Performance regressions, ABI changes, platform-specific
     fallout, dependencies bumped, anything that warrants extra reviewer attention. -->

## Checklist for new passes

See [Adding a Pass](../CONTRIBUTING.md#adding-a-pass) — the flag, the pipeline
entry, the JSON policy key and the link smoke test are all generated from one
registry row, so there is nothing to hand-register.

- [ ] One row in `include/kagura/PassRegistry.def`
- [ ] Declaration in `include/kagura/Passes/<Category>.h`, source in the matching `lib/Transforms/<Category>/`
- [ ] `tests/pass-inputs/` smoke input added
- [ ] `tests/lit/<your-pass>.ll` FileCheck test added
- [ ] `docs/passes/<category>.md` entry added
- [ ] Updates the [pass-order](https://ykus4.github.io/kagura/pass-order/) doc if order-sensitive
- [ ] If it belongs in a strength profile: rows in `lib/Transforms/Profiles.def` + `scripts/ci/gen-profiles.py`
