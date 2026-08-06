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

- [ ] `cl::opt` flag in `lib/Transforms/Options.cpp` + header
- [ ] Pass registered in `Plugin.cpp` (both named-pass and OptimizerLast EP)
- [ ] `tests/pass-inputs/` smoke input added
- [ ] `tests/lit/<your-pass>.ll` FileCheck test added
- [ ] `docs/passes/<category>.md` entry added
- [ ] Updates the [pass-order](https://ykus4.github.io/kagura/pass-order/) doc if order-sensitive
