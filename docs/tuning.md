# Tuning Parameters

> **LLVM 22 required for `-mllvm` flags.** On LLVM 17–21, clang parses `-mllvm`
> options before `-fpass-plugin` has loaded the plugin, so every `-kagura-*`
> flag is rejected with *"Unknown command line argument"*. Use the shipped
> `kagura-opt`, or `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`, both
> of which work on all supported versions. See
> [Known issues](https://github.com/ykus4/kagura/blob/main/CHANGELOG.md).


All flags below can be set via `-mllvm -kagura-<flag>=<value>` on the clang
command line, or under the `"tuning"` key in a [JSON policy file](configuration.md).

## Core tuning

| Option | Default | Description |
|:-------|:--------|:------------|
| `-kagura-seed=<N>` | `0` (entropy) | PRNG seed for reproducible output |
| `-kagura-bcf-prob=<N>` | `30` | Bogus CF probability per BB [0-100] |
| `-kagura-bcf-iter=<N>` | `1` | Bogus CF iterations |
| `-kagura-sub-iter=<N>` | `1` | Substitution iterations |
| `-kagura-dci-prob=<N>` | `40` | Dead code insertion probability [0-100] |

## Infrastructure

| Option | Default | Description |
|:-------|:--------|:------------|
| `-kagura-lto-safe` | `false` | Enable passes during LTO / ThinLTO pipeline phases |
| `-kagura-o0-protect` | `false` | Enable lightweight protection (STR, AntiDebug) at `-O0` |
| `-kagura-dwarf=<mode>` | `keep` | DWARF handling: `keep` / `strip` / `obfuscate` |
| `-kagura-build-id=<id>` | — | Build identifier mixed into PRNG seed for per-build key rotation |

## Build system

| Option | Default | Description |
|:-------|:--------|:------------|
| `-kagura-config=<path>` | — | Path to JSON policy file |
| `-kagura-symmap` | `false` | Emit symbol map after obfuscation |
| `-kagura-symmap-out=<path>` | `kagura_symbols.json` | Output file for symbol map |
| `-kagura-audit` | `false` | Emit audit log of all protected symbols |
| `-kagura-audit-out=<path>` | `kagura_audit.json` | Output file for audit log |

## Symbol filters

| Option | Default | Description |
|:-------|:--------|:------------|
| `-kagura-protect=<pattern>` | — | Force-protect matching symbols (comma-separated, `*` glob) |
| `-kagura-deny=<pattern>` | — | Exclude matching symbols from all obfuscation |
| `-kagura-allow=<pattern>` | — | Allowlist mode: only obfuscate matching symbols |

## Reproducibility

Setting `-kagura-seed=<N>` to a non-zero value makes the entire pipeline
deterministic. Pair with `scripts/ci/verify-reproducible.sh` to confirm two
builds produce byte-identical IR — see [Testing & Evaluation](testing.md).
