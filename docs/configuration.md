# Configuration

Kagura accepts a JSON policy file via `-kagura-config=<path>` to control every
pass setting in one place. This is the recommended way to drive obfuscation in
real projects.

## JSON DSL

```json
{
  "profile": "BALANCED",
  "passes": {
    "str":   true,
    "fla":   true,
    "bcf":   true,
    "honey": true,
    "mvo":   false
  },
  "tuning": {
    "bcf_prob": 40,
    "seed":     12345
  }
}
```

The policy file is read **before the pass pipeline is constructed**, not by a
pass within it. That distinction matters: pass selection is decided while the
pipeline is being built, so a loader running as a pipeline pass would always
arrive too late to influence it — which is exactly why `-kagura-config` was a
no-op prior to the current release.

Precedence, highest first:

1. An explicit `-kagura-*` command-line flag. `-kagura-config=p.json
   -kagura-str=false` disables string encryption even if `p.json` asks for it.
2. A `flavors` block matching `$KAGURA_FLAVOR`.
3. The `passes` / `tuning` objects.
4. The `profile` preset.
5. The built-in default (every pass off).

Per-function
[`__attribute__((annotate("kagura_*")))`](getting-started/quick-start.md#5-per-function-control)
overrides still win on a function-by-function basis.

## Strength profiles

Built-in profiles selected by the `"profile"` key:

| Profile | Passes enabled | Tuning | Intended use |
|:--------|:---------------|:-------|:-------------|
| `FAST`     | `str` `sv` `anti-debug` | — | Debug / CI builds with minimal overhead |
| `BALANCED` | `str` `wstr` `bcf` `bbr` `bbs` `dci` `genc` `mvo` `sv` `anti-debug` `tamper` | `bcf_prob` 20, `bcf_iter` 1 | Standard release builds |
| `STRONG`   | `str` `str-aes` `wstr` `fla` `bcf` `sub` `co` `ibr` `lt` `bbr` `bbs` `dci` `genc` `mvo` `sv` `honey` `anti-debug` `tamper` | `bcf_prob` 50, `bcf_iter` 2, `sub_iter` 2 | Security-critical shipping builds |

Every profile enables `anti-debug`, so **a profile build must link
`kagura_runtime`.**

`STRONG` is not "every pass". It deliberately leaves off the passes that change
the ABI, need a specific target, or carry an outsized cost: `ci`, `pac`, `vm`,
`fsplit`, `pe`, `elt`, `vtp`, `bbcheck`, `telemetry`, `cse-break` and
`string-split`. Enable those explicitly in the `passes` object when you want
them.

The ready-made files in
[`integration/profiles/`](https://github.com/ykus4/kagura/tree/main/integration/profiles)
restate exactly these presets — both they and the compiled presets are
generated from `lib/Transforms/Profiles.def`, so a profile name means the same
thing whichever way you select it. (Until recently it did not: the JSON files
enabled `sv`, `anti-debug` and `tamper` that the compiled preset skipped.)

A profile sets defaults; anything in `"passes"` or `"tuning"` overrides the
profile's choices for that specific key.

## Worked example — bank / FinTech release

Strong profile with per-build AES key rotation so a key extracted from one
version is useless against the next:

```json title="kagura-bank.json"
{
  "profile": "STRONG",
  "passes": {
    "str-aes":  true,
    "mvo":      true,
    "pe":       true,
    "bbcheck":  true,
    "tamper":   true
  },
  "tuning": {
    "bcf_prob": 60,
    "seed":     0
  }
}
```

```bash
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura-bank.json \
      -mllvm -kagura-build-id=$(git rev-parse HEAD) \
      -O2 -c bank_core.c -o bank_core.o
```

## See also

- [Tuning Parameters](tuning.md) — every CLI flag, including symbol filters
  and the `-kagura-build-id` per-build key seed.
- [Pass Order](pass-order.md) — the deterministic order in which the plugin
  applies these passes.
- [Game Protection](game-protection.md) — `Protected<T>` for run-time value
  protection (complementary to `mvo` / `pe`).
