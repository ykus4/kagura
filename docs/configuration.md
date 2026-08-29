# Configuration

Kagura accepts a JSON policy file via `-kagura-config=<path>` to select a
profile, switch individual passes on and off, set the numeric tuning
parameters and scope everything to a set of symbols. This is the recommended
way to drive obfuscation in real projects.

It does not cover *every* `-kagura-*` flag: the build-system switches
(`-kagura-lto-safe`, `-kagura-o0-protect`, `-kagura-build-id`), the reporting
switches (`-kagura-metrics`, `-kagura-symmap`, `-kagura-symmap-out`,
`-kagura-audit`), `-kagura-autoselect` and `-kagura-vtp` have no policy-file
key and must be passed on the command line. See
[Tuning Parameters](tuning.md#what-is-settable-from-a-policy-file). Writing one
of them into `"passes"` or `"tuning"` now produces a warning that names the
flag to use instead.

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

### Key spelling

A pass key is its `-kagura-` flag name with the prefix removed. Both spellings
are accepted, so `"str-aes"` and `"str_aes"` mean the same thing; the
underscore form is canonical and is what the generated files in
`integration/profiles/` use.

Anything the loader does not recognise is reported:

```
[kagura] warning: unknown key "str_ase" in the "passes" object of the policy
file — it is ignored, so this setting has no effect; did you mean "str_aes"?
```

Pass `-kagura-config-strict` to turn that warning into a build failure. Do
this in CI: an ignored key is a silent downgrade of the binary you ship, and
the failure mode is invisible in the output.

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

The symbol filter lists are the one deliberate exception: `"allowlist"`,
`"denylist"` and `"protect"` **merge** with an explicit `-kagura-allow` /
`-kagura-deny` / `-kagura-protect` rather than losing to it. Every entry in one
of those lists is a symbol somebody singled out on purpose, so dropping either
source would silently obfuscate something that was meant to be left alone. The
result is the union: `-kagura-deny=vendor_*` plus `"denylist": ["test_*"]`
excludes both. (Until recently the JSON simply overwrote the flag.)

Per-function
[`__attribute__((annotate("kagura_*")))`](getting-started/quick-start.md#5-per-function-control)
overrides still win on a function-by-function basis.

## Strength profiles

Built-in profiles selected by the `"profile"` key:

| Profile | Passes enabled | Tuning | Intended use |
|:--------|:---------------|:-------|:-------------|
| `FAST`     | `str` `sv` `anti_debug` | — | Debug / CI builds with minimal overhead |
| `BALANCED` | `str` `wstr` `bcf` `bbr` `bbs` `dci` `genc` `mvo` `sv` `anti_debug` `tamper` | `bcf_prob` 20, `bcf_iter` 1 | Standard release builds |
| `STRONG`   | `str` `str_aes` `wstr` `fla` `bcf` `sub` `co` `ibr` `lt` `bbr` `bbs` `dci` `genc` `mvo` `sv` `honey` `anti_debug` `tamper` | `bcf_prob` 50, `bcf_iter` 2, `sub_iter` 2 | Security-critical shipping builds |

Every profile enables `anti_debug`, so **a profile build must link
`kagura_runtime`.**

`STRONG` is not "every pass". It deliberately leaves off the passes that change
the ABI, need a specific target, or carry an outsized cost: `ci`, `pac`, `vm`,
`fsplit`, `pe`, `elt`, `bbcheck`, `telemetry`, `cse_break` and `string_split`,
plus the two platform-gated passes `objc` and `jni` (the Apple and Android
integrations add those). Enable them explicitly in the `passes` object when you
want them.

`vtp` is not in that list because it is not a `passes` key at all —
`-kagura-vtp` is a command-line-only flag.

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
    "str_aes":  true,
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
      -mllvm -kagura-config-strict \
      -mllvm -kagura-build-id=$(git rev-parse HEAD) \
      -O2 -c bank_core.c -o bank_core.o
```

`bbcheck` only inserts the call sites; it needs a `kagura_bb_check` you supply.
See [Anti-Analysis Passes](passes/anti-analysis.md).

## Root keys

| Key | Type | Meaning |
|:----|:-----|:--------|
| `profile` | string | `FAST` / `BALANCED` / `STRONG` / `CUSTOM`. `CUSTOM` means "I am listing the passes myself" and applies no preset. |
| `passes` | object | Per-pass enables. Keys are `-kagura-` flag names without the prefix. `"dwarf"` additionally takes `"keep"` / `"strip"` / `"obfuscate"`. |
| `tuning` | object | The five numeric parameters: `seed`, `bcf_prob`, `bcf_iter`, `sub_iter`, `dci_prob`. |
| `allowlist` | array of string | Same as `-kagura-allow`: when non-empty, only matching symbols are obfuscated. |
| `denylist` | array of string | Same as `-kagura-deny`: matching symbols are left alone. |
| `protect` | array of string | Same as `-kagura-protect`: force-protect matching symbols. Checked first, so it wins over `denylist`, `allowlist`, `kagura_hotpath` and per-function `kagura_no*` annotations alike. |
| `audit_out` | string | Same as `-kagura-audit-out`: where the audit log is written. Only has an effect together with `-kagura-audit`; the default is `kagura_audit.json`. |
| `flavors` | object | Per-flavor override blocks, keyed by `$KAGURA_FLAVOR`. |

All three list keys are matched against the symbol name and accept one trailing
`*` as a prefix glob (`vendor_*`). No other wildcard syntax is supported.

### Flavors

Set `KAGURA_FLAVOR` in the environment and the matching block of `"flavors"` is
applied on top of the base config, so one file can cover several build
variants:

```json title="kagura.json"
{
  "profile": "BALANCED",
  "denylist": ["test_*"],
  "flavors": {
    "staging":    { "profile": "FAST" },
    "production": { "profile": "STRONG", "passes": { "vm": true } }
  }
}
```

```bash
KAGURA_FLAVOR=production clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json -O2 -c app.c -o app.o
```

A flavor block accepts `profile`, `passes`, `tuning`, `allowlist`, `denylist`
and `protect` — the same keys as the root, minus `flavors` and `audit_out`.

## See also

- [Tuning Parameters](tuning.md) — every CLI flag, including symbol filters
  and the `-kagura-build-id` per-build key seed.
- [Pass Order](pass-order.md) — the deterministic order in which the plugin
  applies these passes.
- [Game Protection](game-protection.md) — `Protected<T>` for run-time value
  protection (complementary to `mvo` / `pe`).
