# kagura — Shared obfuscation profiles

Single source of truth for the FAST / BALANCED / STRONG profile → pass-set
mapping used by **every** integration under `integration/`.

| File | Profile |
|:-----|:--------|
| `fast.json`     | `FAST` — string encryption + symbol visibility + anti-debug. Debug / CI builds. |
| `balanced.json` | `BALANCED` — the default for release builds. |
| `strong.json`   | `STRONG` — security-critical shipping builds. |

These are ordinary [kagura JSON policy files](../../docs/configuration.md);
they are consumed by the `kagura-config` infrastructure pass:

```bash
clang -fpass-plugin=/path/to/KaguraObfuscator.dylib \
      -mllvm -kagura-config=/path/to/kagura/integration/profiles/balanced.json \
      -O2 -c foo.c -o foo.o
```

## Why the files repeat the profile name *and* the pass list

`"profile": "<NAME>"` selects the built-in preset compiled into
`lib/Transforms/Infrastructure/ConfigLoader.cpp`. The explicit `"passes"` and
`"tuning"` blocks that follow re-state that preset so the file is
self-documenting, and so the profile definition can be adjusted here without
recompiling the plugin. Keys listed after the blank line are the passes the
profile deliberately leaves **off**.

## Deliberate omissions

| Pass | Why it is not in any profile |
|:-----|:-----------------------------|
| `vm`     | Function virtualization; 10–100× slowdown on the virtualized function. Opt in per target. |
| `pe`     | Pointer encryption; needs the runtime library linked and is ABI-sensitive. Opt in per target. |
| `fsplit` | Function splitting interacts badly with LTO/ThinLTO. Opt in per target. |
| `objc`   | Apple-only; added by the Xcode / CocoaPods / SwiftPM integrations. |
| `jni`    | Android-only; added by the Android / Unity / Unreal integrations. |

## Overriding a profile

Every integration keeps its own per-pass switches. They are applied **after**
`-kagura-config`, so an explicit `-mllvm -kagura-<pass>` on the command line
always wins over the profile. See each integration's README for the variable
names (`KAGURA_ENABLE_*`, `kagura.enable*`, `EditorPrefs`, …).

For build-variant differences prefer a `flavors` block over a second file:

```json
{
  "profile": "STRONG",
  "flavors": {
    "staging":    { "profile": "FAST" },
    "production": { "passes": { "vm": true } }
  }
}
```

…selected at compile time with the `KAGURA_FLAVOR` environment variable.

## Caveat

`-kagura-config` is applied by the `kagura-config` module pass. Confirm with
`-mllvm -kagura-metrics` (or by diffing the output against an explicit-flag
build) that the profile is actually taking effect in the auto-injected
`OptimizerLast` pipeline before relying on it for a shipping build; each
integration therefore still emits its explicit `-mllvm -kagura-*` flags as a
fallback.
