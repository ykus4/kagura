# kagura — Shared obfuscation profiles

> **These files are generated. Do not edit them.**
> The FAST / BALANCED / STRONG profile → pass-set mapping is defined once, in
> [`lib/Transforms/Profiles.def`](../../lib/Transforms/Profiles.def). Change it
> there and run `scripts/ci/gen-profiles.py`; CI fails if these files are stale.

| File | Profile |
|:-----|:--------|
| `fast.json`     | `FAST` — string encryption + symbol visibility + anti-debug. Debug / CI builds. |
| `balanced.json` | `BALANCED` — the default for release builds. |
| `strong.json`   | `STRONG` — security-critical shipping builds. |

Every profile enables `anti_debug`, so **the target must link
`kagura_runtime`** whichever profile it uses. `BALANCED` and `STRONG` also
enable `tamper`.

These are ordinary [kagura JSON policy files](../../docs/configuration.md);
they are consumed by the `kagura-config` infrastructure pass:

```bash
clang -fpass-plugin=/path/to/KaguraObfuscator.dylib \
      -mllvm -kagura-config=/path/to/kagura/integration/profiles/balanced.json \
      -O2 -c foo.c -o foo.o
```

## Why the files repeat the profile name *and* the pass list

`"profile": "<NAME>"` selects the preset compiled into the plugin from
`Profiles.def`. The explicit `"passes"` and `"tuning"` blocks re-state the same
table so the file is self-documenting, and so the CMake, Xcode and Unity
integrations can expand a profile into bare `-kagura-*` flags without loading
the plugin — see [`../cmake/KaguraProfile.cmake`](../cmake/KaguraProfile.cmake).

Both halves come from the same generator, so they cannot disagree. They used to:
the `"passes"` blocks enabled `sv`, `anti_debug` and `tamper` and the compiled
preset did not, which meant a hand-written `{"profile": "BALANCED"}` produced a
weaker binary than the `balanced.json` that claimed to be the same profile.

Keys listed after the blank line are the passes the profile deliberately leaves
**off** — recorded explicitly so "off on purpose" is distinguishable from
"nobody considered it".

## Deliberate omissions

| Pass | Why it is not in any profile |
|:-----|:-----------------------------|
| `vm`     | Function virtualization; 10–100× slowdown on the virtualized function. Opt in per target. |
| `pe`     | Pointer encryption; ABI-sensitive. Opt in per target. |
| `fsplit` | Function splitting interacts badly with LTO/ThinLTO. Opt in per target. |
| `objc`   | Apple-only; added by the Xcode / CocoaPods / SwiftPM integrations. |
| `jni`    | Android-only; added by the Android / Unity / Unreal integrations. |
| `ci` `pac` `elt` `bbcheck` `telemetry` `string_split` `cse_break` | Need a specific target, change the ABI, or cost more than a general-purpose profile should spend. |

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

`-kagura-config` is read while the pipeline is being *built*, not by a pass
inside it, so the policy file does decide which passes run. (It used to be a
pass, which ran after the pipeline was already fixed — `-kagura-config` was
silently a no-op for the `-fpass-plugin` entry point.)

The remaining caveat is the `-mllvm` one: on LLVM 17–21 clang parses `-mllvm`
options before `-fpass-plugin` has loaded the plugin, so
`-mllvm -kagura-config=…` is rejected outright. Use `kagura-opt` or
`opt --load-pass-plugin=…`. The integrations still emit their explicit
`-mllvm -kagura-*` flags alongside `-kagura-config` as a fallback; both come
from the same generated file, so they describe the same configuration.
