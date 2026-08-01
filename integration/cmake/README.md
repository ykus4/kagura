# kagura — CMake Toolchain Integration

A generic CMake toolchain file that wires the KaguraObfuscator plugin and
runtime library into any CMake project (Cocos2d-x, Godot GDNative, custom
engines, …). It also **chains cleanly** with platform toolchains like the
Android NDK toolchain.

## Files

| File | Purpose |
|:-----|:--------|
| `kagura-toolchain.cmake` | Toolchain file — injects `-fpass-plugin=...` and `-mllvm -kagura-*` into `CMAKE_{C,CXX}_FLAGS_INIT`, and the runtime archive into `CMAKE_*_LINKER_FLAGS_INIT` |
| `KaguraProfile.cmake`    | Shared helper — plugin discovery (`.dylib` / `.so` / `.dll`) and profile-JSON → flag expansion. Also used by the Android and Unity integrations |

---

## Quick start

```bash
cmake \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/kagura/integration/cmake/kagura-toolchain.cmake \
  -DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.dylib \
  -B build -S .
cmake --build build
```

## Chaining with another toolchain (e.g. Android NDK)

```bash
cmake \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/kagura/integration/cmake/kagura-toolchain.cmake \
  -DKAGURA_CHAIN_TOOLCHAIN=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DKAGURA_PLUGIN_PATH=/path/to/KaguraObfuscator.so \
  -B build -S .
```

Set `KAGURA_CHAIN_TOOLCHAIN` to the **inner** toolchain. Kagura's toolchain
includes it first, then layers the obfuscation flags on top.

---

## Variables

### Required

| Variable | Description |
|:---------|:------------|
| `KAGURA_PLUGIN_PATH` | Path to `KaguraObfuscator.dylib` / `.so` / `.dll`. Auto-discovered if unset; may also be given as an environment variable |

### Optional

| Variable | Default | Description |
|:---------|:--------|:------------|
| `KAGURA_RUNTIME_LIB`     | auto-detect | Path to `libkagura_runtime.a` |
| `KAGURA_CHAIN_TOOLCHAIN` | —           | Another toolchain file to include first |
| `KAGURA_PROFILE`         | `BALANCED`  | `FAST` / `BALANCED` / `STRONG` / `OFF`, or an absolute path to your own JSON policy file |
| `KAGURA_EXTRA_PASSES`    | —           | Extra `-kagura-*` flags appended after the profile, e.g. `"-kagura-objc;-kagura-vm"` |
| `KAGURA_SEED`            | profile     | PRNG seed override |
| `KAGURA_BCF_PROB`        | profile     | Bogus CF probability override |

---

## Profiles

The pass set for each profile is **not** defined in this toolchain file. It is
read at configure time from the shared policy files in
[`integration/profiles`](https://github.com/ykus4/kagura/tree/main/integration/profiles):

| Profile | Definition |
|:--------|:-----------|
| `FAST`     | `integration/profiles/fast.json` |
| `BALANCED` | `integration/profiles/balanced.json` *(default)* |
| `STRONG`   | `integration/profiles/strong.json` |
| `OFF`      | No obfuscation (toolchain still chains correctly) |
| *path*     | Any absolute path to your own JSON policy file |

With no overrides the toolchain emits **both** `-mllvm -kagura-config=<json>`
and the flag list expanded from that same JSON, so the build is configured
identically whether or not the `kagura-config` pass takes effect.

When `KAGURA_EXTRA_PASSES`, `KAGURA_SEED` or `KAGURA_BCF_PROB` is set, the
toolchain emits the expanded flags plus your overrides and **omits**
`-kagura-config`: the `kagura-config` pass assigns to the `cl::opt` globals
when it runs and would otherwise clobber the overrides.

See [Configuration](https://ykus4.github.io/kagura/configuration/) for the full
JSON policy DSL.

---

## Behaviour notes

- The toolchain emits `[kagura] Toolchain: profile=...`, `Plugin: ...`,
  `Runtime: ...` at configure time so you can verify the wiring.
- If `KAGURA_PLUGIN_PATH` is unset (as both a CMake variable and an
  environment variable), the toolchain tries
  `<kagura>/build/lib/Transforms/KaguraObfuscator.{dylib,so,dll}` before
  warning and disabling obfuscation. All three extensions are probed, because
  a cross build (Android NDK hosted on macOS) loads the *host* plugin.
- Flags go into the `_INIT` variants of `CMAKE_*_FLAGS`, so they take effect
  before `project()` and propagate to sub-projects via cache.
- Setting `KAGURA_PROFILE=OFF` makes the toolchain a no-op (still chains the
  inner toolchain). Use this for debug builds.
