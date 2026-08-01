# kagura — Android NDK Integration

This directory contains the Android NDK CMake integration for the kagura LLVM
obfuscator.  It provides helper functions that wire the obfuscation plugin and
its companion runtime library into an Android Studio / Gradle project with
minimal boilerplate.

---

## Files

| File | Purpose |
|---|---|
| `kagura-android-ndk.cmake` | CMake helper — defines `kagura_android_target()`, `kagura_android_config()`, `kagura_android_runtime_target()` |
| `kagura-cmake.cmake` | Lean single-function include for projects that only need `kagura_target()` |
| `kagura.gradle` | Groovy Gradle script that injects flags into `externalNativeBuild` |

---

## Android Studio Integration

### Step 1 — Build the plugin

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# produces build/lib/Transforms/KaguraObfuscator.so
```

### Step 2 — Add to `app/build.gradle`

```groovy
android {
    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments "-DKAGURA_PLUGIN_PATH=${rootDir}/../kagura/build/lib/Transforms/KaguraObfuscator.so",
                          "-DKAGURA_PROFILE=BALANCED"
            }
        }
    }
    externalNativeBuild {
        cmake { path "src/main/cpp/CMakeLists.txt" }
    }
}
```

### Step 3 — Include in `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.22)
project(mygame)

include(${CMAKE_SOURCE_DIR}/../kagura/integration/android/kagura-android-ndk.cmake)

kagura_android_config()

add_library(mynativelib SHARED src/native.cpp)
kagura_android_target(mynativelib)
```

To also compile the kagura runtime (anti-debug, AES decrypt stubs, Android
integrity checks) into your build, add one line before `kagura_android_target`:

```cmake
kagura_android_runtime_target(kagura_runtime)
kagura_android_target(mynativelib)   # auto-links kagura_runtime
```

The runtime target globs `runtime/core/`, `runtime/anti_debug/` and
`runtime/android/` by directory (plus `runtime/game/` when
`KAGURA_ENABLE_IL2CPP=ON`), so files moving inside `runtime/` do not break it.
`runtime/ios/` and `runtime/windows/` are excluded.

---

## CMake Flags Reference

| Variable | Type | Default | Description |
|---|---|---|---|
| `KAGURA_PLUGIN_PATH` | FILEPATH | auto | Absolute path to `KaguraObfuscator.{dylib,so,dll}`. Auto-discovered under `<kagura>/build/lib/Transforms`; may also come from the environment variable of the same name. All three extensions are probed, because the plugin runs in the *host* clang |
| `KAGURA_PROFILE` | STRING | `BALANCED` | `FAST` / `BALANCED` / `STRONG` / `CUSTOM`, or a path to your own JSON policy file |
| `KAGURA_RUNTIME_DIR` | PATH | auto | The kagura `runtime/` directory |
| `KAGURA_ENABLE_JNI` | BOOL | ON | JNI dynamic registration (Android-only; in no shared profile) |
| `KAGURA_ENABLE_IL2CPP` | BOOL | OFF | Also compile `runtime/game/` into `kagura_runtime` |
| `KAGURA_METRICS` | BOOL | OFF | Print obfuscation metrics to stdout |

### Per-pass overrides

These have **no default** on purpose — leaving one undefined means "the
profile decides". Define one on the CMake command line and it is applied after
the profile (later flag wins), and `-kagura-config` is dropped so the
`kagura-config` pass cannot clobber it.

| Variable | Description |
|---|---|
| `KAGURA_ENABLE_STR` | String encryption |
| `KAGURA_ENABLE_FLA` | CFG flattening |
| `KAGURA_ENABLE_BCF` | Bogus control flow |
| `KAGURA_ENABLE_SUB` | Instruction substitution |
| `KAGURA_ENABLE_CO` | Constant obfuscation (MBA) |
| `KAGURA_ENABLE_ANTIDEBUG` | Anti-debug / Anti-Frida |
| `KAGURA_BCF_PROB` | Bogus CF probability 0–100 |
| `KAGURA_BCF_ITER` | Bogus CF iterations |
| `KAGURA_SUB_ITER` | Instruction substitution iterations |
| `KAGURA_SEED` | PRNG seed (0 = system entropy) |

---

## Profile Presets

The pass set for each profile is **not** defined in this integration. It is
read at configure time from the shared policy files in
[`integration/profiles`](../profiles/README.md), which is what keeps the
Android, Xcode, CMake, Unity, Unreal and Bazel integrations from drifting
apart:

| Profile | Definition | Intended use |
|---|---|---|
| `FAST` | `integration/profiles/fast.json` | Hot paths, CI builds, debug variants |
| `BALANCED` | `integration/profiles/balanced.json` | Release builds (default) |
| `STRONG` | `integration/profiles/strong.json` | Security-critical shipping builds |
| `CUSTOM` | none — only `KAGURA_ENABLE_*` | Fine-grained control |
| *path* | your own JSON policy file | See [Configuration](https://ykus4.github.io/kagura/configuration/) |

```cmake
set(KAGURA_PROFILE "${CMAKE_SOURCE_DIR}/kagura.json")
kagura_android_config()
```

```json
{ "profile": "STRONG", "passes": { "vm": true } }
```

---

## Gradle Plugin Usage

For projects that prefer to configure everything from Gradle, apply the
companion script instead of using CMake arguments directly:

```groovy
// app/build.gradle
apply from: "${rootDir}/../kagura/integration/android/kagura.gradle"
```

Override individual settings before the `apply from` line:

```groovy
ext.kagura = [
    root       : "/opt/kagura",          // plugin + profiles are found from here
    profile    : "strong",               // fast | balanced | strong | off | <path.json>
    enableBcf  : true,                   // override just this pass
    bcfProb    : 40,
]
apply from: "${rootDir}/../kagura/integration/android/kagura.gradle"
```

Every `enable*` / tuning key defaults to `null`, meaning "use the profile".
Setting one switches to the explicit-flag path.

Settings can also be placed in `local.properties` (not committed to VCS):

```properties
kagura.root=/Users/me/kagura
kagura.profile=balanced
kagura.pluginPath=/Users/me/kagura/build/lib/Transforms/KaguraObfuscator.so
```

---

## ABI Notes

| ABI | Notes |
|---|---|
| `arm64-v8a` | Fully supported; all passes tested. Recommended primary target. |
| `armeabi-v7a` | Supported. BCF iterations automatically capped at 1 to limit code-size growth on Thumb-2. |
| `x86_64` | Supported (emulator / Chrome OS). BCF adds branch-prediction overhead; keep `KAGURA_BCF_PROB` at or below 20. |
| `x86` | Compiles but BCF is discouraged — 32-bit x86 Android is effectively end-of-life. |

---

## Performance Impact (Rough Estimates)

These figures are measured on a mid-range Arm Cortex-A55 device running
Android 12.  Actual impact depends heavily on code structure.

| Profile | Binary size increase | CPU overhead (hot loop) | Build time increase |
|---|---|---|---|
| FAST | +5 – 10 % | < 2 % | +10 – 20 % |
| BALANCED | +15 – 25 % | 3 – 8 % | +25 – 40 % |
| STRONG | +40 – 70 % | 10 – 20 % | +60 – 100 % |

Startup time is unaffected by the obfuscation passes themselves; any
measurable startup delta comes from the runtime self-check
(`kagura_self_check`) which typically completes in under 5 ms.

String decryption stubs add a one-time per-string decryption cost on first
use.  Subsequent accesses hit the decrypted copy in `.data` without overhead.
