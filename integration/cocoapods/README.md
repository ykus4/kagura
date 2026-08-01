# kagura — CocoaPods Integration

A `podspec` that vendors the Kagura **runtime library** into an iOS / macOS
app via CocoaPods, and adds a build-phase script that loads the obfuscator
plugin.

## Files

| File | Purpose |
|:-----|:--------|
| `kagura.podspec` | Pod spec for `KaguraObfuscator` — compiles `runtime/**/*.c` into your target and registers a `before_compile` script phase |

---

## Usage

In your `Podfile`:

```ruby
target 'MyApp' do
  pod 'KaguraObfuscator',
      :git    => 'https://github.com/ykus4/kagura.git',
      :tag    => 'v0.2.1'
end
```

```bash
pod install
```

CocoaPods will:

1. Vendor the runtime sources into your workspace as a static library target.
2. Install a `before_compile` script phase that injects the plugin into
   `OTHER_CFLAGS` if it finds
   `${PODS_ROOT}/KaguraObfuscator/build/lib/Transforms/KaguraObfuscator.dylib`.
   Note there is **no `lib` prefix** on the artifact — the CMake target is
   built as `KaguraObfuscator.dylib`, which is also the path
   `.github/workflows/release.yml` packages. Override the lookup with
   `KAGURA_PLUGIN_PATH` (absolute path to the plugin) or `KAGURA_ROOT`
   (kagura checkout root) in your build environment.

You still need to **build the plugin** yourself before opening Xcode:

```bash
cd Pods/KaguraObfuscator
cmake -B build -DLLVM_DIR=$(brew --prefix llvm)/lib/cmake/llvm
cmake --build build
```

After that, an ordinary `xcodebuild` (or pressing ⌘B in Xcode) will pick the
plugin up automatically.

---

## What's vendored

The podspec includes everything under `runtime/**/*.{c,h}` **except** the two
non-Apple platform directories, which are excluded so they don't break the
iOS / macOS build:

```
runtime/android/**   Bionic / Linux: JNI hook detection, Play Integrity,
                     SafetyNet, ART, seccomp, /proc, APK / ELF integrity,
                     direct syscalls
runtime/windows/**   Win32: ETW detection, PE integrity, tamper response
```

The exclusions are **directory-level on purpose**. The previous per-file list
named the pre-reorg flat paths (`runtime/jni_hook_detection.c`, …); once
`runtime/` grew subdirectories the excludes stopped matching anything and
every Android and Windows source was compiled into the iOS pod.

Everything else is vendored:

```
runtime/core/**        AES, secure zeroing, device key, blob integrity,
                       crash symbolication, VM interpreter
runtime/anti_debug/**  ptrace / Frida / breakpoint / hook / emulator detection
runtime/ios/**         jailbreak detection, Mach-O integrity, fishhook
                       countermeasures, Swift / ObjC helpers
runtime/game/**        anti-cheat helpers (IL2CPP, UE4, protected values)
```

Only `include/kagura/game_protect.h` is published as a public header. The rest
of `include/kagura/` (`Options.h`, `Passes.h`, `Utils.h`, `VM.h`) are LLVM
pass-plugin headers and are deliberately not part of the pod.

---

## Choosing a profile

The build phase defaults to
`${KAGURA_ROOT}/integration/profiles/balanced.json`, the
[shared profile](../profiles/README.md) used by every kagura integration.
Point `KAGURA_PROFILE_JSON` at `fast.json`, `strong.json` or your own policy
file to change it.

---

## Compiler settings

| Setting | Value |
|:--------|:------|
| `compiler_flags`           | `-std=c11` |
| `GCC_OPTIMIZATION_LEVEL`   | `2` |
| `HEADER_SEARCH_PATHS`      | `$(PODS_TARGET_SRCROOT)/include` |
| Platforms                  | iOS 13+, macOS 11+ |

For richer Xcode-side configuration (per-target xcconfig, per-file selective
obfuscation, code-signing notes), see [Xcode Integration](https://ykus4.github.io/kagura/integration/xcode/).
