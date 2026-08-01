# kagura — Swift Package Manager Integration

A Swift Package that exposes the Kagura **runtime library** as a Swift / C
target. Use it from Swift or mixed Swift + ObjC projects without CocoaPods or
manual xcconfig wiring.

## Files

| File | Purpose |
|:-----|:--------|
| `Package.swift` | Declares the `KaguraRuntime` product (iOS 13+, macOS 11+, tvOS 13+, watchOS 7+) |
| `include/KaguraRuntime.h` | Public umbrella header for the target — the only header exported to Swift |

---

## ⚠️ The manifest has to live at the repository root

SwiftPM rejects any target whose `path` escapes the package root, so a
`Package.swift` sitting in `integration/swiftpm/` cannot reach `../../runtime`:

```
error: 'swiftpm': target 'KaguraRuntime' in package 'swiftpm' is outside the package root
```

`.package(url: …)` also only ever looks for `Package.swift` at the root of the
checked-out repository. The manifest is therefore written with paths relative
to the repository root and must be symlinked (or copied) there:

```bash
cd /path/to/kagura
ln -s integration/swiftpm/Package.swift Package.swift
swift build
```

---

## Usage

Add the package to your own `Package.swift`:

```swift
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/ykus4/kagura.git", from: "0.2.1"),
    ],
    targets: [
        .target(
            name: "MyApp",
            dependencies: [
                .product(name: "KaguraRuntime", package: "kagura"),
            ]
        ),
    ]
)
```

Or from Xcode → **File → Add Package Dependencies…** and paste the repo URL.

---

## What this gives you

Only the **runtime** library is shipped via SPM (anti-debug, jailbreak
detection, AES, VM interpreter, anti-cheat helpers). The compiler plugin
(`KaguraObfuscator.dylib`) is **not** distributed via SPM — SPM does not have
first-class support for clang pass plugins of this type.

To enable obfuscation, load the plugin through Xcode build settings and point
it at one of the [shared profiles](https://github.com/ykus4/kagura/tree/main/integration/profiles):

```
OTHER_CFLAGS      = $(inherited) -fpass-plugin=$(KAGURA_PLUGIN_PATH) \
                    -mllvm -kagura-config=$(KAGURA_DIR)/integration/profiles/balanced.json
OTHER_SWIFT_FLAGS = $(inherited) -Xcc -fpass-plugin=$(KAGURA_PLUGIN_PATH) \
                    -Xcc -mllvm -Xcc -kagura-config=$(KAGURA_DIR)/integration/profiles/balanced.json
```

See [Xcode Integration](https://ykus4.github.io/kagura/integration/xcode/) for
the full xcconfig and build-phase setup.

---

## Platforms

| Platform | Minimum |
|:---------|:--------|
| iOS      | 13.0    |
| macOS    | 11.0    |
| tvOS     | 13.0    |
| watchOS  | 7.0     |

## Source layout

`Package.swift` selects sources by **directory**, not by file name:

```
runtime/core        AES, zeroing, device key, blob integrity, VM interpreter
runtime/anti_debug  ptrace / Frida / breakpoint / hook detection
runtime/ios         jailbreak detection, Mach-O integrity, ObjC / Swift helpers
runtime/game        anti-cheat helpers (IL2CPP, UE4, protected values)
```

Adding a `.c` file to any of those directories picks it up automatically —
no manifest edit required.

`runtime/android/` and `runtime/windows/` are **not** compiled into the Apple
target. They are real platform implementations (Bionic/Linux syscalls, Win32
APIs), not no-op stubs, and must not be linked into an iOS/macOS binary.

## Public headers

`publicHeadersPath` points at `integration/swiftpm/include`, **not** at the
repository's `include/`. `include/kagura/{Options,Passes,Utils,VM}.h` are LLVM
C++ plugin headers and `include/kagura/game_protect.h` is a C++ template
header; exporting any of them from a C target produces a Clang module that
Swift consumers cannot compile.

C++ users who want `kagura::Protected<T>` should add the repository's
`include/` to their own header search path and include
`"kagura/game_protect.h"` directly.
