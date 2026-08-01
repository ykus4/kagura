// swift-tools-version: 5.9
//
// 4.6.12: Swift Package Manager support for KaguraRuntime.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ IMPORTANT — this manifest must be evaluated from the REPOSITORY ROOT.    │
// │                                                                          │
// │ SwiftPM refuses any target whose `path` escapes the package root         │
// │ ("target 'X' in package 'Y' is outside the package root"), so a          │
// │ Package.swift living in integration/swiftpm/ physically cannot reach     │
// │ ../../runtime. The paths below are therefore written relative to the     │
// │ repository root, which is also what the documented consumer usage        │
// │   .package(url: "https://github.com/ykus4/kagura.git", from: "0.2.1")    │
// │ requires — SwiftPM only ever looks for Package.swift at the root of a    │
// │ checked-out repository.                                                  │
// │                                                                          │
// │ Symlink or copy this file to the repository root before use:             │
// │   ln -s integration/swiftpm/Package.swift Package.swift                  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Usage in a consumer Package.swift:
//   .package(url: "https://github.com/ykus4/kagura.git", from: "0.2.1")
//
// Then add to your target:
//   .target(
//       name: "MyApp",
//       dependencies: [
//           .product(name: "KaguraRuntime", package: "kagura"),
//       ]
//   )
//
// The LLVM pass plugin (KaguraObfuscator.dylib) must still be loaded via the
// Xcode build system (OTHER_SWIFT_FLAGS / OTHER_CFLAGS) since SPM does not
// have first-class support for compiler plugins of this type. See
// integration/xcode/README.md for instructions, and
// integration/profiles/*.json for the shared obfuscation profiles.
//
// Source selection is DIRECTORY-level on purpose: runtime/ is reorganised
// from time to time and naming individual .c files here has broken this
// manifest before. A file added to runtime/core, runtime/anti_debug,
// runtime/ios or runtime/game is picked up automatically.
//
// runtime/android/ and runtime/windows/ are intentionally NOT listed: they
// are platform-specific implementations (Bionic/Linux syscalls, Win32) and
// must never be compiled into an Apple target.

import PackageDescription

let package = Package(
    name: "kagura",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
        .tvOS(.v13),
        .watchOS(.v7),
    ],
    products: [
        .library(
            name: "KaguraRuntime",
            targets: ["KaguraRuntime"]
        ),
    ],
    targets: [
        .target(
            name: "KaguraRuntime",
            path: ".",
            sources: [
                "runtime/core",       // AES, zero_buf, device key, VM interpreter, …
                "runtime/anti_debug", // ptrace/Frida/breakpoint/hook detection
                "runtime/ios",        // jailbreak detection, Mach-O integrity, ObjC
                "runtime/game",       // anti-cheat helpers (IL2CPP, UE4, value guards)
            ],
            // NOT include/ — include/kagura/{Options,Passes,Utils,VM}.h are LLVM
            // C++ plugin headers and game_protect.h is a C++ template header;
            // exposing them as the public headers of a C target produces a
            // Clang module that Swift consumers cannot build.
            publicHeadersPath: "integration/swiftpm/include",
            cSettings: [
                .define("KAGURA_SWIFTPM"),
            ],
            linkerSettings: [
                // dlopen/dladdr (crash symbolication, anti-debug)
                .linkedLibrary("dl", .when(platforms: [.macOS, .linux])),
            ]
        ),
    ],
    cLanguageStandard: .c11
)
