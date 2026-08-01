# Architecture

```
kagura/
├── include/kagura/         Public headers (Passes.h, Options.h, Utils.h, game_protect.h)
├── lib/Transforms/
│   ├── CFG/                Control-flow obfuscation passes
│   ├── Data/               String / constant / global / wide-string / memory-value encryption
│   ├── AntiAnalysis/       Anti-debug, integrity, call indirection, honey values
│   ├── Platform/           iOS (ObjC), Android (JNI), VM virtualization
│   ├── Infrastructure/     DWARF control, config DSL, symbol map
│   ├── Options.cpp         Centralized CLI flag definitions
│   ├── Plugin.cpp          Pass registration & pipeline wiring
│   └── Utils.cpp           Shared IR helpers & PRNG
├── runtime/
│   ├── core/               AES, VM interpreter, crash symbolication, device key
│   ├── anti_debug/         Anti-debug / anti-Frida (cross-platform POSIX)
│   ├── android/            Android + Linux: root detection, attestation, /proc, syscall
│   ├── ios/                iOS / macOS: jailbreak detection, Mach-O integrity
│   ├── windows/            Windows: IsDebuggerPresent, NtQueryInformationProcess, PE integrity
│   └── game/               Anti-cheat, IL2CPP protection, telemetry
├── integration/            Xcode, Gradle, Unity, Unreal, CMake, Bazel, CocoaPods, SPM
├── scripts/                CLI tools, verification, differential testing, review risk assessment
└── tests/                  CTest + FileCheck lit-based regression tests
```

## Plugin entry point

`lib/Transforms/Plugin.cpp` registers all passes with the LLVM **New Pass
Manager** via `PassPluginLibraryInfo`. It does two things:

1. Exposes every pass by name so it can be requested from `opt`
   (`-passes="kagura-str,..."`) or from clang via `-mllvm -kagura-<name>`.
2. Auto-wires the [recommended order](pass-order.md) onto the
   `OptimizerLast` extension point so users only need
   `-fpass-plugin=KaguraObfuscator.dylib` to get a sensible default pipeline.

## Configuration & options

Per-pass enable flags are generated from `PassRegistry.def`, so they cannot
drift from the pass list; `Options.cpp` defines the tuning parameters and the
infrastructure flags by hand. Adding a tunable means adding a `cl::opt<...>`
there, then reading it from the pass.

The [`kagura-config`](configuration.md) loader is **not** a pass. It is called
from `Plugin.cpp` before the pipeline is constructed, because the `opt::`
values are read at construction time to decide which passes to add — a loader
running as a pipeline pass could never affect that decision.
