# Requirements

| Requirement | Version |
|:------------|:--------|
| LLVM        | 17 – 22 (tested on 17, 18, 19, 21, 22) |
| CMake       | 3.20+ |
| C++         | C++17 |

## Platform notes

- **Windows** — Clang-CL only, and `-fpass-plugin` is **not** available: the
  MSVC-targeted LLVM ships with `LLVM_ENABLE_PLUGINS=OFF`, so neither
  `clang -fpass-plugin` nor `opt --load-pass-plugin` can load kagura. The passes
  build into a static library (`KaguraObfuscator.lib`) and are run through
  [`kagura-opt`](build-from-source.md#windows-clang-cl) instead, which links
  them in. See [Build from Source](build-from-source.md) for the workflow.

- **WebAssembly** — `kagura-fla` and `kagura-anti-debug` are skipped because Wasm
  requires structured control flow and has no native debugger surface.

- **iOS / Android** — see [Integration](../integration/index.md) for build-system
  wiring (Xcode, Gradle / NDK).
