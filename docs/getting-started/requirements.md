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
  `kagura-opt` instead, which links them in. See the *Windows (Clang-CL)* tab
  of [Build from Source](build-from-source.md) for the workflow.

- **WebAssembly** — five passes bail out on a Wasm triple, because Wasm requires
  structured control flow, has no native debugger surface, no ptrace, no
  loadable image list, and no way to take the address of code:
  `kagura-fla`, `kagura-anti-debug`, `kagura-pac`, `kagura-tamper` and
  `kagura-vm`. `-kagura-autoselect` also stops proposing `fla` there. Everything
  else — the string, constant, global and data passes — works normally.

- **iOS / Android** — see [Integration](../integration/index.md) for build-system
  wiring (Xcode, Gradle / NDK).
