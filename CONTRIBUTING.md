# Contributing to Kagura

## Getting Started

```bash
git clone https://github.com/ykus4/kagura.git
cd kagura
bash build.sh
cd build && ctest --output-on-failure
```

`build.sh` works on macOS and Linux. It auto-detects LLVM via `llvm-config`,
`brew --prefix llvm` and the usual `/usr/lib/llvm-<N>` locations; override with
`LLVM_PREFIX=/path/to/llvm bash build.sh`. Extra arguments are forwarded to
CMake:

```bash
bash build.sh build-debug -DCMAKE_BUILD_TYPE=Debug
```

## Adding a Pass

`lib/Transforms/PassRegistry.def` is the single source of truth for the pass
list. One row there generates the `cl::opt` enable flag (`Options.cpp`), the
named-pass parsing callback and the `OptimizerLast` auto-pipeline entry
(`Plugin.cpp`). Do **not** hand-register a pass in `Options.cpp` or
`Plugin.cpp` — those files are X-macro expansions of the `.def`.

1. Add the pass declaration to `include/kagura/Passes.h`
2. Implement in `lib/Transforms/<Subsystem>/YourPass.cpp`
3. Register the source in `lib/Transforms/CMakeLists.txt` (an explicit list, not a glob)
4. Add **one row** to `lib/Transforms/PassRegistry.def`:
   - `KAGURA_FN_PASS(Flag, "kagura-x", "Description", YourPass())` for a
     function pass, or `KAGURA_MOD_PASS(...)` for a module pass. `Flag` is the
     `kagura::opt::` symbol name; the row's position sets its position in the
     auto-injected pipeline.
   - `KAGURA_INFRA_PASS("kagura-x", YourPass())` only for infrastructure
     passes that are *not* driven by a plain bool flag — those still need a
     hand-written injection point in `Plugin.cpp`.
5. Add a C source to `tests/pass-inputs/`
6. Add a `kagura_add_pass_test()` entry in `tests/CMakeLists.txt`
7. Add a FileCheck test in `tests/lit/<your-pass>.ll`
8. Add the pass to the shared profiles in `integration/profiles/*.json` if it
   should be on by default for FAST / BALANCED / STRONG

## Pass Guidelines

- Use `PassInfoMixin` (New Pass Manager only — no legacy pass support)
- Skip declarations: `if (F.isDeclaration()) return PA;`
- Check `shouldObfuscate(F, "passname", defaultEnabled)` from `Utils.h` to respect per-function annotations
- Skip functions with exception handling when the pass cannot handle EH: `if (hasExceptionHandling(F)) return PA;`
- Use `kagura::PRNG` from `Utils.h` for all randomness; respect `-kagura-seed`
- Keep `isRequired()` returning `false` for all obfuscation passes
- Use `kagura::getModuleTriple(M)` (not `M.getTargetTriple()` directly) for LLVM 17–22 compatibility

## Runtime Library

`runtime/` is organised by platform:

| Directory | Contents |
|:----------|:---------|
| `runtime/core/` | Cross-platform: AES, secure zeroing, device key, VM interpreter |
| `runtime/anti_debug/` | ptrace / Frida / breakpoint / hook / emulator detection (POSIX) |
| `runtime/ios/` | Darwin: jailbreak detection, Mach-O integrity, ObjC/Swift helpers |
| `runtime/android/` | Bionic / Linux: JNI, Play Integrity, seccomp, APK / ELF integrity |
| `runtime/windows/` | Win32: ETW detection, PE integrity, tamper response |
| `runtime/game/` | Anti-cheat helpers (IL2CPP, UE4, protected values) |

If your pass needs runtime support, add a `.c` file to the right subdirectory
and register it in `runtime/CMakeLists.txt`. Declare any runtime functions in
an `extern "C"` block in the pass file.

The build manifests under `integration/` select runtime sources by
**directory**, never by file name, so moving a file within `runtime/` does not
require touching them. Please keep it that way — an earlier flat-to-nested
reorganisation silently broke the SwiftPM, Bazel, CocoaPods and Android NDK
manifests because they enumerated individual `.c` files.

## Tests

- **Pass-level IR tests** (`tests/pass-inputs/` + `tests/CMakeLists.txt`): each file is compiled to bitcode and run through `opt` to verify the pass executes without crashing
- **FileCheck lit tests** (`tests/lit/`): verify specific IR transformations using `.ll` inputs with `; CHECK:` directives

All tests must pass across LLVM 17, 18, 19, 21, and 22.

To run only the FileCheck tests:

```bash
cd build && ctest -R lit-filecheck --output-on-failure
```

To run the differential tests (obfuscated vs. plain output comparison):

```bash
./scripts/differential-test.sh
```

## Code Style

- Follow LLVM coding conventions (camelCase for functions, PascalCase for types)
- File header comment format:
  ```
  //===-- YourPass.cpp - Short description ---------------------------------===//
  ```
- No `using namespace std`
- No `LLVM_VERSION_MAJOR` guards for the `getTargetTriple()` API — use `kagura::getModuleTriple()` instead

## Pull Requests

- One pass or feature per PR
- Include a FileCheck test (`.ll`) that verifies the pass transformation
- Run `./scripts/differential-test.sh` locally and confirm no regressions
- CI must be green before merge

## Release Process

Releases are published from the `main` branch. On GitHub:

1. Create a new Release tag (e.g., `v0.2.0`) from the GitHub UI.
2. The `release.yml` workflow triggers automatically and uploads pre-built binaries for:
   - macOS arm64 × LLVM 21 and 22
   - Linux x86_64 × LLVM 19, 21, and 22
3. A source tarball (`kagura-<version>-source.tar.gz`) is also attached.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
