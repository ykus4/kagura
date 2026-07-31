# Build from Source

=== "macOS (Homebrew LLVM)"

    ```bash
    brew install llvm
    bash build.sh
    ```

=== "macOS / Linux (Custom LLVM)"

    ```bash
    cmake -B build \
      -DLLVM_DIR=/path/to/llvm/lib/cmake/llvm \
      -DCMAKE_C_COMPILER=/path/to/clang \
      -DCMAKE_CXX_COMPILER=/path/to/clang++ \
      .
    cmake --build build -j$(nproc)
    ```

=== "Windows (Clang-CL)"

    The LLVM dev tree is required for `LLVMConfig.cmake`. Download the
    `clang+llvm-*-x86_64-pc-windows-msvc.tar.xz` release — the `win64.exe`
    installer is binaries-only and has no CMake config.

    **`-fpass-plugin` does not work on Windows.** The MSVC-targeted LLVM sets
    `LLVM_ENABLE_PLUGINS=OFF`, so there is no loadable module for clang to
    open. Kagura instead builds as a static library and is linked into
    `kagura-opt`, which registers the passes by calling `getKaguraPluginInfo()`
    directly. Build it with `-DKAGURA_BITCODE_TOOLS=ON`:

    ```bat
    cmake -B build -G Ninja ^
      -DLLVM_DIR=C:\llvm-dev\lib\cmake\llvm ^
      -DCMAKE_C_COMPILER=C:\llvm-dev\bin\clang-cl.exe ^
      -DCMAKE_CXX_COMPILER=C:\llvm-dev\bin\clang-cl.exe ^
      -DKAGURA_BITCODE_TOOLS=ON ^
      -DKAGURA_BUILD_TESTS=ON
    cmake --build build
    ```

    Then obfuscate through IR rather than through the clang driver:

    ```bat
    clang-cl /clang:-emit-llvm /clang:-S app.c -o app.ll
    build\bin\kagura-opt.exe -kagura-fla -kagura-str -S app.ll -o app.obf.ll
    clang-cl app.obf.ll /link /out:app.exe
    ```

    To link the passes into your own tool instead of using `kagura-opt`,
    declare the entry point and hand it a `PassBuilder` — this is exactly what
    `tools/kagura-opt.cpp` does under `KAGURA_STATIC_PLUGIN`:

    ```cpp
    // Provided by KaguraObfuscator.lib (lib/Transforms/Plugin.cpp)
    llvm::PassPluginLibraryInfo getKaguraPluginInfo();

    llvm::PassBuilder PB;
    getKaguraPluginInfo().RegisterPassBuilderCallbacks(PB);
    ```

    Link `KaguraObfuscator.lib` together with the LLVM components the passes
    need — `Core`, `Support`, `Analysis`, `TransformUtils`, `Passes` — since the
    static archive does not carry them itself.

!!! note "Testing the Windows linkage elsewhere"

    `-DKAGURA_FORCE_STATIC_PLUGIN=ON` selects the same static-linkage path on
    macOS and Linux, which is useful for reproducing a Windows build problem
    without a Windows machine. CI runs this configuration on Linux.

## Outputs

| Platform | Plugin path |
|:---------|:------------|
| macOS    | `build/lib/Transforms/KaguraObfuscator.dylib` |
| Linux    | `build/lib/Transforms/KaguraObfuscator.so` |
| Windows  | `build/lib/Transforms/KaguraObfuscator.lib` (static, run via `build/bin/kagura-opt.exe`) |

Runtime library: `build/runtime/libkagura_runtime.a`

## Verifying the build

```bash
cd build && ctest --output-on-failure
```

See [Testing & Evaluation](../testing.md) for the full test matrix (differential, reproducible, angr / Ghidra / Frida).
