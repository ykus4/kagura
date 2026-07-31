# ソースからビルド

=== "macOS (Homebrew LLVM)"

    ```bash
    brew install llvm
    bash build.sh
    ```

=== "macOS / Linux (カスタム LLVM)"

    ```bash
    cmake -B build \
      -DLLVM_DIR=/path/to/llvm/lib/cmake/llvm \
      -DCMAKE_C_COMPILER=/path/to/clang \
      -DCMAKE_CXX_COMPILER=/path/to/clang++ \
      .
    cmake --build build -j$(nproc)
    ```

=== "Windows (Clang-CL)"

    `LLVMConfig.cmake` が必要なので、LLVM 開発ツリーが必要です。リリースの `clang+llvm-*-x86_64-pc-windows-msvc.tar.xz` を使ってください。`win64.exe` インストーラはバイナリのみで CMake 設定を含みません。

    **Windows では `-fpass-plugin` は動きません。** MSVC 向けの LLVM は `LLVM_ENABLE_PLUGINS=OFF` でビルドされており、clang が開けるロード可能モジュールが存在しないためです。kagura は静的ライブラリとしてビルドされ、`kagura-opt` にリンクされます。`kagura-opt` は `getKaguraPluginInfo()` を直接呼んでパスを登録します。`-DKAGURA_BITCODE_TOOLS=ON` を付けてビルドしてください。

    ```bat
    cmake -B build -G Ninja ^
      -DLLVM_DIR=C:\llvm-dev\lib\cmake\llvm ^
      -DCMAKE_C_COMPILER=C:\llvm-dev\bin\clang-cl.exe ^
      -DCMAKE_CXX_COMPILER=C:\llvm-dev\bin\clang-cl.exe ^
      -DKAGURA_BITCODE_TOOLS=ON ^
      -DKAGURA_BUILD_TESTS=ON
    cmake --build build
    ```

    難読化は clang ドライバ経由ではなく、IR を経由して行います。

    ```bat
    clang-cl /clang:-emit-llvm /clang:-S app.c -o app.ll
    build\bin\kagura-opt.exe -kagura-fla -kagura-str -S app.ll -o app.obf.ll
    clang-cl app.obf.ll /link /out:app.exe
    ```

    `kagura-opt` を使わず自前のツールにパスをリンクする場合は、エントリポイントを宣言して `PassBuilder` を渡します。`tools/kagura-opt.cpp` が `KAGURA_STATIC_PLUGIN` 有効時に行っているのと同じことです。

    ```cpp
    // KaguraObfuscator.lib (lib/Transforms/Plugin.cpp) が提供
    llvm::PassPluginLibraryInfo getKaguraPluginInfo();

    llvm::PassBuilder PB;
    getKaguraPluginInfo().RegisterPassBuilderCallbacks(PB);
    ```

    静的アーカイブ自体は LLVM を抱えていないので、`KaguraObfuscator.lib` と一緒にパスが必要とする LLVM コンポーネント (`Core`, `Support`, `Analysis`, `TransformUtils`, `Passes`) もリンクしてください。

!!! note "Windows のリンク方式を他の OS で検証する"

    `-DKAGURA_FORCE_STATIC_PLUGIN=ON` を指定すると、macOS や Linux でも同じ静的リンク経路が選択されます。Windows 実機なしにビルド問題を再現したいときに使えます。CI では Linux でこの構成を回しています。

## 出力先

| プラットフォーム | プラグインパス |
|:-----------------|:--------------|
| macOS    | `build/lib/Transforms/KaguraObfuscator.dylib` |
| Linux    | `build/lib/Transforms/KaguraObfuscator.so` |
| Windows  | `build/lib/Transforms/KaguraObfuscator.lib` (静的 / `build/bin/kagura-opt.exe` 経由で実行) |

ランタイムライブラリ: `build/runtime/libkagura_runtime.a`

## ビルドの検証

```bash
cd build && ctest --output-on-failure
```

テスト一覧 (differential, reproducible, angr / Ghidra / Frida) は [テスト・評価](../testing.md) を参照。
