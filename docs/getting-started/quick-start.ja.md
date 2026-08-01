# クイックスタート

> **`-mllvm` 経由のフラグは LLVM 22 が必要です。** LLVM 17–21 では、clang が
> `-fpass-plugin` でプラグインを読み込む前に `-mllvm` を解析するため、すべての
> `-kagura-*` フラグが *"Unknown command line argument"* で拒否されます。同梱の
> `kagura-opt`、または `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`
> を使ってください（どちらも全対応バージョンで動作します）。


5分以内に Kagura で保護されたバイナリを作ります。

## 1. プラグインを入手

=== "プリビルトリリース"

    プラグインのバイナリはリリースごとに [GitHub Releases](https://github.com/ykus4/kagura/releases) で配布しています。

    ```
    kagura-<version>-macos-arm64-llvm21.tar.gz
    kagura-<version>-macos-arm64-llvm22.tar.gz
    kagura-<version>-linux-x86_64-llvm19.tar.gz
    kagura-<version>-linux-x86_64-llvm21.tar.gz
    kagura-<version>-linux-x86_64-llvm22.tar.gz
    ```

    各アーカイブの中身:

    - `plugin/KaguraObfuscator.{dylib,so}`
    - `runtime/libkagura_runtime.a`
    - `include/kagura/*.h`

=== "ソースからビルド"

    [ソースからビルド](build-from-source.md) を参照。

## 2. 単一ファイルを難読化

```bash
clang -fpass-plugin=path/to/KaguraObfuscator.dylib \
      -mllvm -kagura-str \
      -mllvm -kagura-fla \
      -mllvm -kagura-bcf \
      -mllvm -kagura-bcf-prob=50 \
      -O1 your_file.c -o your_file
```

## 3. 推奨: JSON 設定を使う

実プロジェクトでは、すべてのパス設定を1つの JSON ファイルにまとめます。

```json title="kagura.json"
{
  "profile": "BALANCED",
  "passes": {
    "str":   true,
    "fla":   true,
    "bcf":   true,
    "honey": true,
    "mvo":   false
  },
  "tuning": {
    "bcf_prob": 40,
    "seed":     12345
  }
}
```

```bash
clang -fpass-plugin=path/to/KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json \
      -O1 your_file.c -o your_file
```

DSL の全仕様は [設定](../configuration.md) を参照。

## 4. `opt` を使った IR レベル運用

```bash
clang -O1 -emit-llvm -c your_file.c -o your_file.bc

opt --load-pass-plugin=path/to/KaguraObfuscator.dylib \
    -passes="kagura-str,function(kagura-fla,kagura-bcf,kagura-sub)" \
    your_file.bc -o your_file.opt.bc

clang your_file.opt.bc -o your_file
```

## 5. 関数単位の制御

```c
// この関数にだけ強制的にパスを適用
__attribute__((annotate("kagura_fla")))
void critical_function(void) { /* ... */ }

// この関数だけパスを無効化
__attribute__((annotate("kagura_nofla")))
void performance_sensitive(void) { /* ... */ }

// VM パスで仮想化
__attribute__((annotate("kagura_vm")))
int verify_license(const char *key) { /* ... */ }
```

## 6. ランタイムをリンク (必要なら)

一部のパス (`str-aes`, `vm`, `anti-debug`, `tamper`, `pac`, `ci`) は `libkagura_runtime.a` のリンクが必要です:

```bash
clang your_file.c path/to/libkagura_runtime.a -o your_file
```

シンボル対応表は [ランタイムライブラリ](../runtime.md) を参照。

## 次のステップ

- [パスリファレンス](../passes/index.md)
- [設定 DSL とプロファイル](../configuration.md)
- [パス順序](../pass-order.md)
- [ビルドシステム統合](../integration/index.md)
