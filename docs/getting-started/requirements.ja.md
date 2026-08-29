# 動作要件

| 要件 | バージョン |
|:-----|:----------|
| LLVM        | 17 – 22 (17, 18, 19, 21, 22 でテスト済) |
| CMake       | 3.20+ |
| C++         | C++17 |

## プラットフォームに関する注意

- **Windows** — Clang-CL のみ対応。かつ `-fpass-plugin` は**使えません**。MSVC 向けの LLVM は `LLVM_ENABLE_PLUGINS=OFF` で配布されているため、`clang -fpass-plugin` も `opt --load-pass-plugin` も kagura をロードできません。パスは静的ライブラリ (`KaguraObfuscator.lib`) としてビルドされ、それをリンクした `kagura-opt` 経由で実行します。手順は [ソースからビルド](build-from-source.md) の *Windows (Clang-CL)* タブを参照してください。

- **WebAssembly** — Wasm のトリプルでは 5 つのパスが早期に処理を打ち切ります。Wasm は構造化制御フローを要求し、ネイティブのデバッガ面も ptrace もロード済みイメージ一覧も持たず、コードのアドレスを取る手段もないためです: `kagura-fla`, `kagura-anti-debug`, `kagura-pac`, `kagura-tamper`, `kagura-vm`。`-kagura-autoselect` も Wasm では `fla` を提案しなくなります。それ以外 — 文字列・定数・グローバル・データ系のパス — は通常どおり動作します。

- **iOS / Android** — ビルドシステムへの組み込み方は [統合](../integration/index.md) を参照 (Xcode, Gradle / NDK)。
