# Kagura

> **`-mllvm` 経由のフラグは LLVM 22 が必要です。** LLVM 17–21 では、clang が
> `-fpass-plugin` でプラグインを読み込む前に `-mllvm` を解析するため、すべての
> `-kagura-*` フラグが *"Unknown command line argument"* で拒否されます。同梱の
> `kagura-opt`、または `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`
> を使ってください（どちらも全対応バージョンで動作します）。


> **モバイル・デスクトップ・WebAssembly 向けの LLVM ベース難読化・耐タンパーツールキット。**

LLVM 17+ の **New Pass Manager** 上に構築。`-fpass-plugin` でパスプラグインとしてロードされ、LLVM のソースツリーに手を加える必要はありません。

**対応プラットフォーム:** iOS · Android · macOS · Windows (MSVC/Clang-CL) · Linux · WebAssembly

!!! warning "Windows は入口が異なります"

    Windows では `-fpass-plugin` は使えません。MSVC 向けの LLVM が `LLVM_ENABLE_PLUGINS=OFF` で配布されており、ロード可能モジュールが存在しないためです。パスは `kagura-opt` に静的リンクされ、IR に対して実行します。詳細は [ソースからビルド](getting-started/build-from-source.md) を参照してください。

!!! tip "はじめての方"
    [**クイックスタート**](getting-started/quick-start.md) からどうぞ。インストールから最初の難読化バイナリまで5分で進めます。

!!! abstract "Kagura の引用"
    研究や本番運用で Kagura に基づく成果を作られた場合は、論文の引用をお願いします — 下記 [引用](#citation) を参照。DOI は
    [10.5281/zenodo.20361447](https://doi.org/10.5281/zenodo.20361447)。

!!! note "コミュニティ"
    質問・アイデア・ユースケース共有は
    [**GitHub Discussions**](https://github.com/ykus4/kagura/discussions) で。
    バグ報告と機能要望は
    [**Issues**](https://github.com/ykus4/kagura/issues) — テンプレートあり。

---

## なぜ Kagura か

ネイティブコードを出荷するということは、リバースエンジニアにスタート地点を提供するということ。静的解析ツール (IDA Pro, Ghidra, Binary Ninja) や動的計装フレームワーク (Frida, Substrate) は、保護されていないバイナリから数時間でロジックを再構成し、鍵を抽出し、セキュリティチェックを回避できます。

Kagura はこれを LLVM IR レベル — コンパイラが IR をマシンコードに変換する**前** — で対処するため、すべての保護がアーキテクチャ非依存となり、一度のビルドステップで全ターゲットに適用できます。

| 脅威 | Kagura の対抗策 |
|:-----|:----------------|
| 文字列の静的抽出 (`strings`、IDA imports) | `kagura-str` / `kagura-str-aes` — 文字列は初使用時まで XOR/AES 暗号化されたブロブ |
| デコンパイラで読める制御フロー | `kagura-fla` + `kagura-bcf` — CFG が switch ディスパッチの状態機械になり、不透明な死分岐を持つ |
| メモリエディタ / GameGuardian の値フリーズ | `kagura-mvo` / `kagura-pe` / `Protected<T>` — alloca のたびに XOR 暗号化された値で格納 |
| Frida / Substrate の動的計装 | `kagura-anti-debug` + ロード済みライブラリスキャン — フッキングフレームワークを実行時に検出・応答 |
| バイナリパッチ (整合性チェックを NOP化) | `kagura-bbcheck` — BB ごとのオペコードチェックサムでバイナリ変更時に abort |
| インポートテーブル分析 (IDA の external calls) | `kagura-ci` — 外部呼び出しを実行時解決のサンクテーブルにルーティング |
| Jailbreak / root 検出のバイパス | ランタイムモジュール: Mach-O 整合性、ELF 改ざん、Magisk/Zygisk/LSPosed 検出 |

---

## ドキュメントマップ

<div class="grid cards" markdown>

- :material-rocket-launch: **[はじめに](getting-started/index.md)**

    インストール・ビルド・最初の難読化バイナリ実行を5分以内に。

- :material-puzzle: **[パス](passes/index.md)**

    すべての IR パスのリファレンス — フラグ、効果、コードサイズ・実行時オーバーヘッド。

- :material-toolbox: **[統合](integration/index.md)**

    Xcode、Gradle/NDK、Unity、Unreal、CMake、Bazel、CocoaPods、SPM。

- :material-cog: **[設定](configuration.md)**

    JSON ポリシー DSL、強度プロファイル、CLI チューニングパラメータ、決定論的なパス順序。

- :material-shield-lock: **[ランタイム](runtime.md)**

    耐タンパー API と HP / 通貨 / ゲーム状態値のための `Protected<T>`。

- :material-test-tube: **[プロジェクト](testing.md)**

    テスト・評価、アーキテクチャ、コントリビュータワークフロー。

</div>

---

## ひとめで分かる例

```bash
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json \
      -O1 your_file.c -o your_file
```

```json
{
  "profile": "BALANCED",
  "passes": { "str": true, "fla": true, "bcf": true, "mvo": true },
  "tuning": { "bcf_prob": 40, "seed": 12345 }
}
```

詳細は **[クイックスタート](getting-started/quick-start.md)** を参照。

---

## 引用 {#citation}

研究や派生プロジェクトで Kagura を使用された場合は、[論文](https://zenodo.org/records/20361447) を引用してください:

```bibtex
@software{kagura,
  author    = {yotti},
  title     = {Kagura: LLVM-based Code Obfuscation and Anti-Tamper Toolkit},
  year      = {2025},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.20361447},
  url       = {https://doi.org/10.5281/zenodo.20361447}
}
```

## ライセンス

MIT — [LICENSE](https://github.com/ykus4/kagura/blob/main/LICENSE) 参照。
