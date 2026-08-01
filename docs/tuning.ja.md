# チューニングパラメータ

> **`-mllvm` 経由のフラグは LLVM 22 が必要です。** LLVM 17–21 では、clang が
> `-fpass-plugin` でプラグインを読み込む前に `-mllvm` を解析するため、すべての
> `-kagura-*` フラグが *"Unknown command line argument"* で拒否されます。同梱の
> `kagura-opt`、または `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`
> を使ってください（どちらも全対応バージョンで動作します）。


以下のすべてのフラグは clang のコマンドラインで `-mllvm -kagura-<flag>=<value>` で指定するか、[JSON ポリシーファイル](configuration.md) の `"tuning"` キー配下で指定できます。

## コアチューニング

| オプション | デフォルト | 説明 |
|:----------|:----------|:-----|
| `-kagura-seed=<N>` | `0` (エントロピー) | 再現可能な出力のための PRNG シード |
| `-kagura-bcf-prob=<N>` | `30` | BB ごとの偽制御フロー確率 [0-100] |
| `-kagura-bcf-iter=<N>` | `1` | 偽制御フローのイテレーション数 |
| `-kagura-sub-iter=<N>` | `1` | 置換のイテレーション数 |
| `-kagura-dci-prob=<N>` | `40` | 死コード挿入確率 [0-100] |

## インフラ

| オプション | デフォルト | 説明 |
|:----------|:----------|:-----|
| `-kagura-lto-safe` | `false` | LTO / ThinLTO パイプラインフェーズ中もパスを有効化 |
| `-kagura-o0-protect` | `false` | `-O0` で軽量保護 (STR, AntiDebug) を有効化 |
| `-kagura-dwarf=<mode>` | `keep` | DWARF 処理: `keep` / `strip` / `obfuscate` |
| `-kagura-build-id=<id>` | — | ビルド識別子を PRNG シードに混入、per-build 鍵ローテーション用 |

## ビルドシステム

| オプション | デフォルト | 説明 |
|:----------|:----------|:-----|
| `-kagura-config=<path>` | — | JSON ポリシーファイルのパス |
| `-kagura-symmap` | `false` | 難読化後にシンボルマップを出力 |
| `-kagura-symmap-out=<path>` | `kagura_symbols.json` | シンボルマップの出力ファイル |
| `-kagura-audit` | `false` | 全保護シンボルの監査ログを出力 |
| `-kagura-audit-out=<path>` | `kagura_audit.json` | 監査ログの出力ファイル |

## シンボルフィルタ

| オプション | デフォルト | 説明 |
|:----------|:----------|:-----|
| `-kagura-protect=<pattern>` | — | マッチするシンボルを強制保護 (カンマ区切り、`*` グロブ) |
| `-kagura-deny=<pattern>` | — | マッチするシンボルを全難読化から除外 |
| `-kagura-allow=<pattern>` | — | 許可リストモード: マッチするシンボルのみ難読化 |

## 再現性

`-kagura-seed=<N>` をゼロでない値にすると、パイプライン全体が決定論的になります。`scripts/verify-reproducible.sh` と組み合わせて、2回のビルドが同じ IR を生成することを確認できます — [テスト・評価](testing.md) を参照。
