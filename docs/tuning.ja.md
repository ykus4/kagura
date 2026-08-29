# チューニングパラメータ

> **`-mllvm` 経由のフラグは LLVM 22 が必要です。** LLVM 17–21 では、clang が
> `-fpass-plugin` でプラグインを読み込む前に `-mllvm` を解析するため、すべての
> `-kagura-*` フラグが *"Unknown command line argument"* で拒否されます。同梱の
> `kagura-opt`、または `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`
> を使ってください（どちらも全対応バージョンで動作します）。
> [既知の問題](https://github.com/ykus4/kagura/blob/main/CHANGELOG.md#known-issues)。


以下のフラグはすべて clang のコマンドラインで `-mllvm -kagura-<flag>=<value>` として指定できます。[JSON ポリシーファイル](configuration.md) に対応するキーがあるのはその一部だけです — [ポリシーファイルから設定できるもの](#what-is-settable-from-a-policy-file) を参照してください。

## コアチューニング

`"tuning"` オブジェクトが読むのは、この 5 つだけです。

| オプション | JSON キー | デフォルト | 説明 |
|:----------|:---------|:----------|:-----|
| `-kagura-seed=<N>` | `seed` | `0` (エントロピー) | 再現可能な出力のための PRNG シード |
| `-kagura-bcf-prob=<N>` | `bcf_prob` | `30` | BB ごとの偽制御フロー確率 [0-100] |
| `-kagura-bcf-iter=<N>` | `bcf_iter` | `1` | 偽制御フローのイテレーション数 |
| `-kagura-sub-iter=<N>` | `sub_iter` | `1` | 置換のイテレーション数 |
| `-kagura-dci-prob=<N>` | `dci_prob` | `40` | 死コード挿入確率 [0-100] |

## インフラ

| オプション | JSON キー | デフォルト | 説明 |
|:----------|:---------|:----------|:-----|
| `-kagura-lto-safe` | — | `false` | LTO / ThinLTO パイプラインフェーズ中もパスを有効化 |
| `-kagura-o0-protect` | — | `false` | `-O0` 向けの軽量サブセットを有効化（下記） |
| `-kagura-dwarf=<mode>` | `passes.dwarf` | `keep` | DWARF 処理: `keep` / `strip` / `obfuscate` |
| `-kagura-build-id=<id>` | — | — | ビルド識別子を PRNG シードに混入、per-build 鍵ローテーション用 |
| `-kagura-vtp` | — | `false` | RTTI / vtable 保護 (C++ ABI) |
| `-kagura-autoselect` | — | `false` | 関数ごとにスコアを付けて適用パスを自動選択 |

`-kagura-o0-protect` が解禁するのは、`-O0` でもコストが有界に収まるパスです: `str`, `str-aes`, `wstr`, `anti-debug`、および `-kagura-dwarf` が `keep` 以外のときの DWARF 制御。個々のパスは別途有効化が必要で、このフラグは解禁するだけです。`fla`, `bcf`, `vm` などの構造変換パスは `-O0` では一切実行されません。

## ビルドシステム

| オプション | JSON キー | デフォルト | 説明 |
|:----------|:---------|:----------|:-----|
| `-kagura-config=<path>` | — | — | JSON ポリシーファイルのパス |
| `-kagura-config-strict` | — | `false` | ポリシーファイルの未知キーを警告ではなくビルド失敗にする |
| `-kagura-metrics` | — | `false` | 難読化前後のメトリクスを出力 |
| `-kagura-symmap` | — | `false` | 難読化後にシンボルマップを出力 |
| `-kagura-symmap-out=<path>` | — | `kagura_symbols.json` | シンボルマップの出力ファイル |
| `-kagura-audit` | — | `false` | 全保護シンボルの監査ログを出力 |
| `-kagura-audit-out=<path>` | `audit_out`（ルート） | `kagura_audit.json` | 監査ログの出力ファイル |

## シンボルフィルタ

| オプション | JSON キー | デフォルト | 説明 |
|:----------|:---------|:----------|:-----|
| `-kagura-protect=<pattern>` | `protect`（ルート） | — | マッチするシンボルを強制保護 (カンマ区切り、末尾 `*` グロブ) |
| `-kagura-deny=<pattern>` | `denylist`（ルート） | — | マッチするシンボルを全難読化から除外 |
| `-kagura-allow=<pattern>` | `allowlist`（ルート） | — | 許可リストモード: マッチするシンボルのみ難読化 |

この 3 つの JSON リストキーは、対応するフラグを置き換えるのではなく **マージ** されます。[設定](configuration.md#json-dsl) を参照してください。

## ポリシーファイルから設定できるもの {#what-is-settable-from-a-policy-file}

`"tuning"` オブジェクトが読むのは、上のコアチューニングの 5 行だけです。`"passes"` オブジェクトはパスごとの有効化キー（`-kagura-<pass>` フラグ 1 つにつき 1 キー）と `"dwarf"` を読みます。`protect` / `denylist` / `allowlist` / `audit_out` は `"tuning"` ではなくルートのキーです。

このページの残り — `-kagura-lto-safe`, `-kagura-o0-protect`, `-kagura-build-id`, `-kagura-vtp`, `-kagura-autoselect`, `-kagura-metrics`, `-kagura-symmap`, `-kagura-symmap-out`, `-kagura-audit`, `-kagura-config` — にはポリシーファイル上の表現が存在せず、コマンドラインで渡す必要があります。これらは保護ポリシーではなくビルド呼び出し側の決定事項（どの成果物をどこに書くか、そもそもパイプラインを走らせるか）だからです。`"passes"` や `"tuning"` にこれらを書くと、以前は黙って無視されていましたが、現在は代わりに使うフラグ名を示す警告が出ます。

## 再現性

`-kagura-seed=<N>` をゼロでない値にすると、パイプライン全体が決定論的になります。`scripts/ci/verify-reproducible.sh` と組み合わせて、2回のビルドが同じ IR を生成することを確認できます — [テスト・評価](testing.md) を参照。
