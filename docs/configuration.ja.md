# 設定

Kagura は `-kagura-config=<path>` で JSON ポリシーファイルを受け取り、プロファイルの選択、個々のパスの有効化・無効化、数値チューニングパラメータの設定、対象シンボルの絞り込みを行えます。実プロジェクトで難読化を運用する推奨方法です。

ただし **すべての** `-kagura-*` フラグを網羅しているわけではありません。ビルドシステム系スイッチ (`-kagura-lto-safe`, `-kagura-o0-protect`, `-kagura-build-id`)、レポート系スイッチ (`-kagura-metrics`, `-kagura-symmap`, `-kagura-symmap-out`, `-kagura-audit`)、`-kagura-autoselect`、`-kagura-vtp` にはポリシーファイル上のキーが存在せず、コマンドラインで渡す必要があります。[チューニングパラメータ](tuning.md#what-is-settable-from-a-policy-file) を参照してください。これらを `"passes"` や `"tuning"` に書くと、代わりに使うべきフラグ名を示す警告が出ます。

## JSON DSL

```json
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

### キーの綴り

パスのキーは `-kagura-` フラグ名からプレフィックスを取り除いたものです。両方の綴りを受け付けるため `"str-aes"` と `"str_aes"` は同じ意味になります。正規形はアンダースコア形で、`integration/profiles/` の生成ファイルもこちらを使います。

ローダが認識できないキーは報告されます:

```
[kagura] warning: unknown key "str_ase" in the "passes" object of the policy
file — it is ignored, so this setting has no effect; did you mean "str_aes"?
```

`-kagura-config-strict` を付けるとこの警告はビルド失敗になります。CI では必ず付けてください。無視されたキーは出荷するバイナリの保護が静かに弱まることを意味し、出力を見てもそれとは分かりません。

ポリシーファイルは **パイプラインの構築前** に読み込まれます。パイプライン内のパスとしてではありません。この区別は重要で、どのパスを有効にするかはパイプライン構築時に決まるため、パスとして動くローダでは常に手遅れになります — 本リリース以前に `-kagura-config` が完全に無効だった原因はまさにこれです。

優先順位（高い順）:

1. コマンドラインで明示指定した `-kagura-*` フラグ。`-kagura-config=p.json -kagura-str=false` は、`p.json` が要求していても文字列暗号化を無効にします。
2. `$KAGURA_FLAVOR` に一致する `flavors` ブロック。
3. `passes` / `tuning` オブジェクト。
4. `profile` プリセット。
5. 組み込みデフォルト（全パス無効）。

シンボルフィルタのリストだけは意図的な例外です。`"allowlist"` `"denylist"` `"protect"` は、明示指定された `-kagura-allow` / `-kagura-deny` / `-kagura-protect` に **負けるのではなくマージされます**。これらのリストの各項目は誰かが意図的に指定したシンボルであり、どちらか一方を捨てると、本来触らないはずのシンボルを黙って難読化してしまいます。結果は和集合になり、`-kagura-deny=vendor_*` と `"denylist": ["test_*"]` を併用すれば両方が除外されます。（以前は JSON がフラグを単純に上書きしていました。）

関数単位の [`__attribute__((annotate("kagura_*")))`](getting-started/quick-start.md#5-per-function-control) オーバーライドは関数ごとに優先されます。

## 強度プロファイル

`"profile"` キーで選択する組み込みプロファイル:

| プロファイル | パス | 用途 |
|:-------------|:-----|:-----|
| `FAST`     | `str` `sv` `anti_debug` | デバッグ / CI ビルド、最小オーバーヘッド |
| `BALANCED` | `str` `wstr` `bcf` `bbr` `bbs` `dci` `genc` `mvo` `sv` `anti_debug` `tamper`（`bcf_prob` 20, `bcf_iter` 1） | 標準リリースビルド |
| `STRONG`   | `str` `str_aes` `wstr` `fla` `bcf` `sub` `co` `ibr` `lt` `bbr` `bbs` `dci` `genc` `mvo` `sv` `honey` `anti_debug` `tamper`（`bcf_prob` 50, `bcf_iter` 2, `sub_iter` 2） | セキュリティクリティカルな出荷ビルド |

どのプロファイルも `anti_debug` を有効にするため、**プロファイルを使うビルドは `kagura_runtime` のリンクが必須**です。

`STRONG` は「全パス」ではありません。ABI を変えるもの、特定ターゲットを要するもの、コストが大きすぎるものは意図的に除外しています: `ci`, `pac`, `vm`, `fsplit`, `pe`, `elt`, `bbcheck`, `telemetry`, `cse_break`, `string_split`。加えてプラットフォーム依存の `objc` と `jni` も含みません（これらは Apple / Android の各インテグレーションが追加します）。必要な場合は `passes` オブジェクトで明示的に有効化してください。

`vtp` がこのリストに無いのは、そもそも `passes` のキーではないからです。`-kagura-vtp` はコマンドライン専用のフラグです。

[`integration/profiles/`](https://github.com/ykus4/kagura/tree/main/integration/profiles) の JSON はこの表とまったく同じ内容です。どちらも `lib/Transforms/Profiles.def` から生成されるため、プロファイル名の意味は選び方によらず一致します。（以前は一致していませんでした: JSON 側だけが `sv` `anti-debug` `tamper` を有効にしていました。）

プロファイルはデフォルトを設定するだけ。`"passes"` や `"tuning"` で個別キーをオーバーライドできます。

## 実例 — 銀行 / FinTech リリース

STRONG プロファイル + per-build AES 鍵ローテーションで、あるバージョンから抽出された鍵が次バージョンで無効になるようにします:

```json title="kagura-bank.json"
{
  "profile": "STRONG",
  "passes": {
    "str_aes":  true,
    "mvo":      true,
    "pe":       true,
    "bbcheck":  true,
    "tamper":   true
  },
  "tuning": {
    "bcf_prob": 60,
    "seed":     0
  }
}
```

```bash
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura-bank.json \
      -mllvm -kagura-config-strict \
      -mllvm -kagura-build-id=$(git rev-parse HEAD) \
      -O2 -c bank_core.c -o bank_core.o
```

`bbcheck` は呼び出し箇所を挿入するだけで、`kagura_bb_check` は利用者が用意する必要があります。[Anti-Analysis パス](passes/anti-analysis.md) を参照してください。

## ルートキー

| キー | 型 | 意味 |
|:-----|:---|:-----|
| `profile` | string | `FAST` / `BALANCED` / `STRONG` / `CUSTOM`。`CUSTOM` は「パスは自分で列挙する」という意味で、プリセットを適用しません。 |
| `passes` | object | パスごとの有効・無効。キーは `-kagura-` フラグ名からプレフィックスを除いたもの。`"dwarf"` だけは `"keep"` / `"strip"` / `"obfuscate"` を取ります。 |
| `tuning` | object | 数値パラメータ 5 つ: `seed`, `bcf_prob`, `bcf_iter`, `sub_iter`, `dci_prob`。 |
| `allowlist` | array of string | `-kagura-allow` と同じ。空でない場合、一致するシンボルだけを難読化します。 |
| `denylist` | array of string | `-kagura-deny` と同じ。一致するシンボルは対象外になります。 |
| `protect` | array of string | `-kagura-protect` と同じ。最初に評価されるため、`denylist` `allowlist` `kagura_hotpath` および関数単位の `kagura_no*` アノテーションすべてに優先します。 |
| `audit_out` | string | `-kagura-audit-out` と同じ。監査ログの出力先。`-kagura-audit` と併用したときのみ効果があり、既定値は `kagura_audit.json` です。 |
| `flavors` | object | `$KAGURA_FLAVOR` をキーとするフレーバ別オーバーライドブロック。 |

3 つのリストキーはシンボル名に対して照合され、末尾 1 個の `*` を前方一致グロブ (`vendor_*`) として解釈します。それ以外のワイルドカード構文はサポートしていません。

### フレーバ

環境変数 `KAGURA_FLAVOR` を設定すると、`"flavors"` の一致するブロックがベース設定の上に適用されます。1 つのファイルで複数のビルドバリアントを扱えます:

```json title="kagura.json"
{
  "profile": "BALANCED",
  "denylist": ["test_*"],
  "flavors": {
    "staging":    { "profile": "FAST" },
    "production": { "profile": "STRONG", "passes": { "vm": true } }
  }
}
```

```bash
KAGURA_FLAVOR=production clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json -O2 -c app.c -o app.o
```

フレーバブロックが受け付けるのは `profile`, `passes`, `tuning`, `allowlist`, `denylist`, `protect` — ルートから `flavors` と `audit_out` を除いたものです。

## 関連

- [チューニングパラメータ](tuning.md) — すべての CLI フラグ、シンボルフィルタと `-kagura-build-id` per-build 鍵シードを含む。
- [パス順序](pass-order.md) — プラグインがこれらのパスを適用する決定論的な順序。
- [ゲーム保護](game-protection.md) — 実行時値保護のための `Protected<T>` (`mvo` / `pe` を補完)。
