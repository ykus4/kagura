# 設定

Kagura は `-kagura-config=<path>` で JSON ポリシーファイルを受け取り、すべてのパス設定を一箇所で制御できます。実プロジェクトで難読化を運用する推奨方法です。

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

ポリシーファイルは **パイプラインの構築前** に読み込まれます。パイプライン内のパスとしてではありません。この区別は重要で、どのパスを有効にするかはパイプライン構築時に決まるため、パスとして動くローダでは常に手遅れになります — 本リリース以前に `-kagura-config` が完全に無効だった原因はまさにこれです。

優先順位（高い順）:

1. コマンドラインで明示指定した `-kagura-*` フラグ。`-kagura-config=p.json -kagura-str=false` は、`p.json` が要求していても文字列暗号化を無効にします。
2. `$KAGURA_FLAVOR` に一致する `flavors` ブロック。
3. `passes` / `tuning` オブジェクト。
4. `profile` プリセット。
5. 組み込みデフォルト（全パス無効）。

関数単位の [`__attribute__((annotate("kagura_*")))`](getting-started/quick-start.md#5) オーバーライドは関数ごとに優先されます。

## 強度プロファイル

`"profile"` キーで選択する組み込みプロファイル:

| プロファイル | パス | 用途 |
|:-------------|:-----|:-----|
| `FAST`     | STR のみ | デバッグ / CI ビルド、最小オーバーヘッド |
| `BALANCED` | `str` `wstr` `bcf` `bbr` `bbs` `dci` `genc` `mvo`（`bcf_prob` 20, `bcf_iter` 1） | 標準リリースビルド |
| `STRONG`   | `str` `str-aes` `wstr` `fla` `bcf` `sub` `co` `ibr` `lt` `bbr` `bbs` `dci` `genc` `mvo` `sv` `honey`（`bcf_prob` 50, `bcf_iter` 2, `sub_iter` 2） | セキュリティクリティカルな出荷ビルド |

`STRONG` は「全パス」ではありません。`kagura_runtime` のリンクを必要とするもの、ABI を変えるもの、コストが大きすぎるものは意図的に除外しています: `anti-debug`, `tamper`, `ci`, `pac`, `vm`, `fsplit`, `pe`, `elt`, `vtp`, `bbcheck`, `telemetry`, `string-split`。必要な場合は `passes` オブジェクトで明示的に有効化してください。

プロファイルはデフォルトを設定するだけ。`"passes"` や `"tuning"` で個別キーをオーバーライドできます。

## 実例 — 銀行 / FinTech リリース

STRONG プロファイル + per-build AES 鍵ローテーションで、あるバージョンから抽出された鍵が次バージョンで無効になるようにします:

```json title="kagura-bank.json"
{
  "profile": "STRONG",
  "passes": {
    "str-aes":  true,
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
      -mllvm -kagura-build-id=$(git rev-parse HEAD) \
      -O2 -c bank_core.c -o bank_core.o
```

## 関連

- [チューニングパラメータ](tuning.md) — すべての CLI フラグ、シンボルフィルタと `-kagura-build-id` per-build 鍵シードを含む。
- [パス順序](pass-order.md) — プラグインがこれらのパスを適用する決定論的な順序。
- [ゲーム保護](game-protection.md) — 実行時値保護のための `Protected<T>` (`mvo` / `pe` を補完)。
