# アンチ解析

ソース: `lib/Transforms/AntiAnalysis/`

| フラグ | パス | 効果 |
|:-------|:-----|:-----|
| `-kagura-anti-debug` | AntiDebug | ptrace, Frida ポート, `/proc/maps`, フック, ブレークポイント, エミュレータ検出 (iOS/Android)。IsDebuggerPresent, NtQueryInformationProcess, PEB ヒープフラグ (Windows)。Wasm ではスキップ |
| `-kagura-tamper` | AntiTamper | FNV-1a 関数チェックサム + 起動時の jailbreak / root 検出 |
| `-kagura-pac` | PointerAuth | XOR タグ付き関数ポインタグローバルによるソフトウェア CFI |
| `-kagura-sv` | SymbolVisibility | 非公開シンボルを hidden に設定、動的シンボルテーブルから削除 |
| `-kagura-honey` | HoneyValue | おとりのシークレットグローバルと偽のセキュリティスタブ関数を注入 |
| `-kagura-bbcheck` | BasicBlockChecksum | 各ブロック先頭に `kagura_bb_check(block_id, expected)` の呼び出しを生成し、0 が返ったら tamper フックへ分岐。**足場のみ** — 下記参照 |
| `-kagura-telemetry` | Telemetry | チート検出用に関数エントリへ `kagura_telemetry_event(id)` プローブを挿入。`id` は関数名の FNV-1a-32。同梱実装は弱いシンボルの no-op で、利用者がオーバーライドします |

ほとんどのアンチ解析パスは実行時に `libkagura_runtime.a` を呼び出します — シンボル対応表と直接呼び出し可能なチェックの一覧は [ランタイムライブラリ](../runtime.md) を参照。

## `-kagura-bbcheck` は同梱状態では何も検出しません {#-kagura-bbcheck-detects-nothing-as-shipped}

`runtime/core/bb_check.c` の `kagura_bb_check` は **弱いシンボルの常に成功するスタブ** です。引数を両方無視して「無傷」を返します。したがってパスが挿入した分岐は、毎回必ず安全側に倒れます。このフラグはコードサイズを増やすだけで、それ自体ではアンチパッチ能力を一切与えません。

これは未完成なのではなく意図的です。パスが渡してくるデータは、実行時に検証できないからです:

- `expected` はブロックの **LLVM IR オペコード** に対する FNV-1a で、命令選択より前に計算されます。IR オペコードは生成されたバイナリには存在しないため、実行時にハッシュを計算し直す対象がありません。
- `block_id` は関数ごとに 1 から振り直されるカウンタで、一意なキーではなく、関数をまたぐと衝突します。

ここで検証したふりをすること — 適当なメモリ範囲をハッシュして検証と称すること — は、このスタブより明確に劣ります。保護があるように見えて実際には無く、誤検出だけが増えるからです。

弱いシンボルをオーバーライドすること自体は可能ですが、正しく実装するには安定したキーで引ける信頼済みテーブルが必要で、そのためにはまずパス側がコード生成後のバイト範囲（アドレス + 長さ + 実機械語のハッシュ）を出力する必要があります。その作業は未着手です。それまでは、ロード済み text セクションをハッシュする `-kagura-tamper` を使ってください。こちらは現時点で機能します。
