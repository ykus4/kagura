# パス

Kagura は LLVM の **New Pass Manager** 上に構築されています。各変換は個別のパスで、`-kagura-<name>` フラグまたは [JSON ポリシー](../configuration.md) で個別に有効化します。

パスは目的別に分類されています:

- [**制御フロー**](control-flow.md) — CFG をフラット化、偽の分岐を注入、BB を分割・並び替え、呼び出しを間接化。
- [**データ難読化**](data.md) — 文字列、定数、グローバル、alloca 値を暗号化。
- [**アンチ解析**](anti-analysis.md) — デバッガ / フックフレームワークの検出、整合性検証、シンボル隠蔽。
- [**プラットフォーム固有**](platform.md) — ObjC セレクタ / クラス名難読化と JNI 動的登録。加えて VM 仮想化（こちらはプラットフォーム固有ではなく、便宜上このページに載せています。実体は `lib/Transforms/VM/`）。
- [**インフラ**](infrastructure.md) — DWARF 制御、設定ローダ、シンボルマップ、監査ログ。

関連:

- [**Before / After 例**](before-after.md) — IR とデコンパイラ出力が実際にどう変わるか。
- [**パフォーマンス・サイズ影響**](performance.md) — 代表的なモバイルゲームモジュールで実測したオーバーヘッド。
- [**パス順序**](../pass-order.md) — `registerOptimizerLastEPCallback` で登録される決定論的パイプライン。
- [**チューニングパラメータ**](../tuning.md) — `bcf-prob`, `seed`, イテレーション回数、シンボルフィルタ。
