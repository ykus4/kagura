# 制御フロー難読化

ソースパスは `lib/Transforms/` からの相対です。大半は `CFG/` にありますが、3 つは制御フローに対する働きでこのページに分類されている一方、実装は関係するサブシステム側に置かれています。`include/kagura/Passes.h` には同じ食い違いをヘッダ側で発見・修正した記録が残っていますが、このページは当時更新されませんでした。

| フラグ | パス | 効果 | ソース |
|:-------|:-----|:-----|:-------|
| `-kagura-fla` | ControlFlowFlattening | CFG を switch ベースの状態機械に変換 (Wasm ではスキップ — 非構造化 CFG を要求するため) | `CFG/` |
| `-kagura-bcf` | BogusControlFlow | MBA 不透明述語でガードされた死ブロックを注入 | `CFG/` |
| `-kagura-ibr` | IndirectBranch | 直接呼び出しを関数ポインタグローバルからのロードに置換 | `CFG/` |
| `-kagura-ci` | CallIndirection | 外部呼び出しを実行時解決のサンクテーブルへルーティング | `AntiAnalysis/` |
| `-kagura-lt` | LoopTransform | 偽の死カウンタと不透明な不変分岐を追加 | `CFG/` |
| `-kagura-fsplit` | FunctionSplit | 内部 BB を抽出してアウトラインされたヘルパー関数にする | `CFG/` |
| `-kagura-bbs` | BasicBlockSplitting | 大きな BB をランダムに分割し CFG 複雑度を増加 | `CFG/` |
| `-kagura-bbr` | BasicBlockReordering | BB レイアウトをシャッフルし線形ディスアセンブラを混乱 | `CFG/` |
| `-kagura-dci` | DeadCodeInsertion | 到達不能なジャンクブロックを挿入し静的解析を誤誘導 | `CFG/` |
| `-kagura-elt` | EncryptedLookupTable | switch 文を XOR 暗号化されたディスパッチテーブルに変換 | `Data/EncryptedLookupTable.cpp` |
| `-kagura-vtp` | VTableProtection | C++ RTTI の typeinfo 名 (`_ZTS*`) を難読化、vtable メタデータを記録 | `ABI/VTableProtection.cpp` |

`-kagura-vtp` はコマンドライン専用のフラグです。[JSON ポリシーファイル](../configuration.md) の `"passes"` にキーはありません。

変換後の IR の見え方は [Before / After 例](before-after.md) を参照。
