# パス順序

プラグインは `registerOptimizerLastEPCallback` でパスを自動登録するため、下記の順序は標準 `-O1` / `-O2` 最適化の**後**に実行されます。順序は重要です。例えば `kagura-tamper` は CFG を変更するパスの**前**に関数チェックサムを計測する必要があります。

`kagura-autoselect` を有効にすると、以下のすべてに先行して実行されます。各関数にパスごとの判断をアノテーションとして書き込み、各パスがそれを読みます。フラグで既に有効になっている集合を狭めることしかできません。

以下のモジュールブロックと関数ブロックは生成物です。`Plugin.cpp` が `include/kagura/PassRegistry.def` を 1 行ずつ展開するため、パイプラインの順序は同ファイルの行順序そのものであり、両者がずれることはありません。

```
-O1 / -O2 (標準最適化が先)
  0. (設定読み込み)          → JSON ポリシーはパイプライン構築前に適用される。
                               パスではない — configuration.md 参照
  1. kagura-ci               → 外部呼び出しの間接化
  2. kagura-pac              → ポインタ認証
  3. kagura-str              → ナロー文字列暗号化 (XOR)
  4. kagura-str-aes          → ナロー文字列暗号化 (AES-128-CTR)
  5. kagura-wstr             → ワイド文字列 / CFString 暗号化
  6. kagura-string-split     → 長い文字列リテラルを分割 (str/str-aes の後)
  7. kagura-tamper           → 整合性ハッシュ (CFG 変更前)
  8. kagura-objc             → ObjC セレクタ/クラス名難読化
  9. kagura-jni              → JNI 動的登録
 10. kagura-anti-debug       → アンチ解析チェック
 11. kagura-fsplit           → 関数分割
 12. kagura-genc             → グローバル暗号化
 13. kagura-honey            → ハニー値と偽スタブを注入
 14. kagura-sv               → シンボル隠蔽
 15. kagura-fla              → CFG フラット化         ┐
 16. kagura-bcf              → 偽制御フロー           │
 17. kagura-sub              → 命令置換               │
 18. kagura-cse-break        → CSE 再結合の阻止       │
 19. kagura-co               → 定数難読化             │
 20. kagura-vm               → 関数の仮想化           │
 21. kagura-ibr              → 間接分岐               │ 関数パス
 22. kagura-lt               → ループ変換             │
 23. kagura-bbr              → BB 並び替え            │
 24. kagura-dci              → 死コード挿入           │
 25. kagura-bbs              → BB 分割                │
 26. kagura-mvo              → メモリ値 XOR           │
 27. kagura-pe               → ポインタ暗号化         │
 28. kagura-telemetry        → テレメトリプローブ     │
 29. kagura-bbcheck          → BB チェックサムガード  │
 30. kagura-elt              → 暗号化ルックアップ表   ┘
 31. kagura-dwarf-control    → DWARF strip/obfuscate (-kagura-dwarf != keep の場合)
 32. kagura-vtp              → RTTI/vtable 保護
 33. kagura-symmap           → JSON シンボルマップ出力 (-kagura-symmap 時)
 34. kagura-audit            → 監査ログ出力           (-kagura-audit 時)
```

## `opt` を使った手動指定

自動登録に任せず `opt` でドライブする場合も同じ順序を使ってください:

```bash
opt --load-pass-plugin=KaguraObfuscator.dylib \
    -passes="kagura-str,function(kagura-fla,kagura-bcf,kagura-sub)" \
    input.bc -o output.bc
```

モジュールレベルパス (config, ci, pac, str, …) はトップレベル、関数レベルパスは `function(...)` でラップします。
