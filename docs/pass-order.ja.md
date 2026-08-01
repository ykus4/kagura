# パス順序

プラグインは `registerOptimizerLastEPCallback` でパスを自動登録するため、下記の順序は標準 `-O1` / `-O2` 最適化の**後**に実行されます。順序は重要です。例えば `kagura-tamper` は CFG を変更するパスの**前**に関数チェックサムを計測する必要があります。

```
-O1 / -O2 (標準最適化が先)
  0. (設定読み込み)          → JSON ポリシーはパイプライン構築前に適用される。
                               パスではない — configuration.md 参照
  2. kagura-ci               → 外部呼び出しの間接化
  3. kagura-pac              → ポインタ認証
  4. kagura-str[-aes]        → ナロー文字列暗号化
  5. kagura-wstr             → ワイド文字列 / CFString 暗号化
  6. kagura-tamper           → 整合性ハッシュ (CFG 変更前)
  7. kagura-objc             → ObjC セレクタ/クラス名難読化
  8. kagura-jni              → JNI 動的登録
  9. kagura-anti-debug       → アンチ解析チェック
 10. kagura-fsplit           → 関数分割
 11. kagura-genc             → グローバル暗号化
 12. kagura-honey            → ハニー値と偽スタブを注入
 13. kagura-sv               → シンボル隠蔽
 14. kagura-fla              → CFG フラット化         ┐
 15. kagura-bcf              → 偽制御フロー           │
 16. kagura-bbs              → BB 分割                │
 17. kagura-bbr              → BB 並び替え            │
 18. kagura-dci              → 死コード挿入           │
 19. kagura-sub              → 命令置換               │ 関数パス
 20. kagura-co               → 定数難読化             │
 21. kagura-mvo              → メモリ値 XOR           │
 22. kagura-pe               → ポインタ暗号化         │
 23. kagura-telemetry        → テレメトリプローブ     │
 24. kagura-bbcheck          → BB チェックサムガード  │
 25. kagura-elt              → 暗号化ルックアップ表   ┘
 26. kagura-dwarf-control    → DWARF strip/obfuscate (-kagura-dwarf != keep の場合)
 27. kagura-vtp              → RTTI/vtable 保護
 28. kagura-symmap           → JSON シンボルマップ出力 (-kagura-symmap 時)
 29. kagura-audit            → 監査ログ出力           (-kagura-audit 時)
```

## `opt` を使った手動指定

自動登録に任せず `opt` でドライブする場合も同じ順序を使ってください:

```bash
opt --load-pass-plugin=KaguraObfuscator.dylib \
    -passes="kagura-str,function(kagura-fla,kagura-bcf,kagura-sub)" \
    input.bc -o output.bc
```

モジュールレベルパス (config, ci, pac, str, …) はトップレベル、関数レベルパスは `function(...)` でラップします。
