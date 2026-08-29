# プラットフォーム固有パス

| フラグ | パス | ターゲット | ソース |
|:-------|:-----|:-----------|:-------|
| `-kagura-objc` | ObjCObfuscation | iOS — ObjC のセレクタ / クラス名を IR メタデータ内で難読化 | `lib/Transforms/Platform/` |
| `-kagura-jni`  | JNIObfuscation  | Android — 静的 `Java_*` を動的 `RegisterNatives` に変換 | `lib/Transforms/Platform/` |
| `-kagura-vm`   | VMObfuscation   | 関数本体をカスタムスタックベース VM バイトコードに仮想化 | `lib/Transforms/VM/` |

`kagura-vm` は便宜上このページに載せていますが、プラットフォーム固有ではなく `Platform/` にもありません。全ターゲットで動作し、独立したサブシステムを持ちます。

## `kagura-vm`

VM パスは選択された関数をカスタムスタックベース VM バイトコードにコンパイルし、実行時に `kagura_vm_execute` (`libkagura_runtime.a` 内) で解釈実行します。元のネイティブコードはバイナリから完全に削除されます。

仮想化したい関数にアノテーションを付けます:

```c
__attribute__((annotate("kagura_vm")))
int verify_license(const char *key) {
    // VM バイトコードにコンパイル — バイナリ内に可読な IR やマシンコードは無い
    ...
}
```

VM 仮想化された関数はネイティブの10〜50倍遅くなるため、ライセンスチェック・鍵導出・暗号初期化のような **小さく・呼び出し頻度の低い** 関数に限定して使用してください。
