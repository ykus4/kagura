# データ難読化

ソース: `lib/Transforms/Data/`

| フラグ | パス | 効果 |
|:-------|:-----|:-----|
| `-kagura-str` | StringEncryption | ナロー文字列リテラルを XOR 暗号化、初使用時に遅延復号 |
| `-kagura-str-aes` | StringEncryptionAES | AES-128-CTR 文字列暗号化 (ランタイム必要) |
| `-kagura-string-split` | StringSplit | 長い文字列リテラル (16 バイト以上) を複数の小さなグローバルに分割し、初使用時に実行時に再結合 |
| `-kagura-wstr` | WideStringEncryption | ワイド文字列 (wchar_t / char16_t / char32_t) と CFString バッファを XOR 暗号化 |
| `-kagura-co` | ConstantObfuscation | 整数定数を MBA 式で置換 |
| `-kagura-sub` | Substitution | 算術 / ビット演算を等価な MBA に置換 |
| `-kagura-genc` | GlobalEncryption | プライベートな整数グローバルを暗号化、ロード箇所にインライン XOR |
| `-kagura-mvo` | MemoryValueObfuscation | alloca された整数ローカルをストア・ロードのたびに XOR 暗号化 |
| `-kagura-pe` | PointerEncryption | alloca されたポインタ変数を XOR 暗号化、メモリダンプ解析を阻止 |
| `-kagura-cse-break` | CSEBreak | 共有された SSA 式を複製し、デコンパイラが CSE 復元によって再度まとめられないようにする |

`kagura-str` と `kagura-sub` の Before/After は [Before / After 例](before-after.md) を参照。

ゲーム実行時の値 (HP, 通貨等) を C++ レベルで守るには [ゲーム保護](../game-protection.md) を参照 — `Protected<T>` は実行時のシャドウコピー整合性チェックを追加することで `kagura-mvo` を補完します。
