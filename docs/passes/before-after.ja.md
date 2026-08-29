# Before / After 例

攻撃者から実際にどう見えるか、Kagura 適用前と適用後。

---

## 文字列暗号化 (`-kagura-str`)

**Before** — 平文の `.rodata` 内の文字列リテラル:

```llvm
@api_key = private constant [33 x i8] c"sk-prod-9f2a1c3e8b4d7f0e1a2c3d4e5f6a7b8c\00"

define void @connect() {
  call void @send_auth(ptr @api_key)
}
```

**After** — XOR 暗号化されたブロブ。初回呼び出しで復号、直後にゼロクリア:

```llvm
@api_key.enc = private constant [33 x i8] c"\xde\xad\x7f\x12..."  ; 暗号化済
@api_key.dec = global [33 x i8] zeroinitializer                    ; 平文は短時間だけここに存在

define void @connect() {
  ; 注入された復号スタブ — フラグ確認、XOR で .dec に展開、send_auth 呼び出し、.dec をゼロ化
  call void @__kagura_str_init_0()
  call void @send_auth(ptr @api_key.dec)
}
```

`strings` を実行してもガベージしか返らない。IDA の文字列リストにこの値は表示されない。

---

## 文字列分割 (`-kagura-string-split`)

**Before** — 連続したオフセットに置かれた 1 個の文字列グローバル。見つけるのは容易:

```llvm
@api_key = private constant [29 x i8] c"this is a long secret API key"
```

バイナリを走査すればシークレットが連続した領域として即座に見つかります。先に `kagura-str` で暗号化していても、*暗号文* はやはり連続しています。

**After** — リテラルをランダムな長さの N 個の断片に切り分け、別々のグローバルに格納。フラグで守られた初期化スタブが初使用時に再結合します:

```llvm
@kagura_str_frag_0_0 = private constant [6 x i8] c"this i"
@kagura_str_frag_0_1 = private constant [5 x i8] c"s a l"
@kagura_str_frag_0_2 = private constant [6 x i8] c"ong se"
@kagura_str_frag_0_3 = private constant [7 x i8] c"cret AP"
@kagura_str_frag_0_4 = private constant [3 x i8] c"I k"
@kagura_str_frag_0_5 = private constant [1 x i8] c"e"
@kagura_str_frag_0_6 = private constant [1 x i8] c"y"
@kagura_str_recombined_0 = private global [29 x i8] zeroinitializer

define internal void @__kagura_strsplit_0() {
entry:
  %f = load i8, ptr @kagura_str_flag_0
  %g = icmp ne i8 %f, 0
  br i1 %g, label %done, label %init
init:
  memcpy(@kagura_str_recombined_0[0], @kagura_str_frag_0_0, 6)
  memcpy(@kagura_str_recombined_0[6], @kagura_str_frag_0_1, 5)
  ...
  store i8 1, ptr @kagura_str_flag_0
  br label %done
done:
  ret void
}
```

`kagura-str`（または `kagura-str-aes`）と組み合わせてください。まず文字列が暗号化され、その暗号文が断片化されます。バイナリ上には連続した平文も連続した暗号文も存在しなくなります。

---

## CFG フラット化 (`-kagura-fla`)

**Before** — 可読な if/else チェーン:

```c
int classify(int x) {
    if (x < 0)  return -1;
    if (x == 0) return 0;
    return 1;
}
```

**After** — switch ディスパッチの状態機械。静的 CFG 解析が失敗:

```c
int classify(int x) {
    uint32_t state = 0xA3F1C2B0u;   // 初期状態 (難読化済)
    int result;
    while (1) {
        switch (state) {
        case 0xA3F1C2B0u:
            state = (x < 0) ? 0x12DE4F91u : 0x7C830B22u;  break;
        case 0x12DE4F91u:
            result = -1; state = 0xFFFFFFFFu;              break;
        case 0x7C830B22u:
            state = (x == 0) ? 0x3A9E17C4u : 0x88D20F5Bu; break;
        case 0x3A9E17C4u:
            result = 0;  state = 0xFFFFFFFFu;              break;
        case 0x88D20F5Bu:
            result = 1;  state = 0xFFFFFFFFu;              break;
        case 0xFFFFFFFFu: return result;
        }
    }
}
```

---

## CSE の分断 (`-kagura-cse-break`)

**Before** — clang `-O2` は共通部分式を複数の利用箇所で共有します:

```llvm
%t = add i32 %a, %b
%x = mul i32 %t, 2
%y = sub i32 %t, 3
```

デコンパイラはこれを `t = a + b; x = t*2; y = t - 3` という可読な形に容易に再結合します。

**After** — 利用箇所ごとに専用のコピーを持たせます:

```llvm
%t = add i32 %a, %b           ; 元の式 — 最初の利用箇所がそのまま使う
%x = mul i32 %t, 2
%cse.break = add i32 %a, %b   ; 2 番目の利用箇所のための新しい複製
%y = sub i32 %cse.break, 3
```

意味的には同一ですが、Ghidra / IDA Hex-Rays / Binary Ninja MLIL はいずれも逆コンパイル時にこれを **2 つの別々の計算** として報告するため、復元された C の可読性が落ちます。

---

## 算術置換 (`-kagura-sub`)

**Before:**

```llvm
%sum = add i32 %a, %b
```

**After** — 7種類の MBA 等価式からランダムに選択:

```llvm
; a + b  ≡  (a | b) + (a & b)
%or  = or  i32 %a, %b
%and = and i32 %a, %b
%sum = add i32 %or, %and
```

デコンパイラはこの式を再構築するため、元の `a + b` には戻らない。パターンマッチ式の難読化解除ツールを破ります。
