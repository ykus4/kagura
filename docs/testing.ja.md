# テスト・評価

## 単体 / 回帰テスト

```bash
cd build && ctest --output-on-failure
```

Lit ベースの FileCheck テストは `tests/` 配下にあります。テストマトリクスは `tests/regression/README.md` と `tests/pass-inputs/README.md` を参照。

## 再現可能ビルドの検証

固定シードでビルドした2回の出力がバイト単位で同一であることを検証:

```bash
./scripts/ci/verify-reproducible.sh
# [kagura-repro] PASS: Both builds produced identical IR.
```

## 差分テスト

難読化バイナリが平文バイナリと同じ出力を生成することを検証:

```bash
./scripts/ci/differential-test.sh
# [diff-test] arithmetic_test ... PASS
# [diff-test] combined_test   ... PASS
# Results: 8 passed, 0 failed, 0 skipped
```

## App Store / Google Play 審査リスク評価

コンパイル済みバイナリをスキャンし、ストア審査拒絶を招くパターンを検出 (非 PIE, 平文 API キー, セレクタを漏らすデバッグシンボル等):

```bash
./scripts/cli/review-risk-assessment.sh path/to/MyApp.dylib --platform ios
# [HIGH    ] [SEC-PIE] ...
# [INFO    ] [ENC-DECL] No obvious encryption keyword references found.
# RESULT: No critical or high review risks detected.
```

## セキュリティ評価ハーネス

```bash
# シンボリック実行耐性 (angr)
cd tests/symbolic_exec && python3 run_angr_eval.py \
    --binary /tmp/my_binary --timeout 30

# デコンパイラ耐性 (Ghidra)
cd tests/decompiler_eval && python3 run_ghidra_eval.py \
    --binary /tmp/my_binary --ghidra /path/to/ghidra

# Frida 計装耐性 (プローブ F1-F8)
cd tests/frida_resistance && for s in probes/F*.js; do
    frida -l "$s" -f /tmp/my_binary
done

# フル レッドチームレポート
cd tests/redteam && python3 run_redteam.py \
    --binary /tmp/my_binary --report report.json
```

各サブディレクトリには独自の README があります — それぞれ
[`tests/symbolic_exec/README.md`](https://github.com/ykus4/kagura/tree/main/tests/symbolic_exec)、
[`tests/decompiler_eval/README.md`](https://github.com/ykus4/kagura/tree/main/tests/decompiler_eval)、
[`tests/frida_resistance/README.md`](https://github.com/ykus4/kagura/tree/main/tests/frida_resistance)、
[`tests/redteam/README.md`](https://github.com/ykus4/kagura/tree/main/tests/redteam) を参照。

## 追加解析ツール

| スクリプト | 目的 |
|:-----------|:-----|
| `scripts/cli/kagura-cli.py` | 設定ジェネレータ、監査ログビューア、シンボルマップアナライザ |
| `scripts/cli/kagura-diff.py` | ベースラインと難読化バイナリのセクション / シンボル / 文字列差分 (text or HTML) |
| `scripts/cli/kagura-strip.py` | ビルド後の衛生処理 — `LC_UUID` (Mach-O) / `.note.gnu.build-id` (ELF) をゼロ化してリビルド指紋を消す |
| `scripts/cli/variant_generator.py` | カスタム鍵を使った顧客 / アプリごとのバリアント生成 |
| `scripts/eval/attacker_cost_model.py` | 攻撃者のリバースエンジニアリングコスト (アナリスト時間) を推定 |
| `scripts/eval/battery_impact.py` | ランタイムパスのバッテリー / CPU 影響をモデル化 |
| `scripts/cli/license_manager.py` | 期限付きライセンストークンの生成、検証、失効 |

### `kagura-diff` — 実際にパスが何を変えたか

ベースラインバイナリと難読化済みバイナリを比較し、セクション増加・シンボル数・文字列数の差分を表示します。リリースビルドが本当に平文 API キーを除去し、非公開シンボルを隠したかを検証するのに便利です。

```bash
scripts/cli/kagura-diff.py baseline.dylib obfuscated.dylib
scripts/cli/kagura-diff.py baseline.dylib obfuscated.dylib --html report.html
```

### `kagura-strip` — 残存ビルドメタデータを消去

IR レベルのパスはリンカが後で書き込むメタデータ (`LC_UUID`, `.note.gnu.build-id`, 埋め込みビルドパス) に届きません。`strip` の**後**に `kagura-strip` を実行してください:

```bash
# macOS / iOS
strip MyApp.dylib                       # まずデバッグシンボルを除去
scripts/cli/kagura-strip.py MyApp.dylib     # LC_UUID をゼロ化

# Linux / Android
llvm-strip MyApp.so
scripts/cli/kagura-strip.py MyApp.so        # .note.gnu.build-id + .comment を削除
```
