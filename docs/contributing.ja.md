# コントリビュート

詳細は GitHub の [`CONTRIBUTING.md`](https://github.com/ykus4/kagura/blob/main/CONTRIBUTING.md) (英語) を参照してください。

> ⚠️ 日本語訳は今後追加予定です。最新かつ完全な手順は上記英語版にあります。

## 最低限知っておくこと

### ローカルビルド & テスト

```bash
git clone https://github.com/ykus4/kagura.git
cd kagura
bash build.sh
cd build && ctest --output-on-failure
```

### 新しいパスを追加する場合

1. `include/kagura/Passes.h` にパスを宣言
2. `lib/Transforms/<Subsystem>/YourPass.cpp` で実装
3. `lib/Transforms/CMakeLists.txt` に登録
4. `lib/Transforms/Options.cpp` と `include/kagura/Options.h` に `cl::opt` フラグ追加
5. `lib/Transforms/Plugin.cpp` で登録 (named-pass + OptimizerLast EP)
6. `tests/pass-inputs/` に C ソース追加
7. `tests/CMakeLists.txt` に `kagura_add_pass_test()` エントリ追加
8. `tests/lit/<your-pass>.ll` に FileCheck テスト追加

### パスのガイドライン

- `PassInfoMixin` を使用 (New Pass Manager のみ、レガシーパス未サポート)
- 宣言だけの関数はスキップ: `if (F.isDeclaration()) return PA;`
- 関数アノテーションを尊重するには `shouldObfuscate(F, "passname", defaultEnabled)` を使用
- すべてのランダム性は `kagura::PRNG` を使用、`-kagura-seed` を尊重
- LLVM 17–22 互換のため `M.getTargetTriple()` ではなく `kagura::getModuleTriple(M)` を使用

### Pull Request

- パス / 機能 ごとに1 PR
- パス変換を検証する FileCheck テスト (`.ll`) を含める
- `./scripts/ci/differential-test.sh` をローカル実行し回帰なしを確認
- マージ前に CI がグリーンであること

## ライセンス

コントリビュートすることで、貢献内容が MIT ライセンス下でライセンスされることに同意することになります。
