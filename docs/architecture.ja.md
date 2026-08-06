# アーキテクチャ

```
kagura/
├── include/kagura/
│   ├── PassRegistry.def    パス一覧。フラグ・パイプライン・JSON ポリシーキー・
│   │                       リンクスモークテストをここから生成する
│   ├── Passes/             lib/Transforms/ のサブディレクトリごとに 1 ヘッダ
│   ├── Passes.h            Passes/ のアンブレラ。Plugin.cpp と fuzzer 用
│   ├── Options.h           CLI フラグ宣言 (レジストリから生成)
│   ├── Utils.h             共通 IR ヘルパー, PRNG, ターゲット判定
│   ├── VM.h + VMOpcodes.def  バイトコード契約。C ランタイムと共有
│   └── game_protect.h      Protected<T> — 唯一の利用者向け公開ヘッダ
├── lib/Transforms/
│   ├── ABI/                C++ RTTI 名と vtable 整合性
│   ├── AntiAnalysis/       アンチデバッグ, 整合性, 呼び出し間接化, ハニー値
│   ├── CFG/                制御フロー難読化パス
│   ├── Data/               文字列 / 定数 / グローバル / ワイド文字列 / メモリ値暗号化
│   ├── Infrastructure/     ポリシー, メトリクス, シンボルマップ, 監査ログ
│   ├── Platform/           iOS (ObjC), Android (JNI)
│   ├── VM/                 関数仮想化
│   ├── Support/            パス間で共有する非公開ヘッダ (AES128.h)
│   ├── Profiles.def        FAST / BALANCED / STRONG。integration/profiles/*.json を生成
│   ├── Options.cpp         CLI フラグ定義
│   ├── Plugin.cpp          パス登録 & パイプライン接続
│   └── Utils.cpp           共通 IR ヘルパー & PRNG
├── runtime/
│   ├── core/               AES, VM インタプリタ, クラッシュシンボル化, デバイス鍵
│   ├── anti_debug/         アンチデバッグ / アンチ Frida (クロスプラットフォーム POSIX)
│   ├── android/            Android + Linux: ルート検出, アテステーション, /proc, syscall
│   ├── ios/                iOS / macOS: jailbreak 検出, Mach-O 整合性
│   ├── windows/            Windows: IsDebuggerPresent, NtQueryInformationProcess, PE 整合性
│   └── game/               アンチチート, IL2CPP 保護, テレメトリ
├── integration/            Xcode, Gradle, Unity, Unreal, CMake, Bazel, CocoaPods, SPM
├── scripts/
│   ├── cli/                自分のビルドに対して使うツール (設定, strip, diff, variant)
│   ├── eval/               コストモデル, バッテリ推定, ベンチマーク
│   └── ci/                 差分テスト, 再現ビルド検証, プロファイル生成
└── tests/                  CTest + FileCheck lit ベース回帰テスト
```

## プラグインエントリポイント

`lib/Transforms/Plugin.cpp` は `PassPluginLibraryInfo` 経由で LLVM **New Pass Manager** にすべてのパスを登録します。2つのことを行います:

1. すべてのパスを名前で公開し、`opt` (`-passes="kagura-str,..."`) または clang の `-mllvm -kagura-<name>` から要求できるようにする。
2. [推奨順序](pass-order.md) を `OptimizerLast` 拡張点に自動接続し、ユーザーが `-fpass-plugin=KaguraObfuscator.dylib` だけで合理的なデフォルトパイプラインを得られるようにする。

## 設定 & オプション

パスごとの有効化フラグと数値チューニングパラメータは `PassRegistry.def` から生成されます。`Options.cpp` の定義と `Options.h` の extern 宣言の両方が生成されるため、どちらもパス一覧とドリフトしません。新しいチューナブルを追加するには `KAGURA_TUNING` 行を足し、パスからフラグを読むだけです。パスごとの行を持たない文字列フラグとパイプライン制御フラグのみ手書きです。

[`kagura-config`](configuration.md) ローダは **パスではありません**。`opt::` の値はパイプライン構築時に読まれてどのパスを追加するか決まるため、`Plugin.cpp` がパイプライン構築前に呼び出します。パイプライン内のパスとして動かしてもその判断には影響できません。
