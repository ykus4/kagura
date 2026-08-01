# アーキテクチャ

```
kagura/
├── include/kagura/         パブリックヘッダ (Passes.h, Options.h, Utils.h, game_protect.h)
├── lib/Transforms/
│   ├── CFG/                制御フロー難読化パス
│   ├── Data/               文字列 / 定数 / グローバル / ワイド文字列 / メモリ値暗号化
│   ├── AntiAnalysis/       アンチデバッグ, 整合性, 呼び出し間接化, ハニー値
│   ├── Platform/           iOS (ObjC), Android (JNI), VM 仮想化
│   ├── Infrastructure/     DWARF 制御, 設定 DSL, シンボルマップ
│   ├── Options.cpp         CLI フラグの集中定義
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
├── scripts/                CLI ツール, 検証, 差分テスト, 審査リスク評価
└── tests/                  CTest + FileCheck lit ベース回帰テスト
```

## プラグインエントリポイント

`lib/Transforms/Plugin.cpp` は `PassPluginLibraryInfo` 経由で LLVM **New Pass Manager** にすべてのパスを登録します。2つのことを行います:

1. すべてのパスを名前で公開し、`opt` (`-passes="kagura-str,..."`) または clang の `-mllvm -kagura-<name>` から要求できるようにする。
2. [推奨順序](pass-order.md) を `OptimizerLast` 拡張点に自動接続し、ユーザーが `-fpass-plugin=KaguraObfuscator.dylib` だけで合理的なデフォルトパイプラインを得られるようにする。

## 設定 & オプション

パスごとの有効化フラグは `PassRegistry.def` から生成されるため、パス一覧とドリフトしません。`Options.cpp` はチューニングパラメータと基盤フラグを手書きで定義します。新しいチューナブルを追加するということは、ここに `cl::opt<...>` を追加し、パスから読み出すことを意味します。

[`kagura-config`](configuration.md) ローダは **パスではありません**。`opt::` の値はパイプライン構築時に読まれてどのパスを追加するか決まるため、`Plugin.cpp` がパイプライン構築前に呼び出します。パイプライン内のパスとして動かしてもその判断には影響できません。
