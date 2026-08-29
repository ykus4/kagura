# ランタイムライブラリ

一部のパスは、自分では定義しないシンボルへの呼び出しを生成します。そうしたターゲットは `libkagura_runtime.a` (`build/runtime/libkagura_runtime.a` でビルド) のリンクが必要です:

| パス | フラグ | 呼び出すが定義しないシンボル |
|:-----|:------|:---------------------------|
| StringEncryptionAES | `-kagura-str-aes` | `kagura_aes128_ctr_decrypt`, `kagura_check_blob_integrity` |
| VMObfuscation | `-kagura-vm` | `kagura_vm_execute` |
| AntiDebug | `-kagura-anti-debug` | `kagura_check_tracer_pid`, `kagura_check_inline_hooks`, `kagura_check_got_hooks`, `kagura_check_sw_breakpoints`, `kagura_check_hw_breakpoints`, `kagura_check_emulator` |
| AntiTamper | `-kagura-tamper` | `kagura_self_check`, `kagura_tamper_detected`, `kagura_runtime_hash_check` |
| BasicBlockChecksum | `-kagura-bbcheck` | `kagura_bb_check`, `kagura_on_tamper_detected` |
| Telemetry | `-kagura-telemetry` | `kagura_telemetry_event` |
| CallIndirection | `-kagura-ci` | `kagura_rtld_default_handle`、およびシステムの `dlsym` |
| PointerAuth | `-kagura-pac` | `kagura_random_u64` |
| JNIObfuscation | `-kagura-jni` | `kagura_jni_get_env`, `kagura_jni_find_class`, `kagura_jni_register_native` |
| ObjCObfuscation | `-kagura-objc` | `kagura_objc_register_remap` |

この表に載っていそうで載っていない名前が 2 つあります。パスが **定義する** 側であって、外部から取り込むわけではないからです: `kagura_anti_debug_init`（AntiDebug が生成するモジュールコンストラクタ）と `kagura_on_tamper_detected`（AntiDebug が `abort()` を呼ぶ弱いデフォルト定義を出力します。独自の応答にしたい場合はこれをオーバーライドしてください）。それ以外のパス — 文字列系・制御フロー系・データ系 — は自己完結したコードを生成し、ランタイムを一切必要としません。

```bash
clang your_file.c build/runtime/libkagura_runtime.a -o your_file
```

## 直接呼び出し可能な API

`include/kagura/runtime.h` はランタイムの公開サブセットです。自分で呼べる検出器、オーバーライドできるフック、保護付き値型を提供します。

```c
#include "kagura/runtime.h"

if (kagura_suspicious_lib_loaded())   { /* Frida gadget, Substrate, … */ }
if (kagura_check_tracer_pid())        { /* ptrace / デバッガアタッチ */ }
if (kagura_check_sw_breakpoints())    { /* コードに int3 / BRK が書き込まれた */ }
if (kagura_jailbreak_detected())      { /* Apple ターゲット */ }
if (kagura_magisk_present())          { /* Android ターゲット */ }
```

モバイルアプリの `main()` や Windows の `DllMain` から呼び出すと、パス注入の初期化コードを経由せずに同じ防御が得られます — チェックの発火タイミングを明示的に制御したい場合に便利です。

### 述語と応答

2 つの形があり、互換ではありません:

| 形 | 戻り値 | 挙動 |
|:---|:------|:-----|
| `int kagura_check_*(void)` | 非ゼロ == 検出 | 報告するだけ。それ以外は何もしません。 |
| `void kagura_*_check(void)` | なし | 述語を実行し、検出時に tamper フックを呼びます。 |

`kagura_self_check()`、`kagura_check_hooks()`、`kagura_check_breakpoints()` は名前に反して後者です。したがって `if (kagura_self_check() != 0)` はこのヘッダに対してコンパイルできません。呼び出し側が自前で `extern int` 宣言を書いていたときだけ通っていたように見えていただけで、実際にはゴミの入ったレジスタで分岐していました。`runtime/ios/device_attest.c` には同じ失敗が 4 つのシンボルで同時に起きた記録が残っており、このヘッダが存在する理由そのものです。

これらを手書きで宣言せず、必ず `#include "kagura/runtime.h"` してください。

## プラットフォーム認証 API

主要なプラットフォーム認証サービスへの薄い C バインディング。C 側はノンス生成と高速なローカル事前スクリーンを実行し、非同期署名トークンのラウンドトリップは Swift / Kotlin から接続します。

### Apple — DeviceCheck / App Attest (`runtime/ios/device_attest.c`)

```c
int kagura_devicecheck_available(void);     // iOS 11+, macOS 10.15+
int kagura_appattest_available(void);       // iOS 14+, A10+ ハードウェア

int kagura_appattest_nonce(uint8_t *out, size_t len);
int kagura_appattest_local_check(void);     // 高速 (<5ms) 環境スクリーン
```

Swift ブリッジ例:

```swift
import DeviceCheck
let service = DCAppAttestService.shared
if service.isSupported && kagura_appattest_local_check() == 1 {
    var nonce = Data(count: 32)
    _ = nonce.withUnsafeMutableBytes { kagura_appattest_nonce($0.baseAddress, 32) }
    service.generateKey { keyId, err in /* サーバー側検証 */ }
}
```

### Android — Play Integrity (`runtime/android/play_integrity.c`)

```c
void kagura_play_integrity_nonce(char *out_hex32, size_t len);
int  kagura_play_integrity_verdict_ok(const char *jwt_payload_b64url);
int  kagura_play_integrity_local_check(void);
```

JWT 署名の完全な検証はサーバー側で行う必要があります — `verdict_ok` は**ローカルの高速パス**であり、セキュリティ境界ではありません。Kotlin 呼び出しのスケルトンはファイルヘッダーコメントを参照してください。

### Windows — ETW 解析ツール検出 (`runtime/windows/etw_detection.c`)

```c
int kagura_etw_provider_present(const wchar_t *provider_guid);
int kagura_etw_analysis_tool_check(void);   // Cheat Engine / Procmon 等を検出
```

このモジュールはデフォルトで**スタブ**として出荷されます。`-DKAGURA_ETW_FULL=1` でビルドし `tdh.lib` をリンクすると、実際の `TdhEnumerateProviders` ベースの列挙を有効化できます — 実装の概要はファイルのヘッダーコメントを参照。

## ソースレイアウト

```
runtime/
├── core/         AES, VM インタプリタ, クラッシュシンボル化, デバイス鍵
├── anti_debug/   クロスプラットフォーム POSIX アンチデバッグ / アンチ Frida
├── android/      ルート検出, アテステーション, /proc, syscall プローブ (Android + Linux)
├── ios/          Jailbreak 検出, Mach-O 整合性 (iOS + macOS)
├── windows/      IsDebuggerPresent, NtQueryInformationProcess, PE 整合性
└── game/         アンチチート, IL2CPP 保護, テレメトリ
```
