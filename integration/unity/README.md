# kagura — Unity Integration

Applies kagura obfuscation to Unity IL2CPP builds for Android and iOS.

## Prerequisites

- Unity 2021.3 LTS or later (IL2CPP scripting backend required)
- kagura built: run `bash build.sh` from the repo root
- Build targets: Android or iOS

## Installation

1. Copy `Editor/KaguraPostBuildProcessor.cs` into your project's
   `Assets/Editor/` directory (create it if it doesn't exist).

2. Open **Edit > Project Settings > Kagura Obfuscator** and set:
   - **Kagura Root** — the kagura checkout (`kagura.root`). The plugin is
     found by probing `<root>/build/lib/Transforms/KaguraObfuscator.{dylib,so,dll}`
   - **Plugin Path** — optional; an absolute path that skips the probe
   - **Runtime Lib Path** — absolute path to `libkagura_runtime.a`

3. Build your project normally.  kagura runs automatically as a post-build step.

## Configuration

All settings are stored in `EditorPrefs` and can be changed via the
**Project Settings > Kagura Obfuscator** UI.

| Setting | Default | Description |
|---------|---------|-------------|
| Release builds only | on | Skip obfuscation for Development builds |
| Use Profile | on | Drive the pass set from the shared profile (recommended) |
| Profile | `balanced` | `fast` / `balanced` / `strong` / `off`, or a path to your own JSON policy file |

When **Use Profile** is on, the only obfuscation flag emitted is
`-mllvm -kagura-config=<kagura>/integration/profiles/<profile>.json`. The pass
set for each profile lives in [`integration/profiles`](../profiles/README.md),
the single source of truth shared by every kagura integration — read those
files rather than the table below, which only applies to the explicit-flag
fallback path (**Use Profile** off, or the profile file missing).

| Setting | Default | Description |
|---------|---------|-------------|
| CFG Flattening | on | `-kagura-fla` |
| Bogus Control Flow | on | `-kagura-bcf` |
| Substitution | on | `-kagura-sub` |
| String Encryption | on | `-kagura-str` |
| Wide String Encryption | on | `-kagura-wstr` |
| AES String Encryption | off | `-kagura-str-aes` (requires runtime) |
| Global Encryption | off | `-kagura-genc` |
| Memory Value Obfuscation | off | `-kagura-mvo` |
| Indirect Branch | on | `-kagura-ibr` |
| BB Reordering | on | `-kagura-bbr` |
| Symbol Visibility | on | `-kagura-sv` |
| Anti-Debug | on | `-kagura-anti-debug` |
| Anti-Tamper | on | `-kagura-tamper` |
| Honey Values | off | `-kagura-honey` |
| BB Splitting | off | `-kagura-bbs` (increases build time) |
| Dead Code Insertion | off | `-kagura-dci` |
| Constant Obfuscation | off | `-kagura-co` |
| VM Obfuscation | off | `-kagura-vm` (significant overhead) |
| Symbol Map | off | `-kagura-symmap` (emit JSON for crash symbolication) |
| BCF Probability | 30 | Bogus CF probability per block [0–100] |

## CMake-only workflow

If you manage the IL2CPP CMake build directly, include the cmake helper:

```cmake
include("/path/to/kagura/integration/unity/kagura_unity_config.cmake")
```

Set variables before the include to override defaults:

```cmake
set(KAGURA_PLUGIN_PATH "/path/to/KaguraObfuscator.so")
set(KAGURA_PROFILE "STRONG")   # FAST | BALANCED | STRONG
include(".../kagura_unity_config.cmake")
```

Or use the JSON config DSL for full control:

```cmake
set(KAGURA_CONFIG_PATH "${CMAKE_SOURCE_DIR}/kagura.json")
```

```json
{
  "profile": "BALANCED",
  "passes": { "honey": true, "mvo": true },
  "tuning": { "bcf_prob": 40, "seed": 42 }
}
```

## Game Value Protection

For IL2CPP C++ plugins or native game code, include `game_protect.h` to protect
game-critical values from memory scanners (GameGuardian, Cheat Engine):

```cpp
#include "kagura/game_protect.h"

class Player {
    kagura::Protected<int>   hp{100};
    kagura::Protected<float> speed{5.5f};
    kagura::Protected<int>   currency{0};
public:
    void takeDamage(int dmg) { hp -= dmg; }
    bool isAlive() const     { return static_cast<int>(hp) > 0; }
};
```

See `include/kagura/game_protect.h` for full documentation.

## IL2CPP Protection Runtime

`libkagura_runtime.a` includes `il2cpp_protection.c` which provides:

| Function | Description |
|---|---|
| `kagura_il2cpp_check_metadata_integrity()` | Verifies `global-metadata.dat` magic and FNV-1a hash |
| `kagura_il2cpp_check_symbol_redirect()` | Detects IL2CPP symbol hooks (BepInEx, MelonLoader) |
| `kagura_il2cpp_protect_method_table()` | XOR-encodes method pointer table at startup |
| `kagura_protect_global_metadata()` | Validates metadata file version and magic |
| `kagura_il2cpp_anti_memory_scan()` | Detects memory scanners (GameGuardian, Frida) |

Call these from your game's startup C++ code (e.g., a native plugin):

```cpp
extern "C" {
    int  kagura_il2cpp_check_metadata_integrity(void);
    int  kagura_il2cpp_check_symbol_redirect(void);
    int  kagura_il2cpp_anti_memory_scan(void);
}

void GameStartup() {
    if (kagura_il2cpp_check_metadata_integrity() ||
        kagura_il2cpp_check_symbol_redirect()    ||
        kagura_il2cpp_anti_memory_scan()) {
        // tamper detected — handle appropriately
    }
}
```
