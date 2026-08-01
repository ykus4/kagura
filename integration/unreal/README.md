# kagura — Unreal Engine Integration

Applies kagura obfuscation to UE native code (C++) for Android and iOS shipping builds.

## Prerequisites

- Unreal Engine 5.1 or later
- kagura built: run `bash build.sh` from the repo root
- Build targets: Android or iOS (Shipping configuration)

## Installation

### 1. Add the UBT toolchain

Copy `KaguraToolchain.cs` to your project or engine:

```
YourProject/
  Source/
    Programs/
      UnrealBuildTool/
        KaguraToolchain.cs   ← here
```

Or for an engine-wide install:
```
Engine/Source/Programs/UnrealBuildTool/Platform/Android/KaguraToolchain.cs
```

### 2. Add the module build rules (optional, for runtime linking)

Copy `KaguraObfuscation.Build.cs` to your project's `Source/ThirdParty/` directory
and add the module to your game module's `.Build.cs`:

```csharp
// YourGame.Build.cs
PublicDependencyModuleNames.AddRange(new string[] {
    "Core", "CoreUObject", "Engine",
    "KaguraObfuscation"   // ← add this
});
```

### 3. Set environment variables

```bash
export KAGURA_PLUGIN_PATH=/path/to/build/lib/Transforms/KaguraObfuscator.dylib
export KAGURA_RUNTIME_LIB=/path/to/build/runtime/libkagura_runtime.a
```

Or edit the defaults in `KaguraConfig` inside `KaguraToolchain.cs`.

### 4. Activate in your Target.cs

```csharp
// YourGameTarget.cs
public class YourGameTarget : TargetRules
{
    public YourGameTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Game;
        // kagura toolchain is activated automatically for Android/iOS Shipping
        // when KaguraToolchain.cs is present in the UBT search path.
    }
}
```

## Configuration

By default the toolchain emits a single obfuscation flag,
`-mllvm -kagura-config=<kagura>/integration/profiles/<profile>.json`. The pass
set for each profile lives in [`integration/profiles`](https://github.com/ykus4/kagura/tree/main/integration/profiles),
the single source of truth shared by every kagura integration.

Environment variables (no code edit needed):

| Variable | Default | Description |
|---|---|---|
| `KAGURA_ROOT` | `<UE root>/../kagura` | kagura checkout; the plugin, runtime and profiles are found from here |
| `KAGURA_PLUGIN_PATH` | auto | Absolute path to `KaguraObfuscator.{dylib,so,dll}`; skips the probe |
| `KAGURA_RUNTIME_LIB` | auto | Absolute path to `libkagura_runtime.a` |
| `KAGURA_PROFILE` | `balanced` | `fast` / `balanced` / `strong` / `off`, or a path to your own JSON policy file |

For a project-specific policy, point `KAGURA_PROFILE` at your own file:

```json
{ "profile": "STRONG", "passes": { "vm": true } }
```

### Explicit-flag fallback

Set `KaguraConfig.UseProfile = false` in `KaguraToolchain.cs` to bypass the
profile and use the explicit `EnableStr` / `EnableFla` / … fields instead.
This is also the automatic fallback if the profile file cannot be found.
Prefer the profile: keeping a second, independent pass list here is exactly
how the six integration copies drifted apart.

```csharp
public static class KaguraConfig
{
    public static bool   UseProfile    = true;   // false => use the fields below
    public static bool   EnableStr     = true;
    public static bool   EnableFla     = true;
    public static bool   EnableBcf     = true;
    public static bool   EnableSub     = true;
    public static bool   ShippingOnly  = true;   // only apply for Shipping builds
    public static int    BcfProb       = 30;
    // ... see file for full list
}
```

## Game Value Protection

For C++ gameplay code, use `game_protect.h` to protect values from memory
scanners and freeze tools:

```cpp
#include "kagura/game_protect.h"

UCLASS()
class AMyCharacter : public ACharacter
{
    kagura::Protected<int>   HP{100};
    kagura::Protected<float> MoveSpeed{600.f};
};
```

## Pass reference

See the [Passes reference](https://ykus4.github.io/kagura/passes/) for the full pass list and options.

## Build verification

After building, run:

```bash
nm -D YourGame.so | grep "your_sensitive_symbol"
```

With `-kagura-sv` enabled, internal symbols should not appear in the dynamic symbol table.
