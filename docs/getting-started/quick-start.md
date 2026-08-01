# Quick Start

> **LLVM 22 required for `-mllvm` flags.** On LLVM 17–21, clang parses `-mllvm`
> options before `-fpass-plugin` has loaded the plugin, so every `-kagura-*`
> flag is rejected with *"Unknown command line argument"*. Use the shipped
> `kagura-opt`, or `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`, both
> of which work on all supported versions. See
> [Known issues](https://github.com/ykus4/kagura/blob/main/CHANGELOG.md).


Get a Kagura-protected binary in under five minutes.

## 1. Get the plugin

=== "Pre-built release"

    Pre-built plugin binaries are published per release on the [GitHub Releases page](https://github.com/ykus4/kagura/releases).

    ```
    kagura-<version>-macos-arm64-llvm21.tar.gz
    kagura-<version>-macos-arm64-llvm22.tar.gz
    kagura-<version>-linux-x86_64-llvm19.tar.gz
    kagura-<version>-linux-x86_64-llvm21.tar.gz
    kagura-<version>-linux-x86_64-llvm22.tar.gz
    ```

    Each archive contains:

    - `plugin/KaguraObfuscator.{dylib,so}`
    - `runtime/libkagura_runtime.a`
    - `include/kagura/*.h`

=== "Build from source"

    See [Build from Source](build-from-source.md).

## 2. Obfuscate a single file

```bash
clang -fpass-plugin=path/to/KaguraObfuscator.dylib \
      -mllvm -kagura-str \
      -mllvm -kagura-fla \
      -mllvm -kagura-bcf \
      -mllvm -kagura-bcf-prob=50 \
      -O1 your_file.c -o your_file
```

## 3. Recommended: use a JSON config

For real projects, use a single JSON file to control every pass.

```json title="kagura.json"
{
  "profile": "BALANCED",
  "passes": {
    "str":   true,
    "fla":   true,
    "bcf":   true,
    "honey": true,
    "mvo":   false
  },
  "tuning": {
    "bcf_prob": 40,
    "seed":     12345
  }
}
```

```bash
clang -fpass-plugin=path/to/KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json \
      -O1 your_file.c -o your_file
```

See [Configuration](../configuration.md) for the full DSL.

## 4. IR-level use with `opt`

```bash
clang -O1 -emit-llvm -c your_file.c -o your_file.bc

opt --load-pass-plugin=path/to/KaguraObfuscator.dylib \
    -passes="kagura-str,function(kagura-fla,kagura-bcf,kagura-sub)" \
    your_file.bc -o your_file.opt.bc

clang your_file.opt.bc -o your_file
```

## 5. Per-function control

```c
// Force-enable a pass for this function
__attribute__((annotate("kagura_fla")))
void critical_function(void) { /* ... */ }

// Force-disable a pass for this function
__attribute__((annotate("kagura_nofla")))
void performance_sensitive(void) { /* ... */ }

// Virtualize with the VM pass
__attribute__((annotate("kagura_vm")))
int verify_license(const char *key) { /* ... */ }
```

## 6. Link the runtime (if required)

Some passes (`str-aes`, `vm`, `anti-debug`, `tamper`, `pac`, `ci`) require linking
`libkagura_runtime.a`:

```bash
clang your_file.c path/to/libkagura_runtime.a -o your_file
```

See the [Runtime Library](../runtime.md) page for the symbol matrix.

## Next steps

- [Passes reference](../passes/index.md)
- [Configuration DSL & profiles](../configuration.md)
- [Pass order](../pass-order.md)
- [Integration with your build system](../integration/index.md)
