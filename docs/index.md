# Kagura

> **LLVM 22 required for `-mllvm` flags.** On LLVM 17–21, clang parses `-mllvm`
> options before `-fpass-plugin` has loaded the plugin, so every `-kagura-*`
> flag is rejected with *"Unknown command line argument"*. Use the shipped
> `kagura-opt`, or `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`, both
> of which work on all supported versions. See
> [Known issues](https://github.com/ykus4/kagura/blob/main/CHANGELOG.md).


> **LLVM-based code obfuscation and anti-tamper toolkit for mobile, desktop, and WebAssembly targets.**

Built on the **New Pass Manager** (LLVM 17+). Loaded as a pass plugin via `-fpass-plugin` — no LLVM source tree modification required.

**Supported platforms:** iOS · Android · macOS · Windows (MSVC/Clang-CL) · Linux · WebAssembly

!!! warning "Windows uses a different entry point"

    `-fpass-plugin` is unavailable on Windows — the MSVC-targeted LLVM ships with
    `LLVM_ENABLE_PLUGINS=OFF`, so there is no loadable module. The passes link
    statically into `kagura-opt` and run over IR instead. See
    [Build from Source](getting-started/build-from-source.md).

!!! tip "New here?"
    Start with the [**Quick Start**](getting-started/quick-start.md) — five
    minutes from install to your first obfuscated binary.

!!! abstract "Citing Kagura"
    If you build research or production work on Kagura, please cite the
    paper — see [Citation](#citation). The DOI is
    [10.5281/zenodo.20361447](https://doi.org/10.5281/zenodo.20361447).

!!! note "Community"
    Questions, ideas, and use-case sharing live in
    [**GitHub Discussions**](https://github.com/ykus4/kagura/discussions).
    Bug reports and feature requests go in
    [**Issues**](https://github.com/ykus4/kagura/issues) — templates provided.

---

## Why Kagura?

Shipping compiled native code means shipping a reverse-engineer's starting point. Static analysis tools (IDA Pro, Ghidra, Binary Ninja) and dynamic instrumentation frameworks (Frida, Substrate) can reconstruct logic, extract keys, and bypass security checks within hours on unprotected binaries.

Kagura addresses this at the IR level — before the compiler turns IR into machine code — so every protection is architecture-agnostic and works across all targets from a single build step.

| Threat | Kagura countermeasure |
|:-------|:----------------------|
| Static string extraction (`strings`, IDA imports) | `kagura-str` / `kagura-str-aes` — strings are XOR/AES-encrypted blobs until first use |
| Decompiler-readable control flow | `kagura-fla` + `kagura-bcf` — CFG becomes a switch-dispatched state machine with opaque dead branches |
| Memory editor / GameGuardian value freeze | `kagura-mvo` / `kagura-pe` / `Protected<T>` — values stored XOR-encrypted at every alloca site |
| Frida / Substrate dynamic instrumentation | `kagura-anti-debug` + loaded-library scan — detects and responds to hooking frameworks at runtime |
| Binary patching (NOP-ing integrity checks) | `kagura-bbcheck` — per-basic-block opcode checksums abort on binary modification |
| Import table analysis (IDA external calls) | `kagura-ci` — external calls routed through runtime-resolved thunk table |
| Jailbreak / root detection bypass | Runtime module: Mach-O integrity, ELF tampering, Magisk/Zygisk/LSPosed detection |

---

## Documentation map

<div class="grid cards" markdown>

- :material-rocket-launch: **[Getting Started](getting-started/index.md)**

    Install, build, and run your first obfuscated binary in under five minutes.

- :material-puzzle: **[Passes](passes/index.md)**

    Reference for every IR pass — flags, effects, code-size and runtime overhead.

- :material-toolbox: **[Integration](integration/index.md)**

    Xcode, Gradle/NDK, Unity, Unreal, CMake, Bazel, CocoaPods, SPM.

- :material-book-open-variant: **[Cookbook](cookbook/index.md)**

    Banking, mobile game, SDK vendor, DRM — recipe-style guides with policy + verification.

- :material-shield-search: **[Security Model](security-model.md)**

    What Kagura protects, what it doesn't, and assumptions you can't violate.

- :material-cog: **[Configuration](configuration.md)**

    JSON policy DSL, strength profiles, CLI tuning parameters, deterministic pass order.

- :material-shield-lock: **[Runtime](runtime.md)**

    Anti-tamper API and `Protected<T>` for HP / currency / game-state values.

- :material-test-tube: **[Project](testing.md)**

    Testing & evaluation, architecture, contributor workflow.

</div>

---

## At a glance

```bash
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json \
      -O1 your_file.c -o your_file
```

```json
{
  "profile": "BALANCED",
  "passes": { "str": true, "fla": true, "bcf": true, "mvo": true },
  "tuning": { "bcf_prob": 40, "seed": 12345 }
}
```

See **[Quick Start](getting-started/quick-start.md)** for a full walkthrough.

---

## Citation

If you use Kagura in your research or build on it, please cite the [paper](https://zenodo.org/records/20361447):

```bibtex
@software{kagura,
  author    = {yotti},
  title     = {Kagura: LLVM-based Code Obfuscation and Anti-Tamper Toolkit},
  year      = {2025},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.20361447},
  url       = {https://doi.org/10.5281/zenodo.20361447}
}
```

## License

MIT — see [LICENSE](https://github.com/ykus4/kagura/blob/main/LICENSE).
