<p align="center">
  <img src="assets/kagura_icon.png" width="512" alt="Kagura">
</p>

<p align="center">
  <a href="https://github.com/ykus4/kagura/actions/workflows/ci.yml">
    <img src="https://github.com/ykus4/kagura/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI">
  </a>
  <a href="https://github.com/ykus4/kagura/actions/workflows/release.yml">
    <img src="https://github.com/ykus4/kagura/actions/workflows/release.yml/badge.svg" alt="Release">
  </a>
  <img src="https://img.shields.io/badge/LLVM-17%E2%80%9322-blue?style=flat-square" alt="LLVM 17-22">
  <img src="https://img.shields.io/badge/C%2B%2B-17-orange?style=flat-square" alt="C++17">
  <img src="https://img.shields.io/badge/platforms-iOS%20%7C%20Android%20%7C%20macOS%20%7C%20Windows%20%7C%20Linux%20%7C%20Wasm-green?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="MIT License">
  <a href="https://github.com/ykus4/kagura/discussions">
    <img src="https://img.shields.io/github/discussions/ykus4/kagura?style=flat-square&label=discussions" alt="Discussions">
  </a>
  <a href="https://doi.org/10.5281/zenodo.20361447">
    <img src="https://zenodo.org/badge/DOI/10.5281/zenodo.20361447.svg" alt="DOI">
  </a>
</p>

# Kagura

> **LLVM-based code obfuscation and anti-tamper toolkit for mobile, desktop, and WebAssembly targets.**

Built on the **New Pass Manager** (LLVM 17+). Loaded as a pass plugin via `-fpass-plugin` — no LLVM source tree modification required.

**Supported platforms:** iOS · Android · macOS · Windows (MSVC/Clang-CL) · Linux · WebAssembly

> On Windows, `-fpass-plugin` is unavailable (the MSVC-targeted LLVM ships with
> `LLVM_ENABLE_PLUGINS=OFF`). The passes link statically into `kagura-opt` and run over
> IR instead — see [Build from Source](docs/getting-started/build-from-source.md).

## What it protects against

| Threat | Countermeasure |
|:-------|:---------------|
| Static string extraction (`strings`, IDA imports) | XOR / AES string encryption (`kagura-str`, `kagura-str-aes`) |
| Decompiler-readable control flow | CFG flattening + bogus control flow (`kagura-fla`, `kagura-bcf`) |
| Memory editor / GameGuardian value freeze | Per-store/load XOR (`kagura-mvo`, `kagura-pe`) + `Protected<T>` runtime |
| Frida / Substrate dynamic instrumentation | Runtime hook & breakpoint detection (`kagura-anti-debug`) |
| Binary patching (NOP-ing checks) | Per-BB opcode checksums (`kagura-bbcheck`) |
| Import table analysis | External calls via runtime-resolved thunks (`kagura-ci`) |
| Jailbreak / root detection bypass | Mach-O / ELF integrity, Magisk / Zygisk / LSPosed detection |

## Documentation

📚 **Full documentation: [ykus4.github.io/kagura](https://ykus4.github.io/kagura)**

| Topic | Link |
|:------|:-----|
| Install & first build | [Quick Start](https://ykus4.github.io/kagura/getting-started/quick-start/) |
| Every pass (flags, effects, overhead) | [Passes](https://ykus4.github.io/kagura/passes/) |
| JSON policy DSL & strength profiles | [Configuration](https://ykus4.github.io/kagura/configuration/) |
| Xcode / Gradle / Unity / Unreal / Bazel / CMake / CocoaPods / SPM | [Integration](https://ykus4.github.io/kagura/integration/) |
| `Protected<T>` for HP / currency / etc. | [Game Protection](https://ykus4.github.io/kagura/game-protection/) |
| Differential, reproducible, angr / Ghidra / Frida | [Testing & Evaluation](https://ykus4.github.io/kagura/testing/) |

## Quick taste

> **LLVM 22 required for `-mllvm` flags.** On LLVM 17–21, clang parses `-mllvm`
> options before `-fpass-plugin` has loaded the plugin, so every `-kagura-*`
> flag is rejected with *"Unknown command line argument"*. Use the shipped
> `kagura-opt`, or `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`, both
> of which work on all supported versions. See
> [Known issues](https://github.com/ykus4/kagura/blob/main/CHANGELOG.md).

```bash
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura.json \
      -O1 your_file.c -o your_file
```

```json
{ "profile": "BALANCED",
  "passes": { "str": true, "fla": true, "bcf": true, "mvo": true },
  "tuning": { "bcf_prob": 40, "seed": 12345 } }
```

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

## Community

- 💬 **[Discussions](https://github.com/ykus4/kagura/discussions)** — questions, ideas, share your use case
- 🐞 **[Issues](https://github.com/ykus4/kagura/issues)** — bugs and feature requests (templates provided)
- 📚 **[Documentation](https://ykus4.github.io/kagura)** — passes, configuration, integration, testing

## License

MIT — see [LICENSE](LICENSE).
