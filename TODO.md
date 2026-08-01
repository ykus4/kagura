# TODO — Unimplemented Items

Features that were not implemented in Phase 4 and are candidates for future work.

| ID | Feature | Priority | Notes |
|:---|:--------|:---------|:------|
| — | White-box cryptography | Low | AES/TDES white-box key encoding so the cipher key is never exposed in plaintext even under full memory disclosure |
| — | Device farm tests (iOS/Android real devices) | Low | Run the integration test suite on physical iOS and Android devices via a cloud device farm (e.g. Firebase Test Lab, AWS Device Farm) |
| — | ML/heuristic-based protection target inference | Low | Use static features (cyclomatic complexity, symbol names, call graph centrality) to recommend which functions to protect |
| — | Machine code / backend-level obfuscation | Low | Apply obfuscation at the assembler / MachineFunction level (after instruction selection) for deeper resistance to IR-level static analysis |
| — | MSVC ABI support in VTableProtection | Med | Handle `??_7` / `??_R` MSVC naming conventions in addition to Itanium `_ZTV`/`_ZTS`/`_ZTI`; required for Windows target support |
| — | Regression corpus expansion | Med | 8 entries in tests/regression/corpus/ (crash_00004, eh_bbr, eh_mvo_pe, empty_function, fsplit_phi_successor, phi_heavy_fla, vararg_passthrough, vm_large_function). EH, PHI-heavy, vararg, empty and large-function shapes are now covered; remaining gap is per-pass coverage — most passes still have no dedicated corpus entry |
| ~~A.1~~ | ~~Windows/MSVC build support~~ | ~~High~~ | ~~Implemented: MSVC/Clang-CL CMake flags, Windows CI job (LLVM 17/19), runtime/windows/ stubs (anti_debug, integrity, tamper_response, device_key), vtp-msvc.ll lit test~~ |
| ~~A.2~~ | ~~Swift / Kotlin Native string encryption~~ | ~~High~~ | ~~Implemented: WideStringEncryptionPass extended to detect and XOR-encrypt Swift ($s mangled) and Kotlin Native (.kotlin/kfun: prefix) string constants via module constructors (priority -1 for Swift, 0 for Kotlin)~~ |
| ~~A.3~~ | ~~BCF opaque predicate diversification~~ | ~~High~~ | ~~Implemented: 7 variants (OR/XOR/ADD complement, consecutive-int products, OR-odd, bit round-trip), selected at random per injection site~~ |
| B.1 | Decompiler resistance scoring | Medium | Automate Binary Ninja / Ghidra analysis to produce a quantitative resilience score; feed back into AutoSelectPass |
| B.2 | CallIndirection hot-path cache | Medium | Resolution happens on every call; a per-site cache would reduce overhead on hot paths |
| B.3 | Deterministic obfuscation sessions | Medium | Given the same seed key and IR, produce a bit-identical output binary to ensure CI reproducibility |
| ~~C.1~~ | ~~WebAssembly backend support~~ | ~~Low~~ | ~~Implemented: `isWasmTarget()` helper + early-exit guards in AntiDebug, PointerAuth, AntiTamper, VMObfuscation, ControlFlowFlattening; AutoSelect skips FLA on Wasm; LIT test wasm-pass-filter.ll~~ |
| C.2 | Automated MBA expression generation | Low | Current SUB uses fixed patterns; auto-generate Z3-verified equivalent expressions for richer MBA substitution |
