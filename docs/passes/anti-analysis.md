# Anti-Analysis

Source: `lib/Transforms/AntiAnalysis/`

| Flag | Pass | Effect |
|:-----|:-----|:-------|
| `-kagura-anti-debug` | AntiDebug | ptrace, Frida port, `/proc/maps`, hook, breakpoint, emulator checks (iOS/Android); IsDebuggerPresent, NtQueryInformationProcess, PEB heap flags (Windows); skipped on Wasm |
| `-kagura-tamper` | AntiTamper | FNV-1a function checksums + jailbreak/root detection at startup |
| `-kagura-pac` | PointerAuth | Software CFI via XOR-tagged function pointer globals |
| `-kagura-sv` | SymbolVisibility | Sets non-public symbols to hidden; strips from dynamic symtab |
| `-kagura-honey` | HoneyValue | Injects decoy secret globals and fake security-stub functions |
| `-kagura-bbcheck` | BasicBlockChecksum | Emits a `kagura_bb_check(block_id, expected)` call site at the top of each block, branching to the tamper hook on a zero return. **Scaffolding only** — see below |
| `-kagura-telemetry` | Telemetry | Inserts `kagura_telemetry_event(id)` probes at function entry for cheat detection. `id` is the FNV-1a-32 of the function name; the shipped implementation is a weak no-op you override |

Most anti-analysis passes call into `libkagura_runtime.a` at run time — see
[Runtime Library](../runtime.md) for the symbol matrix and the list of directly
callable checks.

## `-kagura-bbcheck` detects nothing as shipped

`runtime/core/bb_check.c` defines `kagura_bb_check` as a **weak,
always-passing stub** — it ignores both arguments and returns "intact". Every
branch the pass inserts is therefore taken the safe way, on every run. The flag
costs code size and adds no anti-patching capability by itself.

That is deliberate rather than unfinished, because the data the pass hands over
cannot be verified at run time:

- `expected` is FNV-1a over the **LLVM IR opcodes** of the block, computed
  before instruction selection. IR opcodes do not exist in the emitted binary,
  so there is nothing at run time to recompute the hash from.
- `block_id` is a per-function counter that restarts at 1 in each function, so
  it is not a unique key and collides across functions.

Faking a check here — hashing an arbitrary memory range and calling it
verification — would be strictly worse than the stub: it would look like
protection while providing none and adding false positives.

Overriding the weak symbol is possible, but a correct override needs a trusted
table keyed by something stable, which means the pass first has to emit
post-codegen byte ranges (address + length + hash of the actual machine code).
That work is not done. Until it is, use `-kagura-tamper`, which hashes the
loaded text section and does work today.
