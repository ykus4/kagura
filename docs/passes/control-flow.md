# Control Flow Obfuscation

Source paths are relative to `lib/Transforms/`. Most of these live in `CFG/`,
but three are grouped on this page by what they do to control flow while their
implementation sits with the subsystem they touch. `include/kagura/Passes.h`
records the same mismatch being found and fixed in the headers; this page was
not updated at the time.

| Flag | Pass | Effect | Source |
|:-----|:-----|:-------|:-------|
| `-kagura-fla` | ControlFlowFlattening | Converts CFG into a switch-based state machine (skipped on Wasm — requires unstructured CFG) | `CFG/` |
| `-kagura-bcf` | BogusControlFlow | Injects dead blocks guarded by MBA opaque predicates | `CFG/` |
| `-kagura-ibr` | IndirectBranch | Replaces direct calls with loads from function pointer globals | `CFG/` |
| `-kagura-ci` | CallIndirection | Routes external calls through a runtime-resolved thunk table | `AntiAnalysis/` |
| `-kagura-lt` | LoopTransform | Adds bogus dead counters and opaque invariant branches | `CFG/` |
| `-kagura-fsplit` | FunctionSplit | Extracts interior basic blocks into outlined helper functions | `CFG/` |
| `-kagura-bbs` | BasicBlockSplitting | Splits large BBs at random points to inflate CFG complexity | `CFG/` |
| `-kagura-bbr` | BasicBlockReordering | Shuffles BB layout to confuse linear disassemblers | `CFG/` |
| `-kagura-dci` | DeadCodeInsertion | Inserts unreachable junk blocks to mislead static analysis | `CFG/` |
| `-kagura-elt` | EncryptedLookupTable | Transforms switch statements into XOR-encrypted dispatch tables | `Data/EncryptedLookupTable.cpp` |
| `-kagura-vtp` | VTableProtection | Obfuscates C++ RTTI typeinfo names (`_ZTS*`); records vtable metadata | `ABI/VTableProtection.cpp` |

`-kagura-vtp` is a command-line-only flag: it has no `"passes"` key in a
[JSON policy file](../configuration.md).

See [Before / After Examples](before-after.md) for what the resulting IR looks like.
