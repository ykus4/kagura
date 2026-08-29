# Passes

Kagura is built on the LLVM **New Pass Manager**. Each transformation is a
separate pass; you enable them individually via `-kagura-<name>` flags or
through a [JSON policy file](../configuration.md).

Passes are grouped by purpose:

- [**Control Flow**](control-flow.md) — flatten the CFG, inject bogus branches,
  split / reorder basic blocks, redirect calls.
- [**Data Obfuscation**](data.md) — encrypt strings, constants, globals, and
  alloca'd values.
- [**Anti-Analysis**](anti-analysis.md) — detect debuggers / hooking
  frameworks, verify integrity, hide symbols.
- [**Platform-Specific**](platform.md) — ObjC selector / class obfuscation and
  JNI dynamic registration, plus VM virtualization (which is not
  platform-specific; it is documented there for convenience and lives in
  `lib/Transforms/VM/`).
- [**Infrastructure**](infrastructure.md) — DWARF control, config loader,
  symbol map, audit log.

See also:

- [**Before / After Examples**](before-after.md) — what the IR / decompiler
  output actually looks like.
- [**Performance & Size Impact**](performance.md) — measured overhead on a
  representative mobile game module.
- [**Pass Order**](../pass-order.md) — the deterministic pipeline registered
  via `registerOptimizerLastEPCallback`.
- [**Tuning Parameters**](../tuning.md) — `bcf-prob`, `seed`, iteration counts,
  symbol filters.
