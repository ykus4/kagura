# Pass Order

The plugin auto-registers passes via `registerOptimizerLastEPCallback`, so the
ordering below runs **after** the standard `-O1` / `-O2` optimizations.
Ordering matters: e.g. `kagura-tamper` measures function checksums **before**
CFG-mutating passes change the IR.

`kagura-autoselect`, when enabled, runs ahead of everything below: it annotates
each function with per-pass decisions that the passes then read, and can only
narrow the set the flags already enabled.

The module and function blocks below are generated: `Plugin.cpp` expands
`include/kagura/PassRegistry.def` row by row, so the pipeline order *is* the
row order in that file and the two cannot drift.

```
-O1 / -O2 (standard optimizations first)
  0. (config load)           → JSON policy applied before the pipeline is built,
                               not as a pass — see configuration.md
  1. kagura-ci               → external call indirection
  2. kagura-pac              → pointer auth
  3. kagura-str              → encrypt narrow strings (XOR)
  4. kagura-str-aes          → encrypt narrow strings (AES-128-CTR)
  5. kagura-wstr             → encrypt wide strings / CFString
  6. kagura-string-split     → fragment long string literals (after str/str-aes)
  7. kagura-tamper           → integrity hash (before CFG changes)
  8. kagura-objc             → ObjC selector/class obfuscation
  9. kagura-jni              → JNI dynamic registration
 10. kagura-anti-debug       → anti-analysis checks
 11. kagura-fsplit           → function splitting
 12. kagura-genc             → encrypt globals
 13. kagura-honey            → inject honey values and fake stubs
 14. kagura-sv               → hide symbols
 15. kagura-fla              → CFG flattening        ┐
 16. kagura-bcf              → bogus control flow    │
 17. kagura-sub              → instruction subst.    │
 18. kagura-cse-break        → break CSE re-folding  │
 19. kagura-co               → constant obfuscation  │
 20. kagura-vm               → function virtualization
 21. kagura-ibr              → indirect branching    │ function passes
 22. kagura-lt               → loop transformation   │
 23. kagura-bbr              → BB reordering         │
 24. kagura-dci              → dead code insertion   │
 25. kagura-bbs              → BB splitting          │
 26. kagura-mvo              → memory value XOR      │
 27. kagura-pe               → pointer encryption    │
 28. kagura-telemetry        → telemetry probes      │
 29. kagura-bbcheck          → BB checksum guards    │
 30. kagura-elt              → encrypted lookup tbl  ┘
 31. kagura-dwarf-control    → DWARF strip/obfuscate (if -kagura-dwarf != keep)
 32. kagura-vtp              → RTTI/vtable protection
 33. kagura-symmap           → emit JSON symbol map  (if -kagura-symmap)
 34. kagura-audit            → emit audit log        (if -kagura-audit)
```

## Manual ordering with `opt`

Use the same order if you drive the plugin from `opt` instead of letting the
auto-registration handle it:

```bash
opt --load-pass-plugin=KaguraObfuscator.dylib \
    -passes="kagura-str,function(kagura-fla,kagura-bcf,kagura-sub)" \
    input.bc -o output.bc
```

Module-level passes (config, ci, pac, str, …) appear at the top level;
function-level passes are wrapped in `function(...)`.
