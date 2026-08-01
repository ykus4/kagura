# Pass Order

The plugin auto-registers passes via `registerOptimizerLastEPCallback`, so the
ordering below runs **after** the standard `-O1` / `-O2` optimizations.
Ordering matters: e.g. `kagura-tamper` measures function checksums **before**
CFG-mutating passes change the IR.

`kagura-autoselect`, when enabled, runs ahead of everything below: it annotates
each function with per-pass decisions that the passes then read, and can only
narrow the set the flags already enabled.

```
-O1 / -O2 (standard optimizations first)
  0. (config load)           → JSON policy applied before the pipeline is built,
                               not as a pass — see configuration.md
  2. kagura-ci               → external call indirection
  3. kagura-pac              → pointer auth
  4. kagura-str[-aes]        → encrypt narrow strings
  5. kagura-wstr             → encrypt wide strings / CFString
  5a. kagura-string-split    → fragment long string literals (after str/str-aes)
  6. kagura-tamper           → integrity hash (before CFG changes)
  7. kagura-objc             → ObjC selector/class obfuscation
  8. kagura-jni              → JNI dynamic registration
  9. kagura-anti-debug       → anti-analysis checks
 10. kagura-fsplit           → function splitting
 11. kagura-genc             → encrypt globals
 12. kagura-honey            → inject honey values and fake stubs
 13. kagura-sv               → hide symbols
 14. kagura-fla              → CFG flattening        ┐
 15. kagura-bcf              → bogus control flow    │
 16. kagura-bbs              → BB splitting          │
 17. kagura-bbr              → BB reordering         │
 18. kagura-dci              → dead code insertion   │
 19. kagura-sub              → instruction subst.    │ function passes
 20. kagura-cse-break        → break CSE re-folding  │
 21. kagura-co               → constant obfuscation  │
 21. kagura-mvo              → memory value XOR      │
 22. kagura-pe               → pointer encryption    │
 23. kagura-telemetry        → telemetry probes      │
 24. kagura-bbcheck          → BB checksum guards    │
 25. kagura-elt              → encrypted lookup tbl  ┘
 26. kagura-dwarf-control    → DWARF strip/obfuscate (if -kagura-dwarf != keep)
 27. kagura-vtp              → RTTI/vtable protection
 28. kagura-symmap           → emit JSON symbol map  (if -kagura-symmap)
 29. kagura-audit            → emit audit log        (if -kagura-audit)
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
