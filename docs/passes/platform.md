# Platform-Specific Passes

| Flag | Pass | Target | Source |
|:-----|:-----|:-------|:-------|
| `-kagura-objc` | ObjCObfuscation | iOS — obfuscates ObjC selector and class names in IR metadata | `lib/Transforms/Platform/` |
| `-kagura-jni`  | JNIObfuscation  | Android — converts static `Java_*` to dynamic `RegisterNatives` | `lib/Transforms/Platform/` |
| `-kagura-vm`   | VMObfuscation   | Virtualizes function bodies into a custom stack-based VM bytecode | `lib/Transforms/VM/` |

`kagura-vm` is documented here for convenience, but it is not
platform-specific and does not live in `Platform/` — it works on every target
and has its own subsystem.

## `kagura-vm`

The VM pass takes selected functions and compiles them down to a custom
stack-based VM bytecode that is interpreted at run time by
`kagura_vm_execute` (in `libkagura_runtime.a`). The original native code is
removed from the binary entirely.

Annotate the functions you want virtualized:

```c
__attribute__((annotate("kagura_vm")))
int verify_license(const char *key) {
    // Compiled to VM bytecode — no readable IR or machine code in the binary
    ...
}
```

VM-virtualized functions are 10–50× slower than native — reserve the pass for
**small, rarely-called** functions like license checks, key derivation, or
crypto init.
