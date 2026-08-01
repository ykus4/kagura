; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-vm \
; RUN:     -passes='function(kagura-vm),verify' -S %s | %FileCheck %s

; VMObfuscationPass virtualises annotated functions.
; After the pass:
;   - An encrypted bytecode blob global (kagura_vm_bc_) must exist, and it must
;     be a *constant*.  The interpreter decrypts each byte as it fetches it; the
;     blob used to be a mutable global that the trampoline XOR-decrypted in
;     place on entry, so the second call re-encrypted it and ran garbage.
;   - @vm_add's body must be replaced by a trampoline that packs the arguments
;     and calls kagura_vm_execute with the relocation pool and the key.
;   - The original add instruction must be gone.
;   - So must the inferred `memory(none)`: the trampoline calls into the
;     interpreter, and keeping the attribute lets later passes fold the call.

; CHECK: @[[BC:kagura_vm_bc_[0-9]+]] = private constant
; CHECK: @[[KEY:kagura_vm_key_[0-9]+]] = private constant i64
; CHECK-NOT: memory(none)
; CHECK: define i32 @vm_add(i32 %a, i32 %b)
; CHECK-NOT: add nsw i32 %a, %b
; CHECK-NOT: store i8
; CHECK: %[[K:key]] = load i64, ptr @[[KEY]]
; CHECK: call i64 @kagura_vm_execute(ptr @[[BC]], i32 {{[0-9]+}}, ptr %vmargs, i32 2, ptr null, i32 0, i64 %[[K]])
; CHECK: ret i32

; Function annotated for VM protection.  "kagura_vm" is 9 characters plus the
; NUL terminator, so the array type must be [10 x i8] — getting this wrong makes
; the module fail to parse and the test vacuously "pass" on an empty input.
@llvm.global.annotations = appending global
  [1 x { ptr, ptr, ptr, i32, ptr }]
  [{ ptr, ptr, ptr, i32, ptr }
    { ptr @vm_add,
      ptr @.str_ann,
      ptr @.file,
      i32 1,
      ptr null }]

@.str_ann = private unnamed_addr constant [10 x i8] c"kagura_vm\00"
@.file = private unnamed_addr constant [7 x i8] c"test.c\00"

define i32 @vm_add(i32 %a, i32 %b) memory(none) {
entry:
  %r = add nsw i32 %a, %b
  ret i32 %r
}
