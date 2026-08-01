; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-vm \
; RUN:     -passes='function(kagura-vm),verify' -S %s | %FileCheck %s

; VMObfuscationPass virtualises annotated functions.
; After the pass:
;   - An encrypted bytecode blob global (kagura_vm_bc_) must exist.
;   - @vm_add's body must be replaced by a trampoline that decrypts the blob
;     and calls kagura_vm_execute.
;   - The original add instruction must be gone.

; CHECK: @[[BC:kagura_vm_bc_[0-9]+]] = private global
; CHECK: @kagura_vm_key_
; CHECK: define i32 @vm_add(i32 %a, i32 %b)
; CHECK-NOT: add nsw i32 %a, %b
; CHECK: call i64 @kagura_vm_execute(ptr @[[BC]],
; CHECK: ret i32

; Function annotated for VM protection.  "kagura_vm" is 9 characters plus the
; NUL terminator, so the array type must be [10 x i8] — getting this wrong makes
; the module fail to parse and the test vacuously "pass" on an empty input.
@llvm.global.annotations = appending global
  [1 x { i8*, i8*, i8*, i32, i8* }]
  [{ i8*, i8*, i8*, i32, i8* }
    { i8* bitcast (i32 (i32, i32)* @vm_add to i8*),
      i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str_ann, i32 0, i32 0),
      i8* getelementptr inbounds ([7 x i8], [7 x i8]* @.file, i32 0, i32 0),
      i32 1,
      i8* null }]

@.str_ann = private unnamed_addr constant [10 x i8] c"kagura_vm\00"
@.file = private unnamed_addr constant [7 x i8] c"test.c\00"

define i32 @vm_add(i32 %a, i32 %b) {
entry:
  %r = add nsw i32 %a, %b
  ret i32 %r
}
