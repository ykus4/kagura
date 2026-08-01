; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=7 -kagura-vm \
; RUN:     -passes='function(kagura-vm),verify' -S %s | %FileCheck %s

; Lowering is all-or-nothing.  The pass used to emit OP_NOP for anything it did
; not recognise and virtualise the function anyway, so a shape it could not
; express turned into bytecode that computed the wrong answer or looped forever.
; Every function here must come out byte-for-byte untouched instead.

; CHECK-NOT: kagura_vm_bc_
; CHECK-NOT: kagura_vm_execute

target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"

declare i32 @printf(ptr, ...)
declare <4 x i32> @llvm.smax.v4i32(<4 x i32>, <4 x i32>)

; Floating point has no VM representation.
; CHECK: fadd double
define double @uses_fp(double %a, double %b) {
  %r = fadd double %a, %b
  ret double %r
}

; Neither do vectors.
; CHECK: call <4 x i32> @llvm.smax
define <4 x i32> @uses_vector(<4 x i32> %a, <4 x i32> %b) {
  %r = call <4 x i32> @llvm.smax.v4i32(<4 x i32> %a, <4 x i32> %b)
  ret <4 x i32> %r
}

; A variadic callee's ABI does not match the interpreter's fixed
; all-arguments-are-uint64 prototypes.
; CHECK: call i32 (ptr, ...) @printf
define i32 @calls_variadic(ptr %fmt, i32 %v) {
  %r = call i32 (ptr, ...) @printf(ptr %fmt, i32 %v)
  ret i32 %r
}

; An indirect callee has no link-time address to put in the relocation pool.
; CHECK: call i32 %fp(i32 %x)
define i32 @calls_indirect(ptr %fp, i32 %x) {
  %r = call i32 %fp(i32 %x)
  ret i32 %r
}

; i128 does not fit a VM slot.
; CHECK: add i128
define i128 @wide_int(i128 %a, i128 %b) {
  %r = add i128 %a, %b
  ret i128 %r
}

; A dynamically sized alloca has no fixed offset in the frame arena.
; CHECK: alloca i8, i64 %n
define i64 @dynamic_alloca(i64 %n) {
  %p = alloca i8, i64 %n, align 1
  %i = ptrtoint ptr %p to i64
  ret i64 %i
}

; An aggregate held in a register is not a 64-bit slot.
; CHECK: extractvalue
define i32 @uses_aggregate({ i32, i32 } %s) {
  %r = extractvalue { i32, i32 } %s, 0
  ret i32 %r
}
