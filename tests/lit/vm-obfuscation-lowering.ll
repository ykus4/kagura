; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=7 -kagura-vm \
; RUN:     -passes='function(kagura-vm),verify' -S %s | %FileCheck %s

; The shapes VMObfuscation must actually lower, not silently NOP out.
;
; PHI nodes, direct calls, GEPs and allocas all used to fall through to
; "emit OP_NOP and carry on", which produced bytecode that computed nothing.
; For @sum_loop that was not merely wrong: the loop condition was dropped, the
; lowered branch pushed a literal 0, the VM took the same edge forever, and the
; program hung before its first line of output.
;
; A PHI is lowered as a copy on each incoming edge and a call needs the callee's
; address, which the byte stream cannot hold — so a successful lowering of this
; module is observable as a bytecode blob plus a relocation pool global.

; CHECK: @kagura_vm_bc_
; CHECK-DAG: @kagura_vm_pool_{{[0-9]+}} = private constant [1 x i64] [i64 ptrtoint (ptr @scale to i64)]

; CHECK-LABEL: define i32 @scale(
; CHECK: call i64 @kagura_vm_execute(
; CHECK-NOT: phi

; CHECK-LABEL: define i32 @sum_loop(
; CHECK: call i64 @kagura_vm_execute(
; CHECK-NOT: phi

target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"

define i32 @scale(i32 %x) {
entry:
  %m = mul nsw i32 %x, 3
  ret i32 %m
}

; A counted loop with two PHIs plus a load through a GEP and a direct call.
define i32 @sum_loop(ptr %arr, i32 %n) {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %loop ]
  %acc = phi i32 [ 0, %entry ], [ %acc.next, %loop ]
  %p = getelementptr inbounds i32, ptr %arr, i32 %i
  %v = load i32, ptr %p, align 4
  %s = call i32 @scale(i32 %v)
  %acc.next = add nsw i32 %acc, %s
  %i.next = add nsw i32 %i, 1
  %done = icmp slt i32 %i.next, %n
  br i1 %done, label %loop, label %exit

exit:
  ret i32 %acc.next
}
