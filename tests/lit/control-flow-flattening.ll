; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-fla \
; RUN:     -passes='kagura-fla,verify' -S %s | %FileCheck %s \
; RUN:     --implicit-check-not="br i1"

; ControlFlowFlatteningPass rewrites the CFG into a state machine: every
; original block stores its successor's state key and jumps back to a single
; dispatcher, which switches on the key.  --implicit-check-not asserts that no
; conditional branch survives anywhere — every `br i1` must have been turned
; into a `select` feeding the state variable.
;
; Note the block layout: the dispatcher (kagura.preloop / kagura.loop) is
; *appended* after the original blocks rather than spliced in after entry, so
; in the printed IR the `ret` blocks come before the `switch`.  Only the entry
; block's position is fixed by LLVM, so this ordering is legal; the CHECKs below
; follow it.

; CHECK: define i32 @classify(i32 %x)
; CHECK: entry:
; CHECK: %[[SW:[a-z0-9._]+]] = alloca i32
; CHECK: %[[C0:[a-z0-9._]+]] = icmp slt i32 %x, 0
; CHECK: %[[INIT:[a-z0-9._]+]] = select i1 %[[C0]], i32 [[NEG:-?[0-9]+]], i32 [[CHK0:-?[0-9]+]]
; CHECK: store i32 %[[INIT]], ptr %[[SW]]
; CHECK: br label %kagura.preloop

; Original conditional blocks now select a state key instead of branching.
; CHECK: check_zero:
; CHECK: %[[S1:[a-z0-9._]+]] = select i1 %{{.*}}, i32 [[ZERO:-?[0-9]+]], i32 [[CHK1:-?[0-9]+]]
; CHECK: store i32 %[[S1]], ptr %[[SW]]
; CHECK: br label %kagura.loopend

; CHECK: check_small:
; CHECK: %[[S2:[a-z0-9._]+]] = select i1 %{{.*}}, i32 [[ONE:-?[0-9]+]], i32 [[TWO:-?[0-9]+]]
; CHECK: store i32 %[[S2]], ptr %[[SW]]
; CHECK: br label %kagura.loopend

; All four returns survive.
; CHECK: ret i32 -1
; CHECK: ret i32 0
; CHECK: ret i32 1
; CHECK: ret i32 2

; The dispatcher, with one case per reachable original block.
; CHECK: kagura.loop:
; CHECK: %[[V:[a-z0-9._]+]] = load i32, ptr %[[SW]]
; CHECK: switch i32 %[[V]], label %kagura.default [
; CHECK-DAG: i32 [[CHK0]], label %check_zero
; CHECK-DAG: i32 [[CHK1]], label %check_small
; CHECK-DAG: i32 [[NEG]], label %ret_neg
; CHECK-DAG: i32 [[ZERO]], label %ret_zero
; CHECK-DAG: i32 [[ONE]], label %ret_one
; CHECK-DAG: i32 [[TWO]], label %ret_two
; CHECK: kagura.default:
; CHECK: unreachable

define i32 @classify(i32 %x) {
entry:
  %cmp0 = icmp slt i32 %x, 0
  br i1 %cmp0, label %ret_neg, label %check_zero

check_zero:
  %cmp1 = icmp eq i32 %x, 0
  br i1 %cmp1, label %ret_zero, label %check_small

check_small:
  %cmp2 = icmp slt i32 %x, 10
  br i1 %cmp2, label %ret_one, label %ret_two

ret_neg:
  ret i32 -1

ret_zero:
  ret i32 0

ret_one:
  ret i32 1

ret_two:
  ret i32 2
}
