; RUN: %opt -passes=verify -S %s -o %t.plain.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.lt.ll
; RUN: not diff %t.plain.ll %t.lt.ll
; RUN: %FileCheck %s --input-file=%t.lt.ll

; This file used to assert `define i32 @sum_loop` / `br i1` / `ret i32`, all
; three of which are already present in the input below — `opt -passes=verify`
; alone passed it, so a pass that declined every loop was indistinguishable
; from a working one.
;
; LoopTransformPass draws its three effects (bogus counter 80 %, opaque
; invariant branch 60 %, induction-variable split 40 %) once per *function*,
; so which of them fires for a given -kagura-seed moves whenever anything else
; changes the PRNG draw sequence.  Rather than pin a seed that happens to
; produce a particular shape, this test asserts:
;
;   1. the module is not the module the same printer emits with no kagura pass
;      in the pipeline (`not diff`), and
;   2. at least one `lt.`-prefixed value — the pass's own naming, shared with
;      loop-transform-phi-order.ll — appears.
;
; Four loop-bearing functions make "every effect declined everywhere" a
; (0.2 * 0.4 * 0.6)^4 ≈ 5e-6 event, so neither check depends on the seed.
; loop-transform-phi-order.ll is where the exact split shape is pinned.

; One DAG group: which function the pass chose to touch is a draw, so none of
; these may impose an order on the others.
; CHECK-DAG: define i32 @sum_loop
; CHECK-DAG: define i32 @product_loop
; CHECK-DAG: define i32 @xor_loop
; CHECK-DAG: define i32 @count_loop
; CHECK-DAG: %lt.

define i32 @sum_loop(i32 %n) {
entry:
  br label %loop

loop:
  %i   = phi i32 [ 0, %entry ], [ %i1, %loop ]
  %sum = phi i32 [ 0, %entry ], [ %sum1, %loop ]
  %sum1 = add i32 %sum, %i
  %i1   = add i32 %i, 1
  %cond = icmp slt i32 %i1, %n
  br i1 %cond, label %loop, label %exit

exit:
  ret i32 %sum
}

define i32 @product_loop(i32 %n) {
entry:
  br label %loop

loop:
  %i    = phi i32 [ 1, %entry ], [ %i1, %loop ]
  %prod = phi i32 [ 1, %entry ], [ %prod1, %loop ]
  %prod1 = mul i32 %prod, %i
  %i1    = add i32 %i, 1
  %cond  = icmp slt i32 %i1, %n
  br i1 %cond, label %loop, label %exit

exit:
  ret i32 %prod
}

define i32 @xor_loop(i32 %n) {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %i1, %loop ]
  %h = phi i32 [ 5381, %entry ], [ %h1, %loop ]
  %h1 = xor i32 %h, %i
  %i1 = add i32 %i, 1
  %cond = icmp slt i32 %i1, %n
  br i1 %cond, label %loop, label %exit

exit:
  ret i32 %h
}

define i32 @count_loop(i32 %n) {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %i1, %loop ]
  %c = phi i32 [ 0, %entry ], [ %c1, %loop ]
  %c1 = add i32 %c, 2
  %i1 = add i32 %i, 1
  %cond = icmp slt i32 %i1, %n
  br i1 %cond, label %loop, label %exit

exit:
  ret i32 %c
}
