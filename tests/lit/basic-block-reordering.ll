; RUN: %opt -passes=verify -S %s -o %t.plain.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 \
; RUN:     -passes='kagura-bbr,verify' -S %s -o %t.bbr.ll
; RUN: not diff %t.plain.ll %t.bbr.ll
; RUN: %FileCheck %s --input-file=%t.bbr.ll

; This file used to assert only `switch i32` / `ret i32`, both of which are
; already in the input below, so `opt -passes=verify` alone satisfied it: a BBR
; that reordered nothing — or was never registered at all — passed.  This is
; BBR's only structural test, so that left the pass entirely unguarded.
;
; The assertion is now differential rather than positional.  %t.plain.ll is the
; same module printed by the same printer with no kagura pass in the pipeline,
; so the only thing that can make `diff` disagree is BBR having moved a block.
; Pinning the expected permutation instead would work, but it would have to be
; re-pinned every time an unrelated change shifts the PRNG draw sequence — as
; the per-module reseeding in Utils.cpp just did.
;
; The nine shufflable blocks make "the shuffle happened to be the identity"
; a 1-in-9! event rather than the 1-in-24 it would be with three cases, so the
; check does not depend on the seed either.
;
; -kagura-seed is pinned only so a failure is reproducible.

; CHECK-LABEL: define i32 @multi_block
; CHECK: switch i32
; The blocks must all still be there, in whatever order the shuffle produced.
; CHECK-DAG: case0:
; CHECK-DAG: case1:
; CHECK-DAG: case2:
; CHECK-DAG: case3:
; CHECK-DAG: case4:
; CHECK-DAG: case5:
; CHECK-DAG: case6:
; CHECK-DAG: case7:
; CHECK-DAG: default:

define i32 @multi_block(i32 %x) {
entry:
  switch i32 %x, label %default [
    i32 0, label %case0
    i32 1, label %case1
    i32 2, label %case2
    i32 3, label %case3
    i32 4, label %case4
    i32 5, label %case5
    i32 6, label %case6
    i32 7, label %case7
  ]

case0:
  ret i32 10

case1:
  ret i32 20

case2:
  ret i32 30

case3:
  ret i32 40

case4:
  ret i32 50

case5:
  ret i32 60

case6:
  ret i32 70

case7:
  ret i32 80

default:
  ret i32 -1
}
