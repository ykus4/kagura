; RUN: %opt -passes=verify -S %s -o %t.plain.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=29 \
; RUN:     -passes='kagura-co,verify' -S %s -o %t.co.ll
; RUN: not diff %t.plain.ll %t.co.ll
; RUN: %FileCheck %s --input-file=%t.co.ll

; Constant obfuscation replaces integer constant operands with MBA identities
; that evaluate to the same value.
;
; Regression guard: every identity is built from a constant operand, so a
; constant-folding IRBuilder collapses it straight back to the original
; constant and the pass becomes a silent no-op that still reports success.
; The `co.`-prefixed values below are the evidence that the expression was
; emitted rather than folded — if the pass regresses, there are none of them
; and `not diff` fails as well.
;
; What this file does NOT do any more is name which identity was chosen for
; which constant.  The pass picks one of four at random and rewrites a constant
; with probability 30 %, so pinning that made the test a statement about the
; PRNG draw sequence: it broke when the PRNG moved to per-module seeding, with
; nothing about the pass having changed.  Sixteen candidate constants make
; "not one of them was rewritten" a 0.7^16 ≈ 0.3 % event; the seed is pinned
; only so a failure is reproducible.

; CHECK-DAG: define i32 @get_magic
; CHECK-DAG: define i32 @use_constants
; CHECK-DAG: %co.

define i32 @get_magic() {
  ret i32 42
}

define i32 @use_constants(i32 %x) {
  %a = add i32 %x, 100
  %b = mul i32 %a, 7
  %c = xor i32 %b, 3735928559
  %d = or  i32 %c, 61680
  %e = and i32 %d, 2004318071
  %f = sub i32 %e, 271828
  %g = add i32 %f, 314159
  %h = mul i32 %g, 11
  %i = xor i32 %h, 22
  %j = or  i32 %i, 33
  %k = and i32 %j, 44
  %l = sub i32 %k, 55
  %m = add i32 %l, 66
  %n = mul i32 %m, 77
  %o = xor i32 %n, 88
  %p = or  i32 %o, 99
  ret i32 %p
}
