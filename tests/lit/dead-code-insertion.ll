; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-dci-prob=100 \
; RUN:     -passes='kagura-dci,verify' -S %s | %FileCheck %s

; Dead code insertion adds unreachable blocks containing junk arithmetic.
;
; -kagura-dci-prob=100 rather than the default 40: with the default, whether a
; block is picked is a draw from the module PRNG, so this test passed or failed
; according to where the draw sequence happened to be — it broke when the PRNG
; moved to per-module seeding, with nothing about the pass having changed.
; Turning the probability up makes the insertion a property of the pass.
;
; `unreachable` alone was the whole assertion, and `unreachable` is a terminator
; the input could perfectly well have contained on its own; the dci.* names are
; the pass's own and cannot come from anywhere else.

; CHECK: define i32 @compute
; CHECK-DAG: %dci.slot
; CHECK-DAG: %dci.v
; CHECK-DAG: unreachable
; CHECK-DAG: ret i32

define i32 @compute(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  br label %next

next:
  %mul = mul i32 %sum, %b
  br label %done

done:
  ret i32 %mul
}
