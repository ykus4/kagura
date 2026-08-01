; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=29 -kagura-co \
; RUN:     -passes='kagura-co,verify' -S %s | %FileCheck %s

; Constant obfuscation replaces integer constant operands with MBA identities
; that evaluate to the same value.  Only ~30% of constants are rewritten, so the
; seed is pinned to make the choice deterministic; with seed 29 all three
; constants below are rewritten.
;
; Regression guard: the identities are built from a constant operand, so a
; constant-folding IRBuilder collapses them straight back to the original
; constant and the pass becomes a silent no-op.  The CHECK-NOT lines below fire
; again if that ever regresses.

; CHECK: define i32 @get_magic
; The `((V | ~V) & V)` identity for 42.
; CHECK: %[[NOT:[a-z0-9.]+]] = xor i32 42, -1
; CHECK: %[[OR:[a-z0-9.]+]] = or i32 42, %[[NOT]]
; CHECK: %[[AND:[a-z0-9.]+]] = and i32 %[[OR]], 42
; CHECK: ret i32 %[[AND]]

define i32 @get_magic() {
; CHECK-NOT: ret i32 42
  ret i32 42
}

define i32 @use_constants(i32 %x) {
  ; The `(V + R) - R` identity for 100 ...
  ; CHECK: %[[A1:[a-z0-9.]+]] = add i32 100, [[R:-?[0-9]+]]
  ; CHECK: %[[A2:[a-z0-9.]+]] = sub i32 %[[A1]], [[R]]
  ; CHECK: add i32 %x, %[[A2]]
  ; CHECK-NOT: add i32 %x, 100
  %a = add i32 %x, 100
  ; ... and the `(V ^ R) ^ R` identity for 7.
  ; CHECK: %[[X1:[a-z0-9.]+]] = xor i32 7, [[K:-?[0-9]+]]
  ; CHECK: %[[X2:[a-z0-9.]+]] = xor i32 %[[X1]], [[K]]
  ; CHECK: mul i32 %{{.*}}, %[[X2]]
  ; CHECK-NOT: mul i32 %a, 7
  %b = mul i32 %a, 7
  ret i32 %b
}
