; RUN: %opt -load-pass-plugin=%kagura_plugin \
; RUN:     -passes='kagura-cse-break,verify' -S %s | %FileCheck %s

; The CSE-break pass gives one user of a shared SSA value its own recomputation
; of that value, laundered through a random mask that cancels at the result:
;
;   %cse.mask   = add i32 %a, R
;   %cse.break  = add i32 %cse.mask, %b     ; == %a + %b + R
;   %cse.unmask = sub i32 %cse.break, R     ; == %a + %b
;
; This file used to check for two verbatim `add i32 %a, %b` instructions, which
; is what a plain re-duplication produces — and a plain re-duplication is what
; `opt -passes=early-cse` merges straight back, so the pass stopped emitting
; one.  The mask is what makes the clone survive value numbering, so the mask
; is what this test now names.  The mask constant itself is a random draw, so
; it is matched as a pattern and captured, not spelled out.

; CHECK-LABEL: define i32 @arith
; CHECK:      %cse.mask = add i32 %a, [[R:-?[0-9]+]]
; CHECK-NEXT: %cse.break = add i32 %cse.mask, %b
; CHECK-NEXT: %cse.unmask = sub i32 %cse.break, [[R]]
; The rewritten user must consume the laundered value, not the original %t.
; CHECK-NEXT: mul i32 %cse.unmask, 2

define i32 @arith(i32 %a, i32 %b) {
entry:
  %t = add i32 %a, %b
  %x = mul i32 %t, 2
  %y = sub i32 %t, 3
  %z = add i32 %x, %y
  ret i32 %z
}

; Negative test: a single-use binop should not be duplicated (nothing to break).

; CHECK-LABEL: define i32 @single_use
; CHECK-NOT: cse.
; CHECK: ret i32

define i32 @single_use(i32 %a, i32 %b) {
entry:
  %u = and i32 %a, %b
  ret i32 %u
}
