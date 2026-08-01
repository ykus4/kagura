; Regression test: FunctionSplitPass used to clone an interior block into a
; helper and then simply erase the original instructions, even when those
; instructions were still referenced — by later instructions of the same block
; (the erase loop ran front-to-back) or by the rest of the function.  The freed
; slots were recycled by the next instruction the pass allocated, so the
; surviving operands silently pointed at unrelated values.  The verifier caught
; that as
;
;   PHI node operands are not the same type as the result!
;
; and at -O1 it segfaulted clang outright.
;
; Values computed in an outlined block are now returned through caller-allocated
; out-parameters: the helper stores into them, the caller reloads immediately
; after the call, and every use outside the block is rewired to that reload.
;
; The `verify` pass in the pipeline is the actual regression check.

; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-fsplit \
; RUN:     -passes='kagura-fsplit,verify' -S %s | %FileCheck %s

; --- Chained live-outs -------------------------------------------------------
; Each block feeds the next one, so every extracted block has exactly one
; live-in and one live-out.  The pass must still outline (obfuscation effect
; preserved) and must thread the values through memory.

; CHECK-LABEL: define i32 @chain(
; CHECK: alloca
; CHECK: call void @__kg_chain_bb
; CHECK: load i32
; CHECK: ret i32

define i32 @chain(i32 %x) {
entry:
  %a = add i32 %x, 1
  br label %block1

block1:
  %b = mul i32 %a, 2
  br label %block2

block2:
  %c = sub i32 %b, 3
  br label %block3

block3:
  %d = add i32 %c, 4
  br label %block4

block4:
  %e = mul i32 %d, 5
  br label %exit

exit:
  ret i32 %e
}

; --- Live-out consumed by a PHI in a successor -------------------------------
; %b is defined in the extracted block and read by the PHI in %join.  The
; incoming value must become the reload, never a dangling reference.

; CHECK-LABEL: define i32 @succ_phi(
; CHECK: call void @__kg_succ_phi_bb
; CHECK: %b.reload = load i32
; CHECK: phi i32 [ %b.reload, %work ]

define i32 @succ_phi(i32 %x, i1 %c) {
entry:
  %a = add i32 %x, 1
  br i1 %c, label %work, label %other

work:
  %b = mul i32 %a, 7
  br label %join

other:
  br label %join

join:
  %m = phi i32 [ %b, %work ], [ 0, %other ]
  %d = sub i32 %m, 3
  br label %tail

tail:
  %e = add i32 %d, 11
  br label %exit

exit:
  ret i32 %e
}

; The outlined helpers must be internal and take the out-parameters by pointer.
; CHECK: define internal void @__kg_
; CHECK-SAME: ptr
