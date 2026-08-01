; Regression test: LoopTransformPass used to anchor the induction-variable
; recombination sequence at `PhiHigh->getNextNode()`, i.e. immediately after the
; two PHIs it had just created.  When the loop header carried *other* PHIs (the
; original induction variable, reductions, ...) those stayed below the newly
; emitted zext/shl/or, producing
;
;   PHI nodes not grouped at top of basic block!
;
; which aborts the verifier and crashes clang during ISel at -O1.  The sequence
; now goes to the header's first insertion point, i.e. after every PHI.
;
; The `verify` pass in the pipeline is the actual regression check: it fails the
; RUN line if the malformed ordering ever comes back.

; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-lt \
; RUN:     -passes='function(kagura-lt),verify' -S %s | %FileCheck %s

; The counter split must still happen (the pass has to keep obfuscating) ...
; CHECK-LABEL: define i32 @sum_loop
; CHECK: alloca i64

; ... and every PHI in the header must sit above the first non-PHI instruction.
; CHECK-LABEL: loop:
; CHECK-NEXT: %lt.i_low = phi i32
; CHECK-NEXT: %lt.i_high = phi i32
; CHECK-NEXT: %sum = phi i32
; CHECK-NEXT: %prod = phi i32
; CHECK-NEXT: %lt.high_ext = zext i32 %lt.i_high to i64
; CHECK-NOT: phi
; CHECK: %lt.combined = or i64
; CHECK: ret i32

define i32 @sum_loop(i32 %n) {
entry:
  br label %loop

loop:
  %i    = phi i32 [ 0, %entry ], [ %i1,    %loop ]
  %sum  = phi i32 [ 0, %entry ], [ %sum1,  %loop ]
  %prod = phi i32 [ 1, %entry ], [ %prod1, %loop ]
  %sum1  = add i32 %sum, %i
  %prod1 = mul i32 %prod, 3
  %i1    = add i32 %i, 1
  %cond  = icmp slt i32 %i1, %n
  br i1 %cond, label %loop, label %exit

exit:
  %r = add i32 %sum, %prod
  ret i32 %r
}

; A loop whose step is computed inside the latch cannot be split: the
; recombination lives at the top of the header and would not be dominated by
; the step.  The pass must decline instead of emitting invalid IR.

; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-lt \
; RUN:     -passes='function(kagura-lt),verify' -S %s | %FileCheck %s \
; RUN:     --check-prefix=LATCHSTEP

; LATCHSTEP-LABEL: define i32 @latch_defined_step
; LATCHSTEP-NOT: lt.combined
; LATCHSTEP: ret i32

define i32 @latch_defined_step(i32 %n, ptr %p) {
entry:
  br label %head

head:
  %i = phi i32 [ 0, %entry ], [ %i.next, %latch ]
  %c = icmp slt i32 %i, %n
  br i1 %c, label %latch, label %exit

latch:
  %s = load i32, ptr %p, align 4
  %i.next = add i32 %i, %s
  br label %head

exit:
  ret i32 %i
}
