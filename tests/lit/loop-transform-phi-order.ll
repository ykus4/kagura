; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=1 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run1.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=2 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run2.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=3 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run3.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=4 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run4.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=5 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run5.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=6 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run6.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=7 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run7.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=8 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run8.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=9 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run9.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=10 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run10.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=11 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run11.ll
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=12 \
; RUN:     -passes='function(kagura-lt),verify' -S %s -o %t.run12.ll
; RUN: cat %t.run*.ll | %FileCheck %s
; RUN: %FileCheck %s --input-file=%t.run1.ll --check-prefix=LATCHSTEP

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
; The `verify` pass in each RUN line is the actual regression check: it fails
; that line if the malformed ordering ever comes back.
;
; Why twelve seeds over six subjects rather than one of each: the counter split
; that produces the shape only lands when the per-function DoSplit draw (40 %)
; comes up *and* the opaque-invariant draw (60 %) does not, since the latter
; rewrites the preheader the split needs — about one function in eight.  With a
; single subject and a single seed this test was really a statement about where
; the PRNG draw sequence happened to be, and it broke when the PRNG moved to
; per-module seeding with nothing about the pass having changed.  72 samples
; make "the split fired for none of them" a ~5e-5 event.

; The counter split must still happen somewhere — otherwise the verifier above
; never sees the shape the bug lived in.
; CHECK-DAG: %lt.i_low = phi i32
; CHECK-DAG: %lt.i_high = phi i32
; CHECK-DAG: %lt.high_ext = zext i32 %lt.i_high to i64
; CHECK-DAG: %lt.combined = or i64

define i32 @sum_loop1(i32 %n) {
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

define i32 @sum_loop2(i32 %n) {
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

define i32 @sum_loop3(i32 %n) {
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

define i32 @sum_loop4(i32 %n) {
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

define i32 @sum_loop5(i32 %n) {
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

define i32 @sum_loop6(i32 %n) {
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
