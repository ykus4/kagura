; Flattening rebuilds the entry block's terminator as "store the initial state,
; branch to the dispatcher", and only understands the two BranchInst shapes.
; Anything else fell through to an initial state of 0 — the dispatcher's
; `unreachable` default — while the original terminator was erased along with
; every edge it carried. A switch in the entry block is ordinary at -O2, so
; @dispatch_on below used to compile to a function that is undefined for every
; input. The pass must decline it instead.
;
; @straight_line is here so this test cannot pass vacuously: it has a plain
; branch in the entry block and must still be flattened, which means the
; kagura.loop dispatcher has to appear somewhere in the output.

; RUN: %opt --load-pass-plugin=%kagura_plugin -kagura-seed=41 \
; RUN:     -passes='function(kagura-fla)',verify -S %s | %FileCheck %s

; CHECK-LABEL: define i32 @dispatch_on(
; CHECK:         switch i32 %x, label %def
; CHECK-NOT:     kagura.default
define i32 @dispatch_on(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 0, label %a
    i32 1, label %b
  ]
a:
  br label %join
b:
  br label %join
def:
  br label %join
join:
  %r = phi i32 [ 100, %a ], [ 200, %b ], [ -1, %def ]
  ret i32 %r
}

; CHECK-LABEL: define i32 @straight_line(
; CHECK:         kagura.loop
define i32 @straight_line(i32 %x) {
entry:
  br label %head
head:
  %c = icmp sgt i32 %x, 0
  br i1 %c, label %pos, label %neg
pos:
  br label %join
neg:
  br label %join
join:
  %r = phi i32 [ 1, %pos ], [ -1, %neg ]
  ret i32 %r
}
