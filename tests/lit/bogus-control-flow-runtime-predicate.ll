; The opaque predicate has to be built over a value that is not known at
; compile time. pickIntValue() runs after the block has been split, which
; moves every real instruction into bcf.orig — so the old "first non-PHI
; integer instruction in the block" search found nothing and fell through to
; its 0xCAFEBABE constant on essentially every block. `(K | ~K)` for a literal
; K is folded long before the backend sees it, which left the pass emitting a
; branch that is constant at compile time.
;
; 3405691582 is 0xCAFEBABE in the decimal form the .ll printer uses.

; RUN: %opt --load-pass-plugin=%kagura_plugin -kagura-seed=7 -kagura-bcf-prob=100 \
; RUN:     -passes='function(kagura-bcf)',verify -S %s \
; RUN:   | %FileCheck %s --implicit-check-not=3405691582

; The predicate must consume the incoming argument, not a literal.
; CHECK-LABEL: define i32 @with_arg(
; CHECK:         %bcf.{{.*}} = {{.*}} i32 %x
; CHECK:         br i1 %bcf.pred
define i32 @with_arg(i32 %x) {
entry:
  br label %body
body:
  %a = add i32 %x, 1
  %b = mul i32 %a, 3
  ret i32 %b
}

; No integer parameter and no integer PHI: the address of a local is still a
; run-time value, so the fallback constant is not needed here either.
; CHECK-LABEL: define i32 @with_alloca(
; CHECK:         br i1 %bcf.pred
define i32 @with_alloca() {
entry:
  %slot = alloca i32, align 4
  store i32 7, ptr %slot, align 4
  br label %body
body:
  %v = load i32, ptr %slot, align 4
  %r = add i32 %v, 1
  ret i32 %r
}
