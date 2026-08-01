; RUN: %opt -load-pass-plugin=%kagura_plugin -passes=kagura-fsplit -S %s | %FileCheck %s

; FunctionSplitPass extracts eligible interior basic blocks into outlined
; helper functions.  After the pass:
;   - The original @large_func must still exist.
;   - At least one outlined helper (kagura_split_) must appear.
;   - The function must still return i32.

; The outlined helpers are named __kg_<parent>_bb<N>_<hex>; this test used to
; check for "@kagura_split_", a name the pass has never emitted. It passed only
; because the RUN line omits the enable flag, so the pass never ran at all.
; CHECK: define i32 @large_func
; CHECK: @__kg_large_func_bb
; CHECK: ret i32

define i32 @large_func(i32 %x) {
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
