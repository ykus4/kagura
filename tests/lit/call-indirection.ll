; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-ci \
; RUN:     -passes='kagura-ci,verify' -S %s | %FileCheck %s

; CallIndirectionPass routes calls to external functions through a thunk table
; that a module constructor fills in at load time via dlsym().
; After the pass:
;   - A thunk table global (@__kagura_thunk_table) with one slot per redirected
;     callee, plus the callee's name as a private string for dlsym().
;   - A ctor (@kagura_init_thunk_table) registered in llvm.global_ctors that
;     resolves each name and stores the result into the table.
;   - The direct call to @puts in @main replaced by a load from the table
;     followed by an indirect call through the loaded pointer.

; CHECK: @__kagura_thunk_table = internal global [1 x ptr]
; CHECK: @__kagura_sym_puts = private unnamed_addr constant [5 x i8] c"puts\00"
; CHECK: @llvm.global_ctors = {{.*}}@kagura_init_thunk_table

; CHECK: define i32 @main
; CHECK-NOT: call i32 @puts(
; CHECK: %[[FP:[a-z0-9._]+]] = load ptr, ptr @__kagura_thunk_table
; CHECK: call i32 %[[FP]](ptr @msg)
; CHECK: ret i32

; CHECK: define internal void @kagura_init_thunk_table
; CHECK: call ptr @dlsym(ptr %{{.*}}, ptr @__kagura_sym_puts)
; CHECK: store ptr %{{.*}}, ptr @__kagura_thunk_table

declare i32 @puts(i8* nocapture) nounwind

@msg = private unnamed_addr constant [6 x i8] c"hello\00"

define i32 @main() {
entry:
  %r = call i32 @puts(i8* getelementptr inbounds ([6 x i8], [6 x i8]* @msg, i32 0, i32 0))
  ret i32 %r
}
