; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-sv \
; RUN:     -kagura-sv-keep=external_api \
; RUN:     -passes='kagura-sv,verify' -S %s | %FileCheck %s

; SymbolVisibilityPass shrinks the exported symbol surface by giving *exported
; definitions* hidden visibility.  It changes visibility, never linkage.
;
; Local (internal / private) linkage is deliberately left alone: such symbols
; never reach the dynamic symbol table in the first place, so there is nothing
; to hide, and LLVM asserts "local linkage requires default visibility" if a
; pass sets hidden on them anyway — which this pass used to do, crashing every
; assertions-enabled build.  @helper is the regression guard for that.
;
; -kagura-sv-keep is how a genuine public API stays exported; @external_api is
; on the list, @impl_detail is not.

; CHECK: define internal i32 @helper(i32 %x) {
; A literal match, so an injected `hidden` on the kept public entry point
; breaks this line.
; CHECK: define i32 @external_api(i32 %n) {
; CHECK: define hidden i32 @impl_detail(i32 %n) {

define internal i32 @helper(i32 %x) {
  %r = mul i32 %x, 3
  ret i32 %r
}

define i32 @external_api(i32 %n) {
  %r = call i32 @helper(i32 %n)
  ret i32 %r
}

define i32 @impl_detail(i32 %n) {
  %r = call i32 @helper(i32 %n)
  ret i32 %r
}
