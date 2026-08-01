; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-honey \
; RUN:     -passes='kagura-honey,verify' -S %s | %FileCheck %s

; HoneyValuePass injects decoy global variables and fake stub functions.
; Every symbol it emits carries a kagura_ prefix on purpose: isKaguraSymbol()
; keys off it so later passes do not re-obfuscate the decoys.
;
; After the pass:
;   - Honey globals (kagura_honey_g_*) holding plausible-looking fake secrets.
;   - Fake stub functions (kagura_validate_license / kagura_check_token / ...)
;     with a matching kagura_fakehint_* string constant each.
;   - A module constructor @kagura_honey_ctor, registered in llvm.global_ctors,
;     that volatile-loads every honey global and calls every stub so neither can
;     be dead-stripped.
;   - The original user function @main, unchanged.

; Decoy globals, in the order the pass emits them.
; CHECK: @kagura_honey_g_api_secret_key = private constant {{.*}}c"sk-
; CHECK: @kagura_honey_g_auth_token = private constant {{.*}}c"Bearer
; CHECK: @kagura_honey_g_db_password = private constant
; CHECK: @kagura_fakehint_kagura_validate_license = private constant

; The ctor must be anchored in llvm.global_ctors, or the linker strips the lot.
; CHECK: @llvm.global_ctors = {{.*}}@kagura_honey_ctor

; CHECK: define i32 @main

; Fake stubs, emitted after the user code.
; CHECK: define private i32 @kagura_validate_license(i32 %tok)
; CHECK: define private i32 @kagura_verify_token(i32 %tok)

; The anchor ctor: a volatile load of a honey global and a call to a stub.
; CHECK: define internal void @kagura_honey_ctor()
; CHECK: load volatile i8, ptr @kagura_honey_g_api_secret_key
; CHECK: call i32 @kagura_validate_license
; CHECK: ret void

define i32 @main() {
entry:
  ret i32 0
}
