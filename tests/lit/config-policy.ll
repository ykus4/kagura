; The JSON policy DSL must actually select passes.
;
; Regression test: ConfigLoader used to run as a pipeline pass, i.e. after the
; pipeline had already been built from the opt:: flags, so -kagura-config was
; silently a no-op for the -fpass-plugin / default-pipeline entry point that
; the README documents as the primary usage.
;
; RUN: echo '{ "passes": { "str": true } }' > %t.policy.json
;
; With the policy file, string encryption must run: the plaintext global is
; replaced and a decrypt stub appears.
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.policy.json \
; RUN:      -passes='default<O1>' -S %s | %FileCheck %s --check-prefix=POLICY
;
; Without it, nothing should happen to the string.
; RUN: %opt -load-pass-plugin=%kagura_plugin \
; RUN:      -passes='default<O1>' -S %s | %FileCheck %s --check-prefix=PLAIN
;
; An explicit command-line flag outranks the policy file.
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.policy.json \
; RUN:      -kagura-str=false -passes='default<O1>' -S %s \
; RUN:      | %FileCheck %s --check-prefix=PLAIN

; POLICY: @kagura_enc_
; POLICY-NOT: c"license_key_abcdefgh\00"

; PLAIN: c"license_key_abcdefgh\00"
; PLAIN-NOT: @kagura_enc_

@.msg = private unnamed_addr constant [21 x i8] c"license_key_abcdefgh\00", align 1

declare i32 @puts(ptr)

define i32 @emit() {
entry:
  %call = call i32 @puts(ptr @.msg)
  ret i32 %call
}
