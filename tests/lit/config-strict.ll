; Unknown keys in a policy file are diagnosed, and -kagura-config-strict turns
; the diagnosis into a build failure.
;
; The failure mode this guards is silence: a policy key the loader does not
; recognise is simply ignored, so `{"passes": {"strr": true}}` produces a
; binary with no string encryption and a successful build. Every hand-written
; JSON example in docs/ used hyphenated keys, which the loader now folds to the
; underscore spelling — that fold is checked here too, because a "tolerated"
; spelling that quietly stopped working would look exactly the same.

; ---- A hyphenated key is accepted, silently, and takes effect ---------------
; RUN: echo '{ "passes": { "str-aes": true } }' > %t.hyphen.json
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.hyphen.json \
; RUN:      -passes='default<O1>' -S %s 2>%t.hyphen.err \
; RUN:   | %FileCheck %s --check-prefix=HYPHEN
; RUN: %FileCheck %s --check-prefix=NODIAG --input-file=%t.hyphen.err \
; RUN:      --allow-empty

; HYPHEN: @kagura_aesenc_
; NODIAG-NOT: unknown key

; ---- A misspelt key warns, suggests the nearest real key, and still builds --
;
; Two unknown keys at once: they are reported in StringMap iteration order, so
; the checks below must not impose an order on each other.
; RUN: echo '{ "passes": { "strr": true, "vtp": true } }' > %t.typo.json
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.typo.json \
; RUN:      -passes='default<O1>' -S %s -o %t.typo.ll 2>%t.typo.err
; RUN: %FileCheck %s --check-prefix=WARN --input-file=%t.typo.err

; A typo gets a suggestion ...
; WARN-DAG: warning: unknown key "strr"{{.*}}did you mean "str"?
; ... and a real flag that has no policy-file spelling gets named instead.
; WARN-DAG: warning: unknown key "vtp"{{.*}}command-line-only option: pass -kagura-vtp
; WARN-NOT: error:

; The module must still have been written: without -kagura-config-strict this
; is a warning, not a failure.
; RUN: %FileCheck %s --check-prefix=BUILT --input-file=%t.typo.ll
; BUILT: define {{.*}}@main

; ---- -kagura-config-strict makes the same file fail ------------------------
; RUN: not %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.typo.json \
; RUN:      -kagura-config-strict -passes='default<O1>' -S %s -o %t.strict.ll \
; RUN:      2>%t.strict.err
; RUN: %FileCheck %s --check-prefix=STRICT --input-file=%t.strict.err

; STRICT-DAG: error: unknown key "strr"
; STRICT: -kagura-config-strict

; ---- A clean policy file is not made to fail by -kagura-config-strict -------
; RUN: echo '{ "passes": { "str": true }, "tuning": { "bcf_prob": 50 } }' > %t.clean.json
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.clean.json \
; RUN:      -kagura-config-strict -passes='default<O1>' -S %s -o %t.clean.ll
; RUN: %FileCheck %s --check-prefix=CLEAN --input-file=%t.clean.ll

; CLEAN: @kagura_enc_

@secret = private unnamed_addr constant [21 x i8] c"license_key_abcdefgh\00"

declare i32 @puts(ptr)

define i32 @main() {
entry:
  %r = call i32 @puts(ptr @secret)
  ret i32 %r
}
