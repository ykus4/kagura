; A bare `{"profile": "<NAME>"}` must select the same pass set as the shipped
; integration/profiles/<name>.json.
;
; Regression test: the profile -> pass-set mapping existed twice, in
; applyProfile() and in the JSON files the integrations point -kagura-config
; at, and the two had diverged. The JSON enabled sv / anti_debug / tamper and
; the compiled preset did not, so a hand-written `{"profile": "BALANCED"}`
; produced a materially weaker binary than the balanced.json that claimed to
; be the same profile. Both now come from lib/Transforms/Profiles.def.
;
; The check is on anti-debug, because that is one of the three passes that were
; missing and it leaves an unmistakable mark: a module constructor calling into
; the runtime.
;
; RUN: echo '{ "profile": "BALANCED" }' > %t.balanced.json
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.balanced.json \
; RUN:      -passes='default<O1>' -S %s | %FileCheck %s --check-prefix=PRESET
;
; RUN: echo '{ "profile": "FAST" }' > %t.fast.json
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.fast.json \
; RUN:      -passes='default<O1>' -S %s | %FileCheck %s --check-prefix=PRESET
;
; FAST deliberately leaves anti-tamper off; BALANCED turns it on. If the two
; profiles ever collapse into each other this catches it.
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.fast.json \
; RUN:      -passes='default<O1>' -S %s | %FileCheck %s --check-prefix=FAST
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.balanced.json \
; RUN:      -passes='default<O1>' -S %s | %FileCheck %s --check-prefix=BALANCED
;
; An unknown profile name is a typo, not a silent "no protection".
; RUN: echo '{ "profile": "blanaced" }' > %t.typo.json
; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-config=%t.typo.json \
; RUN:      -passes='default<O1>' -S %s 2>&1 | %FileCheck %s --check-prefix=TYPO

; Both profiles enable anti-debug: the runtime init call must be there.
; PRESET: @llvm.global_ctors
; PRESET: kagura_anti_debug_init

; FAST-NOT: kagura_runtime_hash_check
; BALANCED: kagura_runtime_hash_check

; TYPO: warning: unknown profile "blanaced"

@.msg = private unnamed_addr constant [21 x i8] c"license_key_abcdefgh\00", align 1

declare i32 @puts(ptr)

define i32 @emit() {
entry:
  %call = call i32 @puts(ptr @.msg)
  ret i32 %call
}
