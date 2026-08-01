; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-genc \
; RUN:     -passes='kagura-genc,verify' -S %s \
; RUN:     | %FileCheck %s --implicit-check-not=-559038737

; GlobalEncryptionPass XOR-encrypts integer globals at compile time and injects
; an inline XOR at every load site.  Only *constant* globals are eligible: the
; pass patches loads but not stores, so encrypting a mutable global would let a
; store write plaintext that the load then "decrypts" into garbage.  @g_secret
; therefore has to be declared `internal constant`, not `internal global`.
;
; --implicit-check-not asserts the plaintext 0xDEADBEEF (-559038737) survives
; nowhere in the output — not as an initializer, not as an immediate.

; The encrypted initializer, and no longer `constant` so the linker cannot fold
; the load back to a constant and undo the encryption.
; CHECK: @g_secret = internal global i32

; CHECK: define i32 @get_secret
; CHECK: %[[ENC:[a-z0-9.]+]] = load i32, ptr @g_secret
; CHECK: %[[DEC:[a-z0-9.]+]] = xor i32 %[[ENC]], {{-?[0-9]+}}
; CHECK: ret i32 %[[DEC]]

@g_secret = internal constant i32 -559038737  ; 0xDEADBEEF

define i32 @get_secret() {
entry:
  %v = load i32, i32* @g_secret, align 4
  ret i32 %v
}
