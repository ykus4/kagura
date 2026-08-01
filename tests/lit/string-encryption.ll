; RUN: %opt -load-pass-plugin=%kagura_plugin -kagura-seed=32 -kagura-str \
; RUN:     -passes='kagura-str,verify' -S %s | %FileCheck %s \
; RUN:     --implicit-check-not=sk-test-1234567890abcdef \
; RUN:     --implicit-check-not=api.example.com

; StringEncryptionPass XOR-encrypts string literals at compile time and decrypts
; them lazily on first use.  For each literal it emits a private ciphertext
; global, a one-shot "already decrypted" flag, and the key; the decryptor is an
; internal function called from a guarded block at the first use site.
;
; The two --implicit-check-not patterns assert both plaintexts are gone from the
; whole output.  Note the ciphertext globals are `private`, not `internal`:
; private is the stronger of the two (no symbol table entry at all), which is
; what an encrypted blob wants.

; CHECK: @[[ENC:kagura_enc_[0-9]+]] = private global [25 x i8] c"
; CHECK: @[[FLAG:kagura_flag_[0-9]+]] = private global i8 0
; CHECK: @[[KEY:kagura_key_[0-9]+]] = private constant [8 x i8] c"

; Lazy decrypt guard at the use site.
; CHECK: define i32 @main
; CHECK: %[[F:[a-z0-9._]+]] = load i8, ptr @[[FLAG]]
; CHECK: icmp eq i8 %[[F]], 0
; CHECK: call void @[[DEC:kagura_decrypt_[0-9]+]]()
; CHECK: store i8 1, ptr @[[FLAG]]
; CHECK: call i32 @strlen(ptr @[[ENC]])

; The decryptor XORs the ciphertext with the repeating key in place.
; CHECK: define internal void @[[DEC]]()
; CHECK: getelementptr inbounds [8 x i8], ptr @[[KEY]]
; CHECK: %[[KB:[a-z0-9._]+]] = load i8
; CHECK: xor i8 %{{.*}}, %[[KB]]

@api_key = private unnamed_addr constant [25 x i8] c"sk-test-1234567890abcdef\00"
@base_url = private unnamed_addr constant [27 x i8] c"https://api.example.com/v1\00"

declare i32 @strlen(i8* nocapture) nounwind readonly

define i32 @main() {
  %len = call i32 @strlen(i8* getelementptr inbounds ([25 x i8], [25 x i8]* @api_key, i32 0, i32 0))
  ret i32 %len
}
