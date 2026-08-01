/*===-- runtime/internal.h - Cross-TU contracts for the kagura runtime ----===
 *
 * Single source of truth for every symbol that is shared between two or more
 * translation units of the kagura runtime, plus every symbol that the LLVM
 * passes emit a call to.
 *
 * Rules
 * -----
 *   1. Every non-static definition in runtime/ MUST be declared here, exactly
 *      once.  The build enables -Wmissing-prototypes to enforce this.
 *   2. No .c file may hand-roll an `extern` declaration of a kagura_* symbol.
 *      Divergent hand-written externs are what previously let three symbols
 *      be declared with the wrong name and two with the wrong type.
 *   3. Anything that is genuinely file-local must be `static`.
 *
 * The declarations are unconditional wherever the type is portable, even for
 * functions that only have a definition on one platform: a declaration for a
 * symbol that is not defined on this target is harmless, whereas a *missing*
 * declaration silently reintroduces the class of bug this header exists to
 * prevent.  Only declarations whose parameter types are platform-specific
 * (JNIEnv, Objective-C Class/SEL/IMP, wchar_t on Windows) are guarded.
 *
 *===----------------------------------------------------------------------===*/

#ifndef KAGURA_RUNTIME_INTERNAL_H
#define KAGURA_RUNTIME_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#if !defined(_WIN32)
#  include <sys/types.h>   /* pid_t, ssize_t */
#endif

#if defined(__APPLE__)
#  include <TargetConditionals.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Attribute shims ----------------------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
#  define KAGURA_WEAK     __attribute__((weak))
#  define KAGURA_NORETURN __attribute__((noreturn))
#else
#  define KAGURA_WEAK
#  define KAGURA_NORETURN
#endif

/* ===========================================================================
 * Tamper response  (runtime/core/tamper_response.c)
 * ===========================================================================
 *
 * Two names exist because the passes emit both:
 *   - AntiDebug.cpp and BasicBlockChecksum.cpp emit kagura_on_tamper_detected
 *   - AntiTamper.cpp emits kagura_tamper_detected
 *
 * kagura_on_tamper_detected is the single overridable policy hook (weak).
 * kagura_tamper_detected is a thin noreturn wrapper kept for compatibility;
 * it calls the hook and then hard-terminates if the hook returns.
 */
KAGURA_WEAK void kagura_on_tamper_detected(void);
KAGURA_NORETURN void kagura_tamper_detected(void);

/* ===========================================================================
 * Soft (graduated) response  (runtime/core/soft_response.c)
 * =========================================================================== */

#define KAGURA_RESPONSE_OK        0
#define KAGURA_RESPONSE_WARN      1
#define KAGURA_RESPONSE_PENALISE  2
#define KAGURA_RESPONSE_KICK      3

void kagura_soft_response_add(int score);
int  kagura_soft_response_level(void);
void kagura_soft_response_check(void (*respond)(int level, void *ctx),
                                void *ctx);
void kagura_soft_response_reset(void);

/* ===========================================================================
 * Shared helpers  (runtime/core/hash.c, procfs.c, pathprobe.c, imagelist.c)
 * =========================================================================== */

/* FNV-1a. */
uint32_t kagura_fnv1a32_buf(const void *data, size_t len);
uint64_t kagura_fnv1a64_buf(const void *data, size_t len);
uint32_t kagura_fnv1a32_str(const char *s);
uint64_t kagura_fnv1a64_str(const char *s);

/* Path probing: 1 if the path exists / is readable, 0 otherwise.
 * kagura_path_exists uses access(F_OK), which some jailbreak hiders hook;
 * kagura_path_exists_hardened additionally tries stat() and open(). */
int kagura_path_exists(const char *path);
int kagura_path_exists_hardened(const char *path);
int kagura_any_path_exists(const char *const *paths);

/* /proc scanning (Linux/Android; returns 0 elsewhere).
 *   kagura_procfs_contains  — does <path> contain any of the NULL-terminated
 *                             substring patterns?
 *   kagura_maps_contain     — same, hard-wired to /proc/self/maps. */
int kagura_procfs_contains(const char *path, const char *const *patterns);
int kagura_maps_contain(const char *const *patterns);

/* Loaded-image scanning.
 *   kagura_image_list_contains — walk the loaded image list (dyld on Apple,
 *                                /proc/self/maps on Linux) looking for any of
 *                                the given substrings.
 *   kagura_suspicious_image_patterns — the unified injection-framework
 *                                pattern table (NULL-terminated). */
int kagura_image_list_contains(const char *const *patterns);
const char *const *kagura_suspicious_image_patterns(void);

/* Entropy source for the PAC key constructor emitted by PointerAuth.cpp. */
uint64_t kagura_random_u64(void);

/* ===========================================================================
 * Core primitives
 * =========================================================================== */

/* core/aes.c — nonce is 8 bytes; the counter block is nonce || counter. */
void kagura_aes128_ctr_decrypt(const uint8_t *enc, uint32_t len,
                               const uint8_t key[16], const uint8_t nonce[8],
                               uint8_t *out);

/* core/zero_buf.c */
void kagura_zero_buf(void *ptr, uint32_t len);

/* core/vm_interpreter.c */
uint64_t kagura_vm_execute(const uint8_t *bytecode, uint32_t bc_size,
                           uint64_t *args, uint32_t nargs);

/* core/blob_integrity.c — emitted by StringEncryptionAES.cpp on every target */
void kagura_check_blob_integrity(const uint8_t *blob, uint32_t len,
                                 uint32_t expected);

/* core/bb_check.c — emitted by BasicBlockChecksum.cpp.
 * NOTE the polarity: nonzero == block intact, zero == tampering. */
int kagura_bb_check(uint32_t block_id, uint32_t expected);

/* core/telemetry.c — emitted by Telemetry.cpp; weak no-op by default. */
void kagura_telemetry_event(uint32_t event_id);

/* core/device_key.c and windows/device_key.c.
 * Returns 1 on success, 0 if no stable device identity was available. */
int  kagura_device_key(uint8_t out[16]);
void kagura_device_mix_key(uint8_t key[16]);

/* core/crash_symbolication.c */
void kagura_sym_init(void);
const char *kagura_symbolicate(uintptr_t pc);
void kagura_install_crash_handler(void);
void kagura_symbolicate_tombstone(const char *tombstone_path,
                                  const char *out_path);

/* ===========================================================================
 * Anti-debug / anti-analysis  (runtime/anti_debug/)
 * =========================================================================== */

/* anti_debug.c — kagura_check_tracer_pid is emitted by AntiDebug.cpp on every
 * target, so it always has a definition (real on Linux/Apple, 0 elsewhere). */
int  kagura_check_tracer_pid(void);
int  kagura_check_maps(void);
int  kagura_check_frida_port(void);
int  kagura_check_loaded_dylibs(void);
void *kagura_rtld_default_handle(void);

/* breakpoint_detection.c */
int  kagura_check_sw_breakpoints(void);
int  kagura_check_hw_breakpoints(void);
/* Aggregate RESPONSE, not a predicate: runs the two checks above and invokes
 * the tamper hook on a hit.  It returns void and never reports back, so a
 * caller that wants a yes/no answer must call the two predicates directly.
 * ios/device_attest.c used to declare this `int` and branch on the result. */
void kagura_check_breakpoints(void);

/* hook_detection.c */
int  kagura_check_inline_hooks(void);
int  kagura_check_got_hooks(void);
void kagura_check_hooks(void);

/* emulator_detection.c */
int  kagura_check_emulator(void);
void kagura_assert_real_device(void);

/* loaded_library_scan.c */
int  kagura_suspicious_lib_loaded(void);
void kagura_library_scan_check(void);

/* symbol_interposition.c */
int  kagura_symbol_interposed(void);
void kagura_interposition_check(void);

/* anti_dump.c */
void kagura_poison_region(void *p, size_t n);
int  kagura_rwx_pages_present(void);
int  kagura_anti_dump_check(void);
void kagura_anti_dump_init(void);

/* ===========================================================================
 * Apple / iOS  (runtime/ios/)
 * =========================================================================== */

/* jailbreak_detection.c */
int  kagura_check_cydia_path(void);
int  kagura_check_substrate_dylib(void);
int  kagura_check_sandbox_escape(void);
int  kagura_check_fork(void);
int  kagura_check_dyld_env(void);
int  kagura_check_su_binary(void);
int  kagura_check_root_packages(void);
int  kagura_check_test_keys(void);
int  kagura_check_rw_system(void);
int  kagura_jailbreak_detected(void);
void kagura_self_check(void);
void kagura_runtime_hash_check(void *fn, uint32_t expected_hash);

/* ios_integrity.c */
int  kagura_codesign_valid(void);
void kagura_codesign_check(void);
int  kagura_apple_wx_pages_present(void);
void kagura_apple_wx_page_check(void);

#if defined(__APPLE__) && (TARGET_OS_IOS || TARGET_OS_OSX)
#  include <objc/runtime.h>
int  kagura_objc_swizzled(Class cls, SEL sel, IMP expected_imp);
void kagura_objc_swizzle_check(Class cls, SEL sel, IMP expected_imp);
#else
int  kagura_objc_swizzled(void *cls, void *sel, void *imp);
void kagura_objc_swizzle_check(void *cls, void *sel, void *imp);
#endif

/* ios_platform.c */
int  kagura_is_simulator(void);
void kagura_simulator_check(void);
int  kagura_entitlements_valid(void);
void kagura_entitlements_check(void);
int  kagura_dyld_suspicious(void);
void kagura_dyld_image_check(void);

/* ios_jailbreak_advanced.c */
int  kagura_jailbreak_fs_artifacts(void);
void kagura_jailbreak_fs_check(void);
int  kagura_cydia_substrate_loaded(void);
void kagura_cydia_substrate_check(void);
int  kagura_app_repackaged(const char *expected_bundle_id,
                           const char *expected_team_id);
void kagura_repackage_check(const char *expected_bundle_id,
                            const char *expected_team_id);

/* macho_integrity.c */
int  kagura_macho_tampered(void);
void kagura_macho_check(void);

/* fishhook_countermeasure.c */
void kagura_fishhook_snapshot(void);
int  kagura_fishhook_detected(void);
void kagura_fishhook_check(void);

/* testflight_detect.c */
int  kagura_is_testflight(void);

/* swift_protection.c */
int  kagura_swift_demangle_hooked(void);
int  kagura_swift_metadata_count(void);
void kagura_swift_check(void);

/* objc_name_remap.c */
void kagura_objc_register_remap(const char *original, const char *obfuscated);
const char *kagura_objc_remap(const char *name);

/* device_attest.c */
int  kagura_devicecheck_available(void);
int  kagura_appattest_available(void);
int  kagura_appattest_nonce(uint8_t *out, size_t len);
int  kagura_appattest_local_check(void);

/* ===========================================================================
 * Android / Linux  (runtime/android/)
 * =========================================================================== */

/* android_root_advanced.c */
int  kagura_magisk_present(void);
void kagura_magisk_check(void);
int  kagura_xposed_present(void);
void kagura_xposed_check(void);

/* elf_integrity.c */
int  kagura_elf_tampered(void);
void kagura_elf_integrity_check(void);
int  kagura_wx_pages_present(void);
void kagura_wx_page_check(void);

/* art_environment.c */
int  kagura_art_jit_suspicious(void);
int  kagura_jdwp_active(void);
void kagura_art_check(void);

/* load_order.c */
void kagura_record_load_address(void);
int  kagura_load_order_valid(void);
void kagura_load_order_check(void);

/* apk_integrity.c */
int  kagura_apk_sig_present(const char *apk_path);
void kagura_apk_integrity_check(const char *apk_path);

/* split_apk.c */
int  kagura_is_split_apk(void);
int  kagura_split_apk_native_path_ok(void);
int  kagura_split_apk_check(void);

/* proc_inspection.c */
int  kagura_proc_maps_suspicious(void);
int  kagura_proc_traced(void);
int  kagura_proc_mounts_suspicious(void);
void kagura_proc_check(void);

/* seccomp_checks.c */
int  kagura_seccomp_active(void);
int  kagura_ptrace_unrestricted(void);
int  kagura_no_new_privs_set(void);
void kagura_prctl_check(void);

/* play_integrity.c */
void kagura_play_integrity_nonce(char *out_hex32, size_t len);
int  kagura_play_integrity_verdict_ok(const char *jwt_payload_b64url);
int  kagura_play_integrity_local_check(void);

#if defined(__ANDROID__)
#  include <jni.h>
/* jni_hook_detection.c */
int  kagura_jni_table_hooked(JNIEnv *env);
void kagura_jni_table_check(JNIEnv *env);
/* safetynet_compat.c */
int  kagura_safetynet_available(JNIEnv *env);
int  kagura_attestation_ok(JNIEnv *env, const char *response_b64url,
                           const char *nonce, int is_play_integrity);
#endif
int  kagura_safetynet_verdict_ok(const char *jws_payload_b64url,
                                 const char *expected_nonce);

#if !defined(_WIN32)
/* direct_syscall.c — raw syscalls on Linux/Android, libc on other POSIX. */
pid_t   kagura_syscall_getpid(void);
int     kagura_syscall_open(const char *path, int flags);
int     kagura_syscall_close(int fd);
ssize_t kagura_syscall_read(int fd, void *buf, size_t count);
#endif

/* ===========================================================================
 * Game / anti-cheat  (runtime/game/)
 * =========================================================================== */

/* Protected floating-point value (speed / position / velocity). */
typedef struct {
    uint32_t enc;   /* float bits XOR key */
    uint32_t key;   /* per-instance key */
    uint32_t check; /* FNV-1a-32 of the original enc^key for tamper detect */
} kagura_speed_t;

/* Protected PRNG seed. */
typedef struct {
    uint64_t enc;   /* seed XOR key */
    uint64_t key;   /* per-instance key */
    uint32_t check; /* FNV-1a-32 checksum */
} kagura_seed_t;

/* game_values.c */
void  kagura_speed_init(kagura_speed_t *s, float value);
float kagura_speed_get(const kagura_speed_t *s);
void  kagura_speed_set(kagura_speed_t *s, float value);
int   kagura_speed_valid(const kagura_speed_t *s, float min, float max);
void     kagura_seed_init(kagura_seed_t *s, uint64_t seed);
uint64_t kagura_seed_get(const kagura_seed_t *s);
void     kagura_seed_set(kagura_seed_t *s, uint64_t seed);
int      kagura_seed_tampered(const kagura_seed_t *s);

/* behavior_log.c */
void kagura_log_event(uint8_t type, uint32_t detail);
int  kagura_event_count(uint8_t type);
int  kagura_suspicion_score(void);
void kagura_flush_events(void (*cb)(uint8_t type, uint32_t detail,
                                    void *userdata),
                         void *userdata);
void kagura_clear_events(void);

/* state_integrity.c */
void kagura_register_invariant(int (*fn)(void *ctx), void *ctx);
void kagura_check_invariants(void);
int  kagura_invariant_range_i32(void *ctx);
int  kagura_invariant_nonzero(void *ctx);

/* integrity_report.c */
int  kagura_nonce_is_fresh(const char *nonce, size_t len);
void kagura_nonce_consume(const char *nonce, size_t len);
int  kagura_integrity_report_build(const char *nonce,
                                   char *out_buf, size_t buf_len);

/* il2cpp_protection.c */
int  kagura_il2cpp_check_metadata_integrity(void);
int  kagura_il2cpp_check_symbol_redirect(void);
void kagura_il2cpp_protect_method_table(void *method_table, size_t count);
int  kagura_protect_global_metadata(const char *metadata_path);
int  kagura_il2cpp_anti_memory_scan(void);

/* ue4_protection.c */
int  kagura_ue4_check_symbol_redirect(void);
int  kagura_ue4_check_pak_integrity(const char *pak_path);
void kagura_ue4_protect_function_table(void *vtable, size_t count);
int  kagura_ue4_anti_memory_scan(void);

/* ===========================================================================
 * Windows  (runtime/windows/)
 * =========================================================================== */

#if defined(_WIN32)
#  include <wchar.h>

/* anti_debug.c */
int  kagura_check_debugger_present(void);
void kagura_debugger_present_check(void);
int  kagura_check_remote_debugger(void);
void kagura_remote_debugger_check(void);
int  kagura_check_nt_debug_port(void);
void kagura_nt_debug_port_check(void);
int  kagura_check_heap_flags(void);
void kagura_heap_flags_check(void);
void kagura_frida_port_check(void);
int  kagura_check_injected_dlls(void);
void kagura_injected_dlls_check(void);
void kagura_check_windows_debugger(void);

/* integrity.c */
int  kagura_pe_checksum_valid(void);
void kagura_pe_integrity_check(void);
int  kagura_check_wx_pages(void);
void kagura_memory_protection_check(void);

/* etw_detection.c */
int  kagura_etw_provider_present(const wchar_t *provider_guid);
int  kagura_etw_analysis_tool_check(void);
#endif /* _WIN32 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KAGURA_RUNTIME_INTERNAL_H */
