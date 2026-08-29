/*===-- kagura/runtime.h - Public C API of the Kagura runtime -------------===
 *
 * The integrator-facing subset of libkagura_runtime.a: the detectors you can
 * call yourself, the response hooks you can override, and the protected value
 * types.  Link against `build/runtime/libkagura_runtime.a`.
 *
 *     #include "kagura/runtime.h"
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM runtime/internal.h
 * ------------------------------------------------------
 * runtime/internal.h declares every non-static symbol in runtime/, including
 * several hundred lines of cross-TU plumbing that is not a stable interface
 * and platform-specific declarations that need <jni.h>, <objc/runtime.h> or
 * <wchar.h>.  It is not shipped.  This header is the curated, portable,
 * installable subset, and the two are kept in sync by hand deliberately:
 * adding a symbol here is a decision to support it.
 *
 * NAMES ARE THE WHOLE POINT
 * -------------------------
 * The docs used to hand out three functions that do not exist —
 * kagura_check_loaded_libraries(), kagura_run_review_risk_check() and this
 * header itself — and runtime/ios/device_attest.c records the same class of
 * bug being found the hard way: four weakly-declared misspellings meant every
 * guard in kagura_appattest_local_check() short-circuited and the function
 * returned "environment is clean" unconditionally.  Include this header rather
 * than hand-rolling `extern` declarations, so a wrong name is a compile error
 * instead of a silently disabled check.
 *
 * RETURN-TYPE CONVENTION
 * ----------------------
 * Two shapes appear below and they are not interchangeable:
 *
 *   int  kagura_check_*(void)     PREDICATE. Nonzero == detected.
 *                                 (kagura_bb_check is the one exception; see
 *                                 its comment.)
 *   void kagura_*_check(void)     RESPONSE. Runs the predicates and invokes
 *                                 the tamper hook on a hit. Reports nothing
 *                                 back — `if (kagura_self_check() != 0)` does
 *                                 not compile, and where it did compile via a
 *                                 hand-written extern it branched on garbage.
 *
 * PLATFORM SECTIONS ARE DECLARED EVERYWHERE, DEFINED SOMEWHERE
 * -----------------------------------------------------------
 * The Apple and Android blocks below are declared unconditionally, the same
 * way internal.h does it, because a declaration guarded by #ifdef __APPLE__ is
 * exactly how the misspelling above went unnoticed.  A declaration for a
 * symbol with no definition on the current target is harmless until you call
 * it, at which point you get a link error naming it — which is the diagnostic
 * you want.  Call the Apple block only from Apple targets and the Android
 * block only from Android/Linux targets.
 *
 * Platform:  C99 / C++, no LLVM dependency.
 *
 *===----------------------------------------------------------------------===*/

#ifndef KAGURA_RUNTIME_H
#define KAGURA_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Guarded so a translation unit that also pulls in runtime/internal.h (in-tree
 * runtime builds do) does not hit a macro redefinition. */
#ifndef KAGURA_WEAK
#  if defined(__GNUC__) || defined(__clang__)
#    define KAGURA_WEAK __attribute__((weak))
#  else
#    define KAGURA_WEAK
#  endif
#endif

#ifndef KAGURA_NORETURN
#  if defined(__GNUC__) || defined(__clang__)
#    define KAGURA_NORETURN __attribute__((noreturn))
#  else
#    define KAGURA_NORETURN
#  endif
#endif

/* ===========================================================================
 * Tamper response
 * ===========================================================================
 *
 * kagura_on_tamper_detected is THE policy hook.  It is weak and the default
 * definition is deliberately dull, so define your own to decide what a
 * detection means for your product: crash, degrade, phone home, or nothing.
 * Everything the passes inject funnels through here.
 *
 * kagura_tamper_detected is a noreturn wrapper: it calls the hook and then
 * hard-terminates if the hook returns.  AntiTamper.cpp emits calls to it.
 */
KAGURA_WEAK void kagura_on_tamper_detected(void);
KAGURA_NORETURN void kagura_tamper_detected(void);

/* ---------------------------------------------------------------------------
 * Graduated ("soft") response
 *
 * For anyone who cannot terminate the process on detection — an SDK vendor
 * crashing inside a customer's app, a game that would rather shadow-ban than
 * lose a false-positive player.  Accumulate a score, act on the level.
 * ------------------------------------------------------------------------ */

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
 * Anti-debug / anti-analysis predicates  (nonzero == detected)
 * =========================================================================== */

int kagura_check_tracer_pid(void);      /* ptrace / TracerPid                 */
int kagura_check_inline_hooks(void);    /* trampoline prologues              */
int kagura_check_got_hooks(void);       /* GOT/PLT redirection               */
int kagura_check_sw_breakpoints(void);  /* int3 / BRK patched into code      */
int kagura_check_hw_breakpoints(void);  /* debug registers set               */
int kagura_check_emulator(void);        /* QEMU / emulator artefacts         */
int kagura_symbol_interposed(void);     /* DYLD_INSERT_LIBRARIES-style        */
int kagura_anti_dump_check(void);       /* memory-dump staging detected      */

/* Frida, Substrate, Xposed and friends, by loaded-image name.
 *
 * THIS is the function the docs used to call kagura_check_loaded_libraries().
 * There has never been a symbol under that name. */
int kagura_suspicious_lib_loaded(void);

/* Aggregate responses: run the predicates above and invoke the tamper hook on
 * a hit.  They return void — see the convention note at the top of the file. */
void kagura_check_hooks(void);
void kagura_check_breakpoints(void);
void kagura_library_scan_check(void);
void kagura_interposition_check(void);
void kagura_assert_real_device(void);
void kagura_anti_dump_init(void);

/* ===========================================================================
 * Platform integrity
 * =========================================================================== */

/* Apple (iOS / macOS).  kagura_self_check is a RESPONSE, not a predicate:
 * it runs the jailbreak and image-integrity checks and calls the tamper hook.
 * Use kagura_jailbreak_detected() / kagura_macho_tampered() when you want an
 * answer you can branch on. */
void kagura_self_check(void);
int  kagura_jailbreak_detected(void);
int  kagura_macho_tampered(void);
int  kagura_codesign_valid(void);       /* note the polarity: 1 == valid     */
int  kagura_is_simulator(void);
int  kagura_is_testflight(void);
int  kagura_app_repackaged(const char *expected_bundle_id,
                           const char *expected_team_id);

/* Android / Linux. */
int kagura_magisk_present(void);
int kagura_xposed_present(void);
int kagura_elf_tampered(void);
int kagura_proc_traced(void);
int kagura_proc_maps_suspicious(void);
int kagura_apk_sig_present(const char *apk_path);

/* Cross-platform path / image probes, exposed because detection lists are
 * product-specific and you will want to extend ours rather than replace it.
 * `patterns` is a NULL-terminated array of substrings, matched case-folded. */
int kagura_path_exists(const char *path);
int kagura_path_exists_hardened(const char *path);
int kagura_image_list_contains(const char *const *patterns);
int kagura_maps_contain(const char *const *patterns);

/* ===========================================================================
 * Platform attestation
 * ===========================================================================
 *
 * Local fast-paths only.  The signed token must be verified on your server;
 * none of these is a security boundary on its own.
 *
 * The JNI- and wchar_t-typed entry points of runtime/android/ and
 * runtime/windows/ are intentionally absent from this header because their
 * signatures need <jni.h> / <wchar.h>.  Declare those in the one translation
 * unit that has the platform SDK available.
 */

/* Apple — DeviceCheck / App Attest (runtime/ios/device_attest.c) */
int kagura_devicecheck_available(void);
int kagura_appattest_available(void);
int kagura_appattest_nonce(uint8_t *out, size_t len);
int kagura_appattest_local_check(void);   /* 1 == environment looks clean */

/* Android — Play Integrity (runtime/android/play_integrity.c) */
void kagura_play_integrity_nonce(char *out_hex32, size_t len);
int  kagura_play_integrity_verdict_ok(const char *jwt_payload_b64url);
int  kagura_play_integrity_local_check(void);

/* ===========================================================================
 * Pass-emitted symbols you may want to override or call
 * =========================================================================== */

/* Emitted at every guarded basic block by -kagura-bbcheck.
 *
 * NOTE THE INVERTED POLARITY: nonzero == block intact, zero == tampered.
 *
 * The shipped definition is a WEAK ALWAYS-PASSING STUB that returns 1. The
 * pass builds the call sites and the block-id/checksum plumbing; deciding what
 * a correct checksum *is* for your build requires knowing your final link
 * layout, so supplying the real implementation is your job. Until you define
 * it, -kagura-bbcheck detects nothing. See runtime/core/bb_check.c. */
int kagura_bb_check(uint32_t block_id, uint32_t expected);

/* Emitted by -kagura-telemetry at function entry. Weak no-op by default;
 * override it to route events wherever your analytics live. `event_id` is the
 * FNV-1a-32 hash of the function name, so the mapping back to a symbol comes
 * from the -kagura-symmap output. */
void kagura_telemetry_event(uint32_t event_id);

/* ===========================================================================
 * Protected values  (runtime/game/game_values.c)
 * ===========================================================================
 *
 * Keeps a scalar XOR-encrypted in memory with a per-instance key and a
 * checksum, so a memory scanner cannot find it by value and a freeze tool
 * cannot hold it.  C++ callers may prefer the Protected<T> template in
 * kagura/game_protect.h; these are the C equivalents the runtime itself uses.
 */

/* These two layouts are duplicated from runtime/internal.h and MUST stay
 * byte-identical to it — they are passed by pointer across the ABI boundary.
 * They are typedefs of anonymous structs there, so redefining them in a
 * translation unit that has already seen internal.h is an error rather than a
 * benign repeat; skip them in that case. (The clean fix is for internal.h to
 * include this header instead of restating the types, but internal.h is not
 * installed and this one is, so the dependency has to point this way round.) */
#ifndef KAGURA_RUNTIME_INTERNAL_H
typedef struct {
    uint32_t enc;   /* float bits XOR key */
    uint32_t key;   /* per-instance key */
    uint32_t check; /* FNV-1a-32 of the original enc^key, for tamper detect */
} kagura_speed_t;

typedef struct {
    uint64_t enc;   /* seed XOR key */
    uint64_t key;   /* per-instance key */
    uint32_t check; /* FNV-1a-32 checksum */
} kagura_seed_t;
#endif

void  kagura_speed_init(kagura_speed_t *s, float value);
float kagura_speed_get(const kagura_speed_t *s);
void  kagura_speed_set(kagura_speed_t *s, float value);
int   kagura_speed_valid(const kagura_speed_t *s, float min, float max);

void     kagura_seed_init(kagura_seed_t *s, uint64_t seed);
uint64_t kagura_seed_get(const kagura_seed_t *s);
void     kagura_seed_set(kagura_seed_t *s, uint64_t seed);
int      kagura_seed_tampered(const kagura_seed_t *s);

/* ===========================================================================
 * Behaviour logging and integrity reports  (runtime/game/)
 * =========================================================================== */

void kagura_log_event(uint8_t type, uint32_t detail);
int  kagura_event_count(uint8_t type);
int  kagura_suspicion_score(void);
void kagura_clear_events(void);

/* Build a nonce-bound integrity report for your server to evaluate. Returns
 * the number of bytes written to out_buf, or -1 on failure. `buf_len` must be
 * at least 256. */
int  kagura_integrity_report_build(const char *nonce,
                                   char *out_buf, size_t buf_len);

/* ===========================================================================
 * Utilities
 * =========================================================================== */

/* FNV-1a. Bit-identical to the compile-time hash the passes use, which is what
 * makes a host-side symbol map comparable to a runtime event id. */
uint32_t kagura_fnv1a32_buf(const void *data, size_t len);
uint32_t kagura_fnv1a32_str(const char *s);
uint64_t kagura_fnv1a64_buf(const void *data, size_t len);
uint64_t kagura_fnv1a64_str(const char *s);

/* Overwrite a buffer in a way the optimiser is not allowed to remove. */
void kagura_zero_buf(void *ptr, uint32_t len);

/* Entropy source used by the PointerAuth key constructor. */
uint64_t kagura_random_u64(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KAGURA_RUNTIME_H */
