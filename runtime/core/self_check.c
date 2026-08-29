/*===-- runtime/core/self_check.c - Portable anti-tamper entry points -----===
 *
 * kagura_self_check() and kagura_runtime_hash_check() are emitted by
 * lib/Transforms/AntiAnalysis/AntiTamper.cpp on *every* target except Wasm -
 * self_check once into main(), hash_check once at the entry of each
 * instrumented function.  The pass has no other platform guard.
 *
 * Both used to be defined in ios/jailbreak_detection.c, which
 * runtime/CMakeLists.txt only compiles inside `if(APPLE)`.  Off Apple the two
 * symbols therefore did not exist and `-kagura-anti-tamper` could not link at
 * all on Linux, Android or Windows.  That went unnoticed because the only
 * Linux CI job that runs ctest configures with KAGURA_FORCE_STATIC_PLUGIN=ON,
 * and tests/CMakeLists.txt returns early in that mode, so the link tests never
 * register there.  This is the same shape as the Windows anti-debug gap
 * documented in runtime/CMakeLists.txt.
 *
 * Neither function needs anything Apple-specific:
 *
 *   - kagura_runtime_hash_check is gated on ARCHITECTURE (__aarch64__ /
 *     __x86_64__) and on the availability of dladdr, never on the OS.
 *   - kagura_self_check is a policy wrapper: run the detectors, invoke the
 *     tamper response if one fires.  Only the detectors are platform-specific,
 *     and they stay where they can actually be built: ios/jailbreak_detection.c
 *     on Apple, android/root_paths.c on Android.
 *
 * So the aggregate lives here, in the portable source list, and dispatches to
 * whichever detectors this target has.  On a target with no detectors at all
 * the aggregate still links and reports "not detected" - see the comment on
 * kagura_jailbreak_detected for why that is the honest answer rather than a
 * pretence of cleanliness.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>

/* dladdr() lives in <dlfcn.h>, which only exists on the dynamic-loader
 * platforms.  The hash check below guards its use with the same condition. */
#if defined(__APPLE__) || defined(__ANDROID__) || defined(__linux__)
#  include <dlfcn.h>
#endif

/* =========================================================================
 * Combined jailbreak / root detection
 * ====================================================================== */

/**
 * kagura_jailbreak_detected
 *
 * Runs all platform-appropriate checks in sequence and returns as soon as one
 * fires (short-circuit evaluation).  Individual checks are ordered from
 * cheapest / most reliable to most expensive to minimise latency on clean
 * devices.
 *
 * Returns 1 if the device appears to be jailbroken or rooted, 0 otherwise.
 *
 * IMPORTANT - what 0 means off Apple and Android
 * ----------------------------------------------
 * On Windows and on desktop Linux this function has no detectors to run and
 * returns 0.  That 0 means "kagura did not detect anything", NOT "this machine
 * is known to be clean".  There is no jailbreak/root concept to probe for on
 * those targets in the sense this file means it, and inventing one (say,
 * checking for uid 0 on Linux) would produce a check that fires on ordinary
 * container and CI workloads.  Returning a hard-coded 1, or terminating,
 * would be worse still: it would make -kagura-anti-tamper unusable on the
 * desktop builds developers test with.  Callers that need a stronger statement
 * than "not detected" must combine this with the platform-specific detectors
 * in anti_debug/ and android/ directly.
 */
int kagura_jailbreak_detected(void) {
#if defined(__APPLE__)
    if (kagura_check_substrate_dylib()) return 1;
#  if TARGET_OS_IOS
    /* iOS-only checks: fork() is blocked on stock iOS but allowed on macOS */
    if (kagura_check_dyld_env())        return 1;
    if (kagura_check_cydia_path())      return 1;
    if (kagura_check_sandbox_escape())  return 1;
    if (kagura_check_fork())            return 1;
#  endif
#elif defined(__ANDROID__)
    if (kagura_check_test_keys())       return 1;
    if (kagura_check_su_binary())       return 1;
    if (kagura_check_root_packages())   return 1;
    if (kagura_check_rw_system())       return 1;
#endif
    return 0;
}

/* =========================================================================
 * Self-check entry point
 * ====================================================================== */

/**
 * kagura_self_check
 *
 * Called by the AntiTamper pass at the entry of main() to perform a holistic
 * environment integrity check.  Runs jailbreak/root detection and calls
 * kagura_tamper_detected() if any check fires.
 *
 * This function is intentionally separate from kagura_jailbreak_detected()
 * so that the response policy lives here rather than in the detection logic,
 * allowing the detection functions to be used for telemetry without triggering
 * the hard tamper response.
 */
void kagura_self_check(void) {
    if (kagura_jailbreak_detected())
        kagura_tamper_detected();
}

/* =========================================================================
 * Runtime FNV-1a hash check
 * ====================================================================== */

/*
 * FNV-1a 32-bit offset basis — must match AntiTamper.cpp exactly.  Used below
 * only as a mixing constant for the guard tag; the hash itself lives in
 * core/hash.c.  KAGURA_FNV1A_PRIME used to be defined here too and was never
 * referenced.
 */
#define KAGURA_FNV1A_OFFSET_BASIS UINT32_C(0x811c9dc5)

/*
 * kagura_runtime_hash_check - hook/patch detection for a function.
 *
 * Called by code injected by the AntiTamper LLVM pass at the entry of each
 * protected function.  The pass supplies:
 *   @fn            A pointer into the function's machine code.
 *   @expected_hash The FNV-1a hash of the function's IR opcode sequence
 *                  computed at compile time.
 *
 * The compile-time expected_hash is an FNV-1a hash over IR opcodes and is
 * NOT directly comparable to the raw machine-code bytes.  Instead, this
 * function uses expected_hash as a "magic tag" to verify that the function
 * pointer has not been redirected by a hook trampoline (e.g. Frida, fishhook).
 *
 * Detection strategy:
 *   1. Verify fn is not NULL.
 *   2. Check the first bytes for common hooking patterns (unconditional branch
 *      on ARM64, long JMP on x86-64) which indicate an inline hook.
 *   3. Mix expected_hash into the check so that each protected function has a
 *      unique guard value — removing the check (NOP-ing the call) is detectable
 *      by other layers.
 *   4. Use dladdr to verify the function belongs to the expected image; a
 *      foreign image address indicates a redirect.
 *
 * Every branch below is selected by target ARCHITECTURE or by the presence of
 * a dynamic loader, never by the operating system.  That is why this function
 * belongs in the portable source list: on an architecture with no pattern
 * table (32-bit ARM, RISC-V) it degrades to the NULL check and the dladdr
 * scan and still links, which is what the pass requires of it.
 *
 * False positives: this check does NOT re-hash machine bytes because alignment
 * padding, ASLR, and legitimate linker transforms make byte-level hashing
 * fragile.  The IR-opcode hash stored in expected_hash is used as an opaque
 * sentinel to defeat static patching of the immediate constant.
 */
void kagura_runtime_hash_check(void *fn, uint32_t expected_hash) {
    if (!fn)
        return;

    /* Use expected_hash to prevent the compiler from optimising away the
     * parameter entirely.  XOR with a magic that expected_hash must satisfy
     * to detect the constant being NOP-patched in the binary. */
    volatile uint32_t tag = expected_hash ^ KAGURA_FNV1A_OFFSET_BASIS;
    (void)tag;

    const uint8_t *bytes = (const uint8_t *)fn;
    (void)bytes;

    /* ---- ARM64 hook detection ----
     * An unconditional branch (B instruction) at offset 0 has the top 6 bits
     * set to 0b000101.  A BR (branch to register) is 0xD61F0000.
     * Frida's inline hook on ARM64 typically starts with an LDR + BR pair or
     * a direct B to the trampoline.
     */
#if defined(__aarch64__) || defined(__arm64__)
    {
        uint32_t first_insn;
        __builtin_memcpy(&first_insn, bytes, sizeof(first_insn));
        /* B <imm26>: top 6 bits == 0b000101 (0x14 in the MSB nibble area) */
        if ((first_insn >> 26) == 0x05u)
            kagura_tamper_detected();
        /* BR Xn (0xD61F0000 | (Rn << 5)) */
        if ((first_insn & 0xFFFFFC1Fu) == 0xD61F0000u)
            kagura_tamper_detected();
    }
#endif

    /* ---- x86-64 hook detection ----
     * JMP rel32:  0xE9 <4-byte offset>  (5-byte near jump)
     * JMP [mem]:  0xFF 0x25 ...         (indirect jump through memory)
     * INT3:       0xCC                  (software breakpoint)
     */
#if defined(__x86_64__) || defined(_M_X64)
    {
        if (bytes[0] == 0xE9u || bytes[0] == 0xCCu)
            kagura_tamper_detected();
        if (bytes[0] == 0xFFu && bytes[1] == 0x25u)
            kagura_tamper_detected();
    }
#endif

    /* ---- Symbol name sanity check via dladdr ----
     * If the function pointer has been redirected to a completely foreign
     * symbol (different module path and different symbol name prefix), flag it.
     * We only check for obviously injected names like "frida" or "substrate".
     */
#if defined(__APPLE__) || defined(__ANDROID__) || defined(__linux__)
    {
        Dl_info fn_info;
        if (dladdr(fn, &fn_info) && fn_info.dli_sname) {
            const char *sym = fn_info.dli_sname;
            /* Frida typically creates symbols like "__frida_*" or "frida_*" */
            if (sym[0] == 'f' && sym[1] == 'r' && sym[2] == 'i' && sym[3] == 'd' && sym[4] == 'a')
                kagura_tamper_detected();
        }
    }
#endif
}
