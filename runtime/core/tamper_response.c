/*===-- runtime/core/tamper_response.c - Unified tamper response ----------===
 *
 * The single owner of the kagura tamper-response policy.
 *
 * Two exported names exist because the passes emit both:
 *
 *   kagura_on_tamper_detected  — AntiDebug.cpp, BasicBlockChecksum.cpp
 *   kagura_tamper_detected     — AntiTamper.cpp
 *
 * Neither may be removed.  What *was* removed is the duplication behind them:
 * before this file existed the runtime had three competing definitions -
 * a weak abort() in anti_debug/anti_debug.c, a second weak ExitProcess() in
 * windows/anti_debug.c, and a strong noreturn spin-loop named
 * kagura_tamper_detected buried in ios/jailbreak_detection.c.  The last one
 * was the worst: Android and Windows links that pull in elf_integrity.o (or
 * any of the eight other callers) but not jailbreak_detection.o got an
 * undefined symbol, because the definition lived in an Apple-only file.
 *
 * Policy
 * ------
 * kagura_on_tamper_detected is the overridable hook.  It is weak, so an
 * application replaces it simply by defining a strong symbol with the same
 * signature:
 *
 *     void kagura_on_tamper_detected(void) { my_report_and_quit(); }
 *
 * kagura_tamper_detected is the noreturn entry point.  It runs the hook and,
 * if the hook returns (only possible for an override), falls through to a
 * hard stop.  Keeping the noreturn contract matters: call sites emitted by
 * AntiTamper.cpp and the `unreachable` the passes place after the call both
 * depend on it.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdlib.h>   /* abort */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <unistd.h>  /* sleep */
#endif

/* ---- Overridable policy hook -------------------------------------------- */

KAGURA_WEAK
void kagura_on_tamper_detected(void) {
#if defined(_WIN32)
    /* ExitProcess rather than abort(): abort() raises a Windows Error
     * Reporting dialog, which both annoys legitimate users and hands the
     * attacker a convenient breakpoint. */
    ExitProcess(1);
#else
    abort();
#endif
}

/* ---- Noreturn entry point ------------------------------------------------ */

__attribute__((noreturn, noinline))
void kagura_tamper_detected(void) {
    kagura_on_tamper_detected();

    /* Only reachable when an application override returns.  Spin-sleep first:
     * an apparent hang is harder to trace back to the detection site than a
     * crash dump is, and it keeps an attached reverse-engineering session
     * occupied.  abort() inside the loop guarantees termination even if the
     * platform sleep API has been patched to return immediately. */
    for (;;) {
#if defined(_WIN32)
        Sleep(0xFFFFFFFFu);
        ExitProcess(1);
#else
        sleep(999999u);
        abort();
#endif
    }
}
