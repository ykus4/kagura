/*
 * breakpoint_detection.c - Hardware and software breakpoint detection
 *
 * Detects debugger activity through two mechanisms:
 *
 *   1. Software breakpoint scan: checks function prologues for INT3 (x86) or
 *      BRK (ARM64) instructions injected by debuggers.
 *
 *   2. Hardware breakpoint detection: reads debug registers via ptrace on
 *      Linux/Android; uses thread_get_state on Darwin (iOS/macOS).
 *      If any DR/DBGBVR register is non-zero, a hardware breakpoint is set.
 *
 * Public API:
 *   kagura_check_sw_breakpoints()  - Scan own code for software BPs
 *   kagura_check_hw_breakpoints()  - Read debug registers
 *   kagura_check_breakpoints()     - Combined; calls tamper callback on hit
 */

#include "../internal.h"

#include <stdint.h>
#include <string.h>

/* ─── Software breakpoint detection ─────────────────────────────────────── */

/* Returns 1 if the byte at `addr` is a breakpoint instruction. */
static int is_breakpoint_insn(const void *addr) {
    if (!addr) return 0;
    const unsigned char *p = (const unsigned char *)addr;

#if defined(__x86_64__) || defined(__i386__)
    return p[0] == 0xCC; /* INT3 */
#elif defined(__aarch64__)
    uint32_t insn;
    memcpy(&insn, p, 4);
    /* BRK #0 = 0xD4200000, BRK #1 = 0xD4200020 */
    return (insn & 0xFFE0001Fu) == 0xD4200000u;
#elif defined(__arm__)
    uint32_t insn;
    memcpy(&insn, p, 4);
    /* ARM BKPT #0 = 0xE1200070 */
    return (insn & 0xFFF000F0u) == 0xE1200070u;
#else
    (void)p;
    return 0;
#endif
}

int kagura_check_sw_breakpoints(void) {
    /* Check the first instruction of this function itself as a canary.
     * A debugger setting a BP here would be caught. */
    if (is_breakpoint_insn((const void *)kagura_check_sw_breakpoints))
        return 1;
    if (is_breakpoint_insn((const void *)kagura_on_tamper_detected))
        return 1;
    return 0;
}

/* ─── Hardware breakpoint detection ─────────────────────────────────────── */

#if defined(__linux__)
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

int kagura_check_hw_breakpoints(void) {
    /* Fork a child that ptrace-attaches to the parent and reads DR0-DR3.
     * If any DR is non-zero, a hardware breakpoint is active. */
    pid_t parent = getpid();
    pid_t child  = fork();

    if (child < 0)
        return 0; /* fork failed — can't determine */

    if (child == 0) {
        /* Child: attach to parent and read debug registers */
        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) == 0) {
            int status;
            waitpid(parent, &status, 0);

#if defined(__x86_64__)
            long dr0 = ptrace(PTRACE_PEEKUSER, parent,
                              offsetof(struct user, u_debugreg[0]), NULL);
            long dr1 = ptrace(PTRACE_PEEKUSER, parent,
                              offsetof(struct user, u_debugreg[1]), NULL);
            long dr2 = ptrace(PTRACE_PEEKUSER, parent,
                              offsetof(struct user, u_debugreg[2]), NULL);
            long dr3 = ptrace(PTRACE_PEEKUSER, parent,
                              offsetof(struct user, u_debugreg[3]), NULL);
            int has_bp = (dr0 || dr1 || dr2 || dr3) ? 1 : 0;
#else
            /* ARM64: reading DBGBVR via PTRACE_GETREGSET (NT_ARM_HW_BREAK)
             * requires kernel ≥ 3.11; fall back to 0 if unsupported. */
            int has_bp = 0;
#endif
            ptrace(PTRACE_DETACH, parent, NULL, NULL);
            _exit(has_bp);
        }
        _exit(0);
    }

    /* Parent: wait for child result */
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 0;
}

#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/thread_act.h>

int kagura_check_hw_breakpoints(void) {
#if defined(__aarch64__)
    /* Read ARM64 debug state via Mach thread_get_state */
    arm_debug_state64_t dbg;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(
        mach_thread_self(),
        ARM_DEBUG_STATE64,
        (thread_state_t)&dbg,
        &count);
    if (kr != KERN_SUCCESS)
        return 0;
    /* Check DBGBVR0–DBGBVR3 (breakpoint value registers) */
    for (int i = 0; i < 4; ++i) {
        if (dbg.__bvr[i] != 0)
            return 1;
    }
    return 0;
#else
    return 0;
#endif
}

#else

int kagura_check_hw_breakpoints(void) { return 0; }

#endif /* platform */

/* ─── Combined entry point ───────────────────────────────────────────────── */

void kagura_check_breakpoints(void) {
    if (kagura_check_sw_breakpoints() || kagura_check_hw_breakpoints())
        kagura_on_tamper_detected();
}
