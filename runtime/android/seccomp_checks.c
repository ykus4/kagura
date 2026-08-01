/*===-- runtime/seccomp_checks.c - seccomp/prctl environment checks -------===
 *
 * Detect seccomp/prctl sandbox environment indicators that may signal
 *         a security research or analysis environment on Android/Linux.
 *
 * Checks performed:
 *   1. seccomp mode — if the process is in strict or filter seccomp mode
 *      (PR_GET_SECCOMP returns non-zero), we may be inside a sandbox or
 *      a researcher's harness.
 *   2. dumpability — PR_GET_DUMPABLE == 0 means core dumps are suppressed,
 *      which is normal in production but we record it for completeness.
 *   3. ptrace scope — read /proc/sys/kernel/yama/ptrace_scope to determine
 *      whether ptrace is unrestricted (value 0), which is common on rooted
 *      or researcher-controlled devices.
 *   4. No-new-privs bit — PR_GET_NO_NEW_PRIVS set by a container or
 *      debugger harness.
 *
 * These checks are informational signals that combine with other detections.
 * None of them individually is a definitive indicator of compromise, but
 * combined scores above a threshold should trigger the tamper callback.
 *
 * Public API
 * ----------
 *   int  kagura_seccomp_active(void);     // 1 = seccomp filter/strict active
 *   int  kagura_ptrace_unrestricted(void);// 1 = yama ptrace_scope == 0
 *   int  kagura_no_new_privs_set(void);   // 1 = no_new_privs bit set
 *   void kagura_prctl_check(void);        // combined; tamper cb if score >= 2
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(__linux__) || defined(__ANDROID__)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>

/* PR_GET_SECCOMP — returns 0 if not active, 1 if strict, 2 if filter */
int kagura_seccomp_active(void) {
    int mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return mode > 0 ? 1 : 0;
}

/* yama/ptrace_scope: 0 = unrestricted (researcher / rooted device) */
int kagura_ptrace_unrestricted(void) {
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (!f) return 0; /* file absent means Yama not loaded — default permissive */
    char buf[4] = {0};
    if (fread(buf, 1, 1, f) == 1) {
        fclose(f);
        return buf[0] == '0' ? 1 : 0;
    }
    fclose(f);
    return 0;
}

/* PR_GET_NO_NEW_PRIVS */
int kagura_no_new_privs_set(void) {
    return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 1 : 0;
}

/* Combined check — trigger tamper callback if two or more signals fire */
void kagura_prctl_check(void) {
    int score = 0;
    score += kagura_seccomp_active();
    score += kagura_ptrace_unrestricted();
    score += kagura_no_new_privs_set();
    if (score >= 2)
        kagura_on_tamper_detected();
}

#endif /* __linux__ || __ANDROID__ */
