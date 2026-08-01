/*===-- runtime/testflight_detect.c - TestFlight vs App Store detection ---===
 *
 * Differentiate between TestFlight and production App Store builds.
 *
 * TestFlight builds have a sandboxReceipt file under the app bundle path,
 * while App Store builds have a regular receipt.  Security-sensitive code
 * can use this to watermark or apply different protection levels for beta
 * distribution.
 *
 * Detection:
 *   1. Look for <bundle>/StoreKit/sandboxReceipt via _NSGetExecutablePath()
 *      (strips to the .app bundle root) + stat().
 *
 * Public API
 * ----------
 *   int kagura_is_testflight(void);  // 1 = TestFlight, 0 = App Store/unknown
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR

/* Walk the executable path up to the ".app" bundle root. */
static int bundle_path(char *out, size_t outsz) {
    uint32_t sz = (uint32_t)outsz;
    char exe[1024];
    if (_NSGetExecutablePath(exe, &sz) != 0)
        return 0;
    /* exe is typically .app/AppName or .app/Frameworks/… */
    char *p = exe + strlen(exe);
    while (p > exe) {
        --p;
        if (*p == '/') {
            *p = '\0';
            size_t len = (size_t)(p - exe);
            if (len >= 4 &&
                exe[len-4] == '.' &&
                exe[len-3] == 'a' &&
                exe[len-2] == 'p' &&
                exe[len-1] == 'p') {
                strncpy(out, exe, outsz - 1);
                out[outsz - 1] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

int kagura_is_testflight(void) {
    char bundle[1024];
    if (!bundle_path(bundle, sizeof(bundle)))
        return 0;
    char receipt[1200];
    size_t blen = strlen(bundle);
    if (blen + 32 >= sizeof(receipt))
        return 0;
    memcpy(receipt, bundle, blen);
    /* "/StoreKit/sandboxReceipt" is 24 bytes + null */
    memcpy(receipt + blen, "/StoreKit/sandboxReceipt", 25);
    struct stat st;
    return stat(receipt, &st) == 0 ? 1 : 0;
}

#else /* not iOS device */

int kagura_is_testflight(void) { return 0; }

#endif /* TARGET_OS_IOS */

#endif /* __APPLE__ */
