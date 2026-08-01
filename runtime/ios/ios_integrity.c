/*===-- runtime/ios_integrity.c - iOS code signing & ObjC swizzle detection ===
 *
 * iOS code signing status verification.
 * ObjC method swizzling detection.
 * Hardware breakpoint detection (iOS/macOS side, moved here for grouping;
 *          Linux side is in breakpoint_detection.c).
 * Memory page W+X check on Apple platforms via vm_region_recurse_64.
 *
 * Public API
 * ----------
 *   int  kagura_codesign_valid(void);         // 1 = valid, 0 = invalid/stripped
 *   void kagura_codesign_check(void);
 *   int  kagura_objc_swizzled(Class cls, SEL sel, IMP expected_imp);
 *   void kagura_objc_swizzle_check(Class cls, SEL sel, IMP expected_imp);
 *   int  kagura_apple_wx_pages_present(void); // W+X page detection (Apple)
 *   void kagura_apple_wx_page_check(void);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Code signing status verification
 *
 * Uses the csops(2) syscall (available on iOS and macOS) to query the
 * current process's code signing flags.  The CS_VALID flag (0x1) must be
 * set; if it is absent the signature has been stripped or invalidated (e.g.
 * by a dylib injector that patches the Mach-O in memory).
 *
 * On macOS in a development / simulator context CS_VALID may legitimately be
 * absent, so the check is gated on TARGET_OS_IOS.
 * ---------------------------------------------------------------------- */

#if TARGET_OS_IOS

#include <sys/types.h>

/* csops flags */
#define CS_VALID          0x00000001u
#define CS_ADHOC          0x00000002u
#define CS_HARD           0x00000100u
#define CS_KILL           0x00000200u
#define CS_ENFORCEMENT    0x00001000u

/* csops syscall — declared here to avoid pulling in private headers */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_STATUS 0

int kagura_codesign_valid(void) {
    uint32_t flags = 0;
    if (csops(0 /* self */, CS_OPS_STATUS, &flags, sizeof(flags)) != 0)
        return 1; /* syscall failed — assume valid to avoid false positive */
    return (flags & CS_VALID) ? 1 : 0;
}

void kagura_codesign_check(void) {
    if (!kagura_codesign_valid())
        kagura_tamper_detected();
}

#else /* macOS / tvOS / watchOS */

int  kagura_codesign_valid(void) { return 1; }
void kagura_codesign_check(void) { }

#endif /* TARGET_OS_IOS */

/* -------------------------------------------------------------------------
 * ObjC method swizzling detection
 *
 * Uses the ObjC runtime to resolve the current IMP for (cls, sel) and
 * compares it against the expected_imp recorded at startup.  A mismatch
 * indicates that method_setImplementation / method_exchangeImplementations
 * was called after the expected IMP was recorded.
 *
 * Callers should capture the expected IMP at +load or __attribute__((constructor))
 * time, before any attacker code runs, e.g.:
 *
 *   static IMP g_viewDidLoad_imp;
 *   __attribute__((constructor)) static void capture(void) {
 *       g_viewDidLoad_imp = class_getMethodImplementation(
 *           [UIViewController class], @selector(viewDidLoad));
 *   }
 *   // ... later:
 *   kagura_objc_swizzle_check([UIViewController class],
 *                             @selector(viewDidLoad),
 *                             g_viewDidLoad_imp);
 *
 * ---------------------------------------------------------------------- */

#if TARGET_OS_IOS || TARGET_OS_OSX
#include <objc/runtime.h>

int kagura_objc_swizzled(Class cls, SEL sel, IMP expected_imp) {
    if (!cls || !sel || !expected_imp)
        return 0;
    IMP current = class_getMethodImplementation(cls, sel);
    return (current != expected_imp) ? 1 : 0;
}

void kagura_objc_swizzle_check(Class cls, SEL sel, IMP expected_imp) {
    if (kagura_objc_swizzled(cls, sel, expected_imp))
        kagura_tamper_detected();
}

#else

int  kagura_objc_swizzled(void *cls, void *sel, void *imp)
    { (void)cls; (void)sel; (void)imp; return 0; }
void kagura_objc_swizzle_check(void *cls, void *sel, void *imp)
    { (void)cls; (void)sel; (void)imp; }

#endif /* TARGET_OS_IOS || TARGET_OS_OSX */

/* -------------------------------------------------------------------------
 * W+X memory page detection via vm_region_recurse_64
 *
 * Iterates the process's VM map looking for regions that are both writable
 * and executable.  This catches Substrate / libhooker style memory patches
 * that remap code pages as RWX before writing a trampoline.
 * ---------------------------------------------------------------------- */

int kagura_apple_wx_pages_present(void) {
#if defined(__LP64__)
    vm_address_t addr = 0;
    vm_size_t    size = 0;
    natural_t    depth = 1;

    while (1) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = vm_region_recurse_64(
            mach_task_self(), &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);

        if (kr != KERN_SUCCESS)
            break;

        /* Check for both write and execute protection */
        if ((info.protection & VM_PROT_WRITE) &&
            (info.protection & VM_PROT_EXECUTE)) {
            /* Ignore the JIT region which is expected to be RWX on some
             * iOS versions.  Its user_tag is typically VM_MEMORY_MALLOC_TINY
             * (11) or similar; a tag of 0 (unknown/anonymous) is suspicious. */
            if (info.user_tag == 0)
                return 1;
        }

        addr += size;
    }
#endif /* __LP64__ */
    return 0;
}

void kagura_apple_wx_page_check(void) {
    if (kagura_apple_wx_pages_present())
        kagura_tamper_detected();
}

#else /* !__APPLE__ */

int  kagura_codesign_valid(void)               { return 1; }
void kagura_codesign_check(void)               { }
int  kagura_objc_swizzled(void *a, void *b, void *c)
     { (void)a; (void)b; (void)c; return 0; }
void kagura_objc_swizzle_check(void *a, void *b, void *c)
     { (void)a; (void)b; (void)c; }
int  kagura_apple_wx_pages_present(void)       { return 0; }
void kagura_apple_wx_page_check(void)          { }

#endif /* __APPLE__ */
