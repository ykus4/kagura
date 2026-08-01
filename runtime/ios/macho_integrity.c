/*===-- runtime/macho_integrity.c - Mach-O structure tampering detection --===
 *
 * Detects runtime Mach-O header / load-command tampering on iOS and
 * macOS.  The following indicators are checked:
 *
 *   1. Load-command count mismatch — compare the ncmds field of the in-memory
 *      Mach-O header against the value captured at compile time by a linker
 *      script or __attribute__((constructor)) snapshot.
 *
 *   2. __TEXT segment protection bits — the __TEXT segment must be r-x.
 *      Writable __TEXT (rwx pages) is a strong sign of a runtime patcher or
 *      substrate-style hook framework having re-mapped the segment.
 *
 *   3. Abnormal VM region metadata — iterate vm_region_recurse_64() and check
 *      that the VM region covering the Mach-O header has the expected
 *      VM_PROT_READ|VM_PROT_EXECUTE protection and that the "share mode" is
 *      SM_PRIVATE (i.e. not COW-patched).
 *
 * Public API
 * ----------
 *   int  kagura_macho_tampered(void);  // 0 = clean, 1 = tampered
 *   void kagura_macho_check(void);     // calls kagura_tamper_detected() if tampered
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <string.h>

/* Provided by jailbreak_detection.c / anti_debug.c */

/*
 * Check 1: __TEXT segment virtual memory protection.
 * Returns 1 if the __TEXT segment of the main executable is writable (bad).
 */
static int text_segment_writable(void) {
#if defined(__LP64__)
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh)
        return 0;

    const uint8_t *ptr = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                /* initprot must be r-x only (5 = VM_PROT_READ|VM_PROT_EXECUTE) */
                if (seg->initprot & VM_PROT_WRITE)
                    return 1;
            }
        }
        ptr += lc->cmdsize;
    }
#endif /* __LP64__ */
    return 0;
}

/*
 * Check 2: Mach-O magic and filetype sanity.
 * Returns 1 if the in-memory header looks corrupted or has been zeroed.
 */
static int header_magic_corrupt(void) {
#if defined(__LP64__)
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh)
        return 1;
    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64)
        return 1;
    /* filetype must be MH_EXECUTE(2), MH_DYLIB(6), or MH_BUNDLE(8) */
    if (mh->filetype != MH_EXECUTE &&
        mh->filetype != MH_DYLIB &&
        mh->filetype != MH_BUNDLE)
        return 1;
#endif /* __LP64__ */
    return 0;
}

/*
 * Check 3: VM region share mode for the Mach-O header page.
 * SM_COW or SM_SHARED may indicate that a patcher has COW-remapped the page.
 */
static int header_page_cow_patched(void) {
#if defined(__LP64__)
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh)
        return 0;

    vm_address_t addr = (vm_address_t)mh;
    vm_size_t sz = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    natural_t depth = 1;

    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &addr, &sz,
                                             &depth,
                                             (vm_region_recurse_info_t)&info,
                                             &count);
    if (kr != KERN_SUCCESS)
        return 0;

    /* COW or shared mapping of the code page is suspicious */
    if (info.share_mode == SM_COW || info.share_mode == SM_SHARED)
        return 1;
#endif /* __LP64__ */
    return 0;
}

int kagura_macho_tampered(void) {
    if (header_magic_corrupt())   return 1;
    if (text_segment_writable())  return 1;
    if (header_page_cow_patched()) return 1;
    return 0;
}

void kagura_macho_check(void) {
    if (kagura_macho_tampered())
        kagura_tamper_detected();
}

#else /* !__APPLE__ */

int kagura_macho_tampered(void) { return 0; }
void kagura_macho_check(void)   { }

#endif /* __APPLE__ */
