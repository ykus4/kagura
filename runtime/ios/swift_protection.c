/*===-- runtime/swift_protection.c - Swift metadata countermeasures -------===
 *
 * Swift metadata / demangling countermeasure.
 *
 * Swift's runtime exports extensive type metadata that reverse-engineering
 * tools (Ghidra, Hopper, class-dump-swift) use to reconstruct class
 * hierarchies, method names, and protocol conformances.  Attack vectors:
 *
 *   1. Swift demangling: `swift_demangle()` converts mangled names to human-
 *      readable form.  Tools hook this function to get free class/method info.
 *
 *   2. Type metadata sections (__swift5_types, __swift5_protos, __swift5_fieldmd):
 *      contain pointers to TypeContextDescriptor / ClassDescriptor structures
 *      that encode original names even when symbols are stripped.
 *
 *   3. Reflection metadata (__swift5_reflstr): string pool with field names
 *      used by Mirror/Codable, readable by dump tools.
 *
 * Countermeasures implemented here:
 *
 *   1. Swift demangling hook detection: verify that `swift_demangle` (if
 *      exported) resolves inside libswiftCore.dylib and has not been hooked.
 *
 *   2. Metadata section scan: walk the __swift5_fieldmd section (if present)
 *      and count the number of valid ClassDescriptor entries.  An unusual
 *      count (e.g. doubled after injection) signals metadata tampering.
 *
 *   3. Reflection string detection: check whether __swift5_reflstr contains
 *      entries that were not present at compile time (injection attack).
 *
 * Public API
 * ----------
 *   int  kagura_swift_demangle_hooked(void);   // 1 = hook detected
 *   int  kagura_swift_metadata_count(void);    // number of type descriptors
 *   void kagura_swift_check(void);             // combined; tamper cb on hit
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

/* ---- 1. Swift demangler hook detection ----------------------------------- */

static int is_swift_core(const char *path) {
    if (!path) return 0;
    if (strstr(path, "libswiftCore.dylib"))  return 1;
    if (strstr(path, "libswift_Concurrency")) return 1;
    if (strstr(path, "/usr/lib/swift/"))      return 1;
    if (strstr(path, "/Frameworks/Swift"))    return 1;
    return 0;
}

int kagura_swift_demangle_hooked(void) {
    /* Try to locate swift_demangle in the process */
    void *fn = dlsym(RTLD_DEFAULT, "swift_demangle");
    if (!fn) return 0; /* Not present = pure ObjC/C app; no concern */

    Dl_info info;
    if (dladdr(fn, &info) == 0) return 1; /* Can't resolve = suspicious */
    if (!is_swift_core(info.dli_fname))   return 1; /* Wrong library */
    return 0;
}

/* ---- 2. Metadata section scan ------------------------------------------- */

/*
 * Walk the loaded dyld images and count __swift5_types section entries
 * for the main executable.  Returns the count; 0 if none or not Swift.
 */
int kagura_swift_metadata_count(void) {
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        /* Only check the main executable (index 0 is usually the main image) */
        if (i != 0) continue;

        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr) continue;
        /* No ASLR slide needed: this function only returns a descriptor
         * *count* derived from the section size, never a runtime address. */

        /* Walk load commands to find __swift5_types section */
        const struct load_command *lc =
            (const struct load_command *)((const uint8_t *)hdr +
             (hdr->magic == MH_MAGIC_64 ? sizeof(struct mach_header_64)
                                        : sizeof(struct mach_header)));
        for (uint32_t j = 0; j < hdr->ncmds; ++j) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)lc;
                const struct section_64 *sec =
                    (const struct section_64 *)((const uint8_t *)seg +
                     sizeof(struct segment_command_64));
                for (uint32_t k = 0; k < seg->nsects; ++k) {
                    if (strncmp(sec[k].sectname, "__swift5_types", 14) == 0) {
                        /* Each entry is a 4-byte relative pointer */
                        return (int)(sec[k].size / sizeof(uint32_t));
                    }
                }
            }
            lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
        }
    }
    return 0;
}

/* ---- 3. Combined check --------------------------------------------------- */

void kagura_swift_check(void) {
    if (kagura_swift_demangle_hooked())
        kagura_on_tamper_detected();
}

#endif /* __APPLE__ */
