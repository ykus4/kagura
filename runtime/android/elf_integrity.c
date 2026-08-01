/*===-- runtime/elf_integrity.c - ELF structure tampering detection --------===
 *
 * Detects runtime ELF structure tampering on Android and Linux.
 * Memory page permission check — detects W+X mapped pages.
 *
 * Checks:
 *   1. Main executable ELF header magic / e_type sanity via /proc/self/exe.
 *   2. PT_LOAD segment flags via dl_iterate_phdr: any segment with both
 *      PF_W (write) and PF_X (execute) is a sign of runtime code injection.
 *   3. /proc/self/maps scan for rwx pages.
 *
 * Public API
 * ----------
 *   int  kagura_elf_tampered(void);         // 0 = clean, 1 = tampered
 *   void kagura_elf_integrity_check(void);  // calls tamper_detected on hit
 *   int  kagura_wx_pages_present(void);     // 0 = clean, 1 = W+X page found
 *   void kagura_wx_page_check(void);        // calls tamper_detected on hit
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(__linux__) || defined(__ANDROID__)

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Check 1 + 2: ELF header magic and W+X PT_LOAD segments
 * ---------------------------------------------------------------------- */

/* dl_iterate_phdr callback: returns 1 if a W+X PT_LOAD segment is found. */
static int elf_phdr_cb(struct dl_phdr_info *info,
                                size_t size, void *data) {
    (void)size;
    int *found = (int *)data;
    if (*found) return 1;

    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type != PT_LOAD)
            continue;
        /* PF_W = 0x2, PF_X = 0x1 — a R/W/X segment is abnormal */
        if ((info->dlpi_phdr[i].p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) {
            *found = 1;
            return 1;
        }
    }
    return 0;
}

/* Check ELF header magic of the main executable. */
static int elf_header_corrupt(void) {
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0; /* can't open — not conclusive */

    unsigned char magic[4];
    ssize_t n = read(fd, magic, sizeof(magic));
    close(fd);

    if (n < 4) return 1;
    /* ELF magic: 0x7f 'E' 'L' 'F' */
    if (magic[0] != 0x7f || magic[1] != 'E' ||
        magic[2] != 'L'  || magic[3] != 'F')
        return 1;
    return 0;
}

int kagura_elf_tampered(void) {
    if (elf_header_corrupt())
        return 1;

    int wx_segment = 0;
    dl_iterate_phdr(elf_phdr_cb, &wx_segment);
    if (wx_segment)
        return 1;

    return 0;
}

void kagura_elf_integrity_check(void) {
    if (kagura_elf_tampered())
        kagura_tamper_detected();
}

/* -------------------------------------------------------------------------
 * Check 3: /proc/self/maps scan for rwx pages
 * ---------------------------------------------------------------------- */

int kagura_wx_pages_present(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;

    char line[512];
    while (fgets(line, (int)sizeof(line), f)) {
        /* maps format: addr-addr perms offset dev inode [pathname]
         * perms is 4 chars: r/-, w/-, x/-, p/s
         * rwxp or rwxs → write + exec = suspicious */
        if (strlen(line) < 4)
            continue;
        /* find the permissions field: it follows the first space after address */
        char *perms = strchr(line, ' ');
        if (!perms || strlen(perms) < 5)
            continue;
        ++perms; /* skip space */
        if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
            /* Ignore the anonymous JIT region: it typically has no filename.
             * A named rwx mapping is a strong sign of a code-patching framework. */
            /* Check if there's a non-empty filename */
            char *nl = strchr(perms, '\n');
            if (nl) *nl = '\0';
            /* Find last field (pathname) */
            char *path = strrchr(perms, ' ');
            if (path && *(path + 1) != '\0' && *(path + 1) != '[') {
                /* Named rwx region outside of [stack]/[heap]/[anon] */
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

void kagura_wx_page_check(void) {
    if (kagura_wx_pages_present())
        kagura_tamper_detected();
}

#else /* !Linux && !Android */

int  kagura_elf_tampered(void)       { return 0; }
void kagura_elf_integrity_check(void){ }
int  kagura_wx_pages_present(void)   { return 0; }
void kagura_wx_page_check(void)      { }

#endif /* __linux__ || __ANDROID__ */
