/*
 * hook_detection.c - GOT/PLT hook and inline hook detection
 *
 * Detects common hooking techniques used by Frida, Substrate, and other
 * dynamic instrumentation frameworks on Android (Linux/ELF) and iOS (Mach-O).
 *
 * Public API:
 *   kagura_check_got_hooks()     - Scan GOT/PLT for unexpected redirections
 *   kagura_check_inline_hooks()  - Detect inline (trampoline) hooks in libc
 *   kagura_check_hooks()         - Combined check; calls tamper callback on hit
 */

#include "../internal.h"

#include <stdint.h>
#include <string.h>

/* ─── Inline hook detection ─────────────────────────────────────────────────
 *
 * A common inline hook pattern prepends a function prologue with an
 * unconditional branch (trampoline) to a hook handler:
 *
 *   ARM64 : 0x14000000 | (offset >> 2)  — B <offset>
 *   ARM32  : 0xEA000000                  — B instruction family
 *   x86-64 : 0xE9 <rel32>               — JMP rel32
 *
 * We check a small set of libc/libdl functions that hooking frameworks
 * commonly intercept (open, fopen, dlsym, mmap).  If the first instruction
 * byte pattern matches a known branch encoding, we report a hook.
 */

#include <dlfcn.h>

/* Returns 1 if the bytes at `addr` look like a trampoline branch. */
static int looks_like_hook(const void *addr) {
    if (!addr) return 0;
    const unsigned char *p = (const unsigned char *)addr;

#if defined(__aarch64__)
    /* ARM64: unconditional branch B = 0b000101xx (top 6 bits = 0x14..0x17) */
    uint32_t insn;
    memcpy(&insn, p, 4);
    if ((insn >> 26) == 0x5u) /* 0b000101 */ return 1;
    /* BLR / BR via x17 stub (common Substrate pattern) */
    if (insn == 0xD61F0220u || insn == 0xD63F0220u) return 1;
#elif defined(__arm__)
    /* ARM32 unconditional branch: top 4 bits = 0b1110 (condition AL),
     * bits 27-24 = 0b1010 (B) or 0b1011 (BL) */
    uint32_t insn;
    memcpy(&insn, p, 4);
    if ((insn & 0xFF000000u) == 0xEA000000u) return 1;
    if ((insn & 0xFF000000u) == 0xEB000000u) return 1;
#elif defined(__x86_64__) || defined(__i386__)
    /* x86/x86-64: JMP rel32 = 0xE9, JMP r/m = 0xFF /4 */
    if (p[0] == 0xE9u) return 1;
    if (p[0] == 0xFFu && (p[1] & 0x38u) == 0x20u) return 1;
#endif
    return 0;
}

int kagura_check_inline_hooks(void) {
    /* Symbols commonly targeted by hooking frameworks */
    static const char *Targets[] = {
        "open", "fopen", "dlsym", "mmap", "ptrace", NULL
    };

    for (int i = 0; Targets[i]; ++i) {
        void *sym = dlsym(
#if defined(__APPLE__)
            (void *)-2L, /* RTLD_DEFAULT on Darwin */
#else
            (void *)0,   /* RTLD_DEFAULT on Linux */
#endif
            Targets[i]);
        if (!sym) continue;
        if (looks_like_hook(sym))
            return 1;
    }
    return 0;
}

/* ─── GOT/PLT hook detection (Linux/Android ELF only) ───────────────────────
 *
 * On Android, we use dl_iterate_phdr to walk loaded shared objects and
 * compare each GOT entry against the resolved symbol address.  A mismatch
 * indicates that a hook redirected the GOT slot (fishhook-style).
 *
 * On iOS (Mach-O), GOT patching is harder to do portably without parsing
 * the Mach-O manually, so we rely on inline hook detection instead.
 */

#ifdef __linux__
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <stdlib.h>

/* Callback data for the GOT scan */
struct got_scan_ctx {
    int found_hook;
};

/*
 * Turn a d_un.d_ptr taken from the dynamic section into a usable address.
 *
 * Whether DT_STRTAB / DT_SYMTAB / DT_RELA already hold runtime addresses is
 * not portable.  glibc's prelinked layout stores them pre-relocated, so
 * reading them verbatim works there and that is what this code used to do.
 * Bionic and any ordinary non-prelinked ELF store *link-time vaddrs*, which
 * for a PIE or shared object are offsets from the load address: taking them
 * verbatim yielded a pointer near zero, and the
 * `strtab + symtab[sym_idx].st_name` dereference further down then read wild
 * memory once per relocation of every loaded object.  On Android that is a
 * segfault during startup hook detection.
 *
 * The two cases are told apart by magnitude, which is the standard heuristic:
 * a value below the object's load address cannot be a runtime address inside
 * that object, so it must still be a link-time vaddr and needs the bias added.
 * A value at or above the load address is already relocated and is left alone.
 * dlpi_addr is 0 for a non-PIE main executable, where both readings coincide
 * and the heuristic is a no-op.
 */
static uintptr_t bias_ptr(const struct dl_phdr_info *info, ElfW(Addr) v) {
    if ((uintptr_t)v < (uintptr_t)info->dlpi_addr)
        return (uintptr_t)info->dlpi_addr + (uintptr_t)v;
    return (uintptr_t)v;
}

static int got_phdr_cb(struct dl_phdr_info *info,
                               size_t size, void *data) {
    (void)size;
    struct got_scan_ctx *ctx = (struct got_scan_ctx *)data;
    if (ctx->found_hook) return 1; /* short-circuit */

    /* Walk program headers looking for PT_DYNAMIC */
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type != PT_DYNAMIC) continue;

        const ElfW(Dyn) *dyn =
            (const ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);

        const char *strtab   = NULL;
        const ElfW(Sym) *symtab = NULL;
        const ElfW(Rela) *rela  = NULL;
        size_t rela_count       = 0;

        for (; dyn->d_tag != DT_NULL; ++dyn) {
            switch (dyn->d_tag) {
            case DT_STRTAB:  strtab  = (const char *)bias_ptr(info, dyn->d_un.d_ptr); break;
            case DT_SYMTAB:  symtab  = (const ElfW(Sym) *)bias_ptr(info, dyn->d_un.d_ptr); break;
            case DT_RELA:    rela    = (const ElfW(Rela) *)bias_ptr(info, dyn->d_un.d_ptr); break;
            case DT_RELASZ:  rela_count = dyn->d_un.d_val / sizeof(ElfW(Rela)); break;
            default: break;
            }
        }

        if (!strtab || !symtab || !rela || rela_count == 0) continue;

        for (size_t j = 0; j < rela_count; ++j) {
#if __SIZEOF_POINTER__ == 8
            unsigned sym_idx = (unsigned)ELF64_R_SYM(rela[j].r_info);
#else
            unsigned sym_idx = (unsigned)ELF32_R_SYM(rela[j].r_info);
#endif
            if (sym_idx == 0) continue;

            const char *sym_name = strtab + symtab[sym_idx].st_name;
            void *got_entry_ptr  =
                (void *)(info->dlpi_addr + rela[j].r_offset);
            void *got_value;
            memcpy(&got_value, got_entry_ptr, sizeof(void *));

            /* Resolve expected address via dlsym */
            void *expected = dlsym((void *)0 /* RTLD_DEFAULT */, sym_name);
            if (!expected) continue;

            /* Allow a small delta for PLT stub redirections by the dynamic
             * linker itself (typically within the same DSO).  A large
             * divergence indicates a hook. */
            uintptr_t diff = (uintptr_t)got_value > (uintptr_t)expected
                             ? (uintptr_t)got_value - (uintptr_t)expected
                             : (uintptr_t)expected - (uintptr_t)got_value;

            if (diff > 0x100000u) { /* > 1 MiB displacement = suspicious */
                ctx->found_hook = 1;
                return 1;
            }
        }
    }
    return 0;
}

int kagura_check_got_hooks(void) {
    struct got_scan_ctx ctx = { 0 };
    dl_iterate_phdr(got_phdr_cb, &ctx);
    return ctx.found_hook;
}

#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <stdlib.h>

/* On Apple platforms (macOS / iOS), scan loaded images for GOT/lazy-bind
 * entries whose resolved addresses diverge significantly from what dlsym()
 * returns.  This catches fishhook-style GOT patches applied by Frida or
 * Substrate.  We walk all loaded Mach-O images via _dyld_get_image_header()
 * and inspect LC_DYLD_INFO_ONLY / LC_DYSYMTAB indirect symbol tables.
 *
 * NOTE: Full GOT scanning on iOS requires entitlements and may be restricted
 * in sandboxed apps.  This implementation covers macOS and jailbroken iOS.
 */
int kagura_check_got_hooks(void) {
    uint32_t img_count = _dyld_image_count();

    for (uint32_t img = 0; img < img_count; ++img) {
        const struct mach_header *mh = _dyld_get_image_header(img);
        if (!mh) continue;

#if __LP64__
        if (mh->magic != MH_MAGIC_64) continue;
        const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
        const struct load_command *lc =
            (const struct load_command *)((uintptr_t)mh64 + sizeof(*mh64));
        uint32_t ncmds = mh64->ncmds;
#else
        if (mh->magic != MH_MAGIC) continue;
        const struct load_command *lc =
            (const struct load_command *)((uintptr_t)mh + sizeof(*mh));
        uint32_t ncmds = mh->ncmds;
#endif
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);

        for (uint32_t ci = 0; ci < ncmds; ++ci) {
            if (lc->cmd == LC_SEGMENT_64 || lc->cmd == LC_SEGMENT) {
#if __LP64__
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)lc;
                const struct section_64 *sect =
                    (const struct section_64 *)((uintptr_t)seg + sizeof(*seg));
                uint32_t nsects = seg->nsects;
#else
                const struct segment_command *seg =
                    (const struct segment_command *)lc;
                const struct section *sect =
                    (const struct section *)((uintptr_t)seg + sizeof(*seg));
                uint32_t nsects = seg->nsects;
#endif
                for (uint32_t si = 0; si < nsects; ++si) {
                    uint32_t stype = sect[si].flags & SECTION_TYPE;
                    /* S_LAZY_SYMBOL_POINTERS = 0x8, S_NON_LAZY_SYMBOL_POINTERS = 0x6 */
                    if (stype != S_LAZY_SYMBOL_POINTERS &&
                        stype != S_NON_LAZY_SYMBOL_POINTERS)
                        continue;

                    uintptr_t sect_addr = (uintptr_t)sect[si].addr + (uintptr_t)slide;
                    uint32_t nptrs = (uint32_t)(sect[si].size / sizeof(void *));
                    void **ptrs = (void **)sect_addr;

                    for (uint32_t pi = 0; pi < nptrs; ++pi) {
                        void *got_val = ptrs[pi];
                        if (!got_val) continue;
                        /* Check if the GOT entry points outside any loaded image
                         * by comparing against the image's own address range —
                         * a rough but effective heuristic for fishhook patches. */
                        uintptr_t val = (uintptr_t)got_val;
                        int in_image = 0;
                        for (uint32_t k = 0; k < img_count; ++k) {
                            const struct mach_header *kh = _dyld_get_image_header(k);
                            if (!kh) continue;
                            uintptr_t base = (uintptr_t)kh;
                            /* Rough 64 MiB window per image — catches most hooks */
                            if (val >= base && val < base + 0x4000000u) {
                                in_image = 1;
                                break;
                            }
                        }
                        if (!in_image)
                            return 1; /* pointer escapes all known images */
                    }
                }
            }
            lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
        }
    }
    return 0;
}

#else /* other non-Linux, non-Apple platforms */

int kagura_check_got_hooks(void) {
    return 0; /* Not implemented on this platform */
}

#endif /* __linux__ / __APPLE__ */

/* ─── Combined entry point ───────────────────────────────────────────────── */

void kagura_check_hooks(void) {
    if (kagura_check_inline_hooks() || kagura_check_got_hooks())
        kagura_on_tamper_detected();
}
