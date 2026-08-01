/*===-- runtime/windows/integrity.c - Windows PE integrity checks ---------===
 *
 * A.1: Windows PE integrity and memory-protection checks.
 *
 * Checks implemented:
 *   kagura_pe_checksum_valid     — verify PE optional header checksum
 *   kagura_check_wx_pages        — scan for W+X (RWX) memory pages
 *   kagura_pe_integrity_check    — aggregate PE check
 *   kagura_memory_protection_check — aggregate memory-protection check
 *
 * Public API:
 *   int  kagura_*_valid()   — 1 = valid/clean, 0 = tampered/suspicious
 *   int  kagura_check_*()   — 1 = detected, 0 = clean
 *   void kagura_*_check()   — calls kagura_on_tamper_detected() on detection
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef _WIN32

#include <stdint.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <imagehlp.h>   /* MapFileAndCheckSum */

/* ---- PE optional-header checksum verification ---------------------------- */
/*
 * The PE optional header carries a checksum of the on-disk image computed by
 * the linker.  MapFileAndCheckSum re-derives it from disk; a mismatch means
 * the file has been patched (e.g. by a packer or unpacker that forgot to
 * update the checksum).
 *
 * Note: many legitimate binaries ship with checksum == 0 (the linker only
 * sets it for drivers and signed executables).  We treat 0 as "unchecked"
 * and return 1 (valid) to avoid false positives.
 */
int kagura_pe_checksum_valid(void) {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH))
        return 1; /* can't determine path — assume valid */

    DWORD headerSum  = 0;
    DWORD computedSum = 0;
    if (MapFileAndCheckSumA(path, &headerSum, &computedSum) != CHECKSUM_SUCCESS)
        return 1; /* API failed — assume valid */

    if (headerSum == 0)
        return 1; /* checksum not set — unchecked binary */

    return (headerSum == computedSum) ? 1 : 0;
}

void kagura_pe_integrity_check(void) {
    if (!kagura_pe_checksum_valid())
        kagura_on_tamper_detected();
}

/* ---- W+X (RWX) memory page detection ------------------------------------- */
/*
 * Iterate the virtual address space with VirtualQuery().  Any region that is
 * both PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY indicates a trampoline
 * or code-injection page — suspicious in a normal (non-JIT) binary.
 *
 * Known-safe: .NET / V8 / LuaJIT mark JIT regions RWX; we cannot easily
 * distinguish them here, so this check is conservative (skip MEM_IMAGE pages
 * which are always backed by a mapped PE section).
 */
int kagura_check_wx_pages(void) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE |
                                         PAGE_WRITECOMBINE);
            if (prot == PAGE_EXECUTE_READWRITE ||
                prot == PAGE_EXECUTE_WRITECOPY) {
                return 1;
            }
        }
        /* Advance to the next region */
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    return 0;
}

void kagura_memory_protection_check(void) {
    if (kagura_check_wx_pages())
        kagura_on_tamper_detected();
}

#endif /* _WIN32 */
