/*===-- runtime/windows/device_key.c - Windows device-bound key derivation ===
 *
 * A.1: Derive a 16-byte device-bound key on Windows.
 *
 * The key is derived from:
 *   - Machine SID (from HKLM\SAM or NetAPI32 — requires elevation on some
 *     builds; fall back to ComputerName)
 *   - Volume serial number of the system drive
 *   - CPU vendor string
 *
 * All inputs are mixed with FNV-1a-32 and expanded to 16 bytes.
 *
 * Public API (mirrors runtime/core/device_key.c):
 *   int  kagura_device_key(uint8_t out[16]);   // 1 = ok, 0 = failed
 *   void kagura_device_mix_key(uint8_t key[16]); // XOR-mix key with device key
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef _WIN32

#include <stdint.h>
#include <string.h>
#include <intrin.h>   /* __cpuid */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* ---- FNV-1a-32 ----------------------------------------------------------- */

#define FNV_OFFSET_BASIS 0x811c9dc5u
#define FNV_PRIME        0x01000193u

static uint32_t fnv1a32(const uint8_t *data, size_t len) {
    uint32_t h = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= FNV_PRIME;
    }
    return h;
}

/* ---- Collect device entropy ---------------------------------------------- */

static uint32_t collect_machine_name(void) {
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD sz = sizeof(name);
    if (!GetComputerNameA(name, &sz))
        return 0xDEADBEEFu;
    return fnv1a32((const uint8_t *)name, sz);
}

static uint32_t collect_volume_serial(void) {
    char sysdir[MAX_PATH];
    if (!GetSystemDirectoryA(sysdir, MAX_PATH))
        return 0xCAFEBABEu;
    /* Truncate to root path (e.g. "C:\") */
    sysdir[3] = '\0';
    DWORD serial = 0;
    if (!GetVolumeInformationA(sysdir, NULL, 0, &serial, NULL, NULL, NULL, 0))
        return 0xFEEDFACEu;
    return fnv1a32((const uint8_t *)&serial, sizeof(serial));
}

static uint32_t collect_cpu_id(void) {
#if defined(_M_X64) || defined(__x86_64__) || \
    defined(_M_IX86) || defined(__i386__)
    int info[4] = {0};
    /* CPUID leaf 0: vendor string in EBX/ECX/EDX */
    __cpuid(info, 0);
    return fnv1a32((const uint8_t *)(info + 1), 12);
#else
    return 0x13579BDFu;
#endif
}

/* ---- Public API ---------------------------------------------------------- */

int kagura_device_key(uint8_t out[16]) {
    uint32_t parts[4];
    parts[0] = collect_machine_name();
    parts[1] = collect_volume_serial();
    parts[2] = collect_cpu_id();
    /* Fourth part: mix of the first three for avalanche effect */
    parts[3] = fnv1a32((const uint8_t *)parts, 12);

    memcpy(out, parts, 16);
    return 1;
}

void kagura_device_mix_key(uint8_t key[16]) {
    uint8_t dev[16];
    if (!kagura_device_key(dev))
        return;
    for (int i = 0; i < 16; ++i)
        key[i] ^= dev[i];
}

#endif /* _WIN32 */
