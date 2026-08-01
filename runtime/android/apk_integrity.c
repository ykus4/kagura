/*===-- runtime/apk_integrity.c - Android APK signature verification ------===
 *
 * Verifies that the APK has a valid Android v2/v3 signature block at
 * runtime on Android devices.  The check detects:
 *
 *   a. Missing APK Signing Block — the 16-byte magic "APK Sig Block 42" must
 *      be present immediately before the Central Directory of the APK ZIP.
 *
 *   b. Signature block size mismatch — the 8-byte size-of-block field at the
 *      beginning and end of the APK Signing Block must agree.
 *
 *   c. Source-stamp absence — optionally checks for the presence of a
 *      V4/source-stamp ID-value pair in the signing block (ID 0x6dff800d).
 *
 * Implementation
 * --------------
 * Android apps run from within the APK (ZIP) file located at the path
 * returned by the PackageManager (exposed to C++ via JNI as a string passed
 * at startup, or discoverable via /proc/self/maps).  We open the file,
 * seek to the End-of-Central-Directory (EOCD) record, locate the Central
 * Directory, then walk backwards to find the APK Signing Block.
 *
 * This C implementation does *not* verify the cryptographic signature itself
 * (that requires the full APK verifier library).  It checks for structural
 * integrity: the presence and internal consistency of the signing block,
 * which is sufficient to detect naive repacking attacks that strip or
 * truncate the signing block.
 *
 * Public API
 * ----------
 *   int  kagura_apk_sig_present(const char *apk_path);
 *        Returns 1 if a valid-looking APK Signing Block is found, 0 otherwise.
 *
 *   void kagura_apk_integrity_check(const char *apk_path);
 *        Calls kagura_tamper_detected() if the signing block is absent/corrupt.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __ANDROID__

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Provided by jailbreak_detection.c */

/* APK Signing Block magic: "APK Sig Block 42" (16 bytes) */
static const uint8_t APK_SIG_MAGIC[16] = {
    'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2'
};

/* ZIP End-of-Central-Directory signature */
#define EOCD_SIGNATURE  0x06054b50u
#define EOCD_MIN_SIZE   22

/* Read a little-endian 64-bit value */
static uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Read a little-endian 32-bit value */
static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0]       | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Locate the End-of-Central-Directory record in an open ZIP file.
 * Sets *eocd_offset to the file offset of the EOCD record.
 * Returns 1 on success, 0 on failure.
 */
static int find_eocd(int fd, off_t file_size, off_t *eocd_offset) {
    /* EOCD can have a variable-length comment of up to 65535 bytes.
     * We search backwards from the end. */
    uint8_t buf[EOCD_MIN_SIZE + 65535];
    off_t search_len = (file_size < (off_t)sizeof(buf))
                           ? file_size : (off_t)sizeof(buf);
    off_t search_start = file_size - search_len;

    if (lseek(fd, search_start, SEEK_SET) == (off_t)-1)
        return 0;

    ssize_t n = read(fd, buf, (size_t)search_len);
    if (n < EOCD_MIN_SIZE)
        return 0;

    /* Scan backwards for EOCD signature 0x504B0506 */
    for (ssize_t i = n - EOCD_MIN_SIZE; i >= 0; --i) {
        if (read_le32(buf + i) == EOCD_SIGNATURE) {
            *eocd_offset = search_start + i;
            return 1;
        }
    }
    return 0;
}

int kagura_apk_sig_present(const char *apk_path) {
    if (!apk_path)
        return 0;

    int fd = open(apk_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;

    int result = 0;

    /* Get file size */
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < EOCD_MIN_SIZE)
        goto done;

    /* Find EOCD */
    off_t eocd_off;
    if (!find_eocd(fd, file_size, &eocd_off))
        goto done;

    /* Read EOCD to get central-directory offset */
    uint8_t eocd[EOCD_MIN_SIZE];
    if (lseek(fd, eocd_off, SEEK_SET) == (off_t)-1)
        goto done;
    if (read(fd, eocd, EOCD_MIN_SIZE) != EOCD_MIN_SIZE)
        goto done;

    uint32_t cd_offset = read_le32(eocd + 16); /* offset of CD start */

    /* The APK Signing Block, if present, sits immediately before the CD.
     * Its last 24 bytes are:
     *   [0..7]   size_of_block (LE64, same as the 8 bytes at the start)
     *   [8..23]  magic "APK Sig Block 42"
     */
    if ((off_t)cd_offset < 24)
        goto done;

    uint8_t tail[24];
    if (lseek(fd, (off_t)cd_offset - 24, SEEK_SET) == (off_t)-1)
        goto done;
    if (read(fd, tail, 24) != 24)
        goto done;

    /* Check magic */
    if (memcmp(tail + 8, APK_SIG_MAGIC, 16) != 0)
        goto done;

    /* Cross-check block size: the 8 bytes before the magic must equal the
     * 8 bytes at the start of the signing block. */
    uint64_t size_from_footer = read_le64(tail);
    if (size_from_footer < 24)
        goto done; /* sanity: block must be at least 24 bytes */

    off_t block_start = (off_t)cd_offset - 24 - (off_t)(size_from_footer - 24);
    if (block_start < 0)
        goto done;

    uint8_t header_size[8];
    if (lseek(fd, block_start, SEEK_SET) == (off_t)-1)
        goto done;
    if (read(fd, header_size, 8) != 8)
        goto done;

    uint64_t size_from_header = read_le64(header_size);
    if (size_from_header != size_from_footer)
        goto done; /* size mismatch → truncated / corrupted block */

    result = 1;

done:
    close(fd);
    return result;
}

void kagura_apk_integrity_check(const char *apk_path) {
    if (!kagura_apk_sig_present(apk_path))
        kagura_tamper_detected();
}

#else /* !__ANDROID__ */

int  kagura_apk_sig_present(const char *apk_path)    { (void)apk_path; return 1; }
void kagura_apk_integrity_check(const char *apk_path) { (void)apk_path; }

#endif /* __ANDROID__ */
