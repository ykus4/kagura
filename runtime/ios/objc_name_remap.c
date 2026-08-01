/*===-- runtime/objc_name_remap.c - ObjC class/method name remap table ---===
 *
 * ObjC class/method name obfuscation runtime support.
 *
 * The ObjCObfuscationPass obfuscates selector, class, property, and ivar
 * names at compile time.  However, code that performs dynamic lookups using
 * string APIs (NSClassFromString, NSProtocolFromString, KVO key paths, etc.)
 * would break without a runtime translation layer.
 *
 * This module maintains a hash map of original → obfuscated name mappings
 * and patches the following APIs:
 *
 *   - kagura_objc_register_remap(orig, obf): called by the module constructor
 *     emitted by ObjCObfuscationPass; populates the mapping table.
 *
 *   - kagura_objc_remap(name): translates an original name to its obfuscated
 *     equivalent, or returns name unchanged if no mapping exists.
 *
 * Usage note: callers using NSClassFromString should wrap it:
 *
 *   Class c = NSClassFromString(@(kagura_objc_remap("MyOriginalClass")));
 *
 * Or use the provided KAGURA_NSClassFromString macro (see game_protect.h).
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* ---- Simple open-addressing hash map ------------------------------------- */

#define REMAP_CAPACITY 256   /* power of 2; doubled on 75% load */

typedef struct {
    const char *original;
    const char *obfuscated;
} remap_entry_t;

static remap_entry_t *g_table   = NULL;
static size_t         g_count   = 0;
static size_t         g_cap     = 0;

static uint32_t str_hash(const char *s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) { h ^= (uint8_t)*s++; h *= 0x01000193u; }
    return h;
}

static void table_insert(const char *orig, const char *obf);

static void table_resize(void) {
    size_t new_cap  = g_cap ? g_cap * 2 : REMAP_CAPACITY;
    remap_entry_t *new_table = (remap_entry_t *)calloc(new_cap, sizeof(remap_entry_t));
    if (!new_table) return;

    remap_entry_t *old_table = g_table;
    size_t old_cap  = g_cap;
    g_table = new_table;
    g_cap   = new_cap;
    g_count = 0;

    for (size_t i = 0; i < old_cap; ++i) {
        if (old_table[i].original)
            table_insert(old_table[i].original, old_table[i].obfuscated);
    }
    free(old_table);
}

static void table_insert(const char *orig, const char *obf) {
    if (!g_table || g_count * 4 >= g_cap * 3)
        table_resize();
    if (!g_table) return;

    uint32_t h    = str_hash(orig);
    size_t   idx  = h & (g_cap - 1);
    while (g_table[idx].original) {
        if (strcmp(g_table[idx].original, orig) == 0) {
            g_table[idx].obfuscated = obf;
            return; /* update */
        }
        idx = (idx + 1) & (g_cap - 1);
    }
    g_table[idx].original   = orig;
    g_table[idx].obfuscated = obf;
    ++g_count;
}

static const char *table_lookup(const char *orig) {
    if (!g_table || !orig) return orig;
    uint32_t h   = str_hash(orig);
    size_t   idx = h & (g_cap - 1);
    while (g_table[idx].original) {
        if (strcmp(g_table[idx].original, orig) == 0)
            return g_table[idx].obfuscated;
        idx = (idx + 1) & (g_cap - 1);
    }
    return orig; /* not found: return original unchanged */
}

/* ---- Public API ---------------------------------------------------------- */

/*
 * kagura_objc_register_remap — called by the module constructor emitted by
 * ObjCObfuscationPass for each name pair.  Both strings must be long-lived
 * (typically string literals in the binary).
 */
void kagura_objc_register_remap(const char *original, const char *obfuscated) {
    if (!original || !obfuscated) return;
    table_insert(original, obfuscated);
}

/*
 * kagura_objc_remap — translate original ObjC name to its obfuscated form.
 * Returns the original name unchanged if no mapping was registered.
 *
 * Thread safety: table writes happen only during module constructors (single-
 * threaded startup); reads are safe after that.
 */
const char *kagura_objc_remap(const char *name) {
    return table_lookup(name);
}
