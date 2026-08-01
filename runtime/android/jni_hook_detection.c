/*===-- runtime/jni_hook_detection.c - JNI table hook detection -----------===
 *
 * Detect JNI function table (JavaVM / JNIEnv) hooking.
 *
 * Hooking frameworks (e.g. YAHFA, SandHook, Epic) intercept JNI calls by
 * replacing function pointers in the JNIEnv or JavaVM vtables.  This module
 * verifies that the function pointers in the JNIEnv table still point into
 * the expected library region (libart.so / libjavacore.so) and have not been
 * redirected to a hook trampoline.
 *
 * Detection strategy
 * ------------------
 *   1. Read the JNIEnv function table pointer.
 *   2. For each sampled function pointer slot (FindClass, GetMethodID,
 *      CallObjectMethod, RegisterNatives, etc.) use dladdr() to resolve the
 *      owning shared library.
 *   3. If any pointer belongs to a library outside the expected set
 *      (libart.so, libdvm.so, libjavacore.so) it has been hooked.
 *
 * Public API
 * ----------
 *   int  kagura_jni_table_hooked(JNIEnv *env);
 *   void kagura_jni_table_check(JNIEnv *env);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __ANDROID__

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

/* Indices into the JNINativeInterface_ table that we verify */
static const int kCheckedSlots[] = {
    4,   /* FindClass */
    6,   /* GetSuperclass */
    33,  /* GetMethodID */
    36,  /* CallObjectMethod */
    215, /* RegisterNatives */
    217, /* GetJavaVM */
    -1
};

static int is_trusted_art_lib(const char *path) {
    if (!path) return 0;
    if (strstr(path, "libart.so"))      return 1;
    if (strstr(path, "libdvm.so"))      return 1;
    if (strstr(path, "libjavacore.so")) return 1;
    if (strstr(path, "libandroid_runtime.so")) return 1;
    return 0;
}

int kagura_jni_table_hooked(JNIEnv *env) {
    if (!env || !(*env)) return 0;

    /* The JNINativeInterface_ table is an array of function pointers */
    const void * const *tbl = (const void * const *)(*env);

    for (int i = 0; kCheckedSlots[i] >= 0; ++i) {
        const void *fn = tbl[kCheckedSlots[i]];
        if (!fn) continue;

        Dl_info info;
        if (dladdr(fn, &info) == 0) {
            /* dladdr failed — pointer not in any known shared library */
            return 1;
        }
        if (!is_trusted_art_lib(info.dli_fname)) {
            return 1;
        }
    }
    return 0;
}

void kagura_jni_table_check(JNIEnv *env) {
    if (kagura_jni_table_hooked(env))
        kagura_on_tamper_detected();
}

#endif /* __ANDROID__ */
