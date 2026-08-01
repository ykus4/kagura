/*
 * vm_smoke.c — integration subject for the VM obfuscation pass.
 *
 * The helpers below are the shapes kagura's VM has to lower correctly, and each
 * one is a shape the pass used to get wrong:
 *
 *   vm_fib       loop-carried PHI nodes         (used to hang: the condition was
 *                                                dropped and the VM span on one
 *                                                edge forever)
 *   vm_gcd       loop + signed remainder
 *   vm_bsearch   pointer argument + int32 loads (pointer arguments used to be
 *                                                passed to the VM as 0)
 *   vm_classify  switch cascade
 *   vm_mix       unsigned shifts and 32-bit wraparound
 *   vm_apply     a direct call to another virtualised function
 *   vm_narrow    i8/i16 truncation and sign extension
 *
 * They have external linkage and are `noinline` so that -O2 cannot inline or
 * argument-specialise them away before the pass runs; main() calls printf, which
 * is variadic, so main itself stays native and the output is produced by real
 * code calling virtualised code.
 */

#include <stdio.h>

__attribute__((noinline)) int vm_fib(int n) {
    int a = 0, b = 1;
    for (int i = 0; i < n; ++i) {
        int c = a + b;
        a = b;
        b = c;
    }
    return a;
}

__attribute__((noinline)) int vm_gcd(int a, int b) {
    while (b != 0) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a < 0 ? -a : a;
}

__attribute__((noinline)) int vm_bsearch(const int *arr, int len, int target) {
    int lo = 0, hi = len - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int val = arr[mid];
        if (val == target) return mid;
        if (val < target) lo = mid + 1;
        else              hi = mid - 1;
    }
    return -1;
}

__attribute__((noinline)) int vm_classify(int x) {
    switch (x) {
    case 0:  return 100;
    case 1:  return 200;
    case 2:  return 300;
    case 7:  return 700;
    case 42: return 4200;
    default: return -1;
    }
}

__attribute__((noinline)) unsigned vm_mix(unsigned x) {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

/* Calls another virtualised function, so the callee's address has to travel
 * through the bytecode's relocation pool. */
__attribute__((noinline)) int vm_apply(const int *events, int n) {
    int acc = 0;
    for (int i = 0; i < n; ++i)
        acc += vm_classify(events[i]);
    return acc;
}

__attribute__((noinline)) int vm_narrow(int x) {
    signed char  c = (signed char)x;
    short        s = (short)(x >> 3);
    unsigned char u = (unsigned char)x;
    return (int)c + (int)s + (int)u;
}

int main(void) {
    static const int sorted[] = {2, 5, 8, 12, 16, 23, 38, 56, 72, 91};
    static const int events[] = {0, 1, 2, 7, 42, 5};

    printf("fib      = %d %d %d\n", vm_fib(0), vm_fib(1), vm_fib(20));
    printf("gcd      = %d %d %d\n", vm_gcd(48, 18), vm_gcd(17, 5), vm_gcd(0, 9));
    printf("bsearch  = %d %d %d %d\n",
           vm_bsearch(sorted, 10, 23), vm_bsearch(sorted, 10, 2),
           vm_bsearch(sorted, 10, 91), vm_bsearch(sorted, 10, 99));
    printf("classify = %d %d %d\n",
           vm_classify(2), vm_classify(42), vm_classify(9));
    printf("mix      = %u %u\n", vm_mix(0u), vm_mix(123456789u));
    printf("apply    = %d\n", vm_apply(events, 6));
    printf("narrow   = %d %d\n", vm_narrow(-1234567), vm_narrow(305419896));
    return 0;
}
