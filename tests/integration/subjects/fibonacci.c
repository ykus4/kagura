#include <stdio.h>

/* Iterative fibonacci — avoids recursive-call interactions with FLA
   which rewrites the CFG dispatch but does not alter call semantics.

   fib() has external linkage and is `noinline`, and its argument is derived
   from argc, for the same reason vm_smoke.c does both: as a `static` function
   called with literal arguments, -O2 inlined it into main() and folded all
   three calls to constants before opt ever ran.  What reached the pass was a
   main() containing three printf calls and no branch, no loop and no
   arithmetic — so kagura-fla, -bcf, -bbr and -dci all found nothing to
   transform and "obfuscated output matches baseline" held by doing nothing at
   all.  REQUIRE_IR in tests/integration/CMakeLists.txt is what keeps that from
   coming back. */
__attribute__((noinline)) int fib(int n) {
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return b;
}

int main(int argc, char **argv) {
    (void)argv;
    int z = argc - 1;             /* 0 when run with no arguments, but not a
                                     compile-time constant */
    printf("%d\n", fib(10 + z));  /* 55  */
    printf("%d\n", fib(11 + z));  /* 89  */
    printf("%d\n", fib(12 + z));  /* 144 */
    return 0;
}
