#include <stdio.h>

/* Subject for kagura-sub (instruction substitution), kagura-co (constant
   MBA) and kagura-bbs (basic block splitting).

   The original version was four `int x = <literal op literal>` statements in
   main().  -O2 folded every one of them, so what reached opt was a single
   basic block whose only instruction was a printf call with four literal
   arguments: no arithmetic for -sub to rewrite, no branch for -bbs to split,
   and no constant operand for -co outside a call argument list.  All three
   tests passed by transforming nothing.

   arith_case() is externally visible and `noinline` so it survives -O2, and
   its arguments come from argc so nothing folds through it. */
__attribute__((noinline)) int arith_case(int k, int z) {
    if (k == 0) return (6 + z) * 7;      /* 42  */
    if (k == 1) return (4 + z) * 25;     /* 100 */
    if (k == 2) return (100 + z) - 100;  /* 0   */
    return (-2 + z) + 1;                 /* -1  */
}

int main(int argc, char **argv) {
    (void)argv;
    int z = argc - 1;
    printf("%d\n%d\n%d\n%d\n",
           arith_case(0 + z, z),
           arith_case(1 + z, z),
           arith_case(2 + z, z),
           arith_case(3 + z, z));
    return 0;
}
