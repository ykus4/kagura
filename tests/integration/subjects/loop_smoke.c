#include <stdio.h>

/* Subject for kagura-lt (loop transformation).

   Both loops used to be written directly in main() over literal bounds, which
   -O2 replaced with the closed-form constants 45 and 550 — there was no loop
   left in the IR by the time the pass ran, so lt_correctness passed without
   the pass ever touching a loop.  Moving them into `noinline` functions over
   argc-derived bounds is not enough on its own: indvars/SCEV still recognises
   `sum += i` as a triangular number and rewrites both loops into closed form.
   Accumulating through an opaque `noinline` helper is what actually keeps a
   loop in the IR. */
__attribute__((noinline)) int accumulate(int acc, int x) { return acc + x; }

__attribute__((noinline)) int sum_below(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) sum = accumulate(sum, i);
    return sum;
}

__attribute__((noinline)) int sum_step(int lo, int hi, int step) {
    int sum = 0;
    for (int i = lo; i <= hi; i += step) sum = accumulate(sum, i);
    return sum;
}

int main(int argc, char **argv) {
    (void)argv;
    int z = argc - 1;
    printf("%d\n", sum_below(10 + z));         /* 0+1+...+9 = 45 */
    printf("%d\n", sum_step(z, 100, 10 + z));  /* 0+10+...+100 = 550 */
    return 0;
}
