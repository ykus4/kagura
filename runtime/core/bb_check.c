/*===-- runtime/core/bb_check.c - Basic-block checksum verification -------===
 *
 * Runtime counterpart of the `-kagura-bbcheck` pass
 * (lib/Transforms/AntiAnalysis/BasicBlockChecksum.cpp).
 *
 * The pass emits, at the top of each instrumented block:
 *
 *     %r = call i32 @kagura_bb_check(i32 <block_id>, i32 <expected>)
 *     %z = icmp eq i32 %r, 0
 *     br i1 %z, label %bbchk.tamper, label %bbchk.ok
 *
 * ---------------------------------------------------------------------------
 * POLARITY (the opposite of what the function name suggests):
 *
 *     return != 0  ->  block is intact, execution continues
 *     return == 0  ->  tampering, the pass calls kagura_on_tamper_detected()
 *
 * The polarity is dictated by the IR above and must not be inverted here
 * without changing the pass in lockstep.
 * ---------------------------------------------------------------------------
 *
 * WHY THIS IS AN ALWAYS-PASSING STUB
 * ----------------------------------
 * The runtime cannot verify the `expected` value the pass hands it, for two
 * independent reasons rooted in the pass's current design:
 *
 *   1. `expected` is FNV-1a over the *LLVM IR opcodes* of the block, computed
 *      before instruction selection.  IR opcodes have no representation in the
 *      emitted binary.  At runtime there is only machine code, so there is
 *      nothing to recompute the hash from.
 *
 *   2. `block_id` is a per-function counter that restarts at 1 in every
 *      function (BasicBlockChecksum.cpp: `uint32_t BlockID = 0;` is a local),
 *      so it is not a unique key.  Blocks in different functions collide, and
 *      the runtime could not use it to look anything up even if a table
 *      existed.
 *
 * Real per-block integrity checking would require the pass to emit
 * post-codegen byte ranges (address + length + hash of the actual machine
 * code) into a table the runtime can walk.  That is a change on the pass side;
 * until it happens, the only honest implementation is "intact".  Hashing some
 * arbitrary memory range here and pretending it verifies anything would be
 * strictly worse than this stub: it would look like a real check while
 * providing no security and adding false positives.
 *
 * The symbol is weak, so an integrator who does build a trusted block table
 * can override it:
 *
 *     int kagura_bb_check(uint32_t block_id, uint32_t expected) {
 *         return my_hash_of_block(block_id) == expected;
 *     }
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

__attribute__((weak))
int kagura_bb_check(uint32_t block_id, uint32_t expected) {
    (void)block_id;
    (void)expected;
    /* Nonzero == intact.  See the polarity note above. */
    return 1;
}
