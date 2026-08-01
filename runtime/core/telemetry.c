/*===-- runtime/core/telemetry.c - Telemetry event sink -------------------===
 *
 * Runtime counterpart of the `-kagura-telemetry` pass
 * (lib/Transforms/AntiAnalysis/Telemetry.cpp).
 *
 * The pass inserts, at the entry of every instrumented function:
 *
 *     call void @kagura_telemetry_event(i32 <fnv1a32(function name)>)
 *
 * The default implementation is a weak no-op so that instrumented binaries
 * link and run without a telemetry backend.  Applications that want the events
 * simply define a strong symbol with the same signature, which overrides this
 * one at link time:
 *
 *     void kagura_telemetry_event(uint32_t event_id) {
 *         my_ring_buffer_push(event_id);
 *     }
 *
 * The hook is on the hot path (one call per function entry), so an override
 * must be cheap, reentrant and async-signal-safe.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

__attribute__((weak))
void kagura_telemetry_event(uint32_t event_id) {
    (void)event_id;
}
