# Performance & Size Impact

Overhead varies by pass and function complexity. Measurements below are from
a representative mobile game module (~200 functions, Cortex-A55).

| Pass | Code size delta | Runtime overhead | Notes |
|:-----|:----------------|:-----------------|:------|
| `str` | +5 – 15% | <1% | Decrypt on first access, zero after; hot strings cached |
| `str-aes` | +8 – 20% | <1% | AES-128-CTR; same caching behavior |
| `fla` | +40 – 120% / fn | 5 – 15% on tight loops | Worst case on functions with many small BBs |
| `bcf` | +20 – 50% BBs | <2% | Dead code — never executed |
| `sub` | +10 – 30% / fn | 3 – 8% on arithmetic-heavy code | Use `--kagura-sub-iter=1` (default) |
| `mvo` | +15 – 40% / fn | 5 – 12% on alloca-heavy code | Pairs with `pe` for maximum coverage |
| `vm`  | −30 to +200% | 10 – 50× slowdown | Reserve for small, rarely-called functions (license check, crypto init) |
| `anti-debug` | +<1% | Negligible (startup only) | One-time check at init |
| `bbcheck` | +10 – 20% | 2 – 5% | **Scaffolding cost only.** This is what the call sites cost; the shipped `kagura_bb_check` always returns "intact", so you are paying it for no detection. See [Anti-Analysis](anti-analysis.md#-kagura-bbcheck-detects-nothing-as-shipped) |

## Recommendation

Apply the `BALANCED` [strength profile](../configuration.md) globally, then
annotate the 10–20 most sensitive functions with `STRONG` or `kagura_vm`.
This keeps median overhead under 5% while maximizing protection on critical
paths.

```c
// hot path — default BALANCED is fine
int game_tick(GameState *s) { ... }

// security-critical — VM-virtualize even though it's slower
__attribute__((annotate("kagura_vm")))
int verify_session_token(const char *t) { ... }
```
