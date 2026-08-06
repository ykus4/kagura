# KaguraOptions.cmake — every user-facing build option, in one place.
#
# These used to be declared across four files: six in the root CMakeLists
# interleaved with the logic that consumed them, KAGURA_BUILD_FUZZ buried in
# tests/fuzz/CMakeLists.txt (and therefore unreachable unless tests were also
# enabled), and KAGURA_SAMPLE_ANTIDEB in samples/. There was no single place to
# read them, and `cmake -LH` was the only way to discover most of them.
#
# Keep this file free of anything but option() and documentation — the logic
# that acts on these lives at the point of use.

include_guard(GLOBAL)

# ---- Build performance -------------------------------------------------------

option(KAGURA_USE_CACHE
       "Use a compiler cache (sccache, else ccache) when one is installed" ON)

option(KAGURA_UNITY_BUILD
       "Merge pass sources into unity groups: faster full builds, slower \
incremental single-file rebuilds" OFF)

option(KAGURA_PCH
       "Precompile the LLVM headers, which dominate per-TU include cost" ON)

# ---- What to build -----------------------------------------------------------

option(KAGURA_BUILD_TESTS "Build the test suite" ON)

option(KAGURA_BUILD_FUZZ
       "Build the libFuzzer targets (requires a clang with -fsanitize=fuzzer)" OFF)

option(KAGURA_BITCODE_TOOLS
       "Build kagura-opt, which applies the passes to .bc/.ll without clang" OFF)

# ---- Compatibility -----------------------------------------------------------

option(KAGURA_FORCE_STATIC_PLUGIN
       "Link the passes statically into kagura-opt even where loadable modules \
work, so the Windows linkage path can be exercised from macOS/Linux CI" OFF)
