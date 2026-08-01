/*===-- KaguraRuntime.h - Public umbrella header for the SwiftPM target ---===
 *
 * This is the public headers directory for the `KaguraRuntime` SwiftPM
 * target declared in integration/swiftpm/Package.swift.
 *
 * It deliberately does NOT re-export include/kagura/*.h: Options.h, Passes.h,
 * Utils.h and VM.h are compiler-plugin headers that `#include` LLVM headers,
 * and game_protect.h is a C++ template header. Exposing any of them as the
 * public headers of a C target would make the generated Clang module
 * unbuildable for Swift consumers.
 *
 * C++ users who want `kagura::Protected<T>` should add
 * `<package root>/include` to their own header search path and
 * `#include "kagura/game_protect.h"` directly.
 *
 *===----------------------------------------------------------------------===*/

#ifndef KAGURA_RUNTIME_H
#define KAGURA_RUNTIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keep in sync with project(kagura VERSION ...) in the root CMakeLists.txt. */
#define KAGURA_VERSION_MAJOR 0
#define KAGURA_VERSION_MINOR 2
#define KAGURA_VERSION_PATCH 1
#define KAGURA_VERSION_STRING "0.2.1"

/*
 * Tamper callback.
 *
 * The runtime defines a weak no-op. Provide a strong definition in your own
 * code to react to a detected debugger / hook / integrity failure (kill the
 * process, degrade gracefully, report to your backend, ...).
 */
void kagura_on_tamper_detected(void);

/* Aggregate jailbreak / root check. Non-zero when the device looks
 * compromised. Apple platforms only. */
int kagura_jailbreak_detected(void);

/* Runs the full jailbreak/tamper check set and invokes
 * kagura_on_tamper_detected() on failure. Apple platforms only. */
void kagura_self_check(void);

/* Non-zero when a ptrace-style tracer is attached to this process. */
int kagura_check_tracer_pid(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KAGURA_RUNTIME_H */
