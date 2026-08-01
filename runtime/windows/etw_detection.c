/*===-- runtime/windows/etw_detection.c - ETW-based analysis detection ----===
 *
 * Event Tracing for Windows (ETW) — detect analysis tools by their ETW signature.
 *
 * Many Windows analysis tools register ETW providers or consume specific
 * Microsoft-Windows-Kernel-* providers in ways a normal app does not:
 *
 *   - Cheat Engine: subscribes to Microsoft-Windows-Kernel-Process for the
 *     OpenProcess audit signal so it can find the target process by name
 *   - Process Hacker / System Informer: registers its own provider
 *     `Microsoft-Windows-Process-Hacker`
 *   - Procmon: registers `Microsoft-Windows-Sysinternals-Procmon`
 *   - x64dbg: doesn't use ETW directly but its plugin "ScyllaHide" does for
 *     anti-anti-debug
 *
 * This module exposes:
 *
 *   int kagura_etw_provider_present(const wchar_t *provider_guid)
 *       — returns 1 if the named ETW provider is currently registered system-wide
 *
 *   int kagura_etw_analysis_tool_check(void)
 *       — convenience: scans for a set of known analysis-tool providers and
 *         returns 1 if any are present
 *
 * The detection is conservative: it only flags **provider registration**, not
 * subscription. A legitimate app that happens to call ETW APIs won't trigger.
 *
 * NOTE: This is a stub implementation. The full version uses
 * `EnumerateTraceGuids` (deprecated but still works on Windows 10+) or the
 * newer `TdhEnumerateProviders`. The stub here demonstrates the API shape
 * without pulling in the full TDH dependency — wire it up by replacing the
 * `__kagura_etw_query_providers` body with the real enumeration code.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef _WIN32

#include <stdint.h>
#include <string.h>
#include <wchar.h>

/* ETW headers are heavyweight; only include them when the full
 * implementation is enabled. The stub uses no Win32 APIs at all. */
#ifdef KAGURA_ETW_FULL
#  include <windows.h>
#  include <evntrace.h>
#  include <evntcons.h>
#  include <tdh.h>
#  pragma comment(lib, "tdh.lib")
#endif

/* ---- Known-bad provider GUIDs ------------------------------------------- */

/*
 * Provider GUIDs documented or observed for common analysis tools.
 *
 * NOTE: GUIDs below are PLACEHOLDERS — the real implementation should be
 * audited against current versions of each tool. Some tools change their
 * GUIDs across releases.
 */
static const wchar_t *kAnalysisToolProviders[] = {
    /* Process Hacker / System Informer */
    L"{16FF0FE7-9C53-4f01-86D0-3866C92B6132}",
    /* Sysinternals Procmon */
    L"{B68C0C6E-1A1C-4F1B-A4F2-3A4B89B3B16F}",
    /* ScyllaHide (x64dbg plugin) — uses an MS provider for kernel debug */
    L"{650B9970-39B0-4d6c-887D-DCED9C0BB7BC}",
    NULL,
};

/* ---- Stub: provider query ----------------------------------------------- */

/*
 * Query whether an ETW provider with the given GUID is currently registered
 * on the system. Returns 1 if registered, 0 if not, -1 on query failure.
 *
 * STUB: this implementation always returns 0 (clean). Replace with real
 * TdhEnumerateProviders or EnumerateTraceGuidsEx-based enumeration when
 * deploying. Enable the real path by building with -DKAGURA_ETW_FULL=1 and
 * linking tdh.lib (see CMakeLists.txt commented-out block).
 */
static int __kagura_etw_query_providers(const wchar_t *provider_guid) {
#ifdef KAGURA_ETW_FULL
    /* Real implementation outline:
     *
     *   ULONG bufferSize = 0;
     *   TdhEnumerateProviders(NULL, &bufferSize);  // probe required size
     *   PROVIDER_ENUMERATION_INFO *info = HeapAlloc(GetProcessHeap(), 0, bufferSize);
     *   if (TdhEnumerateProviders(info, &bufferSize) != ERROR_SUCCESS) goto cleanup;
     *   for (ULONG i = 0; i < info->NumberOfProviders; ++i) {
     *       const TRACE_PROVIDER_INFO *p = &info->TraceProviderInfoArray[i];
     *       wchar_t guid_str[64];
     *       StringFromGUID2(&p->ProviderGuid, guid_str, _countof(guid_str));
     *       if (_wcsicmp(guid_str, provider_guid) == 0) {
     *           HeapFree(GetProcessHeap(), 0, info);
     *           return 1;
     *       }
     *   }
     *   HeapFree(GetProcessHeap(), 0, info);
     *   return 0;
     */
    (void)provider_guid;
    return 0;
#else
    /* Stub: pretend no analysis providers are present. */
    (void)provider_guid;
    return 0;
#endif
}

/* ---- Public API --------------------------------------------------------- */

/*
 * kagura_etw_provider_present — check whether a specific ETW provider is
 * currently registered. Useful for targeting a single known-bad tool.
 *
 * Returns 1 if registered, 0 otherwise. Wraps the internal query so callers
 * can be ABI-stable even if the underlying enumeration API changes.
 */
int kagura_etw_provider_present(const wchar_t *provider_guid) {
    if (!provider_guid) return 0;
    int r = __kagura_etw_query_providers(provider_guid);
    return r == 1 ? 1 : 0;
}

/*
 * kagura_etw_analysis_tool_check — fast aggregate check for known analysis
 * tool providers. Returns 1 if any are present, 0 if clean.
 *
 * Designed to be called at startup (cheap when stubbed; ~5–20ms with the
 * full TDH path on a typical Windows 10 system).
 */
int kagura_etw_analysis_tool_check(void) {
    for (const wchar_t **p = kAnalysisToolProviders; *p; ++p) {
        if (kagura_etw_provider_present(*p)) {
            kagura_on_tamper_detected();
            return 1;
        }
    }
    return 0;
}

#endif /* _WIN32 */
