/*===-- runtime/windows/anti_debug.c - Windows anti-debug checks ----------===
 *
 * A.1: Windows runtime stubs for kagura anti-debug protection.
 *
 * Checks implemented:
 *   kagura_check_debugger_present   — IsDebuggerPresent() (user-mode flag)
 *   kagura_check_remote_debugger    — CheckRemoteDebuggerPresent()
 *   kagura_check_nt_debug_port      — NtQueryInformationProcess(DebugPort)
 *   kagura_check_heap_flags         — PEB heap flags set by debuggers
 *   kagura_check_frida_port         — Frida default port 27042 on localhost
 *   kagura_check_injected_dlls      — scan loaded modules for analysis tools
 *   kagura_check_windows_debugger   — aggregate check, calls tamper on detect
 *
 * Public API (mirrors iOS/Android conventions):
 *   int  kagura_check_*()  — 1 = detected, 0 = clean
 *   void kagura_*_check()  — calls kagura_on_tamper_detected() on detection
 *
 *===----------------------------------------------------------------------===*/

#ifdef _WIN32

#include <stdint.h>
#include <string.h>

/* winsock2.h must precede windows.h. */
#include <winsock2.h>
/* Do NOT define WIN32_LEAN_AND_MEAN here: it excludes tlhelp32.h content
 * (MODULEENTRY32, Module32First, etc.) when included indirectly.
 * The CMake build already defines it via -DWIN32_LEAN_AND_MEAN, so we
 * explicitly undo that before the tlhelp32 include. */
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

/* NtQueryInformationProcess — not in standard headers */
typedef LONG (WINAPI *PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength);

#define ProcessDebugPort 7

/* The tamper response hook lives in core/tamper_response.c, which already
 * uses ExitProcess() on _WIN32. */

/* ---- IsDebuggerPresent --------------------------------------------------- */

int kagura_check_debugger_present(void) {
    return IsDebuggerPresent() ? 1 : 0;
}

void kagura_debugger_present_check(void) {
    if (kagura_check_debugger_present())
        kagura_on_tamper_detected();
}

/* ---- CheckRemoteDebuggerPresent ------------------------------------------ */

int kagura_check_remote_debugger(void) {
    BOOL present = FALSE;
    if (!CheckRemoteDebuggerPresent(GetCurrentProcess(), &present))
        return 0; /* API failed — assume clean */
    return present ? 1 : 0;
}

void kagura_remote_debugger_check(void) {
    if (kagura_check_remote_debugger())
        kagura_on_tamper_detected();
}

/* ---- NtQueryInformationProcess(DebugPort) -------------------------------- */
/*
 * The debug port is a kernel handle set when a debugger attaches via
 * DebugActiveProcess().  A non-zero value means a kernel debugger is present.
 * This check bypasses the user-mode IsDebuggerPresent flag which can be
 * cleared trivially with WriteProcessMemory().
 */
int kagura_check_nt_debug_port(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return 0;

    PFN_NtQueryInformationProcess pfn =
        (PFN_NtQueryInformationProcess)(void *)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pfn)
        return 0;

    HANDLE port = NULL;
    LONG status = pfn(GetCurrentProcess(), ProcessDebugPort,
                      &port, sizeof(port), NULL);
    /* STATUS_SUCCESS = 0 */
    if (status != 0)
        return 0;
    return (port != NULL) ? 1 : 0;
}

void kagura_nt_debug_port_check(void) {
    if (kagura_check_nt_debug_port())
        kagura_on_tamper_detected();
}

/* ---- PEB heap flags ------------------------------------------------------- */
/*
 * When a process is launched under a debugger, the Windows loader sets two
 * flags in the PEB's heap header:
 *   NtGlobalFlag  bit 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK |
 *                            FLG_HEAP_ENABLE_FREE_CHECK |
 *                            FLG_HEAP_VALIDATE_PARAMETERS)
 * Reading the PEB directly avoids any user-mode API that can be hooked.
 */
int kagura_check_heap_flags(void) {
#if defined(_M_X64) || defined(__x86_64__)
    /* PEB is at GS:[0x60] on x64 */
    BYTE *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    DWORD ntGlobalFlag = *(DWORD *)(peb + 0xBC);
#elif defined(_M_IX86) || defined(__i386__)
    /* PEB is at FS:[0x30] on x86 */
    BYTE *peb;
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));
    DWORD ntGlobalFlag = *(DWORD *)(peb + 0x68);
#else
    return 0; /* unsupported architecture */
#endif
    return (ntGlobalFlag & 0x70) ? 1 : 0;
}

void kagura_heap_flags_check(void) {
    if (kagura_check_heap_flags())
        kagura_on_tamper_detected();
}

/* ---- Frida port check ---------------------------------------------------- */
/*
 * Frida's default agent port is 27042.  A successful connection to
 * 127.0.0.1:27042 means Frida Server or Gadget is running.
 */
int kagura_check_frida_port(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 0;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }

    /* Non-blocking connect with short timeout */
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    struct timeval tv = { 0, 50000 }; /* 50 ms */
    int result = select(0, NULL, &wfds, NULL, &tv);

    closesocket(s);
    WSACleanup();
    return (result > 0) ? 1 : 0;
}

void kagura_frida_port_check(void) {
    if (kagura_check_frida_port())
        kagura_on_tamper_detected();
}

/* ---- Injected DLL scan --------------------------------------------------- */
/*
 * Enumerate loaded modules via CreateToolhelp32Snapshot and look for known
 * analysis / instrumentation DLL names.
 */
int kagura_check_injected_dlls(void) {
    /* Wide-character patterns: Module32First/Next use WCHAR names when
     * UNICODE is defined (which LLVM's CMake does via -DUNICODE). */
    static const wchar_t *kPatterns[] = {
        L"frida", L"frida-gadget", L"frida-agent",
        L"x64dbg", L"x32dbg", L"ollydbg",
        L"cheatengine", L"winspy", L"injector",
        L"minhook", L"detours", NULL
    };
    /* All declarations at block start to satisfy C11 (no jumping over
     * declarations with goto). */
    MODULEENTRY32W me;
    HANDLE snap;
    int found = 0;
    size_t i;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        return 0;
    }

    do {
        /* Convert wide module name to lowercase in a wide buffer. */
        wchar_t lower[MAX_MODULE_NAME32 + 1];
        size_t len = wcslen(me.szModule);
        if (len > MAX_MODULE_NAME32) len = MAX_MODULE_NAME32;
        for (i = 0; i < len; ++i)
            lower[i] = (me.szModule[i] >= L'A' && me.szModule[i] <= L'Z')
                        ? (wchar_t)(me.szModule[i] + 32) : me.szModule[i];
        lower[len] = L'\0';

        for (i = 0; kPatterns[i]; ++i) {
            if (wcsstr(lower, kPatterns[i])) {
                found = 1;
                goto done;
            }
        }
    } while (Module32NextW(snap, &me));

done:
    CloseHandle(snap);
    return found;
}

void kagura_injected_dlls_check(void) {
    if (kagura_check_injected_dlls())
        kagura_on_tamper_detected();
}

/* ---- Aggregate check ----------------------------------------------------- */

void kagura_check_windows_debugger(void) {
    if (kagura_check_debugger_present()  ||
        kagura_check_remote_debugger()   ||
        kagura_check_nt_debug_port()     ||
        kagura_check_heap_flags()        ||
        kagura_check_injected_dlls())
        kagura_on_tamper_detected();
}

#endif /* _WIN32 */
