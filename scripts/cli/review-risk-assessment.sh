#!/usr/bin/env bash
# review-risk-assessment.sh — 4.7.11: App Store / Google Play review risk assessment
#
# Scans a compiled binary for patterns that may trigger App Store (iOS) or
# Google Play (Android) automated review rejections.  Outputs a risk report
# with severity levels: CRITICAL / HIGH / MEDIUM / LOW / INFO.
#
# Usage:
#   ./scripts/cli/review-risk-assessment.sh <binary_path> [--platform ios|android|auto]
#
# Outputs:
#   A human-readable risk report on stdout.
#   Exit codes:
#     0  — no CRITICAL or HIGH issues found
#     1  — at least one CRITICAL or HIGH risk detected
#     2  — usage / tool error
#
# Required tools:  nm, strings (or llvm-strings), file, otool (macOS) or
#                  readelf/objdump (Linux).

set -euo pipefail

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 2; }

BINARY=""
PLATFORM="auto"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform)
            PLATFORM="${2:-auto}"
            shift 2
            ;;
        -*)
            die "Unknown option: $1"
            ;;
        *)
            BINARY="$1"
            shift
            ;;
    esac
done

[[ -n "${BINARY}" ]] || die "Usage: $0 <binary_path> [--platform ios|android|auto]"
[[ -f "${BINARY}" ]] || die "Binary not found: ${BINARY}"

# --------------------------------------------------------------------------
# Tool detection
# --------------------------------------------------------------------------
NM="${NM:-$(command -v nm 2>/dev/null || true)}"
STRINGS_TOOL="$(command -v llvm-strings 2>/dev/null || command -v strings 2>/dev/null || true)"
FILE_CMD="$(command -v file 2>/dev/null || true)"
OTOOL="$(command -v otool 2>/dev/null || true)"
READELF="$(command -v readelf 2>/dev/null || true)"
OBJDUMP="$(command -v objdump 2>/dev/null || true)"

[[ -x "${NM}" ]]           || NM=""
[[ -x "${STRINGS_TOOL}" ]] || STRINGS_TOOL=""
[[ -x "${FILE_CMD}" ]]     || FILE_CMD=""
[[ -x "${OTOOL}" ]]        || OTOOL=""
[[ -x "${READELF}" ]]      || READELF=""

# --------------------------------------------------------------------------
# Platform auto-detection
# --------------------------------------------------------------------------
if [[ "${PLATFORM}" == "auto" ]]; then
    if [[ -n "${FILE_CMD}" ]]; then
        FILE_OUT="$("${FILE_CMD}" "${BINARY}")"
        if echo "${FILE_OUT}" | grep -qi "mach-o"; then
            PLATFORM="ios"
        elif echo "${FILE_OUT}" | grep -qi "elf"; then
            PLATFORM="android"
        else
            PLATFORM="unknown"
        fi
    else
        PLATFORM="unknown"
    fi
fi

# --------------------------------------------------------------------------
# Report helpers
# --------------------------------------------------------------------------
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

report() {
    local sev="$1"
    local id="$2"
    local msg="$3"
    local detail="${4:-}"
    case "${sev}" in
        CRITICAL) printf "\e[1;31m[CRITICAL]\e[0m [%s] %s\n" "${id}" "${msg}"; (( CRITICAL_COUNT++ )) || true ;;
        HIGH)     printf "\e[0;31m[HIGH    ]\e[0m [%s] %s\n" "${id}" "${msg}"; (( HIGH_COUNT++ )) || true ;;
        MEDIUM)   printf "\e[0;33m[MEDIUM  ]\e[0m [%s] %s\n" "${id}" "${msg}"; (( MEDIUM_COUNT++ )) || true ;;
        LOW)      printf "\e[0;34m[LOW     ]\e[0m [%s] %s\n" "${id}" "${msg}"; (( LOW_COUNT++ )) || true ;;
        INFO)     printf "\e[0;32m[INFO    ]\e[0m [%s] %s\n" "${id}" "${msg}" ;;
    esac
    if [[ -n "${detail}" ]]; then
        echo "           ${detail}"
    fi
}

echo "======================================================================"
echo " Kagura review risk assessment"
echo " Binary:   ${BINARY}"
echo " Platform: ${PLATFORM}"
echo "======================================================================"
echo ""

# --------------------------------------------------------------------------
# 1. Private API usage (iOS — App Store rejection criterion)
# --------------------------------------------------------------------------
if [[ "${PLATFORM}" == "ios" && -n "${NM}" ]]; then
    echo "── iOS: Private API symbols ─────────────────────────────────────────"
    PRIVATE_APIS=(
        "UIGetScreenImage"
        "copySubtitlesFromBundle"
        "setBackgroundColor"
        "SBSCopyIconImagePNGDataForDisplayIdentifier"
        "SpringBoardServices"
        "ABAddressBookCreate"
        "UIWebDocumentView"
        "_UIConstraintBasedLayoutLogUnsatisfiable"
    )
    while IFS= read -r sym; do
        for api in "${PRIVATE_APIS[@]}"; do
            if echo "${sym}" | grep -qi "${api}"; then
                report HIGH "IOS-PRIV" "Private API reference: ${sym}" \
                    "App Store guideline 2.5.1: apps may not use non-public APIs."
            fi
        done
    done < <("${NM}" -u "${BINARY}" 2>/dev/null | awk '{print $NF}' || true)
fi

# --------------------------------------------------------------------------
# 2. ptrace / debugging syscalls (triggers App Store review flags on iOS)
# --------------------------------------------------------------------------
if [[ -n "${NM}" ]]; then
    echo "── Debugging / anti-debug symbols ───────────────────────────────────"
    DEBUG_SYMS=("ptrace" "sysctl" "task_threads" "thread_get_state")
    FOUND_DEBUG=0
    while IFS= read -r sym; do
        for ds in "${DEBUG_SYMS[@]}"; do
            if echo "${sym}" | grep -qw "${ds}"; then
                report MEDIUM "DBG-SYM" "Debugging-related symbol: ${sym}" \
                    "May trigger manual review; ensure anti-debug is disclosed in privacy details."
                FOUND_DEBUG=1
            fi
        done
    done < <("${NM}" -u "${BINARY}" 2>/dev/null | awk '{print $NF}' || true)
    [[ ${FOUND_DEBUG} -eq 0 ]] && report INFO "DBG-SYM" "No suspicious debugging symbols detected."
fi

# --------------------------------------------------------------------------
# 3. Encryption export compliance
# --------------------------------------------------------------------------
echo "── Encryption export compliance ─────────────────────────────────────"
if [[ -n "${STRINGS_TOOL}" ]]; then
    # AES, DES, RSA, RC4 references suggest encryption
    ENC_HITS="$("${STRINGS_TOOL}" "${BINARY}" 2>/dev/null | grep -Ei '\b(AES|DES|RSA|RC4|ChaCha20|Blowfish)\b' | head -5 || true)"
    if [[ -n "${ENC_HITS}" ]]; then
        report MEDIUM "ENC-DECL" "Encryption algorithm references found." \
            "iOS: export compliance key in Info.plist (ITSAppUsesNonExemptEncryption).  Android: applicable for apps exported to restricted countries."
        echo "${ENC_HITS}" | while IFS= read -r line; do echo "           > ${line}"; done
    else
        report INFO "ENC-DECL" "No obvious encryption keyword references found in strings."
    fi
fi

# --------------------------------------------------------------------------
# 4. Suspicious dynamic code loading (iOS — App Store 2.5.2)
# --------------------------------------------------------------------------
if [[ "${PLATFORM}" == "ios" && -n "${NM}" ]]; then
    echo "── Dynamic code / JIT (iOS) ─────────────────────────────────────────"
    DYN_SYMS=("dlopen" "NSBundle.*load" "objc_loadClassPair" "JavaScriptCore" "WKWebView.*evaluateJavaScript")
    while IFS= read -r sym; do
        for ds in "${DYN_SYMS[@]}"; do
            if echo "${sym}" | grep -qiE "${ds}"; then
                report HIGH "IOS-DYN" "Dynamic code loading symbol: ${sym}" \
                    "App Store 2.5.2: apps must not download, install, or execute code."
            fi
        done
    done < <("${NM}" -u "${BINARY}" 2>/dev/null | awk '{print $NF}' || true)
fi

# --------------------------------------------------------------------------
# 5. Hardcoded IP / URL patterns (policy violation risk)
# --------------------------------------------------------------------------
echo "── Hardcoded endpoints ──────────────────────────────────────────────"
if [[ -n "${STRINGS_TOOL}" ]]; then
    # Look for internal/development URLs that should not ship
    IP_HITS="$("${STRINGS_TOOL}" "${BINARY}" 2>/dev/null | grep -Eo '(https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[^ ]*|192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|localhost)' | head -10 || true)"
    if [[ -n "${IP_HITS}" ]]; then
        report HIGH "URL-IP" "Hardcoded private/localhost IP or URL found." \
            "Development endpoints must be removed before App Store / Play Store submission."
        echo "${IP_HITS}" | while IFS= read -r line; do echo "           > ${line}"; done
    else
        report INFO "URL-IP" "No hardcoded private IP/localhost URLs detected."
    fi
fi

# --------------------------------------------------------------------------
# 6. Android: known ad/tracking SDKs (Google Play policy)
# --------------------------------------------------------------------------
if [[ "${PLATFORM}" == "android" && -n "${STRINGS_TOOL}" ]]; then
    echo "── Android: tracking / ad SDK disclosure ────────────────────────────"
    AD_SDKS=("admob" "appsflyer" "firebase" "adjust" "branch.io" "flurry" "mparticle")
    FOUND_SDK=0
    for sdk in "${AD_SDKS[@]}"; do
        if "${STRINGS_TOOL}" "${BINARY}" 2>/dev/null | grep -qi "${sdk}"; then
            report MEDIUM "AND-SDK" "Ad/analytics SDK reference: ${sdk}" \
                "Declare data collection in Google Play Data Safety section."
            FOUND_SDK=1
        fi
    done
    [[ ${FOUND_SDK} -eq 0 ]] && report INFO "AND-SDK" "No known ad/analytics SDK references detected."
fi

# --------------------------------------------------------------------------
# 7. Obfuscation residue (kagura honey-value labels — should not ship as-is)
# --------------------------------------------------------------------------
echo "── Kagura obfuscation artefacts ─────────────────────────────────────"
if [[ -n "${STRINGS_TOOL}" ]]; then
    HONEY_HITS="$("${STRINGS_TOOL}" "${BINARY}" 2>/dev/null | grep -E '(g_api_secret_key|g_db_password|g_license_server_url|validate_license|check_token|verify_receipt)' | head -5 || true)"
    if [[ -n "${HONEY_HITS}" ]]; then
        report LOW "KAG-HONEY" "Kagura honey-value symbol names visible in strings." \
            "Consider combining with -kagura-sv to strip these from the dynamic symbol table."
    else
        report INFO "KAG-HONEY" "No honey-value residue in string table."
    fi
fi

# --------------------------------------------------------------------------
# 8. Stack canary / PIE / NX (security hardening — reviewer expectation)
# --------------------------------------------------------------------------
echo "── Binary security properties ───────────────────────────────────────"
if [[ "${PLATFORM}" == "ios" && -n "${OTOOL}" ]]; then
    # Check PIE
    if "${OTOOL}" -hv "${BINARY}" 2>/dev/null | grep -qi "PIE"; then
        report INFO "SEC-PIE" "Position-independent executable (PIE) flag is set."
    else
        report HIGH "SEC-PIE" "Binary is NOT position-independent (PIE missing)." \
            "iOS requires PIE for all apps since iOS 4.3."
    fi
    # Check stack canary symbol
    if "${NM}" "${BINARY}" 2>/dev/null | grep -q "__stack_chk_fail"; then
        report INFO "SEC-SSP" "Stack canary (__stack_chk_fail) present."
    else
        report MEDIUM "SEC-SSP" "Stack canary not found — consider -fstack-protector-all."
    fi
elif [[ "${PLATFORM}" == "android" && -n "${READELF}" ]]; then
    if "${READELF}" -d "${BINARY}" 2>/dev/null | grep -q "RUNPATH\|RPATH"; then
        report MEDIUM "SEC-RPATH" "RPATH/RUNPATH set — may expose library search paths."
    fi
    if "${READELF}" -W -S "${BINARY}" 2>/dev/null | grep -q "GNU_STACK"; then
        STACK_FLAGS="$("${READELF}" -W -l "${BINARY}" 2>/dev/null | grep "GNU_STACK" || true)"
        if echo "${STACK_FLAGS}" | grep -q "RWE\|RWX"; then
            report HIGH "SEC-NX" "Executable stack (RWX) detected." \
                "Google Play requires NX (non-executable stack)."
        else
            report INFO "SEC-NX" "Non-executable stack (NX) is set."
        fi
    fi
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "======================================================================"
printf " Summary:  %d critical, %d high, %d medium, %d low\n" \
    "${CRITICAL_COUNT}" "${HIGH_COUNT}" "${MEDIUM_COUNT}" "${LOW_COUNT}"
echo "======================================================================"

if [[ ${CRITICAL_COUNT} -gt 0 || ${HIGH_COUNT} -gt 0 ]]; then
    echo " RESULT: Review risk detected — address CRITICAL/HIGH items before submission."
    exit 1
else
    echo " RESULT: No critical or high review risks detected."
    exit 0
fi
