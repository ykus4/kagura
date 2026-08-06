# 4.6.11: Bazel Starlark macros for KaguraObfuscator.
#
# Provides:
#   kagura_runtime_library — cc_library over runtime/ (call from the ROOT BUILD)
#   kagura_cc_binary       — cc_binary with the kagura plugin injected
#   kagura_cc_library      — cc_library with the kagura plugin injected
#
# Usage in BUILD:
#   load("@kagura//integration/bazel:kagura.bzl",
#        "kagura_cc_binary", "kagura_cc_library")
#
#   kagura_cc_binary(
#       name = "my_binary",
#       srcs = ["main.cc"],
#       kagura_config = "@kagura//integration/bazel:profile_balanced",
#   )
#
# Prerequisites:
#   - In WORKSPACE:
#       load("@kagura//integration/bazel:repositories.bzl", "kagura_repositories")
#       kagura_repositories()
#   - Define the @kagura_prebuilt repository pointing at build/lib/Transforms.
#   - Add a BUILD.bazel at the root of the kagura checkout that calls
#     kagura_runtime_library() — see integration/bazel/BUILD.bazel for why.

# ---- Runtime library --------------------------------------------------------

def kagura_runtime_library(name = "kagura_runtime", visibility = None, **kwargs):
    """Declares the kagura runtime cc_library.

    MUST be called from the BUILD file at the root of the kagura repository:
    Bazel glob() patterns cannot contain uplevel references ("../.."), so the
    runtime can only be globbed from a package that physically contains it.

    Source selection is directory-level so that files moving around inside
    runtime/ does not break this rule. allow_empty = False makes a future
    reorganisation fail loudly instead of silently producing an empty archive.

    Args:
      name: target name (default "kagura_runtime").
      visibility: target visibility.
      **kwargs: forwarded to native.cc_library.
    """

    # Cross-platform: core crypto/utilities, anti-debug, anti-cheat helpers.
    common_srcs = native.glob(
        [
            "runtime/core/**/*.c",
            "runtime/anti_debug/**/*.c",
            "runtime/game/**/*.c",
        ],
        allow_empty = False,
    )

    # Platform-specific implementations. These are real implementations
    # (Bionic/Linux syscalls, Darwin Mach-O / ObjC), not no-op stubs, so
    # exactly one set is selected per target platform.
    #
    # runtime/windows/ is intentionally absent: the Windows build also needs a
    # different subset of runtime/core (the POSIX-only files there do not
    # compile with MSVC), which the CMake build expresses with an explicit
    # file list. Use the CMake integration for Windows.
    android_srcs = native.glob(["runtime/android/**/*.c"], allow_empty = False)
    apple_srcs = native.glob(["runtime/ios/**/*.c"], allow_empty = False)

    native.cc_library(
        name = name,
        srcs = common_srcs + select({
            "@platforms//os:android": android_srcs,
            "@platforms//os:linux": android_srcs,
            "@platforms//os:ios": apple_srcs,
            "@platforms//os:macos": apple_srcs,
            "@platforms//os:tvos": apple_srcs,
            "//conditions:default": [],
        }),
        # runtime/**/*.h is internal.h, which every runtime .c includes, and the
        # .def is the VM opcode table core/vm_interpreter.c shares with the
        # pass. Neither is part of the public interface, but both have to be
        # visible to the compile action.
        hdrs = native.glob([
            "include/**/*.h",
            "include/**/*.def",
            "runtime/**/*.h",
        ]),
        includes = ["include"],
        copts = ["-std=c11"],
        linkopts = select({
            "@platforms//os:linux": ["-ldl"],
            "@platforms//os:android": ["-ldl"],
            "//conditions:default": [],
        }),
        visibility = visibility,
        **kwargs
    )

# ---- Obfuscation flag plumbing ----------------------------------------------

# Explicit-flag fallback, used when no kagura_config profile is given.
# Prefer a profile from //integration/profiles — see its README.
_DEFAULT_PASSES = [
    "-kagura-str",
    "-kagura-fla",
    "-kagura-bcf",
    "-kagura-sub",
]

def _mllvm(flags):
    """Every -kagura-* flag has to reach LLVM through clang's -mllvm."""
    out = []
    for f in flags:
        out.append("-mllvm")
        out.append(f)
    return out

def _kagura_copts(passes, config_label):
    """Build the -fpass-plugin and -kagura-* flag list."""
    copts = [
        "-fpass-plugin=$(location @kagura_prebuilt//:KaguraObfuscator)",
    ]
    if config_label:
        copts.extend(_mllvm(["-kagura-config=$(location {})".format(config_label)]))
    copts.extend(_mllvm(passes))
    return copts

def _kagura_deps(extra_deps):
    deps = list(extra_deps)
    deps.append("@kagura//integration/bazel:kagura_runtime")
    deps.append("@kagura_prebuilt//:KaguraObfuscator")
    return deps

def _kagura_data(extra_data, config_label):
    data = list(extra_data)
    data.append("@kagura_prebuilt//:KaguraObfuscator")
    if config_label:
        data.append(config_label)
    return data

def kagura_cc_binary(
        name,
        srcs = [],
        deps = [],
        data = [],
        copts = [],
        kagura_passes = None,
        kagura_config = None,
        **kwargs):
    """cc_binary with kagura obfuscation passes enabled.

    Args:
      name: target name.
      srcs: sources, as for cc_binary.
      deps: extra deps; the kagura runtime and plugin are appended.
      data: extra runfiles; the plugin (and profile, if any) are appended so
            $(location ...) resolves.
      copts: extra copts, prepended to the kagura flags.
      kagura_passes: list of -kagura-* flag strings to enable. Ignored when
                     kagura_config is set to a profile that already covers
                     them; defaults to ["-kagura-str", "-kagura-fla",
                     "-kagura-bcf", "-kagura-sub"] otherwise.
      kagura_config: optional label for a JSON policy file, e.g.
                     "@kagura//integration/bazel:profile_balanced".
      **kwargs: forwarded to native.cc_binary.
    """
    if kagura_passes == None:
        kagura_passes = [] if kagura_config else _DEFAULT_PASSES

    native.cc_binary(
        name = name,
        srcs = srcs,
        deps = _kagura_deps(deps),
        data = _kagura_data(data, kagura_config),
        copts = copts + _kagura_copts(kagura_passes, kagura_config),
        **kwargs
    )

def kagura_cc_library(
        name,
        srcs = [],
        hdrs = [],
        deps = [],
        data = [],
        copts = [],
        kagura_passes = None,
        kagura_config = None,
        **kwargs):
    """cc_library with kagura obfuscation passes enabled.

    Args:
      name: target name.
      srcs: sources, as for cc_library.
      hdrs: public headers, as for cc_library.
      deps: extra deps; the kagura runtime and plugin are appended.
      data: extra runfiles; the plugin (and profile, if any) are appended.
      copts: extra copts, prepended to the kagura flags.
      kagura_passes: list of -kagura-* flag strings to enable.
      kagura_config: optional label for a JSON policy file.
      **kwargs: forwarded to native.cc_library.
    """
    if kagura_passes == None:
        kagura_passes = [] if kagura_config else _DEFAULT_PASSES

    native.cc_library(
        name = name,
        srcs = srcs,
        hdrs = hdrs,
        deps = _kagura_deps(deps),
        data = _kagura_data(data, kagura_config),
        copts = copts + _kagura_copts(kagura_passes, kagura_config),
        **kwargs
    )
