# kagura — Bazel Integration

Starlark macros that wrap `cc_binary` / `cc_library` with the KaguraObfuscator
clang plugin injected.

## Files

| File | Purpose |
|:-----|:--------|
| `kagura.bzl`   | Public Starlark macros (`kagura_runtime_library`, `kagura_cc_binary`, `kagura_cc_library`) |
| `BUILD.bazel`  | Aliases for the runtime library, the plugin and the shared JSON profiles |

---

## ⚠️ A root `BUILD.bazel` is required

Bazel packages cannot reach outside themselves. `glob()` rejects patterns with
uplevel references, so nothing under `integration/bazel/` can enumerate
`runtime/**` — an earlier version of this file tried
`glob(["../../runtime/*.c"])` and silently produced an **empty** archive.

Add a `BUILD.bazel` at the root of the kagura checkout:

```python
# /BUILD.bazel
load("//integration/bazel:kagura.bzl", "kagura_runtime_library")

package(default_visibility = ["//visibility:public"])

kagura_runtime_library(name = "kagura_runtime")

exports_files(glob(["integration/profiles/*.json"]))
```

`kagura_runtime_library()` globs `runtime/` by **directory**
(`runtime/core`, `runtime/anti_debug`, `runtime/game`, plus `runtime/ios` or
`runtime/android` via `select()`), with `allow_empty = False` so a future
reorganisation of `runtime/` fails loudly instead of yielding an empty library.

`runtime/windows/` is not covered by the Bazel integration: a Windows build
also needs a different subset of `runtime/core` (the POSIX-only files there do
not compile with MSVC). Use the CMake integration on Windows.

---

## Prerequisites

In your `WORKSPACE` (or `MODULE.bazel`):

```python
local_repository(
    name = "kagura",
    path = "/path/to/kagura",          # or use http_archive / git_repository
)

# Point Bazel at the pre-built plugin.
# NOTE: the artifact has no "lib" prefix — it is KaguraObfuscator.dylib,
# not libKaguraObfuscator.dylib.
new_local_repository(
    name = "kagura_prebuilt",
    path = "/path/to/kagura/build/lib/Transforms",
    build_file_content = """
cc_import(
    name = "KaguraObfuscator",
    shared_library = "KaguraObfuscator.dylib",  # or .so on Linux
    visibility = ["//visibility:public"],
)
""",
)
```

---

## Usage

```python
load("@kagura//integration/bazel:kagura.bzl",
     "kagura_cc_binary", "kagura_cc_library")

# Preferred: drive the pass set from a shared profile.
kagura_cc_binary(
    name = "my_binary",
    srcs = ["main.cc"],
    kagura_config = "@kagura//integration/bazel:profile_balanced",
)

# Fallback: explicit flags (also used to override a profile).
kagura_cc_library(
    name = "my_lib",
    srcs = ["lib.cc"],
    hdrs = ["lib.h"],
    kagura_passes = ["-kagura-fla", "-kagura-sub", "-kagura-str"],
)
```

### Arguments

| Arg | Default | Meaning |
|:----|:--------|:--------|
| `kagura_config` | `None` | Label of a JSON policy file. Use `profile_fast` / `profile_balanced` / `profile_strong` from this package, or your own — see [Configuration](https://ykus4.github.io/kagura/configuration/) and [`integration/profiles`](https://github.com/ykus4/kagura/tree/main/integration/profiles) |
| `kagura_passes` | `["-kagura-str", "-kagura-fla", "-kagura-bcf", "-kagura-sub"]` when `kagura_config` is unset, otherwise `[]` | Explicit `-kagura-*` flags. Applied after the profile, so they override it |

All other `cc_binary` / `cc_library` arguments (`srcs`, `hdrs`, `deps`,
`copts`, `data`, …) are forwarded as-is.

---

## How it works

The macros add three things to the underlying `cc_*` rule:

1. **`copts`** — `-fpass-plugin=$(location @kagura_prebuilt//:KaguraObfuscator)`,
   then `-mllvm -kagura-config=<profile>` if a profile was given, then
   `-mllvm <flag>` for each requested pass. Every `-kagura-*` flag has to be
   introduced by `-mllvm`; passing it bare makes clang reject the command line.
2. **`deps`** — `@kagura//integration/bazel:kagura_runtime` so the runtime
   library gets linked, plus the plugin target.
3. **`data`** — the plugin and the profile JSON, so both are staged into the
   sandbox and resolvable via `$(location …)`.
