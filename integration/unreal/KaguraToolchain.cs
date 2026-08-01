// Copyright (c) 2025 yotti. MIT License.
//
// KaguraToolchain.cs
// Unreal Build Tool (UBT) toolchain extension for kagura obfuscation.
//
// Installation
// ------------
// 1. Copy this file into your UE project:
//      Source/Programs/UnrealBuildTool/  (engine-level)
//    or any Plugins/KaguraObfuscation/Source/Programs/UnrealBuildTool/ path.
// 2. Set the KAGURA_PLUGIN_PATH and KAGURA_RUNTIME_LIB environment variables,
//    or edit the default paths in KaguraConfig below.
// 3. Add `bUseKagulaObfuscation = true;` to your Target.cs (see README).
//
// How it works
// ------------
// UBT calls GetCompileArguments_Global() / ModifyBuildProducts() on each
// registered toolchain.  We wrap the active Android or iOS toolchain and
// append kagura flags to every clang invocation for Release/Shipping builds.

using System;
using System.Collections.Generic;
using System.IO;
using EpicGames.Core;
using UnrealBuildTool;

namespace KaguraObfuscation
{
    // ── Configuration ─────────────────────────────────────────────────────────

    public static class KaguraConfig
    {
        // Root of the kagura checkout; everything else is derived from it.
        public static string KaguraRoot =>
            Environment.GetEnvironmentVariable("KAGURA_ROOT")
            ?? Path.Combine(Unreal.RootDirectory.FullName, "../kagura");

        // Path to KaguraObfuscator.{dylib,so,dll}.
        // UBT runs the plugin in the HOST clang, so the host's library
        // extension is what matters — probe all three rather than assuming.
        public static string PluginPath
        {
            get
            {
                string explicitPath =
                    Environment.GetEnvironmentVariable("KAGURA_PLUGIN_PATH");
                if (!string.IsNullOrEmpty(explicitPath) && File.Exists(explicitPath))
                {
                    return explicitPath;
                }

                string dir = Path.Combine(KaguraRoot, "build/lib/Transforms");
                foreach (string ext in new[] { "dylib", "so", "dll" })
                {
                    string candidate = Path.Combine(dir, "KaguraObfuscator." + ext);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
                return explicitPath ?? Path.Combine(dir, "KaguraObfuscator.dylib");
            }
        }

        // Path to libkagura_runtime.a
        public static string RuntimeLibPath =>
            Environment.GetEnvironmentVariable("KAGURA_RUNTIME_LIB")
            ?? Path.Combine(KaguraRoot, "build/runtime/libkagura_runtime.a");

        // Profile: fast | balanced | strong | off, or a path to your own JSON
        // policy file. The pass set for each profile lives in
        // <kagura>/integration/profiles/<name>.json — the single source of
        // truth shared by every kagura integration.
        public static string Profile =>
            Environment.GetEnvironmentVariable("KAGURA_PROFILE") ?? "balanced";

        public static string ProfilePath
        {
            get
            {
                string p = Profile;
                if (string.IsNullOrEmpty(p) ||
                    string.Equals(p, "off", StringComparison.OrdinalIgnoreCase))
                {
                    return string.Empty;
                }

                string lower = p.ToLowerInvariant();
                if (lower == "fast" || lower == "balanced" || lower == "strong")
                {
                    return Path.Combine(KaguraRoot,
                                        "integration/profiles/" + lower + ".json");
                }
                return p;
            }
        }

        // Set to false to bypass the shared profile and use the explicit flag
        // list below. Prefer the profile: six copies of this list across the
        // integration directories is exactly how they drifted apart.
        public static bool UseProfile = true;

        // Explicit-flag fallback — mirrors KaguraSettings in the Unity integration
        public static bool EnableStr        = true;
        public static bool EnableFla        = true;
        public static bool EnableBcf        = true;
        public static bool EnableSub        = true;
        public static bool EnableIbr        = true;
        public static bool EnableBbr        = true;
        public static bool EnableBbs        = false;
        public static bool EnableDci        = false;
        public static bool EnableSv         = true;
        public static bool EnableAntiDebug  = true;
        public static bool EnableTamper     = true;
        public static bool EnableGenc       = false;
        public static bool EnableVm         = false;
        public static bool EnableCo         = false;

        public static int  BcfProb          = 30;
        public static int  Seed             = 0;

        // Only apply obfuscation for Shipping / Release configurations
        public static bool ShippingOnly     = true;
    }

    // ── Flag builder ──────────────────────────────────────────────────────────

    internal static class KaguraFlagBuilder
    {
        internal static List<string> Build(string pluginPath)
        {
            var flags = new List<string>();

            if (!File.Exists(pluginPath))
            {
                Log.TraceWarning($"[kagura] Plugin not found: {pluginPath} — skipping");
                return flags;
            }

            flags.Add($"-fpass-plugin={pluginPath}");

            void Add(bool enabled, string flag)
            {
                if (enabled) { flags.Add("-mllvm"); flags.Add(flag); }
            }

            // Preferred path: let the shared profile decide the pass set.
            string profilePath = KaguraConfig.ProfilePath;
            if (KaguraConfig.UseProfile && !string.IsNullOrEmpty(profilePath))
            {
                if (File.Exists(profilePath))
                {
                    Add(true, $"-kagura-config={profilePath}");
                    return flags;
                }

                Log.TraceWarning(
                    $"[kagura] Profile not found: {profilePath} — " +
                    "falling back to the explicit flag list");
            }

            // Fallback: explicit flags. Also the escape hatch for per-pass
            // overrides, since -kagura-config would clobber them.
            Add(KaguraConfig.EnableStr,       "-kagura-str");
            Add(KaguraConfig.EnableFla,       "-kagura-fla");
            Add(KaguraConfig.EnableBcf,       "-kagura-bcf");
            Add(KaguraConfig.EnableSub,       "-kagura-sub");
            Add(KaguraConfig.EnableCo,        "-kagura-co");
            Add(KaguraConfig.EnableIbr,       "-kagura-ibr");
            Add(KaguraConfig.EnableBbr,       "-kagura-bbr");
            Add(KaguraConfig.EnableBbs,       "-kagura-bbs");
            Add(KaguraConfig.EnableDci,       "-kagura-dci");
            Add(KaguraConfig.EnableSv,        "-kagura-sv");
            Add(KaguraConfig.EnableAntiDebug, "-kagura-anti-debug");
            Add(KaguraConfig.EnableTamper,    "-kagura-tamper");
            Add(KaguraConfig.EnableGenc,      "-kagura-genc");
            Add(KaguraConfig.EnableVm,        "-kagura-vm");

            if (KaguraConfig.EnableBcf && KaguraConfig.BcfProb != 30)
            {
                flags.Add("-mllvm");
                flags.Add($"-kagura-bcf-prob={KaguraConfig.BcfProb}");
            }
            if (KaguraConfig.Seed != 0)
            {
                flags.Add("-mllvm");
                flags.Add($"-kagura-seed={KaguraConfig.Seed}");
            }

            return flags;
        }
    }

    // ── UBT Toolchain hook ────────────────────────────────────────────────────

    public class KaguraAndroidToolchain : AndroidToolChain
    {
        public KaguraAndroidToolchain(ReadOnlyTargetRules Target)
            : base(Target) { }

        public override void GetCompileArguments_Global(CppCompileEnvironment CompileEnvironment,
                                                         List<string> Arguments)
        {
            base.GetCompileArguments_Global(CompileEnvironment, Arguments);
            AppendKaguraFlags(CompileEnvironment.Configuration, Arguments);
        }

        private static void AppendKaguraFlags(CppConfiguration config,
                                               List<string> args)
        {
            if (KaguraConfig.ShippingOnly &&
                config != CppConfiguration.Shipping)
                return;

            var flags = KaguraFlagBuilder.Build(KaguraConfig.PluginPath);
            args.AddRange(flags);

            if (flags.Count > 0)
                Log.TraceInformation("[kagura] Android: injected obfuscation flags");
        }

        public override void ModifyBuildProducts(ReadOnlyTargetRules Target,
                                                  UEBuildBinary Binary,
                                                  List<string> Libraries,
                                                  List<UEBuildBundleResource> BundleResources,
                                                  Dictionary<FileReference, BuildProductType> BuildProducts)
        {
            base.ModifyBuildProducts(Target, Binary, Libraries,
                                     BundleResources, BuildProducts);

            if (File.Exists(KaguraConfig.RuntimeLibPath))
                Libraries.Add(KaguraConfig.RuntimeLibPath);
        }
    }

    public class KaguraIOSToolchain : IOSToolChain
    {
        public KaguraIOSToolchain(ReadOnlyTargetRules Target)
            : base(Target) { }

        public override void GetCompileArguments_Global(CppCompileEnvironment CompileEnvironment,
                                                         List<string> Arguments)
        {
            base.GetCompileArguments_Global(CompileEnvironment, Arguments);

            if (KaguraConfig.ShippingOnly &&
                CompileEnvironment.Configuration != CppConfiguration.Shipping)
                return;

            var flags = KaguraFlagBuilder.Build(KaguraConfig.PluginPath);
            Arguments.AddRange(flags);

            if (flags.Count > 0)
                Log.TraceInformation("[kagura] iOS: injected obfuscation flags");
        }

        public override void ModifyBuildProducts(ReadOnlyTargetRules Target,
                                                  UEBuildBinary Binary,
                                                  List<string> Libraries,
                                                  List<UEBuildBundleResource> BundleResources,
                                                  Dictionary<FileReference, BuildProductType> BuildProducts)
        {
            base.ModifyBuildProducts(Target, Binary, Libraries,
                                     BundleResources, BuildProducts);

            if (File.Exists(KaguraConfig.RuntimeLibPath))
                Libraries.Add(KaguraConfig.RuntimeLibPath);
        }
    }
}
