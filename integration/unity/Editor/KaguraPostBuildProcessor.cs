// KaguraPostBuildProcessor.cs
// Unity Editor post-build step that injects kagura obfuscation flags into
// IL2CPP compilation.
//
// Installation
// ------------
// Place this file anywhere under your project's Assets/Editor/ directory.
// Unity will pick it up automatically.  No manual configuration is required
// beyond setting the plugin path in KaguraSettings (see below).
//
// How it works
// ------------
// Unity's IL2CPP pipeline invokes clang for each C++ translation unit.
// This script hooks IPostprocessBuildWithReport to patch the generated
// IL2CPP project's CMakeLists.txt and inject kagura flags via
// CMAKE_C_FLAGS / CMAKE_CXX_FLAGS.  It also copies libkagura_runtime.a
// into the IL2CPP link set.
//
// Supported build targets: Android (Gradle + CMake), iOS (Xcode)

using System;
using System.IO;
using System.Text;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

namespace Kagura.Editor
{
    // ── Settings (edit these or expose via a ScriptableObject) ────────────────

    public static class KaguraSettings
    {
        // Root of the kagura checkout. Everything else is derived from it.
        public static string KaguraRoot =>
            EditorPrefs.GetString("kagura.root",
                Path.GetFullPath(Path.Combine(Application.dataPath, "../../..")));

        // Absolute path to KaguraObfuscator.{dylib,so,dll} built from this repo.
        // Set via Edit > Project Settings > Player > Kagura, or override here.
        // Unity's IL2CPP toolchain runs the plugin in the *host* clang, so the
        // host's library extension is what matters — probe all three.
        public static string PluginPath
        {
            get
            {
                var explicitPath = EditorPrefs.GetString("kagura.pluginPath", string.Empty);
                if (!string.IsNullOrEmpty(explicitPath) && File.Exists(explicitPath))
                    return explicitPath;

                var dir = Path.Combine(KaguraRoot, "build/lib/Transforms");
                foreach (var ext in new[] { "dylib", "so", "dll" })
                {
                    var candidate = Path.GetFullPath(
                        Path.Combine(dir, "KaguraObfuscator." + ext));
                    if (File.Exists(candidate))
                        return candidate;
                }
                return explicitPath;
            }
        }

        // Profile name (fast | balanced | strong | off) or an absolute path to
        // your own JSON policy file. The pass set for each profile lives in
        // <kagura>/integration/profiles/<name>.json — the single source of
        // truth shared by every kagura integration.
        public static string Profile =>
            EditorPrefs.GetString("kagura.profile", "balanced");

        public static string ProfilePath
        {
            get
            {
                var p = Profile;
                if (string.IsNullOrEmpty(p) ||
                    string.Equals(p, "off", StringComparison.OrdinalIgnoreCase))
                    return string.Empty;

                var lower = p.ToLowerInvariant();
                if (lower == "fast" || lower == "balanced" || lower == "strong")
                    return Path.GetFullPath(Path.Combine(
                        KaguraRoot, "integration/profiles/" + lower + ".json"));

                return Path.GetFullPath(p);
            }
        }

        public static string RuntimeLibPath =>
            EditorPrefs.GetString("kagura.runtimeLibPath",
                Path.GetFullPath(
                    Path.Combine(Application.dataPath,
                                 "../../../build/runtime/libkagura_runtime.a")));

        // Per-pass overrides.
        //
        // These are only consulted when "kagura.useProfile" is false, or when
        // the profile file cannot be found. Leaving the profile in charge is
        // strongly preferred — six copies of this list across the integration
        // directories is exactly how they drifted apart.
        public static bool UseProfile       => EditorPrefs.GetBool("kagura.useProfile",       true);

        public static bool EnableFla        => EditorPrefs.GetBool("kagura.enableFla",        true);
        public static bool EnableBcf        => EditorPrefs.GetBool("kagura.enableBcf",        true);
        public static bool EnableSub        => EditorPrefs.GetBool("kagura.enableSub",        true);
        public static bool EnableStr        => EditorPrefs.GetBool("kagura.enableStr",        true);
        public static bool EnableCo         => EditorPrefs.GetBool("kagura.enableCo",         false);
        public static bool EnableIbr        => EditorPrefs.GetBool("kagura.enableIbr",        true);
        public static bool EnableBbr        => EditorPrefs.GetBool("kagura.enableBbr",        true);
        public static bool EnableBbs        => EditorPrefs.GetBool("kagura.enableBbs",        false);
        public static bool EnableDci        => EditorPrefs.GetBool("kagura.enableDci",        false);
        public static bool EnableSv         => EditorPrefs.GetBool("kagura.enableSv",         true);
        public static bool EnableAntiDebug  => EditorPrefs.GetBool("kagura.enableAntiDebug",  true);
        public static bool EnableTamper     => EditorPrefs.GetBool("kagura.enableTamper",     true);
        public static bool EnableGenc       => EditorPrefs.GetBool("kagura.enableGenc",       false);
        public static bool EnableVm         => EditorPrefs.GetBool("kagura.enableVm",         false);

        public static int  BcfProb          => EditorPrefs.GetInt("kagura.bcfProb",           30);
        public static int  BcfIter          => EditorPrefs.GetInt("kagura.bcfIter",           1);
        public static int  SubIter          => EditorPrefs.GetInt("kagura.subIter",           1);
        public static long Seed             => (long)EditorPrefs.GetInt("kagura.seed",        0);

        // Whether to run kagura on release builds only (skip Debug)
        public static bool ReleaseOnly      => EditorPrefs.GetBool("kagura.releaseOnly",      true);
    }

    // ── Flag builder ──────────────────────────────────────────────────────────

    internal static class KaguraFlagBuilder
    {
        internal static string Build(string pluginPath)
        {
            if (!File.Exists(pluginPath))
            {
                Debug.LogWarning($"[kagura] Plugin not found at: {pluginPath} — obfuscation DISABLED");
                return string.Empty;
            }

            var sb = new StringBuilder();
            sb.Append($"-fpass-plugin={pluginPath}");

            void Add(bool enabled, string flag)
            {
                if (enabled) sb.Append($" -mllvm {flag}");
            }

            // Preferred path: let the shared profile decide the pass set, so
            // this integration cannot drift from the others.
            var profilePath = KaguraSettings.ProfilePath;
            if (KaguraSettings.UseProfile && !string.IsNullOrEmpty(profilePath))
            {
                if (File.Exists(profilePath))
                {
                    Add(true, $"-kagura-config={profilePath}");
                    return sb.ToString();
                }

                Debug.LogWarning(
                    $"[kagura] Profile not found at: {profilePath} — " +
                    "falling back to the explicit flag list below");
            }

            // Fallback: explicit flags. Also the escape hatch for per-pass
            // overrides, since -kagura-config would clobber them.
            Add(KaguraSettings.EnableStr,       "-kagura-str");
            Add(KaguraSettings.EnableFla,       "-kagura-fla");
            Add(KaguraSettings.EnableBcf,       "-kagura-bcf");
            Add(KaguraSettings.EnableSub,       "-kagura-sub");
            Add(KaguraSettings.EnableCo,        "-kagura-co");
            Add(KaguraSettings.EnableIbr,       "-kagura-ibr");
            Add(KaguraSettings.EnableBbr,       "-kagura-bbr");
            Add(KaguraSettings.EnableBbs,       "-kagura-bbs");
            Add(KaguraSettings.EnableDci,       "-kagura-dci");
            Add(KaguraSettings.EnableSv,        "-kagura-sv");
            Add(KaguraSettings.EnableAntiDebug, "-kagura-anti-debug");
            Add(KaguraSettings.EnableTamper,    "-kagura-tamper");
            Add(KaguraSettings.EnableGenc,      "-kagura-genc");
            Add(KaguraSettings.EnableVm,        "-kagura-vm");

            if (KaguraSettings.EnableBcf && KaguraSettings.BcfProb != 30)
                sb.Append($" -mllvm -kagura-bcf-prob={KaguraSettings.BcfProb}");
            if (KaguraSettings.EnableBcf && KaguraSettings.BcfIter != 1)
                sb.Append($" -mllvm -kagura-bcf-iter={KaguraSettings.BcfIter}");
            if (KaguraSettings.EnableSub && KaguraSettings.SubIter != 1)
                sb.Append($" -mllvm -kagura-sub-iter={KaguraSettings.SubIter}");
            if (KaguraSettings.Seed != 0)
                sb.Append($" -mllvm -kagura-seed={KaguraSettings.Seed}");

            return sb.ToString();
        }
    }

    // ── Post-build processor ──────────────────────────────────────────────────

    public class KaguraPostBuildProcessor : IPostprocessBuildWithReport
    {
        public int callbackOrder => 100; // run after Unity's own post-processors

        public void OnPostprocessBuild(BuildReport report)
        {
            var target   = report.summary.platform;
            var buildType = report.summary.options;

            // Honour ReleaseOnly setting
            if (KaguraSettings.ReleaseOnly &&
                (buildType & BuildOptions.Development) != 0)
            {
                Debug.Log("[kagura] Development build — skipping obfuscation.");
                return;
            }

            string flags = KaguraFlagBuilder.Build(KaguraSettings.PluginPath);
            if (string.IsNullOrEmpty(flags))
                return;

            switch (target)
            {
                case BuildTarget.Android:
                    PatchAndroid(report.summary.outputPath, flags);
                    break;
                case BuildTarget.iOS:
                    PatchXcode(report.summary.outputPath, flags);
                    break;
                default:
                    Debug.Log($"[kagura] Target {target} not supported — skipping.");
                    break;
            }
        }

        // ── Android ──────────────────────────────────────────────────────────

        static void PatchAndroid(string outputPath, string flags)
        {
            // Unity Android export generates a Gradle project.
            // We patch the top-level build.gradle to inject kagura flags via
            // the CMake externalNativeBuild block.
            string gradleDir = outputPath; // path to the exported Gradle project
            string buildGradle = Path.Combine(gradleDir, "launcher", "build.gradle");
            if (!File.Exists(buildGradle))
                buildGradle = Path.Combine(gradleDir, "build.gradle");

            if (!File.Exists(buildGradle))
            {
                Debug.LogWarning($"[kagura] Android: build.gradle not found at {buildGradle}");
                return;
            }

            // Copy kagura.gradle into the project so it can be applied
            string kaguraGradleSrc = Path.GetFullPath(
                Path.Combine(Application.dataPath,
                             "../../../integration/android/kagura.gradle"));
            string kaguraGradleDst = Path.Combine(gradleDir, "kagura.gradle");

            if (File.Exists(kaguraGradleSrc))
                File.Copy(kaguraGradleSrc, kaguraGradleDst, overwrite: true);

            // Append apply line if not already present
            string content = File.ReadAllText(buildGradle);
            const string applyLine = "apply from: \"kagura.gradle\"";
            if (!content.Contains(applyLine))
            {
                File.AppendAllText(buildGradle,
                    $"\n// kagura obfuscation\n{applyLine}\n");
                Debug.Log($"[kagura] Android: patched {buildGradle}");
            }
        }

        // ── iOS / Xcode ───────────────────────────────────────────────────────

        static void PatchXcode(string outputPath, string flags)
        {
            // Unity iOS export generates an Xcode project.
            // We inject kagura flags into the project's OTHER_CFLAGS via
            // a generated .xcconfig that is included by the project.
            string xcodeDir   = outputPath;
            string xconfigDst = Path.Combine(xcodeDir, "kagura.xcconfig");

            var sb = new StringBuilder();
            sb.AppendLine("// Auto-generated by KaguraPostBuildProcessor — do not edit");
            sb.AppendLine($"KAGURA_FLAGS = {flags}");
            sb.AppendLine("OTHER_CFLAGS = $(inherited) $(KAGURA_FLAGS)");
            sb.AppendLine("OTHER_CPLUSPLUSFLAGS = $(inherited) $(KAGURA_FLAGS)");

            File.WriteAllText(xconfigDst, sb.ToString());
            Debug.Log($"[kagura] iOS: wrote {xconfigDst}");

            // Copy runtime lib into the Xcode project so it can be linked
            string runtimeSrc = KaguraSettings.RuntimeLibPath;
            if (File.Exists(runtimeSrc))
            {
                string runtimeDst = Path.Combine(xcodeDir, "Libraries",
                                                 "libkagura_runtime.a");
                Directory.CreateDirectory(Path.GetDirectoryName(runtimeDst)!);
                File.Copy(runtimeSrc, runtimeDst, overwrite: true);
                Debug.Log($"[kagura] iOS: copied runtime to {runtimeDst}");
            }
            else
            {
                Debug.LogWarning($"[kagura] Runtime lib not found: {runtimeSrc}");
            }
        }
    }

    // ── Settings UI (Project Settings page) ──────────────────────────────────

    public class KaguraSettingsProvider : SettingsProvider
    {
        public KaguraSettingsProvider()
            : base("Project/Kagura Obfuscator", SettingsScope.Project) { }

        public override void OnGUI(string searchContext)
        {
            GUILayout.Label("Kagura Obfuscator Settings", EditorStyles.boldLabel);
            EditorGUILayout.Space();

            string pluginPath = EditorPrefs.GetString("kagura.pluginPath", "");
            pluginPath = EditorGUILayout.TextField("Plugin Path (.dylib/.so)", pluginPath);
            EditorPrefs.SetString("kagura.pluginPath", pluginPath);

            string rtPath = EditorPrefs.GetString("kagura.runtimeLibPath", "");
            rtPath = EditorGUILayout.TextField("Runtime Lib Path (.a)", rtPath);
            EditorPrefs.SetString("kagura.runtimeLibPath", rtPath);

            EditorGUILayout.Space();
            GUILayout.Label("Pass Selection", EditorStyles.boldLabel);

            void Toggle(string key, string label, bool defaultVal)
            {
                bool v = EditorPrefs.GetBool(key, defaultVal);
                v = EditorGUILayout.Toggle(label, v);
                EditorPrefs.SetBool(key, v);
            }

            Toggle("kagura.releaseOnly",      "Release builds only",         true);
            Toggle("kagura.enableFla",        "CFG Flattening (-fla)",        true);
            Toggle("kagura.enableBcf",        "Bogus Control Flow (-bcf)",    true);
            Toggle("kagura.enableSub",        "Substitution (-sub)",          true);
            Toggle("kagura.enableStr",        "String Encryption (-str)",     true);
            Toggle("kagura.enableCo",         "Constant Obfuscation (-co)",   false);
            Toggle("kagura.enableIbr",        "Indirect Branch (-ibr)",       true);
            Toggle("kagura.enableBbr",        "BB Reordering (-bbr)",         true);
            Toggle("kagura.enableBbs",        "BB Splitting (-bbs)",          false);
            Toggle("kagura.enableDci",        "Dead Code Insertion (-dci)",   false);
            Toggle("kagura.enableSv",         "Symbol Visibility (-sv)",      true);
            Toggle("kagura.enableAntiDebug",  "Anti-Debug (-anti-debug)",     true);
            Toggle("kagura.enableTamper",     "Anti-Tamper (-tamper)",        true);
            Toggle("kagura.enableGenc",       "Global Encryption (-genc)",    false);
            Toggle("kagura.enableVm",         "VM Obfuscation (-vm)",         false);

            EditorGUILayout.Space();
            GUILayout.Label("Tuning", EditorStyles.boldLabel);

            int bcfProb = EditorPrefs.GetInt("kagura.bcfProb", 30);
            bcfProb = EditorGUILayout.IntSlider("BCF Probability (%)", bcfProb, 0, 100);
            EditorPrefs.SetInt("kagura.bcfProb", bcfProb);
        }

        [SettingsProvider]
        public static SettingsProvider CreateProvider() =>
            new KaguraSettingsProvider();
    }
}
