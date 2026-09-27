namespace Tamp.Nuclei;

/// <summary>
/// Tamp wrappers for the Nuclei vulnerability scanner. <c>Scan</c> runs a
/// scan; <c>UpdateTemplates</c> refreshes the template store.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nuclei is two tools depending on how you invoke it.</strong> Plain, it's
/// a template-driven prober — fast and broad, excellent at known CVEs, exposed
/// panels, and misconfigurations on a deployed stack, but blind to novel injection
/// in your own code. Add <see cref="NucleiScanSettings.EnableDast"/>, and point
/// <see cref="NucleiScanSettings.InputMode"/> at an OpenAPI definition, and it
/// becomes an active fuzzer against your documented API surface. Those answer
/// different questions; choose deliberately rather than by default.
/// </para>
/// <code>
/// // Fast prober — safe, runs on every deploy.
/// var probe = Nuclei.Scan(s => s
///     .AddTarget(DeployedUrl)
///     .SetSarifExportFile(SecurityArtifactsDir / "nuclei.sarif")
///     .AddExcludeSeverity(NucleiSeverity.Info)
///     .SetNoInteractsh()
///     .SetDisableUpdateCheck()
///     .SetSilent().SetNoColor());
///
/// // API fuzzer — destructive, disposable environments only.
/// var fuzz = Nuclei.Scan(s => s
///     .SetTargetListFile(SecurityArtifactsDir / "openapi.json")
///     .SetInputMode(NucleiInputMode.OpenApi)
///     .SetEnableDast()
///     .SetSarifExportFile(SecurityArtifactsDir / "nuclei-dast.sarif")
///     .AddSecretFile(SecurityArtifactsDir / "nuclei-auth.yaml"));
/// </code>
/// <para>
/// <strong>Exit codes.</strong> Nuclei exits <c>0</c> on a completed scan whether or
/// not it found anything — findings live in the export file, not the exit code. A
/// non-zero exit means the scan itself failed (bad flags, unreachable target,
/// unusable templates), so a build target should treat non-zero as a hard failure
/// rather than as "findings were reported". This is the opposite of the
/// <c>Tamp.OpenGrep</c> / <c>Tamp.Eslint.V9</c> convention, so don't copy their
/// <c>rc &gt; 1</c> handling here.
/// </para>
/// <para>
/// <strong>Template freshness is the value proposition, and a reproducibility
/// hazard.</strong> The community corpus moves daily. Run
/// <c>UpdateTemplates</c> as its own build step and set
/// <see cref="NucleiScanSettings.DisableUpdateCheck"/> on the scan, so template
/// refresh is a visible, attributable event rather than something the scan does to
/// itself mid-run — otherwise a finding can appear or vanish between builds with
/// no code change to explain it.
/// </para>
/// <para>
/// <strong>Interactsh.</strong> Out-of-band tests default to ProjectDiscovery's
/// public interactsh server, which means callbacks about your infrastructure leave
/// your network. Use <see cref="NucleiScanSettings.NoInteractsh"/> or point
/// <see cref="NucleiScanSettings.InteractshServer"/> at a self-hosted instance.
/// </para>
/// </remarks>
public static class Nuclei
{
    /// <summary><c>nuclei -u &lt;target&gt; [flags]</c> — run a scan.</summary>
    public static CommandPlan Scan(Action<NucleiScanSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new NucleiScanSettings();
        configure(settings);
        return settings.ToCommandPlan();
    }

    /// <summary>Object-init overload. Identical CommandPlan to the fluent path.</summary>
    public static CommandPlan Scan(NucleiScanSettings settings)
    {
        if (settings is null) throw new ArgumentNullException(nameof(settings));
        return settings.ToCommandPlan();
    }

    /// <summary><c>nuclei -update-templates</c> — refresh the template store.</summary>
    public static CommandPlan UpdateTemplates(Action<NucleiUpdateTemplatesSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new NucleiUpdateTemplatesSettings();
        configure(settings);
        return settings.ToCommandPlan();
    }

    /// <summary>Object-init overload. Identical CommandPlan to the fluent path.</summary>
    public static CommandPlan UpdateTemplates(NucleiUpdateTemplatesSettings settings)
    {
        if (settings is null) throw new ArgumentNullException(nameof(settings));
        return settings.ToCommandPlan();
    }
}
