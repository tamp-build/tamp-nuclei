using System.Globalization;

namespace Tamp.Nuclei;

/// <summary>
/// Shared base for Nuclei CommandPlan settings — binary resolution, working
/// directory, environment, and the escape hatch for unmodelled flags.
/// </summary>
public abstract class NucleiSettingsBase
{
    /// <summary>
    /// Path to the <c>nuclei</c> binary. Null resolves off PATH. Nuclei ships as
    /// a single static Go binary, so there's no runtime to locate alongside it.
    /// </summary>
    public string? NucleiCommand { get; set; }

    /// <summary>Working directory for the spawned process.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Per-invocation environment variables.</summary>
    public Dictionary<string, string> EnvironmentVariables { get; } = new();

    /// <summary>Escape hatch for flags this wrapper doesn't model.</summary>
    public List<string> ExtraArguments { get; } = new();

    /// <summary>
    /// Secrets to register on the plan so the runner redacts them from logs,
    /// traces, and dry-run output.
    /// </summary>
    protected List<Secret> PlanSecrets { get; } = new();

    /// <summary>Per-verb arguments.</summary>
    protected abstract IEnumerable<string> BuildArguments();

    /// <summary>Per-verb validation.</summary>
    protected virtual void Validate() { }

    /// <summary>Build the <see cref="CommandPlan"/> for this verb.</summary>
    public CommandPlan ToCommandPlan()
    {
        Validate();

        var args = BuildArguments().ToList();
        args.AddRange(ExtraArguments);

        return new CommandPlan
        {
            Executable = NucleiCommand ?? "nuclei",
            Arguments = args,
            Environment = new Dictionary<string, string>(EnvironmentVariables),
            WorkingDirectory = WorkingDirectory,
            Secrets = PlanSecrets.ToArray(),
        };
    }

    internal static string Invariant(int value) => value.ToString(CultureInfo.InvariantCulture);
}

/// <summary>Fluent setters shared by every Nuclei verb.</summary>
public static class NucleiSettingsBaseExtensions
{
    public static T SetNucleiCommand<T>(this T s, string? path) where T : NucleiSettingsBase { s.NucleiCommand = path; return s; }
    public static T SetWorkingDirectory<T>(this T s, string? cwd) where T : NucleiSettingsBase { s.WorkingDirectory = cwd; return s; }
    public static T SetEnvironmentVariable<T>(this T s, string name, string value) where T : NucleiSettingsBase { s.EnvironmentVariables[name] = value; return s; }
    public static T AddArgument<T>(this T s, string arg) where T : NucleiSettingsBase { s.ExtraArguments.Add(arg); return s; }
}

/// <summary>
/// Settings for a Nuclei scan. Covers targets, template selection, output
/// export, rate limiting, and authentication.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nuclei is two tools depending on how you invoke it.</strong> By default
/// it's a template-driven prober: fast, broad, excellent at known CVEs and
/// misconfigurations on a deployed stack, but it won't find novel injection in
/// your own bespoke code paths. Add <see cref="EnableDast"/> — and optionally
/// point <see cref="InputMode"/> at an OpenAPI definition — and it becomes an
/// active fuzzer against your documented API surface. Those are different jobs;
/// pick deliberately.
/// </para>
/// <para>
/// <strong>DAST mode is destructive.</strong> Fuzzing templates submit crafted
/// payloads to every parameter they discover, which means creating, modifying,
/// and deleting data through whatever endpoints answer. Point it at disposable
/// environments only.
/// </para>
/// </remarks>
public sealed class NucleiScanSettings : NucleiSettingsBase
{
    // ---- Targets ----

    /// <summary>Target URLs / hosts (<c>-u</c>). Repeatable.</summary>
    public List<string> Targets { get; } = new();

    /// <summary>File containing one target per line (<c>-l</c>).</summary>
    public string? TargetListFile { get; set; }

    /// <summary>Hosts to exclude (<c>-eh</c>).</summary>
    public List<string> ExcludeHosts { get; } = new();

    /// <summary>
    /// How the target input is interpreted (<c>-im</c>). Null = Nuclei's default
    /// (plain list). Set <see cref="NucleiInputMode.OpenApi"/> with
    /// <see cref="TargetListFile"/> pointing at a spec to scan a documented API.
    /// </summary>
    public NucleiInputMode? InputMode { get; set; }

    // ---- Output ----

    /// <summary>SARIF export path (<c>-se</c>). The Tamp security pipeline's format.</summary>
    public string? SarifExportFile { get; set; }

    /// <summary>JSON export path (<c>-je</c>).</summary>
    public string? JsonExportFile { get; set; }

    /// <summary>JSONL export path (<c>-jle</c>).</summary>
    public string? JsonLinesExportFile { get; set; }

    /// <summary>Markdown export directory (<c>-me</c>).</summary>
    public string? MarkdownExportDirectory { get; set; }

    /// <summary>Plain findings output file (<c>-o</c>).</summary>
    public string? OutputFile { get; set; }

    /// <summary>Print findings only, no banner or progress (<c>-silent</c>).</summary>
    public bool Silent { get; set; }

    /// <summary>Disable ANSI colour (<c>-nc</c>). Worth setting for CI logs.</summary>
    public bool NoColor { get; set; }

    // ---- Template selection ----

    /// <summary>Severities to include (<c>-s</c>). Empty = all.</summary>
    public List<NucleiSeverity> Severities { get; } = new();

    /// <summary>Severities to exclude (<c>-es</c>). <see cref="NucleiSeverity.Info"/> is the usual one to drop in CI.</summary>
    public List<NucleiSeverity> ExcludeSeverities { get; } = new();

    /// <summary>Run templates matching these tags (<c>-tags</c>).</summary>
    public List<string> Tags { get; } = new();

    /// <summary>Exclude templates by tag (<c>-etags</c>).</summary>
    public List<string> ExcludeTags { get; } = new();

    /// <summary>Template or directory paths (<c>-t</c>).</summary>
    public List<string> Templates { get; } = new();

    /// <summary>Remote template URLs (<c>-turl</c>).</summary>
    public List<string> TemplateUrls { get; } = new();

    /// <summary>Specific template IDs (<c>-id</c>).</summary>
    public List<string> TemplateIds { get; } = new();

    /// <summary>Template IDs to exclude (<c>-eid</c>).</summary>
    public List<string> ExcludeTemplateIds { get; } = new();

    /// <summary>Workflow files / directories (<c>-w</c>).</summary>
    public List<string> Workflows { get; } = new();

    /// <summary>Filter templates by author (<c>-author</c>).</summary>
    public List<string> Authors { get; } = new();

    // ---- Protocol toggles ----

    /// <summary>
    /// Enable DAST / fuzzing templates (<c>-dast</c>). Turns Nuclei from a
    /// known-issue prober into an active fuzzer. Destructive — see the class remarks.
    /// </summary>
    public bool EnableDast { get; set; }

    /// <summary>Enable headless-browser templates (<c>-headless</c>). Requires a browser on the runner.</summary>
    public bool EnableHeadless { get; set; }

    /// <summary>Enable code-protocol templates (<c>-code</c>). These execute code locally — only enable for templates you trust.</summary>
    public bool EnableCode { get; set; }

    // ---- Throughput ----

    /// <summary>Requests per second (<c>-rl</c>). Nuclei default 150.</summary>
    public int? RateLimit { get; set; }

    /// <summary>Templates run in parallel (<c>-c</c>). Nuclei default 25.</summary>
    public int? Concurrency { get; set; }

    /// <summary>Hosts per template in parallel (<c>-bs</c>). Nuclei default 25.</summary>
    public int? BulkSize { get; set; }

    /// <summary>Per-request timeout in seconds (<c>-timeout</c>).</summary>
    public int? TimeoutSeconds { get; set; }

    /// <summary>Retries per request (<c>-retries</c>).</summary>
    public int? Retries { get; set; }

    // ---- Auth ----

    /// <summary>
    /// Custom headers (<c>-H</c>), verbatim <c>"Name: value"</c> strings.
    /// </summary>
    /// <remarks>
    /// Values land in the OS process table for the lifetime of the scan. For
    /// credentials prefer <see cref="SecretFiles"/>, or
    /// <see cref="NucleiScanSettingsExtensions.AddSecretHeader"/> which at least
    /// registers the value for log redaction.
    /// </remarks>
    public List<string> Headers { get; } = new();

    /// <summary>
    /// Secret files for authenticated scans (<c>-sf</c>). The preferred way to
    /// give Nuclei credentials — nothing sensitive reaches the command line.
    /// </summary>
    public List<string> SecretFiles { get; } = new();

    /// <summary>Client certificate, PEM (<c>-cc</c>).</summary>
    public string? ClientCertFile { get; set; }

    /// <summary>Client key, PEM (<c>-ck</c>).</summary>
    public string? ClientKeyFile { get; set; }

    // ---- Network / determinism ----

    /// <summary>
    /// Disable Interactsh OOB testing (<c>-ni</c>). Required in air-gapped CI, and
    /// worth considering anywhere you'd rather not send callbacks to a
    /// third-party server.
    /// </summary>
    public bool NoInteractsh { get; set; }

    /// <summary>Self-hosted Interactsh server (<c>-iserver</c>).</summary>
    public string? InteractshServer { get; set; }

    /// <summary>
    /// Skip the engine/template auto-update check (<c>-duc</c>). Worth setting in
    /// CI: an update mid-pipeline changes what the scan covers between runs, so a
    /// finding can appear or vanish without the code changing.
    /// </summary>
    public bool DisableUpdateCheck { get; set; }

    protected override void Validate()
    {
        if (Targets.Count == 0 && string.IsNullOrWhiteSpace(TargetListFile))
        {
            throw new InvalidOperationException(
                "At least one target is required — set via AddTarget (-u) or SetTargetListFile (-l).");
        }

        if (InputMode is NucleiInputMode.OpenApi or NucleiInputMode.Swagger
            && string.IsNullOrWhiteSpace(TargetListFile))
        {
            throw new InvalidOperationException(
                $"InputMode '{InputMode}' reads an API definition from a file — set it via SetTargetListFile (-l).");
        }

        if (string.IsNullOrWhiteSpace(ClientCertFile) != string.IsNullOrWhiteSpace(ClientKeyFile))
        {
            throw new InvalidOperationException(
                "ClientCertFile and ClientKeyFile must be set together — a certificate without its key is unusable.");
        }
    }

    protected override IEnumerable<string> BuildArguments()
    {
        foreach (var t in Targets) { yield return "-u"; yield return t; }
        if (!string.IsNullOrEmpty(TargetListFile)) { yield return "-l"; yield return TargetListFile!; }
        foreach (var h in ExcludeHosts) { yield return "-eh"; yield return h; }
        if (InputMode is { } im) { yield return "-im"; yield return im.ToWire(); }

        if (!string.IsNullOrEmpty(SarifExportFile)) { yield return "-se"; yield return SarifExportFile!; }
        if (!string.IsNullOrEmpty(JsonExportFile)) { yield return "-je"; yield return JsonExportFile!; }
        if (!string.IsNullOrEmpty(JsonLinesExportFile)) { yield return "-jle"; yield return JsonLinesExportFile!; }
        if (!string.IsNullOrEmpty(MarkdownExportDirectory)) { yield return "-me"; yield return MarkdownExportDirectory!; }
        if (!string.IsNullOrEmpty(OutputFile)) { yield return "-o"; yield return OutputFile!; }

        if (Severities.Count > 0) { yield return "-s"; yield return string.Join(",", Severities.Select(x => x.ToWire())); }
        if (ExcludeSeverities.Count > 0) { yield return "-es"; yield return string.Join(",", ExcludeSeverities.Select(x => x.ToWire())); }
        if (Tags.Count > 0) { yield return "-tags"; yield return string.Join(",", Tags); }
        if (ExcludeTags.Count > 0) { yield return "-etags"; yield return string.Join(",", ExcludeTags); }
        foreach (var t in Templates) { yield return "-t"; yield return t; }
        foreach (var t in TemplateUrls) { yield return "-turl"; yield return t; }
        if (TemplateIds.Count > 0) { yield return "-id"; yield return string.Join(",", TemplateIds); }
        if (ExcludeTemplateIds.Count > 0) { yield return "-eid"; yield return string.Join(",", ExcludeTemplateIds); }
        foreach (var w in Workflows) { yield return "-w"; yield return w; }
        if (Authors.Count > 0) { yield return "-author"; yield return string.Join(",", Authors); }

        if (EnableDast) yield return "-dast";
        if (EnableHeadless) yield return "-headless";
        if (EnableCode) yield return "-code";

        if (RateLimit is int rl) { yield return "-rl"; yield return Invariant(rl); }
        if (Concurrency is int c) { yield return "-c"; yield return Invariant(c); }
        if (BulkSize is int bs) { yield return "-bs"; yield return Invariant(bs); }
        if (TimeoutSeconds is int to) { yield return "-timeout"; yield return Invariant(to); }
        if (Retries is int r) { yield return "-retries"; yield return Invariant(r); }

        foreach (var h in Headers) { yield return "-H"; yield return h; }
        foreach (var sf in SecretFiles) { yield return "-sf"; yield return sf; }
        if (!string.IsNullOrEmpty(ClientCertFile)) { yield return "-cc"; yield return ClientCertFile!; }
        if (!string.IsNullOrEmpty(ClientKeyFile)) { yield return "-ck"; yield return ClientKeyFile!; }

        if (NoInteractsh) yield return "-ni";
        if (!string.IsNullOrEmpty(InteractshServer)) { yield return "-iserver"; yield return InteractshServer!; }
        if (DisableUpdateCheck) yield return "-duc";
        if (Silent) yield return "-silent";
        if (NoColor) yield return "-nc";
    }

    /// <summary>Register a secret for runner-side log redaction.</summary>
    internal void RegisterSecret(Secret secret) => PlanSecrets.Add(secret);
}

/// <summary>Fluent setters for <see cref="NucleiScanSettings"/>.</summary>
public static class NucleiScanSettingsExtensions
{
    public static NucleiScanSettings AddTarget(this NucleiScanSettings s, string target) { s.Targets.Add(target); return s; }
    public static NucleiScanSettings SetTargetListFile(this NucleiScanSettings s, string path) { s.TargetListFile = path; return s; }
    public static NucleiScanSettings AddExcludeHost(this NucleiScanSettings s, string host) { s.ExcludeHosts.Add(host); return s; }
    public static NucleiScanSettings SetInputMode(this NucleiScanSettings s, NucleiInputMode? mode) { s.InputMode = mode; return s; }

    public static NucleiScanSettings SetSarifExportFile(this NucleiScanSettings s, string path) { s.SarifExportFile = path; return s; }
    public static NucleiScanSettings SetJsonExportFile(this NucleiScanSettings s, string path) { s.JsonExportFile = path; return s; }
    public static NucleiScanSettings SetJsonLinesExportFile(this NucleiScanSettings s, string path) { s.JsonLinesExportFile = path; return s; }
    public static NucleiScanSettings SetMarkdownExportDirectory(this NucleiScanSettings s, string path) { s.MarkdownExportDirectory = path; return s; }
    public static NucleiScanSettings SetOutputFile(this NucleiScanSettings s, string path) { s.OutputFile = path; return s; }
    public static NucleiScanSettings SetSilent(this NucleiScanSettings s, bool v = true) { s.Silent = v; return s; }
    public static NucleiScanSettings SetNoColor(this NucleiScanSettings s, bool v = true) { s.NoColor = v; return s; }

    public static NucleiScanSettings AddSeverity(this NucleiScanSettings s, NucleiSeverity sev) { s.Severities.Add(sev); return s; }
    public static NucleiScanSettings AddExcludeSeverity(this NucleiScanSettings s, NucleiSeverity sev) { s.ExcludeSeverities.Add(sev); return s; }
    public static NucleiScanSettings AddTag(this NucleiScanSettings s, string tag) { s.Tags.Add(tag); return s; }
    public static NucleiScanSettings AddExcludeTag(this NucleiScanSettings s, string tag) { s.ExcludeTags.Add(tag); return s; }
    public static NucleiScanSettings AddTemplate(this NucleiScanSettings s, string path) { s.Templates.Add(path); return s; }
    public static NucleiScanSettings AddTemplateUrl(this NucleiScanSettings s, string url) { s.TemplateUrls.Add(url); return s; }
    public static NucleiScanSettings AddTemplateId(this NucleiScanSettings s, string id) { s.TemplateIds.Add(id); return s; }
    public static NucleiScanSettings AddExcludeTemplateId(this NucleiScanSettings s, string id) { s.ExcludeTemplateIds.Add(id); return s; }
    public static NucleiScanSettings AddWorkflow(this NucleiScanSettings s, string path) { s.Workflows.Add(path); return s; }
    public static NucleiScanSettings AddAuthor(this NucleiScanSettings s, string author) { s.Authors.Add(author); return s; }

    public static NucleiScanSettings SetEnableDast(this NucleiScanSettings s, bool v = true) { s.EnableDast = v; return s; }
    public static NucleiScanSettings SetEnableHeadless(this NucleiScanSettings s, bool v = true) { s.EnableHeadless = v; return s; }
    public static NucleiScanSettings SetEnableCode(this NucleiScanSettings s, bool v = true) { s.EnableCode = v; return s; }

    public static NucleiScanSettings SetRateLimit(this NucleiScanSettings s, int? rps) { s.RateLimit = rps; return s; }
    public static NucleiScanSettings SetConcurrency(this NucleiScanSettings s, int? n) { s.Concurrency = n; return s; }
    public static NucleiScanSettings SetBulkSize(this NucleiScanSettings s, int? n) { s.BulkSize = n; return s; }
    public static NucleiScanSettings SetTimeoutSeconds(this NucleiScanSettings s, int? secs) { s.TimeoutSeconds = secs; return s; }
    public static NucleiScanSettings SetRetries(this NucleiScanSettings s, int? n) { s.Retries = n; return s; }

    /// <summary>Add a header verbatim. The value is visible in the OS process table — prefer <see cref="AddSecretFile"/> for credentials.</summary>
    public static NucleiScanSettings AddHeader(this NucleiScanSettings s, string header) { s.Headers.Add(header); return s; }

    /// <summary>
    /// Add a credential-bearing header. The value still reaches the command line
    /// (Nuclei has no stdin path for headers) but is registered on the plan so the
    /// runner redacts it from logs, traces, and dry-run output. For a stronger
    /// guarantee use <see cref="AddSecretFile"/>, which keeps it off the command
    /// line entirely.
    /// </summary>
    public static NucleiScanSettings AddSecretHeader(this NucleiScanSettings s, string name, Secret value)
    {
        ArgumentNullException.ThrowIfNull(s);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);
        s.Headers.Add($"{name}: {value.Reveal()}");
        s.RegisterSecret(value);
        return s;
    }

    /// <summary>Add a Nuclei secret file (<c>-sf</c>) — the preferred way to pass credentials.</summary>
    public static NucleiScanSettings AddSecretFile(this NucleiScanSettings s, string path) { s.SecretFiles.Add(path); return s; }

    public static NucleiScanSettings SetClientCertificate(this NucleiScanSettings s, string certPath, string keyPath)
    { s.ClientCertFile = certPath; s.ClientKeyFile = keyPath; return s; }

    public static NucleiScanSettings SetNoInteractsh(this NucleiScanSettings s, bool v = true) { s.NoInteractsh = v; return s; }
    public static NucleiScanSettings SetInteractshServer(this NucleiScanSettings s, string? url) { s.InteractshServer = url; return s; }
    public static NucleiScanSettings SetDisableUpdateCheck(this NucleiScanSettings s, bool v = true) { s.DisableUpdateCheck = v; return s; }
}

/// <summary>
/// Settings for a template-store update (<c>-update-templates</c>).
/// </summary>
/// <remarks>
/// Nuclei's value is its community template corpus, which moves daily. Run this
/// as an explicit step so template refresh is a visible, attributable event in the
/// build log rather than something the scan does to itself mid-run.
/// </remarks>
public sealed class NucleiUpdateTemplatesSettings : NucleiSettingsBase
{
    /// <summary>Also update the Nuclei engine binary (<c>-up</c>). Off by default — upgrading the tool underneath a pinned CI image is rarely what you want.</summary>
    public bool UpdateEngine { get; set; }

    /// <summary>Suppress banner output (<c>-silent</c>).</summary>
    public bool Silent { get; set; }

    /// <summary>Disable ANSI colour (<c>-nc</c>).</summary>
    public bool NoColor { get; set; }

    protected override IEnumerable<string> BuildArguments()
    {
        yield return "-update-templates";
        if (UpdateEngine) yield return "-up";
        if (Silent) yield return "-silent";
        if (NoColor) yield return "-nc";
    }
}

/// <summary>Fluent setters for <see cref="NucleiUpdateTemplatesSettings"/>.</summary>
public static class NucleiUpdateTemplatesSettingsExtensions
{
    public static NucleiUpdateTemplatesSettings SetUpdateEngine(this NucleiUpdateTemplatesSettings s, bool v = true) { s.UpdateEngine = v; return s; }
    public static NucleiUpdateTemplatesSettings SetSilent(this NucleiUpdateTemplatesSettings s, bool v = true) { s.Silent = v; return s; }
    public static NucleiUpdateTemplatesSettings SetNoColor(this NucleiUpdateTemplatesSettings s, bool v = true) { s.NoColor = v; return s; }
}
