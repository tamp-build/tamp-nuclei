namespace Tamp.Nuclei;

/// <summary>
/// Nuclei finding severities (<c>-s</c> / <c>-es</c>). Wire values are the
/// lowercased member names.
/// </summary>
public enum NucleiSeverity
{
    /// <summary>Informational — fingerprints, disclosures, tech detection. High volume.</summary>
    Info,

    /// <summary>Low.</summary>
    Low,

    /// <summary>Medium.</summary>
    Medium,

    /// <summary>High.</summary>
    High,

    /// <summary>Critical.</summary>
    Critical,

    /// <summary>Unknown — templates that declare no severity.</summary>
    Unknown,
}

/// <summary>
/// How Nuclei interprets the target list (<c>-im</c> / <c>-input-mode</c>).
/// </summary>
/// <remarks>
/// <see cref="OpenApi"/> and <see cref="Swagger"/> are the interesting ones for
/// API testing: paired with <c>-dast</c> they turn a published API definition into
/// a fuzzing surface, rather than probing only the URLs you happened to list.
/// </remarks>
public enum NucleiInputMode
{
    /// <summary>Plain list of hosts/URLs, one per line. Nuclei's default.</summary>
    List,

    /// <summary>Burp Suite export.</summary>
    Burp,

    /// <summary>JSONL request records.</summary>
    Jsonl,

    /// <summary>YAML request records.</summary>
    Yaml,

    /// <summary>OpenAPI 3.x definition — every documented operation becomes a target.</summary>
    OpenApi,

    /// <summary>Swagger 2.0 definition.</summary>
    Swagger,
}

/// <summary>Wire-format helpers for the Nuclei enums.</summary>
public static class NucleiEnumExtensions
{
    /// <summary>Lowercased wire value (<c>NucleiSeverity.Critical</c> → <c>"critical"</c>).</summary>
    public static string ToWire(this NucleiSeverity severity) => severity switch
    {
        NucleiSeverity.Info => "info",
        NucleiSeverity.Low => "low",
        NucleiSeverity.Medium => "medium",
        NucleiSeverity.High => "high",
        NucleiSeverity.Critical => "critical",
        NucleiSeverity.Unknown => "unknown",
        _ => severity.ToString().ToLowerInvariant(),
    };

    /// <summary>Lowercased wire value (<c>NucleiInputMode.OpenApi</c> → <c>"openapi"</c>).</summary>
    public static string ToWire(this NucleiInputMode mode) => mode switch
    {
        NucleiInputMode.List => "list",
        NucleiInputMode.Burp => "burp",
        NucleiInputMode.Jsonl => "jsonl",
        NucleiInputMode.Yaml => "yaml",
        NucleiInputMode.OpenApi => "openapi",
        NucleiInputMode.Swagger => "swagger",
        _ => mode.ToString().ToLowerInvariant(),
    };
}
