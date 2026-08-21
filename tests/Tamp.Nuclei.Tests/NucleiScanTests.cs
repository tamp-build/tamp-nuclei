namespace Tamp.Nuclei.Tests;

public class NucleiScanTests
{
    private const string Target = "https://app.example.test";

    private static List<string> ArgsFor(Action<NucleiScanSettings> configure)
        => Nuclei.Scan(configure).Arguments.ToList();

    private static string ValueAfter(List<string> args, string flag)
    {
        var i = args.IndexOf(flag);
        Assert.True(i >= 0 && i + 1 < args.Count, $"expected flag '{flag}' with a value");
        return args[i + 1];
    }

    // ------------------------------------------------------------------
    // Basics
    // ------------------------------------------------------------------

    [Fact]
    public void Scan_resolves_nuclei_off_path_by_default()
    {
        var plan = Nuclei.Scan(s => s.AddTarget(Target));
        Assert.Equal("nuclei", plan.Executable);
    }

    [Fact]
    public void Explicit_binary_path_is_honoured()
    {
        var plan = Nuclei.Scan(s => s.AddTarget(Target).SetNucleiCommand("/opt/nuclei/nuclei"));
        Assert.Equal("/opt/nuclei/nuclei", plan.Executable);
    }

    [Fact]
    public void Targets_are_repeated_per_url()
    {
        var args = ArgsFor(s => s.AddTarget("https://a.test").AddTarget("https://b.test"));
        Assert.Equal(2, args.Count(a => a == "-u"));
        Assert.Contains("https://a.test", args);
        Assert.Contains("https://b.test", args);
    }

    [Fact]
    public void A_target_is_required()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Nuclei.Scan(_ => { }));
        Assert.Contains("At least one target is required", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_target_list_file_satisfies_the_target_requirement()
    {
        var args = ArgsFor(s => s.SetTargetListFile("targets.txt"));
        Assert.Equal("targets.txt", ValueAfter(args, "-l"));
    }

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    [Fact]
    public void Sarif_export_uses_the_short_flag()
    {
        var args = ArgsFor(s => s.AddTarget(Target).SetSarifExportFile("out/nuclei.sarif"));
        Assert.Equal("out/nuclei.sarif", ValueAfter(args, "-se"));
    }

    [Fact]
    public void Export_flags_are_omitted_when_unset()
    {
        var args = ArgsFor(s => s.AddTarget(Target));
        foreach (var flag in new[] { "-se", "-je", "-jle", "-me", "-o" })
            Assert.DoesNotContain(flag, args);
    }

    // ------------------------------------------------------------------
    // Severity + template filtering
    // ------------------------------------------------------------------

    [Fact]
    public void Severities_are_comma_joined_and_lowercased()
    {
        var args = ArgsFor(s => s
            .AddTarget(Target)
            .AddSeverity(NucleiSeverity.Critical)
            .AddSeverity(NucleiSeverity.High));

        Assert.Equal("critical,high", ValueAfter(args, "-s"));
    }

    [Fact]
    public void Excluded_severities_use_the_exclude_flag()
    {
        var args = ArgsFor(s => s.AddTarget(Target).AddExcludeSeverity(NucleiSeverity.Info));
        Assert.Equal("info", ValueAfter(args, "-es"));
    }

    [Theory]
    [InlineData(NucleiSeverity.Info, "info")]
    [InlineData(NucleiSeverity.Low, "low")]
    [InlineData(NucleiSeverity.Medium, "medium")]
    [InlineData(NucleiSeverity.High, "high")]
    [InlineData(NucleiSeverity.Critical, "critical")]
    [InlineData(NucleiSeverity.Unknown, "unknown")]
    public void Every_severity_has_a_wire_value(NucleiSeverity severity, string expected)
        => Assert.Equal(expected, severity.ToWire());

    [Theory]
    [InlineData(NucleiInputMode.List, "list")]
    [InlineData(NucleiInputMode.Burp, "burp")]
    [InlineData(NucleiInputMode.Jsonl, "jsonl")]
    [InlineData(NucleiInputMode.Yaml, "yaml")]
    [InlineData(NucleiInputMode.OpenApi, "openapi")]
    [InlineData(NucleiInputMode.Swagger, "swagger")]
    public void Every_input_mode_has_a_wire_value(NucleiInputMode mode, string expected)
        => Assert.Equal(expected, mode.ToWire());

    [Fact]
    public void Tags_and_templates_use_their_respective_shapes()
    {
        // Tags are comma-joined into one flag; template paths repeat the flag.
        var args = ArgsFor(s => s
            .AddTarget(Target)
            .AddTag("cve").AddTag("exposure")
            .AddTemplate("./custom-a").AddTemplate("./custom-b"));

        Assert.Equal("cve,exposure", ValueAfter(args, "-tags"));
        Assert.Equal(2, args.Count(a => a == "-t"));
    }

    // ------------------------------------------------------------------
    // OpenAPI / DAST
    // ------------------------------------------------------------------

    [Fact]
    public void Openapi_input_mode_emits_the_mode_flag()
    {
        var args = ArgsFor(s => s
            .SetTargetListFile("openapi.json")
            .SetInputMode(NucleiInputMode.OpenApi));

        Assert.Equal("openapi", ValueAfter(args, "-im"));
    }

    [Fact]
    public void Spec_input_modes_require_a_file_not_a_url_target()
    {
        // -u takes hosts; a spec has to arrive via -l. Catching this here beats
        // a scan that silently probes the base URL and reports nothing.
        var ex = Assert.Throws<InvalidOperationException>(() => Nuclei.Scan(s => s
            .AddTarget(Target)
            .SetInputMode(NucleiInputMode.OpenApi)));

        Assert.Contains("reads an API definition from a file", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Swagger_mode_has_the_same_requirement()
    {
        Assert.Throws<InvalidOperationException>(() => Nuclei.Scan(s => s
            .AddTarget(Target)
            .SetInputMode(NucleiInputMode.Swagger)));
    }

    [Fact]
    public void Dast_mode_emits_the_dast_flag_and_is_off_by_default()
    {
        Assert.DoesNotContain("-dast", ArgsFor(s => s.AddTarget(Target)));
        Assert.Contains("-dast", ArgsFor(s => s.AddTarget(Target).SetEnableDast()));
    }

    [Fact]
    public void Protocol_toggles_are_independent()
    {
        var args = ArgsFor(s => s.AddTarget(Target).SetEnableHeadless().SetEnableCode());
        Assert.Contains("-headless", args);
        Assert.Contains("-code", args);
        Assert.DoesNotContain("-dast", args);
    }

    // ------------------------------------------------------------------
    // Auth + secrets
    // ------------------------------------------------------------------

    [Fact]
    public void Secret_headers_are_registered_for_redaction()
    {
        var token = new Secret("nuclei-bearer", "super-secret-value");
        var plan = Nuclei.Scan(s => s.AddTarget(Target).AddSecretHeader("Authorization", token));

        // Nuclei has no stdin path for headers, so the value does reach argv —
        // but it must be registered so the runner redacts it from logs/traces.
        Assert.Contains(plan.Secrets, x => x.Name == "nuclei-bearer");
        Assert.Contains("Authorization: super-secret-value", plan.Arguments);
    }

    [Fact]
    public void Plain_headers_register_no_secret()
    {
        var plan = Nuclei.Scan(s => s.AddTarget(Target).AddHeader("X-Scan: tamp"));
        Assert.Empty(plan.Secrets);
        Assert.Contains("X-Scan: tamp", plan.Arguments);
    }

    [Fact]
    public void Secret_files_keep_credentials_off_the_command_line()
    {
        var args = ArgsFor(s => s.AddTarget(Target).AddSecretFile("auth.yaml"));
        Assert.Equal("auth.yaml", ValueAfter(args, "-sf"));
        Assert.DoesNotContain("-H", args);
    }

    [Fact]
    public void Client_certificate_and_key_must_be_set_together()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Nuclei.Scan(s =>
        {
            s.AddTarget(Target);
            s.ClientCertFile = "client.pem";
        }));

        Assert.Contains("must be set together", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_certificate_pair_emits_both_flags()
    {
        var args = ArgsFor(s => s.AddTarget(Target).SetClientCertificate("client.pem", "client.key"));
        Assert.Equal("client.pem", ValueAfter(args, "-cc"));
        Assert.Equal("client.key", ValueAfter(args, "-ck"));
    }

    // ------------------------------------------------------------------
    // Determinism + egress
    // ------------------------------------------------------------------

    [Fact]
    public void Interactsh_and_update_check_can_be_disabled()
    {
        // Both matter for CI: one stops callbacks leaving the network, the
        // other stops the tool changing itself mid-pipeline.
        var args = ArgsFor(s => s.AddTarget(Target).SetNoInteractsh().SetDisableUpdateCheck());
        Assert.Contains("-ni", args);
        Assert.Contains("-duc", args);
    }

    [Fact]
    public void Nothing_is_disabled_by_default()
    {
        // Mirror the tool's own defaults — surprising a caller with silently
        // altered behaviour is worse than making them opt in.
        var args = ArgsFor(s => s.AddTarget(Target));
        Assert.DoesNotContain("-ni", args);
        Assert.DoesNotContain("-duc", args);
        Assert.DoesNotContain("-silent", args);
    }

    [Fact]
    public void Throughput_knobs_are_emitted_with_invariant_numbers()
    {
        var args = ArgsFor(s => s
            .AddTarget(Target)
            .SetRateLimit(50).SetConcurrency(10).SetBulkSize(5)
            .SetTimeoutSeconds(15).SetRetries(2));

        Assert.Equal("50", ValueAfter(args, "-rl"));
        Assert.Equal("10", ValueAfter(args, "-c"));
        Assert.Equal("5", ValueAfter(args, "-bs"));
        Assert.Equal("15", ValueAfter(args, "-timeout"));
        Assert.Equal("2", ValueAfter(args, "-retries"));
    }

    // ------------------------------------------------------------------
    // Escape hatch + overloads
    // ------------------------------------------------------------------

    [Fact]
    public void Extra_arguments_are_appended_last()
    {
        var args = ArgsFor(s => s.AddTarget(Target).AddArgument("-proxy").AddArgument("http://127.0.0.1:8080"));
        Assert.Equal("-proxy", args[^2]);
        Assert.Equal("http://127.0.0.1:8080", args[^1]);
    }

    [Fact]
    public void Object_init_overload_matches_the_fluent_path()
    {
        var fluent = Nuclei.Scan(s => s.AddTarget(Target).SetSarifExportFile("o.sarif"));
        var settings = new NucleiScanSettings { SarifExportFile = "o.sarif" };
        settings.Targets.Add(Target);
        var direct = Nuclei.Scan(settings);

        Assert.Equal(fluent.Executable, direct.Executable);
        Assert.Equal(fluent.Arguments, direct.Arguments);
    }

    [Fact]
    public void Null_arguments_throw()
    {
        Assert.Throws<ArgumentNullException>(() => Nuclei.Scan((Action<NucleiScanSettings>)null!));
        Assert.Throws<ArgumentNullException>(() => Nuclei.Scan((NucleiScanSettings)null!));
        Assert.Throws<ArgumentNullException>(() => Nuclei.UpdateTemplates((Action<NucleiUpdateTemplatesSettings>)null!));
        Assert.Throws<ArgumentNullException>(() => Nuclei.UpdateTemplates((NucleiUpdateTemplatesSettings)null!));
    }

    // ------------------------------------------------------------------
    // Update verb
    // ------------------------------------------------------------------

    [Fact]
    public void Update_templates_does_not_upgrade_the_engine_by_default()
    {
        // Swapping the binary underneath a pinned CI image is rarely intended.
        var plan = Nuclei.UpdateTemplates(_ => { });
        Assert.Contains("-update-templates", plan.Arguments);
        Assert.DoesNotContain("-up", plan.Arguments);
    }

    [Fact]
    public void Update_templates_can_opt_into_an_engine_upgrade()
    {
        var plan = Nuclei.UpdateTemplates(s => s.SetUpdateEngine().SetSilent().SetNoColor());
        Assert.Contains("-up", plan.Arguments);
        Assert.Contains("-silent", plan.Arguments);
        Assert.Contains("-nc", plan.Arguments);
    }

    [Fact]
    public void Update_templates_needs_no_target()
    {
        var ex = Record.Exception(() => Nuclei.UpdateTemplates(_ => { }));
        Assert.Null(ex);
    }
}
