# Tamp.Nuclei

Tamp wrappers for **Nuclei** — template-driven vulnerability scanning and DAST fuzzing against a deployed target, with native SARIF export for the Tamp security pipeline. A Tamp satellite.

| | |
|---|---|
| **Wrapped tool** | [Nuclei](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery) |
| **Tool license** | **MIT** — engine *and* the `nuclei-templates` corpus |
| **This package** | MIT |
| **Platform** | Single static Go binary — Windows · Linux · macOS · ARM. No runtime dependencies, no JRE, no Docker required |
| **Target frameworks** | net8.0 · net9.0 · net10.0 |
| **SARIF** | Native (`-sarif-export`) — no converter step |

## Nuclei is two tools depending on how you invoke it

This is the thing to understand before adopting it.

**Plain, it's a prober.** The community template corpus matches known CVEs, exposed admin panels, default credentials, and misconfigurations against whatever you point it at. Fast, broad, low false-positive — and structurally blind to novel injection in your own code, because no template describes your application.

**With `-dast`, it's a fuzzer.** Fuzzing templates actively probe discovered parameters for injection classes. Point `-input-mode` at an OpenAPI definition and every documented operation becomes a target.

Those answer different questions. A scan that only does the first should not be described to an auditor as dynamic application security testing.

```csharp
using Tamp.Nuclei;

// Prober — fast, safe, every deploy.
var probe = Nuclei.Scan(s => s
    .AddTarget(DeployedUrl)
    .SetSarifExportFile(SecurityArtifactsDir / "nuclei.sarif")
    .AddExcludeSeverity(NucleiSeverity.Info)
    .SetNoInteractsh()
    .SetDisableUpdateCheck()
    .SetSilent().SetNoColor());

// Fuzzer — destructive, disposable environments only.
var fuzz = Nuclei.Scan(s => s
    .SetTargetListFile(SecurityArtifactsDir / "openapi.json")
    .SetInputMode(NucleiInputMode.OpenApi)
    .SetEnableDast()
    .SetSarifExportFile(SecurityArtifactsDir / "nuclei-dast.sarif")
    .AddSecretFile(SecurityArtifactsDir / "nuclei-auth.yaml"));
```

> **DAST mode writes.** Fuzzing templates submit crafted payloads to every parameter they find — creating, modifying, and deleting data through whatever endpoints answer. Disposable environments only.

## Install

```bash
dotnet add package Tamp.Nuclei
```

Nuclei itself is a single binary — `go install`, a release archive, or your package manager of choice. `SetNucleiCommand(path)` if it isn't on PATH.

## Exit codes differ from the other Tamp scanners

Nuclei exits **`0` on a completed scan whether or not it found anything** — findings live in the export file, not the exit code. Non-zero means the scan itself failed.

```csharp
var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
if (rc != 0) throw new Exception($"nuclei exited with {rc}");
```

This is the **opposite** of `Tamp.OpenGrep` and `Tamp.Eslint.V9`, where `1` means "findings exist, scan was fine" and adopters write `if (rc > 1) throw`. Copying that pattern here silently swallows real scan failures.

## Template freshness is the value proposition — and a reproducibility hazard

The corpus moves daily. That's why Nuclei finds things; it also means an unpinned scan can report a finding today that it didn't yesterday, with no code change to explain it.

Make the refresh an explicit, attributable build step:

```csharp
Target UpdateNucleiTemplates => _ => _
    .Executes(() => ProcessRunner.Execute(
        Nuclei.UpdateTemplates(s => s.SetSilent().SetNoColor())));

Target SecurityScanNuclei => _ => _
    .DependsOn(nameof(UpdateNucleiTemplates))
    .Executes(() => /* ... .SetDisableUpdateCheck() ... */);
```

`UpdateTemplates` does **not** upgrade the engine binary by default — swapping the tool underneath a pinned CI image is rarely what anyone means. Opt in with `SetUpdateEngine()`.

## Credentials

Three options, best first:

```csharp
// 1. Secret file (-sf). Nothing sensitive touches the command line.
.AddSecretFile("nuclei-auth.yaml")

// 2. Secret-typed header. The value still reaches argv — Nuclei has no stdin
//    path for headers — but it's registered on the plan so the runner redacts
//    it from logs, traces, and dry-run output.
.AddSecretHeader("Authorization", new Secret("bearer", token))

// 3. Plain header. Visible in the OS process table. Non-credential use only.
.AddHeader("X-Scan-Source: tamp")
```

## Out-of-band testing leaves your network by default

Interactsh templates call back to ProjectDiscovery's public server, which means DNS and HTTP callbacks about your infrastructure go to a third party. Either disable it or self-host:

```csharp
.SetNoInteractsh()                                  // off entirely
.SetInteractshServer("https://oast.internal.example") // or self-hosted
```

Required for air-gapped CI either way.

## Typed enums

`NucleiSeverity` (`Info` … `Critical`, `Unknown`) and `NucleiInputMode` (`List`, `Burp`, `Jsonl`, `Yaml`, `OpenApi`, `Swagger`) with `.ToWire()` for the lowercased CLI values. Severities comma-join into one flag; template paths and targets repeat their flag — the wrapper handles both shapes.

## Validation

The wrapper fails at plan-build time, with an explanation, rather than letting the scan run and quietly do the wrong thing:

- no target at all (`-u` or `-l`)
- `OpenApi` / `Swagger` input mode without a file — a spec has to arrive via `-l`, and passing it as `-u` produces a scan that probes the base URL and reports nothing
- a client certificate without its key

## Anything not modelled

```csharp
.AddArgument("-proxy").AddArgument("http://127.0.0.1:8080")
```

Extra arguments append last.

## License

MIT. See [LICENSE](LICENSE). Nuclei itself is MIT and is not redistributed by this package.
