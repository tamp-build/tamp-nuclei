# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-20 - .NET 11 in, .NET 8 and .NET 9 out

### Changed

- **Multi-targets `net10.0;net11.0`** instead of `net8.0;net9.0;net10.0` ([ADR 0015](https://github.com/tamp-build/tamp/blob/main/docs/adr/0015-target-framework-strategy.md)). .NET 11 shipped 2026-11-10 and .NET 8 and .NET 9 reached end of support the same day; the rule is to add a TFM the day a release ships and drop one the day Microsoft ends its support. `global.json` pins SDK 11.0.100.

  **If you target `net8.0` or `net9.0`, stay on the previous version** — this one carries no assets your project can resolve.

- **`Tamp.*` pinned to 1.21.0**, which carries a SARIF fix worth knowing about if this project's output is read as evidence: before 1.21.0, a SARIF result whose scanner omitted `level` was read as `none` — the least severe value — instead of the declared `warning`, on every runtime before net11 ([tamp#166](https://github.com/tamp-build/tamp/issues/166)).

- **Publishing moved to nuget.org trusted publishing (OIDC).** The `tamp_nuget_api_key` org secret expired 2026-11-01 along with every other pre-2026-08-17 nuget.org key. The publish job now mints a short-lived key from its own OIDC token, so there is no long-lived credential to rotate or leak.

## [0.1.1] — 2026-09-27

### Added

- Package now ships XML documentation files (`.xml`) alongside the assembly, so consumers get IntelliSense and API docs. (Mirrors [tamp-build/tamp#3](https://github.com/tamp-build/tamp/pull/50).)


## [0.1.0] - 2026-08-21

Initial release.

### Added

- `Nuclei.Scan` — targets (`-u` / `-l`), input modes including OpenAPI/Swagger, SARIF/JSON/JSONL/markdown export, severity and tag filtering, template selection, throughput knobs, and authentication.
- `Nuclei.UpdateTemplates` — explicit template-store refresh, so freshness is an attributable build step rather than something the scan does to itself mid-run. Engine upgrade is opt-in.
- `NucleiSeverity` and `NucleiInputMode` enums with `ToWire()` for the lowercased CLI values.
- `AddSecretHeader(name, Secret)` — registers the value on `CommandPlan.Secrets` for runner-side log/trace redaction; `AddSecretFile` for the stronger `-sf` path that keeps credentials off the command line entirely.
- Plan-build validation for: missing targets, spec input modes without a `-l` file, and a client certificate supplied without its key.

### Notes

- Nuclei exits `0` on a completed scan regardless of findings — non-zero means the scan failed. This inverts the `Tamp.OpenGrep` / `Tamp.Eslint.V9` convention; don't reuse their `rc > 1` handling.
- Interactsh OOB testing defaults to ProjectDiscovery's public server. `SetNoInteractsh()` or `SetInteractshServer()` for air-gapped or egress-sensitive environments.
- Both the engine and the `nuclei-templates` corpus are MIT.
