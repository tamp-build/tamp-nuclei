# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

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
