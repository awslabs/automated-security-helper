# dotnet-vulnerable (alpha plugin)

`dotnet-vulnerable` reports NuGet packages that have known vulnerabilities, using the .NET SDK's own `dotnet list package --vulnerable`. ASH runs it once for each `.csproj`, `.fsproj` and `.vbproj` file in the scan set and converts the JSON report into findings, with the package and its advisory link in each. It covers top-level and transitive packages.

## Enabling it

`dotnet-vulnerable` is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins
```

With the module listed, `dotnet-vulnerable` runs by default, like every other scanner. `scanners.dotnet-vulnerable.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners dotnet-vulnerable` without the module listed is refused, with a message naming the module to add. If `dotnet` is not installed, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## Installing the .NET SDK

ASH does not download this tool. `dotnet list package` is built into the .NET SDK, so there is no separate tool to pin: the scanner runs the `dotnet` command that the SDK provides, and the SDK has to be on `PATH`:

- **Container mode:** the ASH image does not include the .NET SDK. Use an image that adds it, or mount one.
- **Local mode:** install the SDK from [dotnet.microsoft.com/download](https://dotnet.microsoft.com/download). `ash dependencies install` has nothing to install for this scanner.
- **Nix mode:** the flake does not supply the SDK. Have `dotnet` on `PATH`.

The JSON output (`--format json`) needs SDK 7.0.200 or later. From SDK 9.0.300 the vulnerability data comes from the `AuditSources` of the project's NuGet configuration, and from its package sources when none is set. See the [command reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-list-package). The committed test captures come from SDK 10.0.404.

## Restore first

`dotnet list package` reads the `obj/project.assets.json` that `dotnet restore` writes. ASH does not pass `--no-restore`: the option exists only from SDK 10, and SDK 7 to 9 (the range this scanner supports) reject it as an unrecognized option. Before SDK 10 the command never restores; from SDK 10 it restores on its own, writing `obj/` into the scanned tree and fetching packages. A project that was never restored on SDK 7 to 9 has no assets file, and the command reports that as an error. ASH counts that project as one it could not evaluate. The scan is incomplete and the error names the project; the project is not reported as clean. Restore the solution before the scan, as a build job does.

## What is scanned

ASH's scan set is searched for project files. Each is passed to its own `dotnet list <project> package` run, so every finding is placed on the project that references the package. Solution files are not passed: their projects are scanned directly, and a solution run would report each finding twice. A project file that resolves outside the scanned tree through a link is skipped with a warning. A tree with no project file is skipped, and the scanner is reported as having scanned nothing, not as passing.

The command runs with these fixed options:

```text
dotnet list <project> package --vulnerable --include-transitive --format json --output-version 1
```

`--output-version 1` names the one JSON format that exists, so a later SDK's new format is not read as this one. `--outdated`, `--deprecated`, `--source`, `--config`, `--framework` and `--interactive` are never passed.

A finding is reported once for each project, package, version and advisory. A package that several target frameworks use is one finding that lists them. It sits on line 1 of the project file, because the report names no line. The report gives each vulnerability a severity and an advisory URL and nothing else: no CVE id, title or fixed version, so those are not in the finding. The advisory URL is in the message, and its GHSA id becomes the rule id. A URL with no GHSA id is reported under `NUGET-VULNERABLE-PACKAGE`.

## Configuration

```yaml
scanners:
  dotnet-vulnerable:
    enabled: true
    options:
      # Seconds for the whole scan, every project together (default 1800; null
      # for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override: ALL, LOW, MEDIUM, HIGH,
      # CRITICAL, or null for the global threshold.
      severity_threshold: null
```

The scanner has no option of its own. Nothing in the scanned tree can turn a finding off through ASH: a `nuget.config` can choose which sources the advisory data comes from, as it does for `dotnet restore`.

## Severity

| NuGet severity | ASH severity | SARIF level |
|---|---|---|
| Critical | CRITICAL | `error` |
| High | HIGH | `error` |
| Moderate | MEDIUM | `warning` |
| Low | LOW | `note` |
| none stated | MEDIUM | `warning` |
| any other name | HIGH | `error` |

ASH's severity and the SARIF level always agree. An advisory source that states no severity gives an empty value, which is rated MEDIUM: nothing says it is minor and nothing says it is severe. A severity name ASH does not know is rated HIGH, so one that NuGet adds later is never reported as less than it is. With ASH's default `severity_threshold` of `MEDIUM`, a Moderate, High or Critical finding fails the scan.

## Failures

`dotnet list package` exits 0 for a run that completed, whether or not it found anything. A project fails, and is named in the scan's errors, when any of these holds:

- the command exits with any other status;
- its JSON `problems` list holds an entry at level `error` (an unrestored project, a source that could not be read);
- its output is not the JSON report.

The other projects are still scanned and reported. A scan that outlasts `scan_timeout` stops and fails, with one time budget for all the projects together. The tool's standard error is not copied into the scan's errors, since a NuGet message can quote text from the scanned tree.

## Suppressions

ASH suppressions by rule, path and line work as for any scanner:

```yaml
global_settings:
  suppressions:
    - rule_id: GHSA-xxxx-xxxx-xxxx
      path: src/Legacy/Legacy.csproj
      line_start: 1
      line_end: 1
      reason: the vulnerable code path is not reachable from this service
```

Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

The vulnerability lookup reads advisory data from a NuGet source, so the scanner needs a network and does not run offline. Under `--offline` it is skipped and reported `MISSING` (the incomplete-scan gate), as the Snyk Code scanner is. To scan offline, leave it out with `--exclude-scanners dotnet-vulnerable`, or run it before going offline.

The client downloads the sources' vulnerability data files and matches them against the project's packages locally, so the project's package list is not sent anywhere ([the NuGet vulnerability info resource](https://learn.microsoft.com/en-us/nuget/api/vulnerability-info)). Under `--sandbox` the scanner is given a network, and the `DOTNET_` and `NUGET_` environment variables; other variables and credentials for a private feed are not passed, so a source that needs one is not read and its project reports an error.

## Differences from other scanners

`dotnet-vulnerable` checks only the packages the projects resolve, against the advisories its configured NuGet sources publish. It does not read source code and it does not look at packages outside the .NET projects.

## License

The .NET SDK is MIT-licensed (the `LICENSE.txt` at the root of the SDK, read at SDK 10.0.404, is the `LICENSE.TXT` of the [dotnet/sdk](https://github.com/dotnet/sdk) repository at that release's tag). ASH neither downloads nor redistributes it: this scanner runs the copy you installed, and the ASH container image does not carry it.
