# CodeQL (community plugin)

> **License terms gate.** The CodeQL CLI is not open-source software. Its terms (the CodeQL Terms and Conditions, shipped as `LICENSE.md` in the [CodeQL CLI binaries repository](https://github.com/github/codeql-cli-binaries)) allow analysis of an open-source codebase, and allow generating a CodeQL database "for or during automated analysis, CI, or CD" only for an open-source codebase hosted and maintained on GitHub.com. They bar generating a database "in any other context ... for or during automated analysis, CI or CD" and bar use "in connection with any codebase that is not an Open Source Codebase (e.g., code in a private repo in GitHub)". Those limits do not apply under a paid GitHub Advanced Security customer license. Whether a given run is permitted is yours to decide, not ASH's.

[CodeQL](https://codeql.github.com) is a semantic code analysis engine. The plugin builds a CodeQL database for each language you configure and runs that language's standard code scanning query suite over it. It reports SAST findings (injection, unsafe deserialization, path traversal, weak cryptography and the like) as ASH findings.

## Enabling it

The plugin is off until you turn on three things: list its module, set `enabled: true`, and acknowledge the license terms. Without `license_terms_acknowledged: true` the scan fails before CodeQL starts, with an error that quotes the terms constraint.

<!-- doctest: illustrative reason="the module and options are the user's choice, and the scan needs the CodeQL CLI" -->
```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_codeql_plugins

scanners:
  codeql:
    enabled: true
    options:
      # Your confirmation that running CodeQL on this code, this way, is
      # permitted by its terms or by your GitHub Advanced Security license.
      license_terms_acknowledged: true
      languages: [python]
```

A scan that does not list the module is unchanged.

## Installing CodeQL

ASH does not install or redistribute CodeQL, because its terms are yours to accept. Download the CLI, or a CodeQL bundle that includes the query packs, from the [CodeQL CLI binaries repository](https://github.com/github/codeql-cli-binaries) and put `codeql` on `PATH`. The ASH container image does not include it. If `codeql` is not found, the scanner is reported `MISSING`.

Analysis runs with `--no-download`, so it never fetches anything. The standard query packs (`codeql/python-queries`, `codeql/javascript-queries` and so on) must already be installed: use a bundle, or run `codeql pack download <pack>` yourself.

## What is scanned

For each language in `languages`, ASH runs two commands (CodeQL's `database create` and `database analyze`):

<!-- doctest: illustrative reason="shows the commands ASH runs; they need the CodeQL CLI" -->
```bash
codeql database create --language=python --source-root=<dir> --build-mode=none --overwrite --threads=1 -- <db>
codeql database analyze --format=sarifv2.1.0 --output=<report> --no-download --sarif-add-snippets --sarif-category=ash-codeql-python --threads=1 -- <db> codeql/python-queries:codeql-suites/python-code-scanning.qls
```

`--build-mode=none` means CodeQL never builds the scanned tree, so none of its build scripts run. That supports Python, JavaScript/TypeScript, Ruby, C#, Java, C/C++ and Rust. Go, Swift and Kotlin need a build, and the plugin refuses them: a `java-kotlin` database made without a build holds the Java sources only, so naming `kotlin` would report a clean scan of code that was never analyzed. ASH passes no query path or config from the scanned tree. A language with no source in the tree (CodeQL exit code 32) is skipped, and if every language is skipped the target reads as nothing scanned.

## Configuration

<!-- doctest: illustrative reason="shows every option; the scan needs the CodeQL CLI" -->
```yaml
scanners:
  codeql:
    enabled: true
    options:
      license_terms_acknowledged: true
      # python, javascript-typescript, java-kotlin, csharp, c-cpp, ruby, rust.
      # javascript, typescript, java, c and cpp are accepted as aliases (java is Java only).
      languages: [python, javascript-typescript]
      # CodeQL --threads for both steps (0 is one per core).
      threads: 1
      # Seconds for the whole scan; every CodeQL process shares one budget.
      scan_timeout: 1800
      severity_threshold: null
```

## Severity

CodeQL's SARIF rules carry GitHub's documented properties, and the plugin turns them into one ASH severity and a SARIF level that agrees with it:

| Rule data | ASH severity | SARIF level |
|---|---|---|
| `security-severity` 9.0 or over | CRITICAL | error |
| `security-severity` 7.0 to 8.9 | HIGH | error |
| `security-severity` 4.0 to 6.9 | MEDIUM | warning |
| `security-severity` 0.1 to 3.9 | LOW | note |
| no score, `problem.severity` error | HIGH | error |
| no score, `problem.severity` warning | MEDIUM | warning |
| no score, `problem.severity` recommendation | LOW | note |

A rule with neither property uses the result's own level (error HIGH, warning MEDIUM, note LOW, no level MEDIUM, anything else HIGH). GitHub's documentation leaves a score of exactly 9.0 unassigned; the plugin rates it CRITICAL, the more severe reading.

## Exit status

CodeQL exits 0 when a command completes, whether or not it finds anything. The plugin accepts 0, and 32 from `database create` (nothing to analyze). Any other code, including 33 (a query timed out), 99 (out of memory) and 100 (fatal), fails the scan even if a report is on disk. CodeQL's stderr is kept out of ASH's error text, because it can quote the scanned tree.

## Suppressions

Use ASH suppressions (`rule_id`, `path`, `line_start`, `line_end`) to tune findings. Package-scoped and symbol-scoped suppressions do not apply.

## Offline and air-gapped use

Analysis makes no network call (`--no-download`) once the query packs are installed. Install a CodeQL bundle on the machine that runs the scan.

## License

The plugin code is Apache-2.0. CodeQL is licensed separately under the terms quoted at the top of this page, and you accept them when you install it. See [third-party licenses](../../../how-to/run-in-a-container.md#third-party-licenses) for what the ASH image does ship.
