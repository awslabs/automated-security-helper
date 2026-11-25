# ASH CodeQL Plugin

> **License terms gate.** The CodeQL CLI is not open-source software. Its terms allow analysis of an open-source codebase, and allow generating a CodeQL database "for or during automated analysis, CI, or CD" only for an open-source codebase hosted and maintained on GitHub.com. They bar generating a database in any other automated or CI/CD context and bar use "in connection with any codebase that is not an Open Source Codebase (e.g., code in a private repo in GitHub)". Those limits do not apply under a paid GitHub Advanced Security license. Whether a run is permitted is yours to decide. This scanner is **off by default**, does not start CodeQL until you set `license_terms_acknowledged: true`, and ASH neither installs nor redistributes the CLI.

[CodeQL](https://codeql.github.com) is a semantic code analysis engine. This plugin builds one database per configured language and runs the language's standard code scanning query suite over it, with `--build-mode=none`, so the scanned tree's own build scripts are never run.

## Enabling

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_codeql_plugins

scanners:
  codeql:
    enabled: true
    options:
      license_terms_acknowledged: true
      languages: [python, javascript]
```

## Installing

ASH does not install CodeQL. Download the CLI (or a CodeQL bundle, which includes the query packs) from https://github.com/github/codeql-cli-binaries after reading its terms, and put `codeql` on `PATH`. Analysis runs with `--no-download`, so the standard query packs (`codeql/<language>-queries`) must already be present: use a bundle, or run `codeql pack download` yourself.

## Configuration

```yaml
scanners:
  codeql:
    enabled: true
    options:
      license_terms_acknowledged: true
      languages: [python]       # python, javascript-typescript, java-kotlin, csharp, c-cpp, ruby, rust
      threads: 1                # CodeQL --threads for both steps (0: one per core)
      scan_timeout: 1800        # one budget for every CodeQL process of the scan
```

Go, Swift and Kotlin need a build to make a database and are refused (without a build, `java-kotlin` extracts Java only).

## Severity

The rule's `security-severity` score decides: 9.0 and over CRITICAL, 7.0 to 8.9 HIGH, 4.0 to 6.9 MEDIUM, 0.1 to 3.9 LOW. Without a score, `problem.severity` decides (error HIGH, warning MEDIUM, recommendation LOW), then the result's level. The SARIF level is rewritten to agree.

## Documentation

See https://awslabs.github.io/automated-security-helper/docs/plugins/community/codeql-plugin/
