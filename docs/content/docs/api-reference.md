# Python API Reference

## Scan Execution

::: automated_security_helper.interactions.run_ash_scan
    options:
      show_root_heading: true
      members_order: source

## Data Models

::: automated_security_helper.models.core
    options:
      show_root_heading: true
      members_order: source

## Configuration Models

::: automated_security_helper.config.ash_config.ScannerConfigSegment
    options:
      show_root_heading: true
      members_order: source
      show_bases: false

::: automated_security_helper.config.ash_config.ReporterConfigSegment
    options:
      show_root_heading: true
      members_order: source
      show_bases: false

## Scanner Plugins

::: automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner.BanditScanner
    options:
      show_root_heading: true
      members: [scan]
      show_bases: false

::: automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner.CheckovScanner
    options:
      show_root_heading: true
      members: [scan]
      show_bases: false

::: automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner.SemgrepScanner
    options:
      show_root_heading: true
      members: [scan]
      show_bases: false

## Reporter Plugins

::: automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter.SarifReporter
    options:
      show_root_heading: true
      members: [report]
      show_bases: false

::: automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter.HtmlReporter
    options:
      show_root_heading: true
      members: [report]
      show_bases: false

::: automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter.GitLabCycloneDXReporter
    options:
      show_root_heading: true
      members: [report]
      show_bases: false
