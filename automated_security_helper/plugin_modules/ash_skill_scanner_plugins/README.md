# ASH skill-scanner Plugin

[skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (from Cisco AI Defense) checks AI agent
skills: directories that hold a `SKILL.md`, with the scripts and files beside it. It reports prompt-injection
wording, risky bundled code and manifest problems. This plugin wraps it.

## The package is `cisco-ai-skill-scanner`

Cisco publishes the tool on PyPI as `cisco-ai-skill-scanner`. The bare PyPI name with no `cisco-ai-` prefix is a
different, unrelated project. The tool's executable is named like that bare name, which is how the wrong package
gets installed. This plugin installs `cisco-ai-skill-scanner==2.3.2` and no other, and a test keeps install text
that names the bare package out of the plugin.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is
unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_skill_scanner_plugins
```

With the module listed, `skill_scanner` runs by default. `scanners.skill_scanner.enabled: false` turns it off
again.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_skill_scanner_plugins]" --tool skill_scanner
```

Without ASH, the equivalent is `uv tool install --python '>=3.11,<3.15' 'cisco-ai-skill-scanner==2.3.2'`.

## What it runs

`skill-scanner scan-all --recursive --format=sarif --output-sarif=<file> -- <target>`. A tree with no
`SKILL.md` is skipped (SKIPPED, not PASSED) without starting the tool.

Only the static analyzers run. ASH passes none of the flags that call a model (`--use-llm`), a service
(`--use-virustotal`, `--use-aidefense`, `--use-osv`) or read a file or pack you name (`--policy`,
`--custom-rules`, `--rule-packs`). Scanning needs no network; only installing the tool does.

## Configuration

```yaml
scanners:
  skill_scanner:
    enabled: true          # once the module is listed; false turns it off
    options:
      scan_timeout: 1800   # seconds
      tool_version: null   # default "==2.3.2"
      install_timeout: 300
```

## Severity

The tool rates each finding CRITICAL, HIGH, MEDIUM, LOW or INFO. ASH keeps those five. SARIF levels follow the
tool's own table: CRITICAL and HIGH are `error`, MEDIUM is `warning`, LOW and INFO are `note`.

## Exit status

The tool exits 0 whether or not it found anything, and 1 for a usage or input error. ASH accepts only 0.
