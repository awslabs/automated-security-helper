# ASH SkillSpector Plugin

[SkillSpector](https://github.com/NVIDIA/SkillSpector) (NVIDIA) scans AI agent skills, directories
that hold a `SKILL.md`, for prompt injection, hidden instructions, remote script fetching and
similar problems, with pattern and YARA rules that ship in its package. ASH runs it in static
mode (`--no-llm`): nothing is sent to a language-model provider and the scan needs no network.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_skillspector_plugins
```

or, for one run:

<!-- doctest: illustrative reason="runs a full ash scan of the current directory" -->
```bash
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_skillspector_plugins
```

With the module listed, `skillspector` runs by default. `scanners.skillspector.enabled: false` turns it off again. No account or API key is needed.

## Installing the tool

<!-- doctest: illustrative reason="downloads and installs the scanner's tool" -->
```bash
ash dependencies install --config-overrides "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_skillspector_plugins]" --tool skillspector
```

This runs `uv tool install skillspector==2.13.7`. Windows is not supported (SkillSpector cannot write
its report to a file there).

## What is scanned

One `skillspector scan` per skill directory: the top-most directory holding `SKILL.md` or `skill.md`
in the scan set. A tree with no skill is skipped. A skill SkillSpector could not inspect completely
fails the run instead of reading as clean.

## Configuration

```yaml
scanners:
  skillspector:
    enabled: true                # once the module is listed; false turns it off
    options:
      scan_timeout: 1800         # seconds per skill
      tool_version: null         # default "==2.13.7"
      install_timeout: 300
```

There is no option that points at a file. ASH never passes SkillSpector's `--baseline`,
`--use-shipped-baseline` or `--yara-rules-dir`, so a skill cannot suppress its own findings.
