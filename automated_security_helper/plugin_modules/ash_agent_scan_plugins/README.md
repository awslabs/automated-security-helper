# ASH Snyk Agent Scan Plugin

[Snyk Agent Scan](https://github.com/snyk/agent-scan) (PyPI `snyk-agent-scan`, formerly
invariantlabs' `mcp-scan`) scores the AI agent skills in a repository, each a directory
holding a `SKILL.md`, for threats such as prompt injection, suspicious download URLs and
malicious code. This plugin runs `snyk-agent-scan==0.7.1` once per skill.

## What leaves the machine

`snyk-agent-scan scan` has no offline mode. It sends the skill's files (after its own
secret redaction) to Snyk's analysis API at `api.snyk.io` and prints the scores the service
returns. It needs a Snyk API token in `SNYK_TOKEN`, and Snyk's free tier has a daily usage
limit. Without the token, or offline, the scanner is reported `MISSING` and nothing is
sent. ASH offers no option that changes where the files are sent.

## Enabling

This plugin ships with ASH and is loaded only when its module is listed. An `ash scan` that
does not list it is unchanged.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_agent_scan_plugins
```

With the module listed, `agent-scan` runs by default. `scanners.agent-scan.enabled: false`
turns it off again.

## Configuration

```yaml
scanners:
  agent-scan:
    enabled: true          # once the module is listed; false turns it off
    options:
      scan_timeout: 1800   # seconds per skill
      tool_version: null   # default "==0.7.1"
```

The result parser is locked to the 0.7.1 `--json` document and refuses output it does not
recognize, so a different `tool_version` is read only if its output has the same shape.

## Notes

The module docstring of `agent_scan_scanner.py` records what was measured about the tool:
the flags ASH passes and never passes, the exit status, the result format and the severity
bands.
