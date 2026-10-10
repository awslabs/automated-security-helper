# Write a reporter plugin

This page builds `findings-list`, a reporter plugin that writes `ash.findings.txt`: the number of actionable findings, then one line per finding with its scanner, rule and location. A reporter receives the aggregated results after every scanner has run and returns the text of its report; ASH writes the file.

Before you start, you need ASH installed ([Install ASH](../how-to/install.md)) and a directory for the plugin package outside the repositories you scan. This page uses `~/ash-plugins`. [Plugins](index.md) explains how ASH loads plugin packages and what a loaded plugin can do.

## 1. Write the plugin

Save this as `~/ash-plugins/acme_ash_plugins/__init__.py`:

```python
from typing import Literal

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class FindingsListOptions(ReporterOptionsBase):
    include_suppressed: bool = False


class FindingsListConfig(ReporterPluginConfigBase):
    name: Literal["findings-list"] = "findings-list"
    extension: str = "findings.txt"
    enabled: bool = True
    options: FindingsListOptions = FindingsListOptions()


@ash_reporter_plugin
class FindingsListReporter(ReporterPluginBase[FindingsListConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = FindingsListConfig()
        super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> str:
        stats = model.metadata.summary_stats
        lines = [f"{stats.actionable} actionable, {stats.total} total"]
        for finding in model.to_flat_vulnerabilities():
            if finding.is_suppressed and not self.config.options.include_suppressed:
                continue
            lines.append(
                f"{finding.scanner}\t{finding.rule_id}\t"
                f"{finding.file_path}:{finding.line_start}"
            )
        return "\n".join(lines) + "\n"


ASH_REPORTERS = [FindingsListReporter]
```

## 2. Check that ASH finds it

<!-- doctest: illustrative reason="needs the plugin package saved in step 1" -->
```bash
export PYTHONPATH="$HOME/ash-plugins"
ash plugin list --ash-plugin-modules acme_ash_plugins
```

The reporters table has a row for the plugin:

```text
│ findings-list   │ True    │ FindingsListRe… │ acme_ash_plug… │               │
```

## 3. Scan with it

A loaded reporter runs in every scan, beside the built-in ones. This scan uses only detect-secrets, which needs no download:

<!-- doctest: illustrative reason="needs the plugin package saved in step 1" -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners detect-secrets --offline
cat .ash/ash_output/reports/ash.findings.txt
```

In a repository with one hardcoded password, the scan exits with code 2 and the report reads:

```text
1 actionable, 1 total
detect-secrets	SECRET-SECRET-KEYWORD	app.py:3
```

To render the report again from the last scan's results without scanning, use `ash report`, which takes the module through a config override:

<!-- doctest: illustrative reason="needs the plugin package saved in step 1" -->
```bash
ash report --format findings-list --config-overrides 'ash_plugin_modules+=[acme_ash_plugins]'
```

`ash scan --output-formats` cannot select this reporter: it accepts only the built-in format names, and when you pass it, only the reporters it names run. The reporter's options go under `reporters.findings-list` in an ASH config, where `enabled: false` leaves it out of a scan:

<!-- doctest: config kind=other reason="configures the example plugin, which the docs environment does not install" -->
```yaml
project_name: my-service
ash_plugin_modules: [acme_ash_plugins]
reporters:
  findings-list:
    enabled: true
    options:
      include_suppressed: true
```

## What ASH does with the return value

ASH calls `report(model)` once per scan, in the report phase, and handles what it returns:

| `report()` | Result |
|---|---|
| returns a non-empty string | ASH writes it to `.ash/ash_output/reports/ash.<extension>`, replacing any file there |
| returns `None` | an error is logged and no file is written |
| returns an empty string | a warning is logged and no file is written |
| raises an exception | the error is logged and the other reporters still run |

None of these changes the scan's exit code, which is decided by the findings and by whether the scan was complete.

Set `extension` in the config class. It is the end of the file name, so it must be a plain suffix such as `findings.txt`: a value with `/`, `\` or `..`, from any config, is replaced by the default with a warning, and a reporter with no extension writes `ash.None`. To write a second file beside the report, call `write_report_file(report_dir, filename, content)` from `automated_security_helper.base.reporter_plugin` with `report_dir` set to `Path(self.context.output_dir) / "reports"`. It writes only inside that directory and does not follow a symbolic link at the file name.

## Read the results model

`model` is an `AshAggregatedResults`, the same data as `.ash/ash_output/ash_aggregated_results.json` ([Output files](../reference/output-files.md)). The parts a reporter usually needs:

- `model.metadata.summary_stats`: `actionable`, `total` (findings not suppressed), and `severity_counts` with `critical`, `high`, `medium`, `low`, `info` and `suppressed`;
- `model.to_flat_vulnerabilities()`: one flat record per finding, with `scanner`, `rule_id`, `severity`, `file_path`, `line_start`, `line_end`, `description` and `is_suppressed`. The flat `severity` can differ from the severity the summary and the gate use: a SARIF result at level `error` with no `issue_severity` counts as critical in the summary but appears as HIGH here;
- `model.sarif`: the aggregated SARIF, one run with every scanner's results;
- `model.scanner_results`: the outcome of each scanner, with `status` (PASSED, FAILED, MISSING, SKIPPED or ERROR) and `finding_count`.

## A reporter that sends findings somewhere

ASH keeps the destination and credential options of its own AWS reporters to the operator ([trust model](../concepts/trust-model.md#what-each-tier-may-set)). It does not know which options of a third-party reporter are destinations, so a repository's own config can set any option of yours. If your reporter sends results to a URL, bucket or account, take that destination from an environment variable, or check where the option came from with `set_by_operator` from `automated_security_helper.utils.config_trust`:

```python
from automated_security_helper.utils.config_trust import set_by_operator


def endpoint_from_operator(reporter, endpoint):
    key = f"reporters.{reporter.config.name}.options.endpoint"
    return endpoint if set_by_operator(reporter.context.config, key, endpoint) else None
```

`set_by_operator` returns false for a value that a config file inside a git checkout or the scanned directory, or one an MCP client delivered, set and your own sources (`--config-overrides`, a config file outside every checkout) would not have. With the function above, a repository that names an endpoint in its `.ash/.ash.yaml` gets `None`, while the same option passed with `--config-overrides` is used. A reporter that makes network calls also runs in the ASH process, outside the scanner sandbox, so it can reach any host ASH can.

## Workspace scans

In a workspace scan (`ash scan --workspace`), ASH asks each reporter what to do with several projects through its `workspace_behaviour` class variable. The default, `ReporterWorkspaceBehaviour.PER_PROJECT`, writes the report once per project, under each project's own output directory, and no workspace-level file. Set `MERGED` only if your reporter handles results with one SARIF run per project. [Scale to large repositories](../how-to/scale-large-repos.md) covers workspace scans.
