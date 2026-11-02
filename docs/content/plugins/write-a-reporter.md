# Write a reporter plugin

This page builds `findings-list`, a reporter plugin that writes `ash.findings.txt`: the number of actionable findings, then one line per finding with its scanner, rule, and location. A reporter receives the aggregated results after every scanner has run and returns the text of its report; ASH writes the file.

Prerequisites:

- ASH installed ([Install ASH](../how-to/install.md));
- a repository to scan, with your shell in its top directory. To keep the steps short, this page saves the plugin package in an `ash-plugins` directory there; a plugin you keep belongs outside the repositories you scan ([Package a third-party plugin](index.md#package-a-third-party-plugin)).

[Plugins](index.md) explains how ASH loads plugin packages and what a loaded plugin can do.

## 1. Write the plugin

Save this as `ash-plugins/acme_ash_plugins/__init__.py`:

<!-- doctest: save-as=ash-plugins/acme_ash_plugins/__init__.py -->
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

```bash
export PYTHONPATH="$PWD/ash-plugins"
ash plugin list --ash-plugin-modules acme_ash_plugins
```

The reporters table has a row for the plugin:

<!-- doctest: output -->
```text
│ findings-list   │ True    │ FindingsListRe… │ acme_ash_plug… │               │
```

## 3. Scan with it

A loaded reporter runs in every scan, beside the built-in ones. This scan uses only detect-secrets, which needs no download:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners detect-secrets --offline
```

In a repository with one hardcoded password, the scan exits with code 2. Read the report:

```bash
cat .ash/ash_output/reports/ash.findings.txt
```

It reads:

<!-- doctest: output -->
```text
1 actionable, 1 total
detect-secrets	SECRET-SECRET-KEYWORD	app.py:3
```

To see the report again from the last scan's results without scanning, use `ash report`, which takes the module through a config override. It prints the report to the terminal and writes no file:

```bash
ash report --format findings-list --config-overrides 'ash_plugin_modules+=[acme_ash_plugins]'
```

`ash scan --output-formats` and the `output_formats` config key cannot select this reporter: they accept only the names of the reporters that ship with ASH, and when either names any, only the reporters it names run. `--output-formats` refuses the name of another reporter as a usage error, with exit code 5, and the config key refuses it as an invalid configuration, with exit code 3:

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners detect-secrets --offline \
  --output-formats findings-list
```

The reporter's options go under its name, `findings-list`, in the `reporters` section of an ASH config, where `enabled: false` leaves it out of a scan:

<!-- doctest: config kind=ash -->
```yaml
project_name: my-service
ash_plugin_modules: [acme_ash_plugins]
reporters:
  findings-list:
    enabled: true
    options:
      include_suppressed: true
```

ASH checks that section with `FindingsListOptions` once it has loaded the module, before anything is scanned: an option the class does not declare, or a value of the wrong type, refuses the configuration with exit code 3, as for a scanner plugin ([Write a scanner plugin](write-a-scanner.md#3-scan-with-it)).

## What ASH does with the return value

ASH calls `report(model)` once per scan, in the report phase, and handles what it returns:

| `report()` | Result |
|---|---|
| returns a non-empty string | ASH writes it to `.ash/ash_output/reports/ash.<extension>`, replacing any file there |
| returns `None` | an error is logged and no file is written |
| returns an empty string | a warning is logged and no file is written |
| raises an exception | the error is logged and the other reporters still run |

None of these changes the scan's exit code, which is decided by the findings and by whether the scan was complete.

Set `extension` in the config class. It is the end of the file name, so it must be a plain suffix such as `findings.txt`: a value with `/`, `\`, `:`, `..`, or a NUL character, from any config, is replaced by the default with a warning, and a reporter with no extension writes `ash.txt`. The colon is refused on every platform because on NTFS `ash.json:stream` names an alternate data stream of `ash.json`, another reporter's file. To write a second file beside the report, call `write_report_file(report_dir, filename, content)` from `automated_security_helper.base.reporter_plugin` with `report_dir` set to `Path(self.context.output_dir) / "reports"`, and declare the name in `companion_file_names` so that ASH checks it before any reporter writes. It writes only inside that directory, under the same file-name rule as the report itself: a name that is not a single file name there is logged as a warning and the function returns `None`. A symbolic link at the file name, or a `reports/` directory that is itself a symbolic link or a Windows directory junction, is refused and the refusal raised (`OutputLinkRefused` for a symbolic link, `OutputDirLinkRefused` for a junction), as for any other output file ([Links are refused](../reference/output-files.md#links)); nothing is written through the link.

## Read the results model

`model` is an `AshAggregatedResults`, the same data as `.ash/ash_output/ash_aggregated_results.json` ([Output files](../reference/output-files.md)). The parts a reporter usually needs:

- `model.metadata.summary_stats`: `actionable`, `total` (findings not suppressed), and `severity_counts` with `critical`, `high`, `medium`, `low`, `info`, and `suppressed`;
- `model.to_flat_vulnerabilities()`: one flat record per finding, with `scanner`, `rule_id`, `severity`, `file_path`, `line_start`, `line_end`, `description`, and `is_suppressed`. The flat `severity` is the severity the summary and the gate use ([Set the severity](write-a-scanner.md#set-the-severity));
- `model.sarif`: the aggregated SARIF, one run with every scanner's results;
- `model.scanner_results`: the outcome of each scanner, with `status` (PASSED, FAILED, MISSING, SKIPPED, or ERROR) and `finding_count`.

## Test the reporter

A reporter is a class, so a test can build it, give it a results model, and check the text it returns. This test builds `FindingsListReporter` and gives it a model with no findings, so the report is the header line alone. The package from step 1 is not installed, so the test imports it by name. Run `pytest` with `PYTHONPATH` set as in step 2:

```python
import importlib
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults


def test_findings_list_reporter():
    plugin = importlib.import_module("acme_ash_plugins")
    context = PluginContext(source_dir=Path("."), output_dir=Path("out"))
    reporter = plugin.FindingsListReporter(context=context)

    report = reporter.report(AshAggregatedResults())

    assert report == "0 actionable, 0 total\n"
```

## A reporter that sends findings somewhere

The plugin from step 1 writes a local report. A reporter can also send the results elsewhere. This one uploads them to an S3 bucket and returns the object's `s3://` URL, which ASH writes as the report. Its region, profile, and bucket default to values from the environment of the process that runs ASH, and `validate_plugin_dependencies()` checks that it can reach the bucket before the scan uses it. Add it to the package from step 1, and list `FindingsBucketReporter` in the reporter list of `__init__.py` beside `FindingsListReporter`:

```python
import json
import logging
import os
from datetime import datetime, timezone
from typing import ClassVar, Literal, Optional, Tuple

import boto3

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER


class FindingsBucketOptions(ReporterOptionsBase):
    aws_region: Optional[str] = os.environ.get("AWS_REGION")
    aws_profile: Optional[str] = os.environ.get("AWS_PROFILE")
    bucket_name: Optional[str] = os.environ.get("ACME_FINDINGS_BUCKET")
    key_prefix: str = "ash-reports/"


class FindingsBucketConfig(ReporterPluginConfigBase):
    name: Literal["findings-bucket"] = "findings-bucket"
    extension: str = "bucket.txt"
    enabled: bool = False
    options: FindingsBucketOptions = FindingsBucketOptions()


@ash_reporter_plugin
class FindingsBucketReporter(ReporterPluginBase[FindingsBucketConfig]):
    destination_options: ClassVar[Tuple[str, ...]] = (
        "aws_region",
        "aws_profile",
        "bucket_name",
        "key_prefix",
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = FindingsBucketConfig()
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        options = self.config.options
        self.dependencies_satisfied = False
        if options.aws_region is None or options.bucket_name is None:
            return self.dependencies_satisfied
        try:
            session = boto3.Session(
                profile_name=options.aws_profile, region_name=options.aws_region
            )
            caller = session.client("sts").get_caller_identity()
            session.client("s3").head_bucket(Bucket=options.bucket_name)
            self.dependencies_satisfied = "Account" in caller
        except Exception as error:
            self._plugin_log(
                f"Cannot reach the bucket {options.bucket_name}: {error}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )
        return self.dependencies_satisfied

    def report(self, model: AshAggregatedResults) -> str | None:
        options = self.config.options
        stamp = model.metadata.generated_at or datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
        key = f"{options.key_prefix}ash-report-{stamp}.json"
        body = json.dumps(model.to_simple_dict(), default=str, indent=2)
        try:
            session = boto3.Session(
                profile_name=options.aws_profile, region_name=options.aws_region
            )
            session.client("s3").put_object(
                Bucket=options.bucket_name,
                Key=key,
                Body=body,
                ContentType="application/json",
            )
        except Exception as error:
            self._plugin_log(
                f"Error uploading to S3: {error}",
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            return None
        url = f"s3://{options.bucket_name}/{key}"
        ASH_LOGGER.info(f"Uploaded the report to {url}")
        return url
```

`validate_plugin_dependencies()` returns `False` when the region or bucket is missing, or when an AWS call fails, and ASH skips the reporter. `report()` returns `None` when the upload fails, so ASH logs an error and writes no file ([What ASH does with the return value](#what-ash-does-with-the-return-value)). Each failure is also logged with `_plugin_log`, which takes a number from `logging` as its level, such as `logging.ERROR`. A string such as `"ERROR"` raises `TypeError`.

## Declare the destination options

A reporter that sends findings somewhere, or writes them to a path its options name, declares those options in `destination_options`, as `FindingsBucketReporter` does. List every option that chooses where findings are sent or written, or which credentials send them: an endpoint, a region, an account, a bucket, a profile, a token, an output path. Name each as its field in the options model. An alias of the field is covered as well. The default is `()`.

When the config was built from a file inside the scanned tree (a discovered `.ash/.ash.yaml`, a `--config` inside the tree, an `extends` base, or `ASH_CONFIG`), or from a file an MCP client delivered, ASH takes these options from the trusted base instead: the defaults, an operator config outside the tree, and `--config-overrides`. A value such a file set is replaced, under any spelling of the reporter's section that ASH reads as this reporter's, and one warning names each option it ignored. The reporter's other options still apply from the file. ASH does this once it has imported your plugin module and before it builds any reporter, in a scan and in `ash report`. The built-in AWS reporters declare theirs the same way ([Configuration trust model](../concepts/trust-model.md#what-each-tier-may-set)).

A reporter that declares any destination option sends findings somewhere, so whether it runs is the operator's choice too, in both directions. Its `enabled` comes from the trusted base, or from the default of your config model's `enabled` when the trusted base sets none: such a file's `enabled: true` or `enabled: false` is replaced with a warning where it differs, and leaving the section out leaves the reporter as the trusted base has it. That is why `FindingsBucketConfig` sets `enabled` to `False`. A reporter that declares no destination options writes only local files, and its `enabled` applies from the file.

Under the MCP server, a delivered file that sets a declared option is scanned with the server's value rather than refused, because the server checks the file against `denied_paths` before it imports your plugin module. To have such a file refused, add the option to the profile's [`global_settings.mcp.runtime_overrides.denied_paths`](../reference/configuration.md#global_settings.mcp.runtime_overrides.denied_paths), for example `/reporters/findings-bucket/options/bucket_name`.

## A destination that is not an option

A destination the reporter reads itself, and not from its options, has to come from a source the scanned repository cannot write, such as an environment variable of the process that runs ASH:

```python
import os


def endpoint_from_operator():
    """The endpoint the operator set for this run, or None when there is none."""
    return os.environ.get("ACME_FINDINGS_ENDPOINT") or None
```

A repository that names an endpoint in its `.ash/.ash.yaml` then changes nothing. A reporter that makes network calls also runs in the ASH process, outside the scanner sandbox, so it can reach any host ASH can.

## Workspace scans

In a workspace scan (`ash scan --workspace`), ASH asks each reporter what to do with several projects through its `workspace_behaviour` class variable. The default, `ReporterWorkspaceBehaviour.PER_PROJECT`, writes the report once per project, under each project's own output directory, and no workspace-level file. Set `MERGED` only if your reporter handles results with one SARIF run per project. [Scale to large repositories](../how-to/scale-large-repos.md) covers workspace scans.
