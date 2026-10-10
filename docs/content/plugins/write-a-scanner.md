# Write a scanner plugin

This page builds `ruff-security`, a scanner plugin that runs [ruff](https://docs.astral.sh/ruff/)'s security rules (the `S` rules, ported from flake8-bandit) and gives ASH the SARIF file ruff writes. The same pattern fits any command-line tool that can write SARIF.

Before you start, you need:

- ASH installed ([Install ASH](../how-to/install.md));
- `ruff` on your `PATH` (`ruff --version` prints a version);
- a directory for the plugin package outside the repositories you scan. This page uses `~/ash-plugins`.

[Plugins](index.md) explains how ASH loads plugin packages and what a loaded plugin can do.

## 1. Write the plugin

Save this as `~/ash-plugins/acme_ash_plugins/__init__.py`:

```python
from typing import Literal

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class RuffSecurityOptions(ScannerOptionsBase):
    select: str = "S"


class RuffSecurityConfig(ScannerPluginConfigBase):
    name: Literal["ruff-security"] = "ruff-security"
    enabled: bool = True
    options: RuffSecurityOptions = RuffSecurityOptions()


@ash_scanner_plugin
class RuffSecurityScanner(ScannerPluginBase[RuffSecurityConfig]):
    command: str = "ruff"
    tool_type: ScannerToolType = ScannerToolType.SAST

    def model_post_init(self, context):
        if self.config is None:
            self.config = RuffSecurityConfig()
        super().model_post_init(context)

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_file = self.results_dir / target_type / "ruff.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        args = [
            self.command,
            "check",
            "--isolated",
            "--no-cache",
            "--select",
            self.config.options.select,
            "--output-format",
            "sarif",
            "--output-file",
            results_file.as_posix(),
        ]
        output_dir = self._output_dir_inside(target)
        if output_dir is not None:
            args += ["--extend-exclude", (target / output_dir).as_posix()]
        args.append(target.as_posix())
        return args, results_file, None


ASH_SCANNERS = [RuffSecurityScanner]
```

## 2. Check that ASH finds it

Put the package's parent directory on Python's import path, then list the plugins with the module loaded:

<!-- doctest: illustrative reason="needs the plugin package saved in step 1" -->
```bash
export PYTHONPATH="$HOME/ash-plugins"
ash plugin list --ash-plugin-modules acme_ash_plugins
```

The scanners table has a row for the plugin:

```text
│ ruff-security  │ True    │ RuffSecuritySc… │ acme_ash_plugi… │               │
```

## 3. Scan with it

From the repository you want to scan:

<!-- doctest: illustrative reason="needs the plugin package saved in step 1" -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners ruff-security
```

ASH runs ruff, reads its SARIF, and adds a row to the summary. In a repository with a hardcoded password and a `subprocess` call with `shell=True`, ruff reports both, the scanner is FAILED, and the scan exits with code 2:

```text
┃ Scanner        ┃ S ┃ C ┃ H ┃ M ┃ L ┃ I ┃ Time ┃ Action ┃ Result  ┃ Thresh  ┃
│ ruff-security  │ 0 │ 2 │ 0 │ 0 │ 0 │ 0 │ 46ms │ 2      │ FAILED  │ MED (g) │
```

The findings are in every report under `.ash/ash_output/reports/`, and ruff's own SARIF file is in `.ash/ash_output/scanners/ruff-security/source/`. [Read the results](../how-to/read-results.md) explains the output directory.

To load the plugin on every scan instead of passing the option, add it to an ASH config file. A repository's own config may name it only while the package is installed outside every git checkout and the scanned directory, as `~/ash-plugins` is unless your home directory is itself a git checkout:

<!-- doctest: config kind=other reason="configures the example plugin, which the docs environment does not install" -->
```yaml
project_name: my-service
ash_plugin_modules: [acme_ash_plugins]
scanners:
  ruff-security:
    options:
      select: "S,B"
```

## How ASH runs a scanner

Before the scan, ASH checks that `command` is on `PATH`, and refuses a copy inside the scanned tree unless the operator passed `--allow-in-tree-tools`. If the tool is not found, the scanner is MISSING, which fails the scan unless incomplete scans are allowed ([Set the gate](../how-to/set-the-gate.md)).

ASH then calls `_execute_scan(target, target_type, global_ignore_paths)` once with the source directory (`target_type` is `source`) and, if converters produced files, once more with the directory that holds them (`converted`). Your method returns three things: the command line, the path of the SARIF file the tool will write, and the environment for the tool (`None` to inherit ASH's). For each call, ASH:

1. runs the command in the source directory, with the scanner's `scan_timeout` (default 1800 seconds), and inside the scanner sandbox when one is enabled;
2. reads the SARIF file. A missing file, or one that is not JSON, makes the scanner ERROR. A JSON file that is not valid SARIF is logged as a warning and the scanner is recorded as PASSED with no findings, so check that your tool writes SARIF. The tool's exit code does not decide the outcome: it is recorded in the SARIF invocation, as successful when it is in `success_exit_codes` (0 and 1 by default);
3. adds the command line and timing to the SARIF, makes paths relative to the source directory, applies `ignore_paths` and suppressions, and merges the results into the aggregated SARIF.

A scanner with findings at or above its threshold is FAILED; one without is PASSED.

Run the tool only by returning its command from `_execute_scan`. A process you start with `subprocess` yourself gets none of this: ASH does not check where its program is, does not time it out and does not sandbox it.

## Parts of the plugin

- The config class. `name` is the scanner's name: the key under `scanners` in an ASH config, the value `--scanners` takes, and the directory under `.ash/ash_output/scanners/`. Options go in a subclass of `ScannerOptionsBase`, which already has `severity_threshold` and `scan_timeout`. Option models accept unknown keys without complaint, so a misspelled option in a config is silently ignored.
- `model_post_init`. ASH constructs the scanner with no config when the ASH config has no section for it, and the base class refuses an empty config, so set the default before calling `super()`.
- `command` and `tool_type`. `command` is the program the default dependency check looks for; `tool_type` labels the findings (SAST, SCA, SECRETS, IAC and others).
- `self.results_dir`. A directory for this scanner's files, `.ash/ash_output/scanners/<name>/`; write the tool's output under it, one subdirectory per `target_type`.
- `self._output_dir_inside(target)`. ASH writes its output under the source directory by default. A tool that walks the whole directory would read ASH's earlier reports and converted files, so pass this path to the tool's exclude option.
- `ruff check --isolated`. ruff, like many tools, reads its configuration from files in the repository it checks, which would let the repository turn off the rules you selected. Pass the tool's option for ignoring those files. If your plugin takes an option that names a file the tool reads as configuration, use `operator_path` from `automated_security_helper.utils.config_trust`, the check ASH's own scanners use, which accepts the value only when the operator set it and the file is outside the scanned tree.
- The module-level list. The decorator registers the class for scans, and `ash plugin list` shows the classes in this list.

## Set the severity

ASH takes a finding's severity from, in order: the result's `properties.issue_severity` (CRITICAL, HIGH, MEDIUM, LOW or INFO); the `security-severity` score in its rule's properties; or its SARIF level, where `error` counts as critical, `warning` as medium and `note` as low. ruff marks every result `error`, so both findings above count as critical. To report them as HIGH, add this method to `RuffSecurityScanner` and import `PropertyBag` at the top of the module:

```python
from automated_security_helper.schemas.sarif_schema_model import PropertyBag


def _post_process_sarif(self, sarif_report, final_args, target):
    for run in sarif_report.runs:
        for result in run.results or []:
            if result.properties is None:
                result.properties = PropertyBag()
            result.properties.issue_severity = "HIGH"
    return sarif_report
```

ASH calls `_post_process_sarif` after reading the SARIF file. The other hooks you can override are `_process_config_options` (turn options into arguments before the scan), `_read_results_file` (parse a file that is not SARIF JSON) and `validate_plugin_dependencies` (a different availability check; call `super()` from it to keep the in-tree tool refusal and its MISSING reason).

## A scanner with no external tool

A scanner that does its work in Python overrides `scan()` instead of `_execute_scan()`, and must still define `_execute_scan`, which is abstract, as a stub that raises `NotImplementedError`. `scan()` must return a `SarifReport` (from `automated_security_helper.schemas.sarif_schema_model`) for its findings to reach the reports. Return `False` if the scanner cannot run, which reports it MISSING. Any other return value, including a dictionary of findings, is recorded as PASSED with no findings, so do not catch an exception and return something else: let it propagate, and ASH reports the scanner as ERROR. Read files from the scan set with `open_in_scanned_tree` from `automated_security_helper.utils.scanned_tree`, which refuses links and paths outside the source directory.
