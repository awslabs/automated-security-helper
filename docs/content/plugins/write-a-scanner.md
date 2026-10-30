# Write a scanner plugin

This page builds `ruff-security`, a scanner plugin that runs [ruff](https://docs.astral.sh/ruff/)'s security rules (the `S` rules, ported from flake8-bandit) and gives ASH the SARIF file ruff writes. The same pattern fits any command-line tool that can write SARIF.

Prerequisites:

- ASH installed ([Install ASH](../how-to/install.md));
- `ruff` on your `PATH` (`ruff --version` prints a version);
- a repository to scan, with your shell in its top directory. To keep the steps short, this page saves the plugin package in an `ash-plugins` directory there; a plugin you keep belongs outside the repositories you scan ([Package a third-party plugin](index.md#package-a-third-party-plugin)).

[Plugins](index.md) explains how ASH loads plugin packages and what a loaded plugin can do.

## 1. Write the plugin

Save this as `ash-plugins/acme_ash_plugins/__init__.py`:

<!-- doctest: save-as=ash-plugins/acme_ash_plugins/__init__.py -->
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
        for output_dir in self._ash_output_dirs_inside(target):
            args += ["--extend-exclude", (target / output_dir).as_posix()]
        args.append(target.as_posix())
        return args, results_file, None


ASH_SCANNERS = [RuffSecurityScanner]
```

## 2. Check that ASH finds it

Put `ash-plugins` on Python's import path, then list the plugins with the module loaded:

```bash
export PYTHONPATH="$PWD/ash-plugins"
ash plugin list --ash-plugin-modules acme_ash_plugins
```

The scanners table has a row for the plugin:

<!-- doctest: output -->
```text
│ ruff-security  │ True    │ RuffSecuritySc… │ acme_ash_plugi… │               │
```

## 3. Scan with it

In the same shell:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners ruff-security
```

ASH runs ruff, reads its SARIF, and adds a row to the summary. In a repository with a hardcoded password and a `subprocess` call with `shell=True`, ruff reports both, the scanner is FAILED, and the scan exits with code 2:

```text
┃ Scanner        ┃ S ┃ C ┃ H ┃ M ┃ L ┃ I ┃ Time ┃ Action ┃ Result  ┃ Thresh  ┃
│ ruff-security  │ 0 │ 2 │ 0 │ 0 │ 0 │ 0 │ 46ms │ 2      │ FAILED  │ MED (g) │
```

The findings are in the finding reports under `.ash/ash_output/reports/`, such as `ash.sarif`, `ash.html`, and `ash.csv`, and ruff's own SARIF file is in `.ash/ash_output/scanners/ruff-security/source/`. [Read scan results](../how-to/read-results.md) explains the output directory.

To load the plugin on every scan instead of passing the option, add it to an ASH config file. A repository's own config may name it only while the package is installed outside every git checkout and the scanned directory ([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)), which `ash-plugins` inside the repository is not; until you install it elsewhere, use this in a config file outside every git checkout, passed with `--config`:

<!-- doctest: config kind=ash -->
```yaml
project_name: my-service
ash_plugin_modules: [acme_ash_plugins]
scanners:
  ruff-security:
    options:
      select: "S,B"
```

ASH checks the options of every section a loaded plugin reads with the plugin's own options model, once it has loaded the plugins and before it converts or scans anything. An option the model does not declare, or a value of the wrong type, refuses the configuration with exit code 3, and the message names the section and the key:

<!-- doctest: run expect-exit=3 -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners ruff-security \
  --config-overrides 'scanners.ruff-security.options.selct=S,B'
```

```text
ERROR (3) Invalid configuration: Configuration validation failed: scanners.ruff-security.options
(scanner 'ruff-security'): Value error, Unknown key 'selct' (did you mean 'select'?) in these plugin
options. Accepted keys: offline, scan_timeout, select, severity_threshold.
```

`ash config validate` and `ash config lint` do not import the modules in `ash_plugin_modules`, so they cannot check these options; `ash config lint` names each section it could not check.

## How ASH runs a scanner

Before the scan, ASH looks for `command`: on `PATH`, then in ASH's bin directory (`~/.ash/bin`, or the directory `ASH_BIN_PATH` names), then in the Python environment that runs ASH (its interpreter's directory and its scripts directory), then in `/usr/local/bin`, except on Windows. It refuses a copy inside the scanned tree unless the operator passed `--allow-in-tree-tools`. If the tool is not found, the scanner is MISSING, which fails the scan unless incomplete scans are allowed ([Set the gate](../how-to/set-the-gate.md)). A scanner that picks its own inputs out of the scan set, as cfn-nag picks CloudFormation templates, can override `nothing_to_scan_reason()` to return why it has nothing to scan in this run, from the same selection its scan makes; with a reason, a scanner whose tool is not found is SKIPPED instead of MISSING. The default, `None`, keeps MISSING.

ASH then calls `_execute_scan(target, target_type, global_ignore_paths)` once with the source directory (`target_type` is `source`) and, if converters produced files, once more with the directory that holds them (`converted`). Your method returns three things: the command line, the path of the SARIF file the tool will write, and the environment for the tool (`None` to inherit ASH's). For each call, ASH:

1. runs the command in the source directory, with the scanner's `scan_timeout` (default 1800 seconds), and inside the scanner sandbox when one is enabled;
2. reads the SARIF file. A missing file, or one with content that is not JSON, makes the scanner ERROR. An empty file is read as a report with no findings, and the scanner is PASSED, with a warning, whatever the tool's exit code, so do not let the tool create its output file before it has results. A JSON file that is not valid SARIF is logged as a warning, and the scanner is also recorded as PASSED with no findings, so check that your tool writes SARIF. The tool's exit code does not decide the outcome: it is recorded in the SARIF invocation, as successful when it is in `success_exit_codes` (0 and 1 by default);
3. adds the command line and timing to the SARIF, makes paths relative to the source directory, drops the results located in ASH's output directories (apart from the converted files and the files git tracks there), applies `ignore_paths` and suppressions, and merges the results into the aggregated SARIF.

A scanner with findings at or above its threshold is FAILED; one without is PASSED.

Run the tool only by returning its command from `_execute_scan`. A process you start with `subprocess` yourself gets none of this: ASH does not check where its program is, does not time it out, and does not sandbox it.

## Parts of the plugin

| Part | What it does |
|---|---|
| The config class | `name` is the scanner's name: the key under `scanners` in an ASH config, the value `--scanners` takes, and the directory under `.ash/ash_output/scanners/`. Options go in a subclass of `ScannerOptionsBase`, which already has `severity_threshold`, `scan_timeout`, and `offline`. An option the model does not declare refuses the configuration ([above](#3-scan-with-it)). |
| `model_post_init` | ASH constructs the scanner with no config when the ASH config has no section for it, and the base class refuses an empty config, so set the default before calling `super()`. |
| `command` and `tool_type` | `command` is the program the default dependency check looks for; `tool_type` labels the findings (SAST, SCA, SECRETS, IAC, and others). |
| `self.results_dir` | A directory for this scanner's files, `.ash/ash_output/scanners/<name>/`. Write the tool's output under it, one subdirectory per `target_type`. |
| `self._ash_output_dirs_inside(target)` | ASH writes its output under the source directory by default. ASH leaves its own files there out of the scan set and drops the results a scanner reports in them, but a tool that walks the whole directory still reads ASH's earlier reports and converted files, so pass each of these paths to the tool's exclude option. They are ASH's output directories inside `target`, relative to it: this run's output directory and an earlier run's `.ash/ash_output`, less those that hold files git tracks, which ASH scans. The list is empty for the converted target. |
| `ruff check --isolated` | ruff, like many tools, reads its configuration from files in the repository it checks, which would let the repository turn off the rules you selected, so pass the tool's option for ignoring those files. If your plugin takes an option that names a file the tool reads as configuration, use `operator_path` from `automated_security_helper.utils.config_trust`, the check ASH's own scanners use, which accepts the value only when the operator set it and the file is outside the scanned tree. |
| The module-level list | Optional. The decorator registers the class, and `ash plugin list` shows every registered plugin, listed or not. |

## Declare what the scanner needs under the sandbox

Under `--sandbox`, a scanner gets the strictest policy unless it declares more: no network, no extra read paths, and no environment beyond the sandbox's allowlist ([Scanner sandbox](../concepts/sandbox.md)). `ruff-security` needs nothing more, so it declares nothing. A scanner whose tool downloads a rule pack into a cache would add a `sandbox_requirements` class attribute, or a property when the need depends on the scanner's options:

```python
from typing import ClassVar

from automated_security_helper.utils.sandbox.policy import SandboxRequirements

sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
    network=True,
    cache_paths=("~/.cache/acme-rules",),
    cache_env=("ACME_CACHE_DIR",),
    env_prefixes=("ACME_",),
)
```

`network` asks for a network on online scans, `read_paths` for read-only host paths, and `cache_paths` for cache directories the tool keeps. Those are writable through a throwaway overlay under bwrap, where bwrap and the kernel support one, and read-only everywhere else, so a tool that has to write its cache also needs `cache_env`: variables that move the cache, which ASH points at a private, empty directory wherever `cache_paths` are read-only. `env_prefixes` and `env_names` are for environment variables. A variable whose name marks it as a credential passes only when `env_names` names it exactly.

If the read paths or environment variables come from the scanner's own options, which the scanned repository can write, also set `read_paths_require_grant=True` or `env_requires_grant=True`. The sandbox then mounts those paths only for a scanner named in `sandbox.read_path_scanners`, and only when a path resolves inside the source tree or an `extra_read_paths` entry and is a regular file or a directory. It passes those variables only to a scanner named in `sandbox.env_scanners`, and with `read_paths_require_grant` it never mounts the scanner's `cache_paths`. Only the operator can set those lists ([Give a scanner more access](../docs/scanner-sandbox.md#grants)).

## Declare whether the scanner is Python-only

`ash scan --python-only` runs only the scanners that need nothing but Python, and records every other scanner SKIPPED without looking for its tool. A scanner says which it is with the `python_only` class variable. `True` puts it in a `--python-only` run, `False` keeps it out, and a scanner that declares nothing (`None`) counts as Python-only only when it runs its tool through uv (`use_uv_tool`). `ruff-security` runs the `ruff` program from `PATH` and declares nothing, so a `--python-only` run leaves it out. With no other scanner selected, that scan would run no scanner and report itself clean, so ASH refuses it with exit code 5 and names the scanner it left out:

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --ash-plugin-modules acme_ash_plugins --scanners ruff-security --python-only
```

A scanner that does its work in ASH's own process, such as the one in [A scanner with no external tool](#a-scanner-with-no-external-tool), declares `True` in its class body; one that runs a binary, Node.js, or anything else that is not a Python package declares `False`:

```python
from typing import ClassVar

python_only: ClassVar[bool] = True
```

## Set the severity

ASH takes a finding's severity from, in order: the result's `properties.issue_severity` (CRITICAL, HIGH, MEDIUM, LOW, or INFO); the `security-severity` score in its rule's properties; or its SARIF level, where `error` counts as critical, `warning` as medium, `note` as low, and `none` as info. A result with no level counts as medium: SARIF's default level is `warning`. The summary counts, the gate, and the finding reports read the severity this way. ruff marks every result `error`, so both findings above count as critical. To report them as HIGH, add this method to `RuffSecurityScanner` and import `PropertyBag` at the top of the module:

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

ASH calls `_post_process_sarif` after reading the SARIF file. The other hooks you can override are `_process_config_options` (turn options into arguments before the scan), `_read_results_file` (parse a file that is not SARIF JSON), and `validate_plugin_dependencies` (a different availability check; call `super()` from it to keep the in-tree tool refusal and its MISSING reason).

## Test the plugin

ASH constructs a plugin with keyword arguments, `context` and `config`, so a unit test can do the same and call the method ASH calls. Build a `PluginContext` (from `automated_security_helper.base.plugin_context`) whose `source_dir` holds the files to scan, an `output_dir`, and a `config` such as `AshConfig(project_name="scanner-test")` (from `automated_security_helper.config.ash_config`). Then `RuffSecurityScanner(context=context).scan(target=context.source_dir, target_type="source")` runs ruff and returns the `SarifReport` read from its output, with one result per finding, before ASH makes paths relative and applies suppressions.

## Logging from threads your plugin starts

Each scan logs to its own `ash.log`. ASH knows which scan a line belongs to from the context the line is logged in, and ASH's own scanner threads carry that context. A thread your plugin starts with `threading.Thread`, or a task it submits to a `ThreadPoolExecutor`, starts in an empty context, so its lines belong to no scan. A CLI scan's `ash.log` still takes them, because that scan is the process's only one. The MCP server runs several sessions' scans in one process, so it puts such lines in no scan's `ash.log`, only in the server's own log (stderr, at the level the server was started with — its own log-level option, `INFO` when not given; `quiet` and `simple` name no logging level, so with either it is `ASH_LOG_LEVEL`, or `WARNING` when that is unset — when the server has no handler of its own on that logger). So start every thread your plugin makes with `ash_thread`: when the MCP server runs your plugin, a line from a thread without the scan's context never reaches the scan's `ash.log`.

Under `ash scan`, a line no handler takes reaches stderr at the scan's console level: its flags first, then `ASH_DEBUG` or `ASH_VERBOSE`, then `INFO`, and `ERROR` for `--quiet` and `--simple` unless `--verbose` or `--debug` is also given. `--log-level INFO` reads as the default, so it does not override `ASH_DEBUG` or `ASH_VERBOSE`; every other `--log-level` does. `ASH_LOG_LEVEL` does not change it there; under the MCP server it is the fallback for `quiet` and `simple`.

Start the thread with `ash_thread`, which runs the target in a copy of the scan's context, and submit to an executor through a copy the same way:

```python
import contextvars
from concurrent.futures import ThreadPoolExecutor

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.threads import ash_thread


def check_one(path):
    ASH_LOGGER.info("checked %s", path)


worker = ash_thread(check_one, args=("app.py",), name="my-plugin-worker")
worker.start()
worker.join()

with ThreadPoolExecutor(4) as pool:
    pool.submit(contextvars.copy_context().run, check_one, "lib.py").result()
```

`ash_thread` takes the copy when it makes the thread, so make it in your scanner's own code (inside `scan()`), not at import time. It returns the thread unstarted, as `threading.Thread` does.

## A scanner with no external tool

A scanner that does its work in Python overrides `scan()` instead of `_execute_scan()`, and must still define `_execute_scan`, which is abstract, as a stub that raises `NotImplementedError`. Declare `python_only: ClassVar[bool] = True` on it ([above](#declare-whether-the-scanner-is-python-only)). ASH calls `scan(target=..., target_type=...)` once for the source directory and, when a converter wrote files, once more for the converted files, with `target_type` set to `converted`. `scan()` must return a `SarifReport` (from `automated_security_helper.schemas.sarif_schema_model`) for its findings to reach the reports. Return `False` if the scanner cannot run, which reports it MISSING; so does any other empty value, such as `[]`. Returning `None` reports it ERROR. Any other value, including a dictionary of findings, is recorded as PASSED with no findings, so do not catch an exception and return something else: let it propagate, and ASH reports the scanner as ERROR. Read files from the scan set with `open_in_scanned_tree` from `automated_security_helper.utils.scanned_tree`, which refuses links and paths outside the source directory. The scanner of the example plugin package in the ASH repository, [`examples/ash_plugins_example/my_ash_plugins/scanner.py`](https://github.com/awslabs/automated-security-helper/blob/main/examples/ash_plugins_example/my_ash_plugins/scanner.py), overrides `scan()` and returns a `SarifReport`, and a test in the repository runs it through a scan.
