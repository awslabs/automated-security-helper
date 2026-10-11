# Python API

`run_ash_scan` runs an ASH scan from Python. It is the function that `ash scan` and the MCP server's scan tool call, so a scan started from Python behaves like one started from the command line, with one difference that matters: it ends a non-zero result by raising `SystemExit`.

```python
import automated_security_helper.config.ash_config  # noqa: F401  (see "Import order")
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

results = run_ash_scan(
    source_dir=".",
    scanners=["detect-secrets"],
    offline=True,
    fail_on_findings=False,
    progress=False,
    show_summary=False,
    quiet=True,
)
stats = results.metadata.summary_stats
print(f"{stats.actionable} actionable of {stats.total} findings")
for name, row in results.scanner_results.items():
    if row.status != "SKIPPED":
        print(name, row.status.value, row.finding_count)
```

Run in a repository with one hardcoded password, this prints:

```text
1 actionable of 1 findings
detect-secrets FAILED 1
```

The scan also writes its usual output directory, here `.ash/ash_output` under the working directory.

## Return value and exit behavior

| Outcome | What `run_ash_scan` does |
|---|---|
| exit code 0 | returns an `AshAggregatedResults`, the model that `ash_aggregated_results.json` holds ([Output files](output-files.md)) |
| actionable findings (exit code 2) | raises `SystemExit(2)`, with no results attached |
| incomplete scan: a scanner MISSING or ERROR, a converter that lost inputs, a stale content database | raises `ScanIncompleteExit`, a `SystemExit` with code 1 whose `incompleteness` says why and whose `results` holds the model |
| other errors (exit code 1) | raises `SystemExit(1)` |
| invalid configuration | raises `SystemExit(3)` |
| an output directory ASH refuses because it, a directory on the way to it, or one of its `reports`, `scanners`, `converted` or `analysis` directories is a symbolic link | raises `OutputDirRefusedExit`, a `SystemExit` with code 1 whose `found` names the link and whose `reason` says what to do |

The exit codes are those of the CLI ([Exit codes](exit-codes.md)). To get the results of a scan that has findings, pass `fail_on_findings=False`, as the example does. To get them from an incomplete scan, catch `ScanIncompleteExit`:

```python
import automated_security_helper.config.ash_config  # noqa: F401
from automated_security_helper.interactions.run_ash_scan import (
    ScanIncompleteExit,
    run_ash_scan,
)

try:
    results = run_ash_scan(
        source_dir=".",
        scanners=["detect-secrets", "bandit"],
        offline=True,
        progress=False,
        show_summary=False,
        quiet=True,
    )
except ScanIncompleteExit as incomplete:
    print("incomplete:", incomplete.incompleteness.scanners)
    results = incomplete.results
except SystemExit as stopped:
    print("exit code", stopped.code)
    results = None
```

When bandit is not installed, this prints `incomplete: (('bandit', 'MISSING'),)`. `incompleteness.scanners` lists `(name, status)` pairs; `incompleteness.converters` lists `(name, reason)` pairs; `incompleteness.stale_content_databases` lists the databases past their age bound. ASH also prints its incomplete-scan message, even with `quiet=True`.

With a `workspace_plan`, `run_ash_scan` returns the workspace result instead of `AshAggregatedResults`, and raises `SystemExit` with the workspace exit code when it is not 0.

## Parameters

Every parameter is optional and can be passed by keyword. Unless the table says otherwise, a parameter means what the [`ash scan`](cli.md#scan) option of the same name means. `run_ash_scan` also accepts and ignores any other positional or keyword argument, so a misspelled parameter name is silently dropped.

| Parameter | If not passed | Notes |
|---|---|---|
| `source_dir` | the working directory | |
| `output_dir` | `.ash/ash_output` under the working directory | Not under `source_dir`, as the CLI's default is. Pass it whenever `source_dir` is not the working directory. |
| `config` | `None` | Path to a config file. When unset, ASH discovers one in `source_dir`. |
| `config_overrides` | `None` | List of `key=value` strings, as `--config-overrides` takes. |
| `offline` | `False` | |
| `strategy` | `ExecutionStrategy.PARALLEL` | From `automated_security_helper.core.enums`. |
| `scanners`, `exclude_scanners` | `None` | Lists of scanner names. |
| `progress` | `True` | Set `False` outside a terminal. |
| `output_formats` | `None` | List of `ExportFormat` members (`automated_security_helper.core.enums`). |
| `cleanup` | `False` | |
| `phases` | `None` (all but inspect) | List of `ExecutionPhase` members. |
| `inspect` | `False` | |
| `existing_results` | `None` | Path to an `ash_aggregated_results.json` to report from, which `--use-existing` sets. |
| `python_based_plugins_only` | `False` | `--python-only`. |
| `quiet`, `simple`, `verbose`, `debug` | `False` | |
| `color` | `True` | |
| `log_level` | `AshLogLevel.INFO` | |
| `fail_on_findings`, `fail_on_incomplete_scanners` | `None` | `None` takes the value from the config, else `True`. |
| `ignore_suppressions` | `False` | |
| `min_severity` | `"low"` | |
| `changed_files_only`, `base_ref` | `False`, `"origin/main"` | |
| `shard_index`, `shard_count` | `None` | |
| `mode` | `RunMode.local` | `RunMode.container`, `RunMode.nix` or `RunMode.precommit` for the other run modes. |
| `show_summary` | `True` | Prints the results table. |
| `build`, `run`, `force`, `oci_runner`, `build_target`, `offline_semgrep_rulesets`, `container_uid`, `container_gid`, `ash_revision_to_install`, `custom_containerfile`, `custom_build_arg` | as the CLI | Container mode only. |
| `container_network` | `"bridge"` | Container mode only: the network the scan container uses when the scan is online. |
| `ash_plugin_modules` | `None` | Plugin modules to load. This is an operator source: ASH imports every module it names ([Plugins](../plugins/index.md#who-may-load-a-module)). |
| `workspace_plan`, `allow_missing_projects` | `None`, `False` | A workspace scan, which `--workspace` builds the plan for. |
| `config_base_gate`, `untrusted_config`, `trusted_config_path`, `client_config_policy` | `None`, `False`, `None`, `None` | Used by the MCP server to apply the MCP-client limits of the [trust model](../concepts/trust-model.md). `untrusted_config` and `client_config_policy` raise `ValueError` in container or nix mode. |

Some `ash scan` options have no parameter. They become config overrides or an environment variable:

| `ash scan` option | Python equivalent |
|---|---|
| `--sandbox auto` | `config_overrides=["sandbox.mode=auto"]` |
| `--compact-report` | `config_overrides=["reporters.markdown.options.compact=true"]` |
| `--allow-stale-content-db` | `config_overrides=["content_db_staleness=warn", "content_db_staleness_overrides=[]"]` |
| `--allow-in-tree-tools` | set `ASH_ALLOW_IN_TREE_TOOLS=1` in `os.environ` before the call |

## Import order

Import `automated_security_helper.config.ash_config` before `run_ash_scan`, as the examples do. When `run_ash_scan` is the first part of ASH a program imports, a circular import makes ASH log an ERROR that its built-in reporters failed to import, and the error is recorded in `results.metadata.plugin_load_errors`. The reporters register later in the same call and the reports are written, but the error remains in the results. This is a defect in ASH; the `ash` command does not have it.

## Side effects

`run_ash_scan` runs in your process. It sets environment variables while it runs (`offline=True` sets `ASH_OFFLINE`, and restores the previous value when the scan ends), configures ASH's logger, and registers plugins in a process-wide registry. A plugin module loaded by one call stays loaded for every later call in the same process.
