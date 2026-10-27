# Python API

`run_ash_scan` runs an ASH scan from Python. It is the function that `ash scan` and the MCP server's scan tool call, so a scan started from Python behaves like one started from the command line, with one difference that matters: it ends a non-zero result by raising `SystemExit`.

## Programmatic usage

```python
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
print(f"Found {stats.total} findings, {stats.actionable} actionable")
for name, row in results.scanner_results.items():
    if row.status != "SKIPPED":
        print(name, row.status.value, row.finding_count)
```

Run in a repository with one hardcoded password, this prints:

<!-- doctest: output -->
```text
Found 1 findings, 1 actionable
detect-secrets FAILED 1
```

The scan also writes its usual output directory, here `.ash/ash_output` under the working directory.

## Return value and exit behavior

| Outcome | What `run_ash_scan` does |
|---|---|
| exit code 0 | returns an `AshAggregatedResults`, the model that `ash_aggregated_results.json` holds ([Output files](output-files.md)) |
| actionable findings (exit code 2) | raises `SystemExit(2)`, with no results attached |
| incomplete scan: a scanner MISSING, ERROR, or with lost targets, no scanner ran, a converter that lost inputs, a rule that could not be evaluated, or a stale content database | raises `ScanIncompleteExit`, a `SystemExit` with code 1 whose `incompleteness` says why and whose `results` holds the model |
| other errors (exit code 1) | raises `SystemExit(1)` |
| a configuration that cannot be used or is invalid, as for [`ash scan`](exit-codes.md#scan): a `config` path or an `ASH_CONFIG` that names no readable file, a config file that does not parse or does not validate, or an override that does not validate (exit code 3) | raises `SystemExit(3)` |
| a scanner selection that selects nothing: no name in `scanners` matches a scanner, or every name in `scanners` is also in `exclude_scanners` (exit code 5) | raises `SystemExit(5)` before any scanner runs |
| an output directory ASH refuses because it, a directory on the way to it, or one of its `reports`, `scanners`, `converted`, or `analysis` directories is a symbolic link | raises `OutputDirRefusedExit`, a `SystemExit` with code 1 whose `found` names the link and whose `reason` says what to do |
| interrupted with Ctrl-C | lets `KeyboardInterrupt` propagate; `ash scan` turns it into exit code 130 |

The exit codes are those of the CLI ([Exit codes](exit-codes.md)). To get the results of a scan that has findings, pass `fail_on_findings=False`, as the example does. To get them from an incomplete scan, catch `ScanIncompleteExit`:

```python
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

When bandit is not installed, this prints `incomplete: (('bandit', 'MISSING'),)`. `incompleteness.scanners` lists `(name, status)` pairs; `incompleteness.converters` lists `(name, reason)` pairs; `incompleteness.stale_content_databases` lists the databases past their age bound; `incompleteness.unevaluated_rules` lists the rules that could not be evaluated; and `incompleteness.no_scanner_ran` is `True` when no scanner reached a verdict, as when every scanner was skipped. ASH also prints its incomplete-scan message, even with `quiet=True`.

A scanner name that matches no scanner stops the call before any scanner runs, so a misspelled name is never reported as a clean scan:

<!-- doctest: run expect-exit=5 -->
```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

run_ash_scan(
    source_dir=".",
    scanners=["detect_secrets"],
    offline=True,
    progress=False,
    show_summary=False,
    quiet=True,
)
```

ASH prints `ERROR (5) None of the requested scanners exist: detect_secrets.` and the names it has, and the uncaught `SystemExit(5)` ends the script with exit code 5. Scanner names use hyphens: `detect-secrets`. When only some of the names match, the scan runs the scanners they name and logs a warning about the rest.

A `config` that names no file stops the call the same way, with `SystemExit(3)`, instead of scanning with the default configuration:

<!-- doctest: run expect-exit=3 -->
```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

run_ash_scan(
    source_dir=".",
    config="no-such-config.yaml",
    scanners=["detect-secrets"],
    offline=True,
    progress=False,
    show_summary=False,
    quiet=True,
)
```

With a `workspace_plan`, `run_ash_scan` returns the workspace result instead of `AshAggregatedResults`, and raises `SystemExit` with the workspace exit code when it is not 0.

## Parameters

Every parameter is optional and can be passed by keyword. Unless the table says otherwise, a parameter means what the [`ash scan`](cli.md#scan) option of the same name means. An unknown keyword argument raises `TypeError`, so a misspelled parameter name stops the call before anything runs, and so does a positional argument past the last parameter.

<!-- doctest: options of=python.automated_security_helper.interactions.run_ash_scan.run_ash_scan -->
| Parameter | Default | Notes |
|---|---|---|
| `source_dir` | `None` | The directory to scan. `None` scans the working directory. |
| `output_dir` | `None` | `None` writes to `.ash/ash_output` under the working directory, not under `source_dir` as the CLI does. Pass it whenever `source_dir` is not the working directory. |
| `config` | `None` | Path to a config file. `None` discovers one in `source_dir`. |
| `config_overrides` | `None` | List of `key=value` strings, as `--config-overrides` takes. |
| `offline` | `False` |  |
| `strategy` | `ExecutionStrategy.PARALLEL` | An `ExecutionStrategy` from `automated_security_helper.core.enums`. |
| `scanners` | `None` | List of scanner names. |
| `exclude_scanners` | `None` | List of scanner names. |
| `progress` | `True` | Set `False` outside a terminal. |
| `output_formats` | `None` | List of `ExportFormat` members from `automated_security_helper.core.enums`. |
| `cleanup` | `False` |  |
| `phases` | `None` | List of `ExecutionPhase` members. `None` runs every phase but inspect. |
| `inspect` | `False` |  |
| `existing_results` | `None` | Path to an `ash_aggregated_results.json` to report from, as `--use-existing` sets it. |
| `python_based_plugins_only` | `False` | As `--python-only`. |
| `quiet` | `False` |  |
| `simple` | `False` |  |
| `verbose` | `False` |  |
| `debug` | `False` |  |
| `color` | `True` |  |
| `fail_on_findings` | `None` | `None` takes the value from the config, else `True`. |
| `fail_on_incomplete_scanners` | `None` | `None` takes the value from the config, else `True`. |
| `ignore_suppressions` | `False` |  |
| `min_severity` | `'low'` |  |
| `changed_files_only` | `False` |  |
| `base_ref` | `'origin/main'` |  |
| `shard_index` | `None` |  |
| `shard_count` | `None` |  |
| `mode` | `RunMode.local` | `RunMode.container`, `RunMode.nix`, or `RunMode.precommit` for the other run modes. |
| `show_summary` | `True` | Prints the results table. |
| `log_level` | `AshLogLevel.INFO` |  |
| `build` | `True` | Container mode only. |
| `run` | `True` | Container mode only. |
| `force` | `False` | Container mode only. |
| `oci_runner` | `None` | Container mode only. |
| `build_target` | `None` | Container mode only. |
| `offline_semgrep_rulesets` | `'p/ci'` | Container mode only. |
| `container_uid` | `None` | Container mode only. |
| `container_gid` | `None` | Container mode only. |
| `ash_revision_to_install` | `None` | Container mode only. |
| `custom_containerfile` | `None` | Container mode only. |
| `custom_build_arg` | `None` | Container mode only. |
| `ash_plugin_modules` | `None` | Plugin modules to load. This is an operator source: ASH imports every module it names ([Who may load a module](../plugins/index.md#who-may-load-a-module)). |
| `container_network` | `'bridge'` | Container mode only: the network the scan container uses when the scan is online. |
| `workspace_plan` | `None` | A workspace scan, which `--workspace` builds the plan for. |
| `allow_missing_projects` | `False` | For a workspace scan. |
| `config_base_gate` | `None` | Used by the MCP server; see below. |
| `untrusted_config` | `False` | Used by the MCP server; see below. |
| `trusted_config_path` | `None` | Used by the MCP server; see below. |
| `client_config_policy` | `None` | Used by the MCP server; see below. |
| `severity_threshold_restriction` | `None` | Used by the MCP server: a threshold the scan must be at least as strict as. The scan runs at the stricter of this and `global_settings.severity_threshold`. Local mode only. |
| `keep_previous_results` | `False` | Used by the MCP server: keeps the previous scan's results until this scan has its own, instead of deleting them when it starts. Local and workspace mode only. |

`config_base_gate`, `untrusted_config`, `trusted_config_path`, and `client_config_policy` let the MCP server apply the MCP-client limits of the [Configuration trust model](../concepts/trust-model.md) to the scans it runs; leave them at their defaults. `untrusted_config` raises `ValueError` in container or nix mode and with a `workspace_plan`, and `client_config_policy` raises it in container or nix mode.

Some `ash scan` options have no parameter. They become config overrides or an environment variable:

| `ash scan` option | Python equivalent |
|---|---|
| `--sandbox auto` | `config_overrides=["sandbox.mode=auto"]` |
| `--compact-report` | `config_overrides=["reporters.markdown.options.compact=true"]` |
| `--allow-stale-content-db` | `config_overrides=["content_db_staleness=warn", "content_db_staleness_overrides=[]"]` |
| `--allow-in-tree-tools` | set `ASH_ALLOW_IN_TREE_TOOLS=1` in `os.environ` before the call |

## Side effects

`run_ash_scan` runs in your process. It sets environment variables while it runs (`offline=True` sets `ASH_OFFLINE`, and restores the previous value when the scan ends), configures ASH's logger, and registers plugins in a process-wide registry. A plugin module loaded by one call stays loaded for every later call in the same process. To change which plugin modules a scan loads, run it in a new process.
