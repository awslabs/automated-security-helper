# Subscribe to scan events

An event subscriber is a function that ASH calls at a point in a scan: when a phase starts, when a scanner finishes, when the whole scan ends. Use one to log progress somewhere ASH does not, to time scans, or to start work that depends on a scanner's result. This page builds a module with two subscribers, one that prints a line as each scanner finishes and one that prints the scan's duration at the end.

Before you start, you need ASH installed ([Install ASH](../how-to/install.md)) and a directory for the module outside the repositories you scan. This page uses `~/ash-plugins`. [Plugins](index.md) explains how ASH loads plugin modules and what a loaded module can do.

## 1. Write the subscribers

Save this as `~/ash-plugins/acme_ash_plugins/__init__.py`:

```python
from automated_security_helper.plugins.decorators import event_subscriber
from automated_security_helper.plugins.events import AshEventType


@event_subscriber(AshEventType.SCAN_COMPLETE)
def scanner_finished(**kwargs):
    print(f"acme: {kwargs['scanner']} finished, {kwargs['remaining_count']} left")


@event_subscriber(AshEventType.EXECUTION_COMPLETE)
def run_finished(**kwargs):
    print(f"acme: run finished in {kwargs['duration']:.1f} s")
```

## 2. Scan with them

<!-- doctest: illustrative reason="needs the module saved in step 1" -->
```bash
export PYTHONPATH="$HOME/ash-plugins"
ash scan --ash-plugin-modules acme_ash_plugins --scanners detect-secrets --offline
```

Among the scan's output are the two lines the subscribers print:

```text
acme: detect-secrets finished, 0 left
acme: run finished in 0.9 s
```

`ash plugin list` does not show event subscribers.

## How subscribing works

`@event_subscriber(event_type)` subscribes the function when ASH imports the module, which happens when a module list names it ([Load a plugin module](index.md#load-a-plugin-module)). ASH calls each subscriber with keyword arguments only, so declare `**kwargs` and read the arguments you need; the table below lists them. Return values are ignored. Subscribing the same function to the same event twice has no effect.

A module can instead list its subscribers in a dict at module level, which ASH reads when it loads a module from a module list:

```python
from automated_security_helper.plugins.events import AshEventType


def scanner_finished(**kwargs):
    print(kwargs["scanner"])


ASH_EVENT_HANDLERS = {AshEventType.SCAN_COMPLETE: [scanner_finished]}
```

Subscribers to one event run in the order they were subscribed. The order between modules is not fixed, so do not make one module's subscriber depend on another's.

## Events

These are the events a scan emits, in the order they happen. Events emitted during a phase also receive `phase` and `plugin_context`.

| Event | When | Keyword arguments |
|---|---|---|
| `EXECUTION_START` | once, before the first phase | `phases`, `plugin_context`, `source_dir`, `output_dir`, `enabled_scanners`, `excluded_scanners`, `python_based_plugins_only`, `strategy`, `message` |
| `CONVERT_PHASE_START`, `SCAN_PHASE_START`, `REPORT_PHASE_START`, `INSPECT_PHASE_START` | when each phase starts; inspect runs only with `--inspect` | the scan phase adds `enabled_scanners`, `excluded_scanners`, `parallel`, `max_workers`, `global_ignore_paths`, `shard_index`, `shard_count`; the report phase adds `report_dir`, `cli_output_formats` |
| `CONVERT_START` | before each converter runs | `converter`, `converter_class`, `message` |
| `CONVERT_COMPLETE` | after each converter that did not raise | the same, plus `converted_files`, `file_count` |
| `SCAN_START` | before each scanner, only with `--strategy sequential` | `scanner`, `scanner_class`, `scan_targets`, `message` |
| `SCAN_COMPLETE` | after each scanner, including one that failed | `scanner`, `completed_count`, `total_count`, `remaining_count`, `remaining_scanners`, `message` |
| `REPORT_START` | before each reporter | `reporter`, `reporter_class`, `message` |
| `REPORT_COMPLETE` | after each reporter that wrote a file | the same, plus `output_file`, `output_filename` |
| `CONVERT_PHASE_COMPLETE`, `SCAN_PHASE_COMPLETE`, `REPORT_PHASE_COMPLETE`, `INSPECT_PHASE_COMPLETE` | when each phase ends | the phase's start arguments, plus `results` |
| `EXECUTION_COMPLETE` | once, at the end, also when the scan failed | `phases`, `results`, `duration` (seconds), `completed_scanners`, `message` |
| `ERROR`, `WARNING`, `INFO` | when ASH records a problem or a validation checkpoint | `message`, and details that depend on the source |

`AshEventType` also has `EXECUTION_PROGRESS`, `CONVERT_PHASE_PROGRESS`, `SCAN_PHASE_PROGRESS`, `REPORT_PHASE_PROGRESS`, `INSPECT_PHASE_PROGRESS`, `INSPECT_START` and `INSPECT_COMPLETE`. ASH never emits them. Under the default parallel strategy, `SCAN_START` is not emitted either; use `SCAN_PHASE_START` to learn which scanners will run.

## When a subscriber fails

A subscriber runs in ASH's own process, in the thread that emitted the event, and ASH waits for it before it continues. Keep subscribers fast: one that calls a network service delays the scan by that call.

If a subscriber raises an exception, the subscribers after it for that event do not run. What else happens depends on the event:

- For a `_PHASE_START` or `_PHASE_COMPLETE` event, the scan stops. It exits with code 1 and writes no reports.
- For any other event, ASH logs the error and the scan continues.

Catch exceptions inside your subscriber unless you mean it to stop the scan.

## Built-in subscribers

ASH subscribes two functions of its own. At `SCAN_COMPLETE` one logs which scanners are still running, as in `Scanner bandit completed. 2 remaining: semgrep, checkov`, and `All scanners completed!` after the last one. At `EXECUTION_START` the other warns about every suppression in the config that expires within 30 days ([Suppress findings](../how-to/suppress-findings.md)).
