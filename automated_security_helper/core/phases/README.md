# ASH engine phases

This directory holds the phases of the ASH scan engine. Each phase is a subclass of
`EnginePhase` (`automated_security_helper/base/engine_phase.py`):

- `ConvertPhase` (`convert_phase.py`) turns archives and notebooks into files the scanners can read.
- `ScanPhase` (`scan_phase.py`) runs the selected scanners over the source and the converted files.
- `ReportPhase` (`report_phase.py`) writes the reports from the aggregated results.
- `InspectPhase` (`inspect_phase.py`) runs the optional inspection step.

`ScanExecutionEngine` (`automated_security_helper/core/execution_engine.py`) creates each phase
with the scan's `PluginContext` and the plugins for that phase, then runs them in order. The phases
are internal: to run a scan, use `ash scan` or the
[Python API](https://awslabs.github.io/automated-security-helper/reference/python-api/) rather than
creating phases yourself.

- `ConvertPhase`: Handles the conversion of files to formats that can be scanned
- `ScanPhase`: Executes security scanners on the source and converted files
- `ReportPhase`: Generates reports from the scan results

## Usage

The phases are designed to be used by the `ScanExecutionEngine` class. Each phase can be executed independently or as part of a sequence.

Example:

```python
# Every phase takes the run's PluginContext (source, output and work
# directories, and the config), the plugin classes it runs, a progress display
# and the results model it updates.
convert_phase = ConvertPhase(
    plugin_context=plugin_context,
    plugins=converter_classes,
    progress_display=progress_display,
    asharp_model=results,
)
results = convert_phase.execute(aggregated_results=results)

scan_phase = ScanPhase(
    plugin_context=plugin_context,
    plugins=scanner_classes,
    progress_display=progress_display,
    asharp_model=results,
)
results = scan_phase.execute(aggregated_results=results, parallel=True)

# A report phase runs only the reporters it is given, here ASH's built-ins and
# those of the modules the config names; given none, it runs none.
report_phase = ReportPhase(
    plugin_context=plugin_context,
    plugins=reporter_classes_for_run(plugin_context.config.ash_plugin_modules),
    progress_display=progress_display,
    asharp_model=results,
)
results = report_phase.execute(
    report_dir=plugin_context.output_dir / "reports", aggregated_results=results
)
```

## Benefits of the Phase-Based Architecture

1. **Modularity**: Each phase is a separate class with clear responsibilities
2. **Testability**: Each phase can be tested independently
3. **Extensibility**: New phases can be added by creating new classes
4. **Readability**: The main execution engine class is much smaller and easier to understand
5. **Maintainability**: Changes to one phase don't affect others

## Extending

To add a new phase:

1. Create a new class that inherits from `EnginePhase`
2. Implement the `phase_name` property
3. Implement the `execute` method

Example:

```python
from automated_security_helper.base.engine_phase import EnginePhase


class NewPhase(EnginePhase):
    @property
    def phase_name(self) -> str:
        return "new_phase"

    def execute(self, **kwargs) -> Any:
        # Implement phase logic here
        pass
```
