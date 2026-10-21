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

To add a phase, subclass `EnginePhase`, implement the `phase_name` property and the
`_execute_phase` method, and add it to the engine's sequence in `execution_engine.py`.
