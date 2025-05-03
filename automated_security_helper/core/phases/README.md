# ASH Engine Phases

This directory contains the implementation of the different phases of the ASH execution engine.

## Phase Structure

Each phase inherits from the `EnginePhase` base class and implements the specific logic for that phase:

- `ConvertPhase`: Handles the conversion of files to formats that can be scanned
- `ScanPhase`: Executes security scanners on the source and converted files
- `ReportPhase`: Generates reports from the scan results

## Usage

The phases are designed to be used by the `ScanExecutionEngine` class. Each phase can be executed independently or as part of a sequence.

Example:

```python
# Create a convert phase
convert_phase = ConvertPhase(
    source_dir=source_dir,
    output_dir=output_dir,
    work_dir=work_dir,
    config=config,
    progress_display=progress_display,
    asharp_model=asharp_model
)

# Execute the convert phase
converted_paths = convert_phase.execute(plugin_registry=plugin_registry)

# Create a scan phase
scan_phase = ScanPhase(
    source_dir=source_dir,
    output_dir=output_dir,
    work_dir=work_dir,
    config=config,
    progress_display=progress_display,
    asharp_model=asharp_model
)

# Execute the scan phase
results = scan_phase.execute(
    scanner_factory=scanner_factory,
    plugin_registry=plugin_registry,
    enabled_scanners=enabled_scanners,
    parallel=True
)

# Create a report phase
report_phase = ReportPhase(
    source_dir=source_dir,
    output_dir=output_dir,
    work_dir=work_dir,
    config=config,
    progress_display=progress_display,
    asharp_model=results
)

# Execute the report phase
report_phase.execute()
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
