# ASH example plugin package

This package demonstrates how to create external plugins for the Automated Security Helper (ASH): one plugin of each kind and two event subscribers, in a module that ASH imports when a module list names it.

## Overview

This example package includes:

1. **ExampleConverter** (`my-example-converter`): copies each Python template in the scan set, `*.py.tmpl`, to a `.py` file under its results directory, so that scanners that select files by extension read it too. It skips templates under `global_settings.ignore_paths`, and reads each one through `open_source_file()`, which refuses a symbolic link or a path outside the scanned directory.
2. **ExampleScanner** (`my-example-scanner`): reports every line that contains `TODO(security)`, the text its `marker` option sets, as a SARIF `note` result, which ASH counts as LOW. LOW is below the default severity threshold, so the findings appear in the reports and do not fail the scan.
3. **ExampleReporter** (`my-example-reporter`): writes the findings as a Markdown list to `reports/ash.example.md`, under the heading its `title` option sets.
4. **Event Subscribers**: `handle_scan_start` and `handle_scan_complete`, which print a line when a scanner starts and when it finishes, subscribed through a dict at module level.

`tests/unit/plugins/test_example_plugin_package.py` in the ASH repository runs a scan with this package and checks that it exits with code 0, that each plugin did its part, and that the subscribers ran.

## Installation

Install the package into the Python environment that runs ASH, which imports it by name. It declares no dependency on ASH, so installing it changes nothing else in that environment. From a checkout of the ASH repository, with ASH in a virtual environment:

<!-- doctest: illustrative reason="installs into the virtual environment that runs ASH" -->
```bash
uv pip install --python /path/to/venv/bin/python -e ./examples/ash_plugins_example
```

With ASH installed by `uv tool install`, install it again with the package added:

<!-- doctest: illustrative reason="installs ASH from its git repository" -->
```bash
uv tool install --python 3.12 --with ./examples/ash_plugins_example \
  'automated-security-helper @ git+https://github.com/awslabs/automated-security-helper.git@main'
```

## Usage

ASH loads the package only when a module list names it. The example's `.ash/.ash.yaml`
names it in `ash_plugin_modules` and sets the converter's and the reporter's options, but
ASH ignores a module that a repository's config names when the module itself is inside a
git checkout or the scanned directory, and the command above installs this package in
editable mode, from this directory of the ASH checkout. Name the module on the command
line instead, which counts as operator configuration:

<!-- doctest: illustrative reason="needs the example package installed" -->
```bash
# Run ASH with the example plugins
ash --source-dir /path/to/code --ash-plugin-modules my_ash_plugins
```

In a directory holding a file such as `settings.py.tmpl` with a line that contains
`TODO(security)`, the scan exits with code 0, and `.ash/ash_output/reports/ash.example.md`
lists the finding twice: in the template, and in the `settings.py` the converter wrote
under `.ash/ash_output/converted/my-example-converter/`.

## Plugin development

This package demonstrates the key components of ASH plugins:

### 1. Plugin registration

Each plugin class carries a decorator, `@ash_converter_plugin`, `@ash_scanner_plugin`, or
`@ash_reporter_plugin`, which registers it when ASH imports the package. The lists at the
end of `__init__.py` register nothing, and are optional:

<!-- doctest: illustrative reason="an excerpt of my_ash_plugins/__init__.py" -->
```python
# The plugins this package declares. The decorators do the registering; the loader
# reads these lists only to report what each package provided.
ASH_CONVERTERS = [ExampleConverter]
ASH_SCANNERS = [ExampleScanner]
ASH_REPORTERS = [ExampleReporter]
```

### 2. Interface implementation

Each plugin subclasses `ConverterPluginBase`, `ScannerPluginBase`, or `ReporterPluginBase`,
with a config class whose `name` is the plugin's key in an ASH config and whose options are
a class of their own:

- `ExampleConverter.convert(self)` takes no arguments: ASH calls it once per scan. It finds
  its inputs in the scan set, writes under `self.results_dir`, and returns the paths it
  wrote, which ASH scans as a second target.
- `ExampleScanner` does its work in Python, so it overrides `scan()` and returns a
  `SarifReport`, the only return value whose findings reach the reports.
- `ExampleReporter.report()` returns the report as a string, and ASH writes it to
  `reports/ash.<extension>`.

### 3. Event subscription

Event subscribers are listed in a dict at module level, which ASH reads when it loads the module:

<!-- doctest: illustrative reason="an excerpt of my_ash_plugins/__init__.py" -->
```python
from automated_security_helper.plugins.events import AshEventType


def handle_scan_complete(**kwargs):
    """Called as each scanner finishes."""
    scanner = kwargs.get("scanner", "Unknown")
    print(f"Example plugin: scanner '{scanner}' completed")
    return True


# Event handlers, registered when ASH loads the package.
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_START: [handle_scan_start],
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
}
```

### Available event types

Every event a scan emits, when it fires and the keyword arguments it receives are listed in
[Subscribe to scan events](https://awslabs.github.io/automated-security-helper/plugins/event-subscribers/#events). The two this example uses:

- `AshEventType.SCAN_COMPLETE` fires after each scanner, with `scanner`, `completed_count`,
  `total_count`, `remaining_count`, `remaining_scanners`, and `message`, plus `phase` and
  `plugin_context`.
- `AshEventType.SCAN_START` fires before each scanner only when scanners run one at a time:
  with `ash scan --strategy sequential`, or when only one scanner runs. When two or more
  scanners run under the default parallel strategy it is not emitted, so
  `handle_scan_start` does not run.

## Plugin discovery

ASH has no automatic discovery. It imports a plugin module when a module list names it:
`ash_plugin_modules` in a config file, `--ash-plugin-modules`, or the `ASH_PLUGIN_MODULES`
environment variable. Importing the module runs the decorators, which register its
plugins, and ASH subscribes the functions in its dict of event subscribers, shown above.

For more information, see [Plugins](https://awslabs.github.io/automated-security-helper/plugins/).
