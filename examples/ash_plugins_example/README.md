# ASH example plugin package

This package shows how to write external plugins for the Automated Security Helper
(ASH). It contains one plugin of each kind and two event handlers:

1. `ExampleConverter` (`my-example-converter`) copies each Python template in the
   scan set, `*.py.tmpl`, to a `.py` file in its work directory, so that scanners
   which select files by extension read it too.
2. `ExampleScanner` (`my-example-scanner`) reports every line containing
   `TODO(security)` as a SARIF `note` result. ASH maps `note` to LOW, which is below
   the default severity threshold, so the findings appear in every report and do not
   fail the scan.
3. `ExampleReporter` (`my-example-reporter`) writes the findings as a Markdown list
   to `reports/ash.example.md`.
4. `handle_scan_start` and `handle_scan_complete` print a line as each scanner
   starts and finishes.

`tests/unit/plugins/test_example_plugin_package.py` in the ASH repository runs a real
scan with this package, so the code here is kept working.

## Installation

Install the package into the Python environment ASH runs in. ASH imports it by name,
so it has to be importable there. From a checkout of the ASH repository:

<!-- doctest: illustrative reason="installs into the virtual environment that runs ASH" -->
```bash
# ASH installed with uv tool install: reinstall it with the package added
uv tool install --with ./examples/ash_plugins_example git+https://github.com/awslabs/automated-security-helper.git

# ASH installed in a virtual environment: install the package into that environment
uv pip install --python /path/to/venv/bin/python -e ./examples/ash_plugins_example
```

The package declares no dependency on `automated-security-helper`: ASH installs from
its git repository, and the PyPI project with that name is not published by ASH.

## Usage

ASH loads only its built-in plugins unless a plugin module is named. Name this one in
any of three ways:

<!-- doctest: illustrative reason="needs the example package installed" -->
```bash
# On the command line
ash --source-dir /path/to/code --ash-plugin-modules my_ash_plugins

# With this directory's config, which also sets the plugins' options
ash --source-dir /path/to/code --config examples/ash_plugins_example/.ash/.ash.yaml
```

or copy `.ash/.ash.yaml` into the repository you scan, where ASH finds it.

A config file inside the scanned tree, such as a copied `.ash/.ash.yaml`, can name only
modules installed outside that tree. The scanned tree is the scanned directory, or the
outermost git checkout that contains it. An `ash_plugin_modules` entry from such a file
that resolves inside the tree is not imported, and ASH logs "Ignoring
ash_plugin_modules entries 'my_ash_plugins' (it resolves inside the scanned tree)". So
a copied config loads `my_ash_plugins` only when the package is installed from a
directory outside that repository's checkout. The rule covers config files inside the
scanned tree; modules named by whoever runs ASH, with `--ash-plugin-modules`,
`--config-overrides` or a config file outside the tree, are loaded as named.

To see each plugin work, scan a directory holding a file such as `settings.py.tmpl`
with a line containing `TODO(security)`. The scan exits 0; `reports/ash.example.md`
lists the finding in the template and again in the `settings.py` the converter wrote
under `converted/my-example-converter/`.

## How the plugins are written

### Registration

Each class carries `@ash_converter_plugin`, `@ash_scanner_plugin` or
`@ash_reporter_plugin`, which registers it when ASH imports the package. The
`ASH_CONVERTERS`, `ASH_SCANNERS` and `ASH_REPORTERS` lists in `__init__.py` register
nothing; the loader reads them to report what the package provided.

### Converters

ASH calls `convert()` once per scan, with no arguments. The converter finds its inputs
in the scan set under `self.context.source_dir`, reads each one through
`self.open_source_file()` (which refuses symlinks, files with a second hard link and
paths outside the scanned tree),
writes its output under `self.results_dir`, and returns the paths it wrote. ASH then
scans those files as a second, `converted`, target.

A converter written as `convert(self, target)`, the form of earlier versions, is
refused with an error that says to declare `convert(self)`.

### Scanners

A scanner that runs an external tool implements `_execute_scan()` and lets the base
class run the tool and read its SARIF. A pure-Python scanner like this one overrides
`scan()` and returns a `SarifReport`. Only a `SarifReport` carries findings into the
reports; a scanner that cannot run returns `False`, which ASH reports as MISSING. It
reads each file through `open_in_scanned_tree()` from
`automated_security_helper.utils.scanned_tree`, which refuses the same files
`open_source_file()` does.

### Reporters

`report()` returns the report as a string, and ASH writes it to
`reports/ash.<extension>`, here `reports/ash.example.md`.

### Event handlers

`ASH_EVENT_HANDLERS` maps an `AshEventType` to a list of callables, which ASH
registers when it loads the package. Every handler receives keyword arguments,
including `phase` and `plugin_context`.

- The convert, scan, report and inspect phases each emit `<PHASE>_PHASE_START` and
  `<PHASE>_PHASE_COMPLETE` once, for example `SCAN_PHASE_START`.
  `AshEventType` also declares `<PHASE>_PHASE_PROGRESS`, but no phase emits it.
- The convert, scan and report phases also emit `<PHASE>_START` and
  `<PHASE>_COMPLETE` once per plugin, for example `SCAN_START` as each scanner
  starts.
- `EXECUTION_START` and `EXECUTION_COMPLETE` cover the whole run, and `ERROR`,
  `WARNING` and `INFO` report conditions.

`SCAN_START` passes `scanner`, `scanner_class`, `scan_targets` and `message`.
`SCAN_COMPLETE` passes `scanner`, `completed_count`, `total_count`,
`remaining_count`, `remaining_scanners` and `message`.

## More information

The plugin pages of the ASH documentation are under
[docs/content/docs/plugins](../../docs/content/docs/plugins/index.md), and the
configuration schema is
[automated_security_helper/schemas/AshConfig.json](../../automated_security_helper/schemas/AshConfig.json).
