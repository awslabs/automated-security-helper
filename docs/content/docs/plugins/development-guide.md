# Plugin Development Guide

This guide provides comprehensive information on developing custom plugins for ASH. Whether you're creating scanners, reporters, converters, or event subscribers, this document will help you understand the plugin architecture and development process.

## Plugin Architecture Overview

ASH's plugin system is designed to be extensible and modular. Plugins are Python classes that inherit from base plugin classes and implement specific interfaces.

### Plugin Types

ASH supports four main types of plugins:

1. **Scanner Plugins**: Analyze code and infrastructure for security issues
2. **Reporter Plugins**: Generate reports in various formats
3. **Converter Plugins**: Process files before scanning
4. **Event Subscribers**: React to events during the scan lifecycle

### Plugin Lifecycle

All plugins follow a similar lifecycle:

1. **Registration**: Plugins are registered with the plugin manager
2. **Configuration**: Plugin settings are loaded from the ASH configuration
3. **Initialization**: Plugins are initialized with required dependencies
4. **Execution**: Plugins perform their specific tasks
5. **Cleanup**: Plugins clean up resources when done

## Creating a Custom Plugin

### Basic Plugin Structure

A plugin is a class derived from a base plugin class, paired with a config class whose `name` is the key used in the ASH configuration file. Options go in a class derived from the matching options base and sit under `options` in the config:

```python
from typing import Annotated, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class MyCustomScannerConfigOptions(ScannerOptionsBase):
    custom_option: str = "default_value"


class MyCustomScannerConfig(ScannerPluginConfigBase):
    """Configuration for MyCustomScanner."""

    name: Literal["my-custom-scanner"] = "my-custom-scanner"
    enabled: bool = True
    options: Annotated[MyCustomScannerConfigOptions, Field()] = (
        MyCustomScannerConfigOptions()
    )


@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase[MyCustomScannerConfig]):
    """Custom scanner implementation."""

    def model_post_init(self, context):
        # ASH constructs plugins with keyword arguments (context=..., config=...);
        # supply the default config here rather than overriding __init__.
        if self.config is None:
            self.config = MyCustomScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        """Return (argv, results_file, subprocess_env) for the tool to run."""
        raise NotImplementedError("see Scanner Plugin Development below")
```

A plugin class, and a config or options class derived from ASH's bases, inherits `hide_input_in_errors=True`. A validation error then names the field and the problem but not the value it refused: a config value can be a secret read from the environment, and the error's text can reach the console, the log and an MCP response. Keep that setting if a class sets its own `model_config`. pydantic merges a subclass's settings with its base's, so leaving the key out keeps it.

If your `validate_plugin_dependencies` can start the tool where a PATH lookup does not find it (it runs a library in-process, or finds the tool its own way), set `resolves_tool_off_path: ClassVar[bool] = True` on the class: `ash dependencies install` asks the check only for scanners that do, and judges the rest by the PATH lookup. The check is asked only when the PATH lookup fails, only for a plugin a scan here would run or one named with `--tool`, and never after one of the plugin's install commands failed or errored. A tool managed through `uv tool run` is judged by `uv tool list` instead, so the flag has no effect there. The check runs in check-only mode: ASH's own install helpers are skipped and every `uv tool run` probe runs `--offline`, but that mode cannot stop an install the check performs itself (its own `pip install`, for example), so a flagged check must answer without installing anything.

### Plugin Registration

The `@ash_scanner_plugin`, `@ash_reporter_plugin` and `@ash_converter_plugin` decorators register a class when its module is imported. ASH imports the modules named in `ash_plugin_modules` in the configuration file or with `--ash-plugin-modules`; there is no separate registration call. A module named there must sit in a top-level package whose name ends in `ash_plugins` (for example `my_ash_plugins`, or `ash_plugins` itself), or be a module of ASH's own `automated_security_helper` package; ASH logs a warning for any other name.

## Scanner Plugin Development

Scanner plugins analyze code and infrastructure for security issues.

### Scanner Plugin Interface

`scan()` is a template method rather than an abstract one: it owns the fixed
sequence around a scan, and `_execute_scan()` is the abstract hook it calls for
the tool-specific part.

```python
class ScannerPluginBase(PluginBase, Generic[T]):
    """Base class for all scanner plugins."""

    @abstractmethod
    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths,
    ) -> Tuple[List[str], Path, Optional[dict]]:
        """Return (argv, results_file, subprocess_env) for this tool."""

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths=None,
        config=None,
    ) -> Any | SarifReport | CycloneDXReport:
        """Template: preamble -> _execute_scan -> read results -> invocation -> postamble."""
```

Only `_execute_scan()` is required. A plugin that does not fit the template
overrides `scan()` instead, and still declares `_execute_scan()` as a stub that
raises — see [Scanner Plugins](scanner-plugins.md) for that variant. There is no
abstract `cleanup()`; release resources in `_post_scan()` if you need to.

ASH calls `scan()` once for the source directory and, when a converter wrote files, once more for the converted files (`target_type="converted"`). Only a `SarifReport` carries findings into the reports. A dict is recorded as PASSED with 0 findings, so its findings are lost; return `False` when the scanner cannot run, which ASH records as MISSING.

### Scanner Plugin Example

A pure-Python scanner that reports lines matching a regular expression. It overrides `scan()` and returns a `SarifReport`:

```python
import re
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)


class CustomRegexScannerConfigOptions(ScannerOptionsBase):
    patterns: List[str] = Field(
        default=[r"password\s*=\s*['\"]([^'\"]+)['\"]"],
        description="Regular expressions to report",
    )


class CustomRegexScannerConfig(ScannerPluginConfigBase):
    """Configuration for CustomRegexScanner."""

    name: Literal["custom-regex"] = "custom-regex"
    enabled: bool = True
    options: Annotated[CustomRegexScannerConfigOptions, Field()] = (
        CustomRegexScannerConfigOptions()
    )


@ash_scanner_plugin
class CustomRegexScanner(ScannerPluginBase[CustomRegexScannerConfig]):
    """Scanner that uses regex patterns to find security issues."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CustomRegexScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target,
        target_type,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        patterns = [re.compile(p) for p in self.config.options.patterns]
        if target_type == "converted":
            root = Path(target)
            files = [p for p in root.rglob("*") if p.is_file()]
        else:
            root = Path(self.context.source_dir)
            files = [
                Path(name.rstrip("\n"))
                for name in scan_set(
                    source=self.context.source_dir, output=self.context.output_dir
                )
            ]

        results = []
        for path in files:
            # Never open a file by name: open_in_scanned_tree refuses a symlink, a
            # file with a second hard link and a path outside the tree.
            try:
                with open_in_scanned_tree(path, root) as handle:
                    lines = handle.read().decode("utf-8").splitlines()
            except (TreeInputRefused, OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(lines, start=1):
                for pattern in patterns:
                    if pattern.search(line):
                        results.append(
                            {
                                "ruleId": "CUSTOM-REGEX",
                                "level": "error",
                                "message": {"text": f"Matched {pattern.pattern}"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": path.absolute().as_posix()
                                            },
                                            "region": {"startLine": number},
                                        }
                                    }
                                ],
                            }
                        )

        self._post_scan(target=target, target_type=target_type)
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "custom-regex", "rules": []}},
                        "results": results,
                    }
                ],
            }
        )
```

ASH makes a URI under the source directory relative to it. The example plugin package in the ASH repository, `examples/ash_plugins_example`, has a scanner written the same way, and a test runs it through a real scan.

## Reporter Plugin Development

Reporter plugins generate reports in various formats.

### Reporter Plugin Interface

```python
class ReporterPluginBase(PluginBase, Generic[T]):
    """Base class for all reporter plugins."""

    @abstractmethod
    def report(self, model: AshAggregatedResults) -> str | None:
        """Return the report, which ASH writes to reports/ash.<extension>."""
```

Return the report as a string and let ASH write it to `reports/ash.<extension>`. Set `extension` on the config class explicitly, as the example below does.

### Reporter Plugin Example

```python
import json
from typing import Annotated, Literal

from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class CustomJSONReporterConfigOptions(ReporterOptionsBase):
    pretty_print: bool = True


class CustomJSONReporterConfig(ReporterPluginConfigBase):
    """Configuration for CustomJSONReporter."""

    name: Literal["custom-json"] = "custom-json"
    extension: str = "custom.json"
    enabled: bool = True
    options: Annotated[CustomJSONReporterConfigOptions, Field()] = (
        CustomJSONReporterConfigOptions()
    )


@ash_reporter_plugin
class CustomJSONReporter(ReporterPluginBase[CustomJSONReporterConfig]):
    """Reporter that generates a custom JSON report."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CustomJSONReporterConfig()
        return super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> str:
        counts = model.metadata.summary_stats.severity_counts
        report_data = {
            "project": model.metadata.project_name,
            "generated_at": model.metadata.generated_at,
            "summary": {
                "total": model.metadata.summary_stats.total,
                "critical": counts.critical,
                "high": counts.high,
                "medium": counts.medium,
                "low": counts.low,
                "info": counts.info,
            },
            "findings": [],
        }

        if model.sarif and model.sarif.runs:
            for run in model.sarif.runs:
                for result in run.results or []:
                    report_data["findings"].append(
                        {
                            "rule_id": result.ruleId,
                            "level": getattr(result.level, "value", result.level),
                            "message": result.message.root.text
                            if result.message
                            else "No message",
                        }
                    )

        indent = 2 if self.config.options.pretty_print else None
        return json.dumps(report_data, indent=indent)
```

## Converter Plugin Development

Converter plugins process files before scanning.

### Converter Plugin Interface

```python
class ConverterPluginBase(PluginBase):
    """Base class for all converter plugins."""

    @abstractmethod
    def convert(self) -> List[Path]:
        """Convert this converter's inputs and return the files written."""
```

ASH calls `convert()` once per scan, with no arguments. A converter finds its inputs under `self.context.source_dir`, reads each one through `self.open_source_file()`, writes its output under `self.results_dir`, and returns the paths it wrote. ASH scans those files as a second, `converted`, target. A converter declared as `convert(self, target)`, the signature of earlier versions, is refused with an error that says to declare `convert(self)`.

### Converter Plugin Example

```python
from pathlib import Path
from typing import List, Literal

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scanned_tree import TreeInputRefused


class YamlTemplateConverterConfig(ConverterPluginConfigBase):
    """Configuration for YamlTemplateConverter."""

    name: Literal["yaml-template"] = "yaml-template"
    enabled: bool = True


@ash_converter_plugin
class YamlTemplateConverter(ConverterPluginBase[YamlTemplateConverterConfig]):
    """Copies ``*.yaml.tmpl`` files to ``.yaml`` files the scanners read."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = YamlTemplateConverterConfig()
        return super().model_post_init(context)

    def convert(self) -> List[Path]:
        source_dir = Path(self.context.source_dir)
        written: List[Path] = []
        for name in scan_set(source=source_dir, output=self.context.output_dir):
            candidate = Path(name.rstrip("\n"))
            if not candidate.name.endswith(".yaml.tmpl"):
                continue
            try:
                handle = self.open_source_file(candidate)
            except TreeInputRefused as refused:
                self.record_refused_input(refused)
                continue
            with handle:
                content = handle.read()
            relative = candidate.relative_to(source_dir)
            target = (
                self.results_dir / relative.parent / candidate.name[: -len(".tmpl")]
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            written.append(target)
        return written
```

See [Converter Plugins](converter-plugins.md) for the full contract and a tested example.

## Event Subscriber Development

Event subscribers react to events during the scan lifecycle.

### Event Subscriber Interface

```python
# automated_security_helper/plugins/events.py (excerpt)
class AshEventType(Enum):
    SCAN_START = auto()  # as each scanner starts
    SCAN_COMPLETE = auto()  # as each scanner finishes
    CONVERT_START = auto()
    CONVERT_COMPLETE = auto()
    REPORT_START = auto()
    REPORT_COMPLETE = auto()
    ERROR = auto()
    WARNING = auto()
    INFO = auto()


# A subscriber is any callable that takes keyword arguments.
EventSubscriberFunc = Callable[..., bool]
```

### Event Subscriber Example

```python
from automated_security_helper.plugins.events import AshEventType


def scan_complete_handler(**kwargs):
    """Handle scan completion events."""
    scanner = kwargs.get("scanner", "unknown")
    remaining = kwargs.get("remaining_count", 0)

    print(f"Scanner {scanner} completed. {remaining} scanners remaining.")

    # Return True to indicate successful handling
    return True


# In the plugin package's __init__.py: ASH registers these when it loads the package.
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [scan_complete_handler],
}
```

Where the handler is defined decides which scans notify it. A handler defined in your
own program, outside ASH's plugin namespace, is notified in every scan that program
runs. A handler defined in a plugin package is notified only in scans whose
`ash_plugin_modules` name that package, and only when the package defines, imports or
lists it (see [Using Custom Plugin Packages](#using-custom-plugin-packages)).

## Plugin Configuration

Plugins are configured through the ASH configuration file. Each plugin's options go under `options`:

```yaml
ash_plugin_modules:
  - my_ash_plugins

# Custom scanner configuration
scanners:
  custom-regex:
    enabled: true
    options:
      patterns:
        - "password\\s*=\\s*['\"]([^'\"]+)['\"]"
        - "api_key\\s*=\\s*['\"]([^'\"]+)['\"]"

# Custom reporter configuration
reporters:
  custom-json:
    enabled: true
    options:
      pretty_print: true

# Custom converter configuration
converters:
  yaml-template:
    enabled: true
```

## Plugin Distribution

### Creating a Plugin Package

To distribute your plugins, create a Python package whose top-level package name ends in `ash_plugins`:

```
my-ash-plugins/
├── pyproject.toml
├── my_ash_plugins/
│   ├── __init__.py
│   ├── scanners.py
│   ├── reporters.py
│   └── converters.py
```

Install it into the Python environment ASH runs in. `examples/ash_plugins_example` in the ASH repository is a complete package of this shape.

### Plugin Registration in Package

Import the plugin modules in the package's `__init__.py`, so that importing the package runs the decorators:

```python
from my_ash_plugins.scanners import CustomRegexScanner
from my_ash_plugins.reporters import CustomJSONReporter
from my_ash_plugins.converters import YamlTemplateConverter

# Read by the loader to report what the package provided; the decorators do the
# registering.
ASH_SCANNERS = [CustomRegexScanner]
ASH_REPORTERS = [CustomJSONReporter]
ASH_CONVERTERS = [YamlTemplateConverter]
```

### Using Custom Plugin Packages

Configure ASH to use your custom plugin package:

```yaml
# ASH configuration
ash_plugin_modules:
  - "my_ash_plugins"
```

Or specify via command line:

```bash
ash --ash-plugin-modules my_ash_plugins
```

The flag can be repeated, and it, the `ASH_PLUGIN_MODULES` environment variable and each `ash_plugin_modules` entry also take a comma-separated list, such as `"my_ash_plugins, other_ash_plugins"`.

The package name has to be inside ASH's plugin namespace, which `my_ash_plugins` is
because it ends in `_ash_plugins`; a name outside it refuses the scan with exit code 3
(see [Custom Plugin Modules](../configuration-guide.md#custom-plugin-modules)).

A scan that names your package uses three kinds of plugin from it: those defined in
the package's own `__init__.py`, the classes and functions `__init__.py` imports into
its namespace (as in the example above), and those it lists in `ASH_SCANNERS`,
`ASH_REPORTERS`, `ASH_CONVERTERS` or `ASH_EVENT_HANDLERS`. A plugin defined only in a
submodule, such as a class in `my_ash_plugins/scanners.py` that `__init__.py` neither
imports nor lists, is not used through the package; the scan uses it only if it names
that submodule (`my_ash_plugins.scanners`) itself. The same holds for a plugin defined
in another package, for example a helper library whose classes carry
`@ash_scanner_plugin`: `from helper_lib import HelperScanner` in `__init__.py` makes
the scan use it, and `import helper_lib` alone does not, though the class registers
either way. The scan logs how many registered plugins it leaves out ("... registered
plugin(s) not used by this scan"), in the console and in `ash.log` in the output
directory. Run it with `--debug` to have the console list them, in a line starting
"Registered plugins not used by this scan". `ash.log` keeps only the count, because in
a process that runs several scans, such as the MCP server, the plugins one scan leaves
out are often the ones other scans named.

Plugin classes are registered by module and class name, so your class may share its
name with a class in another plugin package or with one of ASH's built-in plugins.
Each one registers, neither replaces the other, and each takes part in the scans that
select it.

A process that runs several scans, such as the MCP server or a program calling
`run_ash_scan` more than once, keeps every plugin module any of them imported
registered, but each scan still uses only the modules it names. A module the operator
named for one scan, for example in one MCP session's profile, takes no part in a later
scan that does not name it. If your own program registers plugin classes itself
instead of shipping them in a package, define them in a module inside the plugin
namespace and name that module in each scan's `ash_plugin_modules`: a class registered
from a module the scan does not name is not used by that scan.

`ash plugin list --ash-plugin-modules my_ash_plugins` shows the plugins that are registered once the modules are imported, which is the set a scan selects from: a decorated class appears whether or not the package lists it in `ASH_SCANNERS`, and a listed class that no decorator registered does not.

## Best Practices

### Plugin Design

- **Single Responsibility**: Each plugin should do one thing well
- **Configurability**: Make plugins configurable for different use cases
- **Error Handling**: Handle errors gracefully and provide useful error messages
- **Performance**: Optimize for performance, especially for large codebases
- **Documentation**: Document your plugins thoroughly

### Logging from threads your plugin starts

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

### Testing Plugins

Create tests for your plugins. Construct a plugin with a `PluginContext` and call the method ASH calls:

```python
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from my_ash_plugins.scanners import CustomRegexScanner


def test_custom_regex_scanner(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "test.py").write_text('password = "secret123"\n', encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="scanner-test"),
    )

    scanner = CustomRegexScanner(context=context)
    report = scanner.scan(target=source, target_type="source")

    (result,) = report.runs[0].results
    location = result.locations[0].physicalLocation.root
    assert Path(location.artifactLocation.uri).name == "test.py"
    assert location.region.startLine == 1
```

## Troubleshooting

### Common Issues

- **Plugin Not Found**: Ensure your plugin module is in the Python path
- **Configuration Errors**: Validate your configuration against the plugin's schema
- **Dependency Issues**: Check that all required dependencies are installed
- **Performance Problems**: Profile your plugin to identify bottlenecks

### Debugging Plugins

Enable debug logging to troubleshoot plugin issues:

```bash
ash --debug
```

## Next Steps

- **[Scanner Plugin Guide](scanner-plugins.md)**: Detailed guide for scanner plugins
- **[Reporter Plugin Guide](reporter-plugins.md)**: Detailed guide for reporter plugins
- **[Converter Plugin Guide](converter-plugins.md)**: Detailed guide for converter plugins
- **[Event Subscriber Guide](event-subscribers.md)**: Detailed guide for event subscribers
- **[Plugin Best Practices](plugin-best-practices.md)**: Best practices for plugin development
