# Converter Plugins

Converter plugins transform files before scanning to make them compatible with security scanners. For example, converting Jupyter notebooks to Python files.

> For detailed visual diagrams of converter plugin architecture and workflow, see [Converter Plugin Diagrams](converter-plugins-diagrams.md).

## Converter Plugin Interface

A converter subclasses `ConverterPluginBase` and implements `convert(self)`:

```python
from pathlib import Path
from typing import List, Literal

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin


class MyConverterConfig(ConverterPluginConfigBase):
    name: Literal["my-converter"] = "my-converter"


@ash_converter_plugin
class MyConverter(ConverterPluginBase[MyConverterConfig]):
    """My custom converter implementation"""

    def model_post_init(self, context):
        if self.config is None:
            self.config = MyConverterConfig()
        return super().model_post_init(context)

    def convert(self) -> List[Path]:
        """Convert this converter's inputs and return the files written."""
        return []
```

ASH calls `convert()` once per scan, with no arguments. The converter:

- finds its inputs under `self.context.source_dir`, usually from the scan set (`automated_security_helper.utils.get_scan_set.scan_set`, which applies `.gitignore` and `.ignore` files), skipping the config's `global_settings.ignore_paths`;
- reads each input through `self.open_source_file(path)`, which refuses a symlink or a path outside the scanned directory, and passes a refusal to `self.record_refused_input()`;
- writes its output under `self.results_dir`, which is `<output-dir>/converted/<converter name>`;
- returns the list of paths it wrote, or an empty list when there was nothing to convert.

ASH then scans the files under `<output-dir>/converted` as a second target, of type `converted`.

A converter written as `convert(self, target)`, the signature `ConverterPluginBase` declared in earlier versions, does not run: ASH refuses any `convert()` that requires an argument, and the converter's row records an error that names it and says to declare `convert(self)`.

## Converter Plugin Configuration

Define a configuration class for your converter. Options go in a class derived from `ConverterOptionsBase`:

```python
from typing import Annotated, List, Literal

from pydantic import Field

from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.options import ConverterOptionsBase


class MyConverterConfigOptions(ConverterOptionsBase):
    suffixes: List[str] = Field(
        default=[".py.tmpl"],
        description="File name endings to convert into .py files",
    )


class MyConverterConfig(ConverterPluginConfigBase):
    name: Literal["my-converter"] = "my-converter"
    enabled: bool = True
    options: Annotated[
        MyConverterConfigOptions,
        Field(description="Configure my-converter"),
    ] = MyConverterConfigOptions()
```

## Converter Plugin Example

Here is a complete converter. It is the converter of the example plugin package in the ASH repository, `examples/ash_plugins_example`, which a test runs through a real scan. It copies each Python template in the scan set, `*.py.tmpl`, to a `.py` file, so that scanners which select files by extension read it too:

```python
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import TreeInputRefused
from automated_security_helper.utils.suppression_matcher import file_path_matches


class ExampleConverterConfigOptions(ConverterOptionsBase):
    suffixes: List[str] = Field(
        default=[".py.tmpl"],
        description="File name endings to convert into .py files",
    )


class ExampleConverterConfig(ConverterPluginConfigBase):
    """Configuration for the example converter."""

    name: Literal["my-example-converter"] = "my-example-converter"
    enabled: bool = True
    options: Annotated[
        ExampleConverterConfigOptions,
        Field(description="Configure my-example-converter"),
    ] = ExampleConverterConfigOptions()


@ash_converter_plugin
class ExampleConverter(ConverterPluginBase[ExampleConverterConfig]):
    """Copies Python templates (``*.py.tmpl``) to ``.py`` files the scanners read."""

    def model_post_init(self, context):
        # Do not assign to self.context: it is shared by every plugin in the run.
        if self.config is None:
            self.config = ExampleConverterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Pure Python, so there is nothing to install."""
        return True

    def convert(self) -> List[Path]:
        source_dir = Path(self.context.source_dir)
        suffixes = tuple(self.config.options.suffixes)
        ignore_paths = self.context.config.global_settings.ignore_paths or []

        written: List[Path] = []
        for name in scan_set(source=source_dir, output=self.context.output_dir):
            # Only the line ending a cached list leaves: "a.py.tmpl " is its own file.
            candidate = Path(name.rstrip("\n"))
            if not candidate.name.endswith(suffixes) or not candidate.is_file():
                continue
            relative = candidate.relative_to(source_dir)
            if any(
                file_path_matches(relative.as_posix(), ignore.path)
                for ignore in ignore_paths
            ):
                continue

            # Read through open_source_file, never open(): it refuses a symlink or
            # a path outside the scanned tree before anything is read.
            try:
                handle = self.open_source_file(candidate)
            except TreeInputRefused as refused:
                self.record_refused_input(refused)
                continue
            with handle:
                content = handle.read()

            suffix = next(s for s in suffixes if candidate.name.endswith(s))
            target = self.results_dir.joinpath(
                relative.parent, candidate.name[: -len(suffix)] + ".py"
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            ASH_LOGGER.debug(f"ExampleConverter: {relative.as_posix()} -> {target}")
            written.append(target)

        return written
```

## Converter Plugin Best Practices

1. **Preserve Line Numbers**: Keep each converted line on the line it came from where you can, so a finding in the converted file points at the right place in the original
2. **Read Through `open_source_file`**: Never `open()` an input by name; record a refused input with `record_refused_input`
3. **Write Under `results_dir`**: Do not assign to `self.context`, which every plugin in the run shares
4. **Error Handling**: Catch the errors a single input can raise, so one bad file does not stop the others; an exception out of `convert()` marks the whole converter failed
5. **Return Paths**: Return the list of files written, or an empty list

## Converter Plugin Configuration in ASH

Configure your converter in the ASH configuration file:

```yaml
# ASH config file (.ashrc.yaml in a new project)
converters:
  jupyter:
    enabled: true
    options:
      tool_version: null      # Version constraint for the conversion tool
      install_timeout: 300    # Seconds allowed for tool installation
```

## Testing Converter Plugins

Create unit tests for your converter. Construct it with a `PluginContext` and call `convert()`:

```python
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from my_ash_plugins.converter import ExampleConverter


def test_example_converter(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "settings.py.tmpl").write_text("NAME = 'x'\n", encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="converter-test"),
    )

    converter = ExampleConverter(context=context)
    written = converter.convert()

    assert [Path(p).name for p in written] == ["settings.py"]
    assert Path(written[0]).read_text(encoding="utf-8") == "NAME = 'x'\n"
```
