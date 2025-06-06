# Converter Plugins

Converter plugins transform files before scanning to make them compatible with security scanners. For example, converting Jupyter notebooks to Python files.

## Converter Plugin Interface

Converter plugins must implement the `ConverterPluginBase` interface:

```python
from automated_security_helper.base.converter_plugin import ConverterPluginBase, ConverterPluginConfigBase
from automated_security_helper.plugins.decorators import ash_converter_plugin

@ash_converter_plugin
class MyConverter(ConverterPluginBase):
    """My custom converter implementation"""

    def convert(self, target):
        """Convert the target file or directory"""
        # Your code here
```

## Converter Plugin Configuration

Define a configuration class for your converter:

```python
from typing import List
from pydantic import Field

class MyConverterConfig(ConverterPluginConfigBase):
    name: str = "my-converter"
    enabled: bool = True

    class Options:
        file_extensions: List[str] = Field(default=[".ipynb"], description="File extensions to convert")
        preserve_line_numbers: bool = Field(default=True, description="Preserve line numbers in converted files")
```

## Converter Plugin Example

Here's a complete example of a custom converter plugin:

```python
import json
import os
from pathlib import Path
from typing import List

from pydantic import Field

from automated_security_helper.base.converter_plugin import ConverterPluginBase, ConverterPluginConfigBase
from automated_security_helper.plugins.decorators import ash_converter_plugin

class JupyterConverterConfig(ConverterPluginConfigBase):
    """Configuration for JupyterConverter"""
    name: str = "jupyter"
    enabled: bool = True

    class Options:
        file_extensions: List[str] = Field(default=[".ipynb"], description="File extensions to convert")
        preserve_line_numbers: bool = Field(default=True, description="Preserve line numbers in converted files")
        include_markdown: bool = Field(default=False, description="Include markdown cells in output")

@ash_converter_plugin
class JupyterConverter(ConverterPluginBase):
    """Converts Jupyter notebooks to Python files"""

    def convert(self, target: Path):
        """Convert Jupyter notebooks to Python files"""
        if target.is_file():
            if target.suffix in self.config.options.file_extensions:
                return self._convert_file(target)
            return None

        # Process directory
        converted_dir = self.converted_dir / target.name
        converted_dir.mkdir(parents=True, exist_ok=True)

        # Find all notebook files
        notebook_files = []
        for ext in self.config.options.file_extensions:
            notebook_files.extend(target.glob(f"**/*{ext}"))

        # Convert each notebook
        for notebook_file in notebook_files:
            rel_path = notebook_file.relative_to(target)
            output_path = converted_dir / rel_path.with_suffix(".py")
            output_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                self._convert_notebook(notebook_file, output_path)
            except Exception as e:
                self._plugin_log(
                    f"Error converting {notebook_file}: {str(e)}",
                    level="ERROR",
                    append_to_stream="stderr",
                )

        return converted_dir

    def _convert_file(self, file_path: Path):
        """Convert a single notebook file"""
        output_path = self.converted_dir / file_path.with_suffix(".py").name
        self.converted_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._convert_notebook(file_path, output_path)
            return output_path
        except Exception as e:
            self._plugin_log(
                f"Error converting {file_path}: {str(e)}",
                level="ERROR",
                append_to_stream="stderr",
            )
            return None

    def _convert_notebook(self, input_path: Path, output_path: Path):
        """Convert a notebook to a Python file"""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                notebook = json.load(f)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"# Converted from {input_path.name}\n\n")

                cell_count = 0
                for cell in notebook.get("cells", []):
                    cell_type = cell.get("cell_type")
                    source = cell.get("source", [])

                    # Skip non-code cells if not including markdown
                    if cell_type != "code" and not self.config.options.include_markdown:
                        continue

                    # Join source lines
                    if isinstance(source, list):
                        source = "".join(source)

                    # Add cell marker
                    cell_count += 1
                    f.write(f"# Cell {cell_count} ({cell_type})\n")

                    # Write content
                    if cell_type == "code":
                        f.write(source)
                    else:
                        # Comment out markdown
                        for line in source.split("\n"):
                            f.write(f"# {line}\n")

                    f.write("\n\n")

            return output_path
        except Exception as e:
            raise Exception(f"Failed to convert notebook: {str(e)}")
```

## Converter Plugin Best Practices

1. **Preserve Line Numbers**: Try to preserve line numbers for better mapping of findings
2. **Handle Directories**: Support converting both individual files and directories
3. **Error Handling**: Use try/except blocks to handle errors
4. **Logging**: Use the `_plugin_log` method for logging
5. **Return Paths**: Return the path to the converted file or directory

## Converter Plugin Configuration in ASH

Configure your converter in the ASH configuration file:

```yaml
# .ash/.ash.yaml
converters:
  jupyter:
    enabled: true
    options:
      file_extensions: [".ipynb"]
      preserve_line_numbers: true
      include_markdown: false
```

## Testing Converter Plugins

Create unit tests for your converter:

```python
import pytest
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from my_ash_plugins.converters import JupyterConverter

def test_jupyter_converter():
    # Create a plugin context
    context = PluginContext(
        source_dir=Path("test_data"),
        output_dir=Path("test_output"),
        converted_dir=Path("test_output/converted")
    )

    # Create converter instance
    converter = JupyterConverter(context=context)

    # Create a test notebook
    notebook_path = Path("test_data/test.ipynb")
    with open(notebook_path, "w") as f:
        f.write('{"cells": [{"cell_type": "code", "source": ["print(\\"Hello, world!\\")\\n"]}]}')

    # Convert the notebook
    converted_path = converter.convert(notebook_path)

    # Assert conversion
    assert converted_path is not None
    assert converted_path.exists()
    with open(converted_path, "r") as f:
        content = f.read()
        assert "print(\"Hello, world!\")" in content
```