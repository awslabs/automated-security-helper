# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterConverter implementation."""

from importlib.metadata import version
from pathlib import Path
from typing import Annotated, List, Literal
from nbconvert import PythonExporter

from pydantic import Field

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)

from automated_security_helper.base.options import (
    ConverterOptionsBase,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename


class JupyterConverterConfigOptions(ConverterOptionsBase):
    pass


class JupyterConverterConfig(ConverterPluginConfigBase):
    """Jupyter Notebook (.ipynb) to Python converter configuration."""

    name: Literal["jupyter"] = "jupyter"
    enabled: bool = True
    options: Annotated[
        JupyterConverterConfigOptions,
        Field(description="Configure Jupyter Notebook converter"),
    ] = JupyterConverterConfigOptions()


@ash_converter_plugin
class JupyterConverter(ConverterPluginBase[JupyterConverterConfig]):
    """Converter implementation for Jupyter notebooks security scanning."""

    def model_post_init(self, context):
        self.context.work_dir = self.context.output_dir.joinpath(
            ASH_WORK_DIR_NAME
        ).joinpath("jupyter")
        self.tool_version = version("nbconvert")
        if self.config is None:
            self.config = JupyterConverterConfig()
        # Ensure the config name is set correctly
        if hasattr(self.config, "name"):
            self.config.name = "jupyter"
        return super().model_post_init(context)

    def validate(self):
        # Return True since this scanner is entirely within the same Python module,
        # so there is nothing further to validate in terms of availability.
        return True

    def convert(self, target: Path | str = None) -> List[Path]:
        """Convert Jupyter notebooks to Python files.

        Args:
            target: Optional target path to convert. If None, all notebooks in source_dir are converted.

        Returns:
            List[Path]: List of converted Python files
        """
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.context.source_dir}"
        )

        # If target is provided, only convert that file if it's a notebook
        if target:
            target_path = Path(target)
            if target_path.suffix == ".ipynb":
                ipynb_files = [str(target_path)]
            else:
                return []
        else:
            # Find all JSON/YAML files to scan from the scan set
            ipynb_files = scan_set(
                source=self.context.source_dir,
                output=self.context.output_dir,
                # filter_pattern=r"\.(ipynb)",
            )
            ipynb_files = [
                f.strip() for f in ipynb_files if f.strip().endswith(".ipynb")
            ]

        ASH_LOGGER.verbose(f"Found {len(ipynb_files)} .ipynb files in scan set.")
        py_exporter: PythonExporter = PythonExporter()
        results: List[Path] = []

        for ipynb_file in ipynb_files:
            ASH_LOGGER.debug(f"Converting {ipynb_file} to .py")
            short_ipynb_file = get_shortest_name(ipynb_file)
            normalized_ipynb_file = get_normalized_filename(short_ipynb_file)
            # Ensure the target path has a .py extension
            target_path = self.context.work_dir.joinpath(
                normalized_ipynb_file.replace(".ipynb", "") + ".py"
            )
            target_path.parent.mkdir(parents=True, exist_ok=True)
            ASH_LOGGER.verbose(
                f"Converting {ipynb_file} to target_path: {Path(target_path).as_posix()}"
            )
            try:
                with open(ipynb_file, "r") as f:
                    (python_code, _) = py_exporter.from_file(f)
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_path, "w") as py_file:
                        py_file.write(python_code)
                    results.append(target_path)
            except Exception as e:
                ASH_LOGGER.error(f"Error converting {ipynb_file}: {e}")

        return results
