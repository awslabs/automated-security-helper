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
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.sarif_utils import path_matches_pattern


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
        self.tool_version = version("nbconvert")
        return super().model_post_init(context)

    def validate(self):
        return self.tool_version is not None

    def convert(self) -> List[Path]:
        """Converts Jupyter notebooks (.ipynb files) in the source_dir to Python files.

        Returns:
            List[Path]: List of converted Python files
        """
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.context.source_dir}"
        )
        # Find all notebook files to scan from the scan set
        ipynb_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
        )
        ipynb_files = [f.strip() for f in ipynb_files if f.strip().endswith(".ipynb")]

        ASH_LOGGER.debug(f"Found {len(ipynb_files)} .ipynb files in scan set.")
        py_exporter: PythonExporter = PythonExporter()
        results: List[Path] = []

        # Add warning if no Jupyter notebook files found
        if not ipynb_files:
            ASH_LOGGER.warning(
                f"No Jupyter notebook (.ipynb) files found in {self.context.source_dir}"
            )
            return results

        self.results_dir.mkdir(parents=True, exist_ok=True)

        for ipynb_file in ipynb_files:
            try:
                skip_item = False
                # Skip directories
                if Path(ipynb_file).is_dir():
                    ASH_LOGGER.debug(f"Skipping directory: {ipynb_file}")
                    skip_item = True
                else:
                    for ignore_path in self.context.config.global_settings.ignore_paths:
                        rel_path = (
                            Path(ipynb_file)
                            .relative_to(self.context.source_dir)
                            .as_posix()
                        )
                        if path_matches_pattern(rel_path, ignore_path.path):
                            ASH_LOGGER.debug(
                                f"Skipping conversion of ignored path: {ipynb_file} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                            )
                            skip_item = True
                            break
                if skip_item:
                    continue
                ASH_LOGGER.debug(f"Converting {ipynb_file} to .py")
                short_ipynb_file = get_shortest_name(ipynb_file)
                normalized_ipynb_file = get_normalized_filename(short_ipynb_file)
                # Ensure the target path has a .py extension
                target_path = self.results_dir.joinpath(
                    normalized_ipynb_file.replace(".ipynb", "") + ".py"
                )
                target_path.parent.mkdir(parents=True, exist_ok=True)
                ASH_LOGGER.verbose(
                    f"Converting {ipynb_file} to target_path: {Path(target_path).as_posix()}"
                )

                with open(ipynb_file, mode="r", encoding="utf-8") as f:
                    (python_code, _) = py_exporter.from_file(f)
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_path, mode="w", encoding="utf-8") as py_file:
                        py_file.write(python_code)
                    results.append(target_path)
            except Exception as e:
                ASH_LOGGER.error(f"Error converting {ipynb_file}: {e}")
                import traceback

                ASH_LOGGER.debug(
                    f"Jupyter conversion error traceback: {traceback.format_exc()}"
                )

        return results
