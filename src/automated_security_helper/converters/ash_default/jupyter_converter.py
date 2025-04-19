# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterScanner implementation."""

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
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename


class JupyterNotebookConverterConfigOptions(ConverterOptionsBase):
    pass


class JupyterNotebookConverterConfig(ConverterPluginConfigBase):
    """Jupyter Notebook (.ipynb) to Python converter configuration."""

    name: Literal["jupyter"] = "jupyter"
    enabled: bool = True
    options: Annotated[
        JupyterNotebookConverterConfigOptions,
        Field(description="Configure Jupyter Notebook converter"),
    ] = JupyterNotebookConverterConfigOptions()


class JupyterNotebookConverter(ConverterPluginBase[JupyterNotebookConverterConfig]):
    """Converter implementation for Jupyter notebooks security scanning."""

    config: JupyterNotebookConverterConfig = JupyterNotebookConverterConfig()

    def model_post_init(self, context):
        self.work_dir = (
            self.output_dir.joinpath("temp").joinpath("converters").joinpath("jupyter")
        )
        self.tool_version = version("nbconvert")
        if self.config is None:
            self.config = JupyterNotebookConverterConfig()
        return super().model_post_init(context)

    def validate(self):
        # Return True since this scanner is entirely within the same Python module,
        # so there is nothing further to validate in terms of availability.
        return True

    def convert(
        self,
    ) -> List[Path]:
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.source_dir}"
        )
        # Find all JSON/YAML files to scan from the scan set
        ipynb_files = scan_set(
            source=self.source_dir,
            output=self.output_dir,
            # filter_pattern=r"\.(ipynb)",
        )
        ipynb_files = [f.strip() for f in ipynb_files if f.strip().endswith(".ipynb")]
        ASH_LOGGER.verbose(f"Found {len(ipynb_files)} .ipynb files in scan set.")
        py_exporter: PythonExporter = PythonExporter()
        results: List[Path] = []
        for ipynb_file in ipynb_files:
            ASH_LOGGER.debug(f"Converting {ipynb_file} to .py")
            # Convert to Python
            normalized_archive_file = get_normalized_filename(ipynb_file)
            py_file = (
                self.work_dir.joinpath(self.config.name)
                .joinpath(normalized_archive_file)
                .joinpath(ipynb_file)
                .with_suffix(".py")
            )
            py_file.parent.mkdir(exist_ok=True, parents=True)
            (body, resources) = py_exporter.from_filename(
                filename=ipynb_file,
            )
            ASH_LOGGER.debug(f"Converted file body: {body}")
            ASH_LOGGER.debug(f"Converted file resources: {resources}")
            with open(py_file, "w") as f:
                f.write(body)
            ASH_LOGGER.verbose(
                f"Successfully converted {ipynb_file} to {py_file.as_posix()}!"
            )
            results.append(Path(py_file))

        return results
