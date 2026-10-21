# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example converter plugin for ASH."""

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
    """Copies Python templates (``*.py.tmpl``) to ``.py`` files the scanners read.

    A scanner that selects files by extension skips ``app.py.tmpl``. This converter
    writes a copy named ``app.py`` under its results directory, and ASH scans the
    converted files as a second target.
    """

    def model_post_init(self, context):
        # Do not assign to self.context here. The context is one object shared by
        # every plugin in the run, so repointing work_dir would move where the
        # builtin converters' output is looked for, not just this plugin's.
        # ConverterPluginBase.model_post_init derives self.results_dir underneath
        # the shared work_dir, which is the directory a converter should write to.
        if self.config is None:
            self.config = ExampleConverterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Pure Python, so there is nothing to install."""
        return True

    def convert(self) -> List[Path]:
        """Convert every matching file in the scan set.

        ASH calls this once per scan with no arguments. The inputs come from the
        scan set under ``self.context.source_dir`` and the output goes under
        ``self.results_dir``.

        Returns:
            List[Path]: The files written, or an empty list when there was nothing
            to convert.
        """
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

            # Read through open_source_file, never open(): it refuses a symlink, a
            # file with a second hard link, or a path outside the scanned tree
            # before anything is read.
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
