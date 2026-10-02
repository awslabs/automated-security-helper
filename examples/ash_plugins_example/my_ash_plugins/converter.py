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
from automated_security_helper.utils.log import ASH_LOGGER


class ExampleConverterConfigOptions(ConverterOptionsBase):
    pass


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
    """Example converter plugin that demonstrates the decorator pattern."""

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
        """Validate converter configuration.

        Returns:
            bool: True if validation passes
        """
        ASH_LOGGER.info("ExampleConverter: Validating configuration")
        return True

    def convert(self, target: Path | str) -> List[Path]:
        """Convert a target file/directory.

        This example converter simply logs the target and returns it unchanged.

        Args:
            target: Target file or directory to convert

        Returns:
            List[Path]: List of converted paths
        """
        if self.context is None:
            ASH_LOGGER.warning("ExampleConverter: No context provided!")
            return []

        target_path = Path(target)
        ASH_LOGGER.info(f"ExampleConverter: Converting {target_path}")

        # In a real converter, you would do some conversion here
        # For this example, we'll just return the target unchanged
        return [target_path]
