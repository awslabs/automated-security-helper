# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from pydantic import Field
import yaml

from typing import Annotated, Literal, TYPE_CHECKING

try:
    import boto3
except ImportError:
    boto3 = None

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class AsffReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}"
        ),
    ] = None
    aws_profile: str | None = None


class AsffReporterConfig(ReporterPluginConfigBase):
    name: Literal["asff"] = "asff"
    extension: str = "asff"
    enabled: bool = True
    options: AsffReporterConfigOptions = AsffReporterConfigOptions()


@ash_reporter_plugin
class AsffReporter(ReporterPluginBase[AsffReporterConfig]):
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = AsffReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in Amazon Security Finding Format (ASFF)."""
        # TODO - Replace with ASFF reporter
        return yaml.dump(
            model.model_dump(by_alias=True, exclude_unset=True, exclude_none=True),
            indent=2,
        )
