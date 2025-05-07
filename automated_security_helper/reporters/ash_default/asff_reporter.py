# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from pydantic import Field
import yaml

from typing import Annotated, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResult
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class ASFFReporterConfigOptions(ReporterOptionsBase):
    aws_account_id: Annotated[str, Field(pattern=r"^\d{12}$")] = "123456789012"
    aws_region: Annotated[
        str,
        Field(
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}"
        ),
    ] = "us-east-1"


class ASFFReporterConfig(ReporterPluginConfigBase):
    name: Literal["asff"] = "asff"
    extension: str = "asff"
    enabled: bool = False
    options: ASFFReporterConfigOptions = ASFFReporterConfigOptions()


@ash_reporter_plugin
class AsffReporter(ReporterPluginBase[ASFFReporterConfig]):
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = ASFFReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResult") -> str:
        """Format ASH model in Amazon Security Finding Format (ASFF)."""
        # TODO - Replace with ASFF reporter
        return yaml.dump(
            model.model_dump(by_alias=True, exclude_unset=True, exclude_none=True),
            indent=2,
        )
