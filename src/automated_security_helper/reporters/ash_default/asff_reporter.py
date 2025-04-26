# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from pydantic import Field
import yaml

from typing import Annotated, Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


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


class ASFFReporter(ReporterPluginBase[ASFFReporterConfig]):
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def report(self, model: Any) -> str:
        """Format ASH model in Amazon Security Finding Format (ASFF)."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        # TODO - Replace with ASFF reporter
        return yaml.dump(model.model_dump(by_alias=True), indent=2)
