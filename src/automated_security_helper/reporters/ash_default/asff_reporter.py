# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml

from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class ASFFReporterConfigOptions(ReporterOptionsBase):
    pass


class ASFFReporterConfig(ReporterPluginConfigBase):
    name: Literal["asff"] = "asff"
    extension: str = "asff"
    enabled: bool = True


class ASFFReporter(ReporterPluginBase[ASFFReporterConfig]):
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def report(self, model: Any) -> str:
        """Format ASH model in Amazon Security Finding Format (ASFF)."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        # TODO - Replace with ASFF reporter
        return yaml.dump(model.model_dump(by_alias=True), indent=2)
