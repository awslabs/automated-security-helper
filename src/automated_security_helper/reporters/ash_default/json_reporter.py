# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class JSONReporterConfigOptions(ReporterOptionsBase):
    pass


class JSONReporterConfig(ReporterPluginConfigBase):
    name: Literal["json"] = "json"
    extension: str = "json"
    enabled: bool = False


class JSONReporter(ReporterPluginBase[JSONReporterConfig]):
    """Formats results as JSON."""

    def report(self, model: Any) -> str:
        """Format ASH model as JSON string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        return model.model_dump_json(by_alias=True)
