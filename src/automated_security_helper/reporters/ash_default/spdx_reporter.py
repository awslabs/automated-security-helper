# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class SPDXReporterConfigOptions(ReporterOptionsBase):
    pass


class SPDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["spdx"] = "spdx"
    extension: str = "spdx.json"
    enabled: bool = True


class SPDXReporter(ReporterPluginBase[SPDXReporterConfig]):
    """Formats results as SPDX."""

    def report(self, model: Any) -> str:
        """Format ASH model in SPDX."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")
        # TODO - Replace with SPDX adapter
        return yaml.dump(model.model_dump(by_alias=True), indent=2)
