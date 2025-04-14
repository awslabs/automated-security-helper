# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class CycloneDXReporterConfigOptions(ReporterOptionsBase):
    pass


class CycloneDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["cyclonedx"] = "cyclonedx"
    extension: str = "cdx.json"
    enabled: bool = True


class CycloneDXReporter(ReporterPluginBase[CycloneDXReporterConfig]):
    """Formats results as CycloneDX."""

    def format(self, model: Any) -> str:
        """Format ASH model in CycloneDX."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        return model.cyclonedx.model_dump_json()
