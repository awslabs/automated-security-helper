# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class CycloneDXReporterConfigOptions(ReporterOptionsBase):
    pass


class CycloneDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["cyclonedx"] = "cyclonedx"
    extension: str = "cdx.json"
    enabled: bool = True
    options: CycloneDXReporterConfigOptions = CycloneDXReporterConfigOptions()


@ash_reporter_plugin
class CycloneDXReporter(ReporterPluginBase[CycloneDXReporterConfig]):
    """Formats results as CycloneDX."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CycloneDXReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "ASHARPModel") -> str:
        """Format ASH model in CycloneDX."""

        return model.cyclonedx.model_dump_json(
            by_alias=True,
            exclude_unset=True,
            exclude_none=True,
            # exclude_defaults=True,
        )
