# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.utils.clean_dict import clean_dict


class SARIFReporterConfigOptions(ReporterOptionsBase):
    pass


class SARIFReporterConfig(ReporterPluginConfigBase):
    name: Literal["sarif"] = "sarif"
    extension: str = "sarif"
    enabled: bool = True
    options: SARIFReporterConfigOptions = SARIFReporterConfigOptions()


class SARIFReporter(ReporterPluginBase[SARIFReporterConfig]):
    """Formats results as SARIF."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SARIFReporterConfig()
        return super().model_post_init(context)

    def report(self, model: Any) -> str:
        """Format ASH model in SARIF."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        clean_sarif = clean_dict(
            input=model.sarif.model_dump(
                by_alias=True,
                exclude_unset=True,
                exclude_none=True,
                # exclude_defaults=True,
                # round_trip=True,
                mode="json",
            )
        )
        return json.dumps(clean_sarif, default=str)
