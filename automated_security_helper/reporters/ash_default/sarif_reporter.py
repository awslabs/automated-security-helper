# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class SARIFReporterConfigOptions(ReporterOptionsBase):
    pass


class SARIFReporterConfig(ReporterPluginConfigBase):
    name: Literal["sarif"] = "sarif"
    extension: str = "sarif"
    enabled: bool = True
    options: SARIFReporterConfigOptions = SARIFReporterConfigOptions()


@ash_reporter_plugin
class SarifReporter(ReporterPluginBase[SARIFReporterConfig]):
    """Formats results as SARIF."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SARIFReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in SARIF."""
        return model.sarif.model_dump_json(
            by_alias=True,
            exclude_none=True,
            exclude_unset=True,
            # exclude_defaults=True,
        )
        # clean_sarif = clean_dict(
        #     input=model.sarif.model_dump(
        #         by_alias=True,
        #         exclude_unset=True,
        #         exclude_none=True,
        #         # exclude_defaults=True,
        #         # round_trip=True,
        #         mode="json",
        #     )
        # )
        # return json.dumps(clean_sarif, default=str)
