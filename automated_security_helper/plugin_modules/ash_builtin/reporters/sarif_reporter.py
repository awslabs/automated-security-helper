# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
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
    """Formats results as SARIF.

    Workspace mode: one merged artefact carrying one run per project, each with
    its own ``originalUriBaseIds`` -- which is exactly the shape
    ``WorkspaceAggregator`` already built, so this reporter needs no code change
    beyond declaring that it passes it through whole.

    That "whole" is the load-bearing part, and it is why this reporter is tested
    in workspace mode rather than assumed correct. A future optimisation that
    collapsed the runs -- ``SarifReport.merge_sarif_report`` does precisely that,
    and it is a method on the object being dumped here -- would produce a
    document declaring one root for findings relative to N different roots, which
    GitHub code scanning mis-locates or rejects. The test that pins the run count
    fails first.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

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
