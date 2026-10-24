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
from automated_security_helper.utils.converter_refusals import refusal_invocations


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
        """Format ASH model in SARIF.

        An input a converter did not read is added to the document as an
        invocation of its own, one execution notification per input, so a SARIF
        reader learns which parts of the tree were not scanned
        (``utils/converter_refusals.py``). Added to a copy: the scan's own SARIF,
        which the exit-code gates read, is left as it is.
        """
        sarif = model.sarif
        invocations = refusal_invocations(model)
        if invocations and sarif is not None and sarif.runs:
            sarif = sarif.model_copy(deep=True)
            run = sarif.runs[0]
            run.invocations = list(run.invocations or []) + invocations
        return sarif.model_dump_json(
            by_alias=True,
            exclude_none=True,
            exclude_unset=True,
            # exclude_defaults=True,
        )
