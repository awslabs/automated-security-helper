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


class CycloneDXReporterConfigOptions(ReporterOptionsBase):
    pass


class CycloneDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["cyclonedx"] = "cyclonedx"
    extension: str = "cdx.json"
    enabled: bool = True
    options: CycloneDXReporterConfigOptions = CycloneDXReporterConfigOptions()


@ash_reporter_plugin
class CycloneDXReporter(ReporterPluginBase[CycloneDXReporterConfig]):
    """Formats results as CycloneDX.

    Workspace mode: per project. A workspace of independently versioned
    deliverables is N SBOMs, not one.

    A CycloneDX document describes the bill of materials of a single subject, and
    its ``metadata.component`` names that subject. Concatenating N projects'
    components under one subject produces a document that is true of nothing an
    operator can ship, sign, or hand to a downstream consumer: two projects
    pinning different versions of the same library appear as one deliverable
    depending on both.

    There is also a mechanical consequence worth naming, because it is what makes
    the ruling safe rather than merely principled. The unified workspace file
    carries no ``cyclonedx`` at all -- ``WorkspaceAggregator`` omits it for
    exactly the reason above -- so ``model.cyclonedx.model_dump_json()`` here
    would raise ``AttributeError`` on ``None``. ``ReportPhase`` catches reporter
    exceptions and logs them, so at workspace level this would have produced no
    artefact and no clear reason, which is the silence this contract exists to
    prevent. Declaring per project means the reporter is never invoked with that
    model, so the crash is unreachable rather than merely unlikely.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = CycloneDXReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in CycloneDX."""

        return model.cyclonedx.model_dump_json(
            by_alias=True,
            exclude_unset=True,
            exclude_none=True,
            # exclude_defaults=True,
        )
