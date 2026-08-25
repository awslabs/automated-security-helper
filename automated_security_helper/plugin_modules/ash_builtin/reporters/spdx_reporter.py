# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import yaml
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
from automated_security_helper.utils.log import ASH_LOGGER


class SPDXReporterConfigOptions(ReporterOptionsBase):
    pass


class SPDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["spdx"] = "spdx"
    extension: str = "spdx.json"
    enabled: bool = False
    options: SPDXReporterConfigOptions = SPDXReporterConfigOptions()


@ash_reporter_plugin
class SpdxReporter(ReporterPluginBase[SPDXReporterConfig]):
    """Formats results as SPDX.

    Workspace mode: per project, on the same ground as ``cyclonedx_reporter`` --
    an SPDX document describes one package with one set of licence and
    provenance conclusions, and N independently versioned deliverables are N
    documents.

    Worth stating explicitly here because this reporter would not have *failed*
    at workspace level. It dumps the whole model, so it would have emitted a
    file: a workspace-shaped YAML blob presented as an SPDX document. An artefact
    that is confidently wrong is harder to notice than one that is missing, and
    the ruling is what keeps it from being produced. (The document is not valid
    SPDX in single-directory mode either -- see the stub warning in ``report()``
    -- but that is a separate gap and not one this phase closes.)
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = SPDXReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in SPDX."""
        # TODO - Replace with SPDX adapter
        ASH_LOGGER.warning(
            "SpdxReporter.report() is a stub -- proper SPDX document generation is "
            "not yet implemented. The returned YAML is a raw model dump, not a valid "
            "SPDX document."
        )
        return yaml.dump(model.model_dump(by_alias=True), indent=2)
