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
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    AggregateType,
    Compositions,
    CycloneDXReport,
)


def serialize_bom(report: CycloneDXReport) -> str:
    """The CycloneDX document the reporter writes for ``report``.

    The one place the reporter's dump shape lives, so a test of what ``ash
    report`` emits calls the reporter's own function instead of copying its
    flags. With no SBOM scanner in the run, ``report`` is the default
    ``CycloneDXReport()``. Nothing in it is set, so ``exclude_unset`` alone would
    dump ``{}``, which lacks the ``bomFormat`` and ``specVersion`` the CycloneDX
    schema requires, and a consumer given the file refuses it. A results file
    read back by ``ash report`` stores those defaults explicitly but no
    ``components``, which would be a second, different document for the same
    scan. Both give the envelope with an empty component list, and a
    ``compositions`` entry with aggregate ``unknown``: no SBOM scanner produced
    an inventory (it was missing, skipped or failed), so an empty list is not a
    statement that the project has no components. An SBOM a scanner produced
    already sets these fields, carries its own metadata, and is dumped
    unchanged. ``report`` itself is left as it was: the copy is what is marked.
    """
    bom = report.model_copy()
    # Every SBOM a scanner writes has metadata or a serial number; the default
    # model and its dump read back from a results file have neither.
    no_sbom = bom.metadata is None and bom.serialNumber is None and not bom.components
    # Assigning a field marks it set, so exclude_unset keeps it. The copy keeps
    # the model the other reporters read untouched.
    bom.bomFormat = bom.bomFormat
    bom.specVersion = bom.specVersion
    bom.version = bom.version
    if bom.components is None:
        bom.components = []
    if no_sbom and bom.compositions is None:
        bom.compositions = [Compositions(aggregate=AggregateType.unknown)]
    return bom.model_dump_json(
        by_alias=True,
        exclude_unset=True,
        exclude_none=True,
    )


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
    exactly the reason above. :meth:`report` writes an empty SBOM for a model
    without one, so at workspace level it would publish a document saying the
    workspace has no components, which is false. Declaring per project means the
    reporter is never invoked with that model.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = CycloneDXReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in CycloneDX (:func:`serialize_bom` says how)."""
        return serialize_bom(
            model.cyclonedx if model.cyclonedx is not None else CycloneDXReport()
        )
