# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, Literal, TYPE_CHECKING

from pydantic import BaseModel

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
    LicenseChoice,
    LicenseEntry,
    LicenseExpression,
)


def _conforming_licenses(value: Any, counts: Dict[str, int]) -> Any:
    """``value`` with every license list reduced to what CycloneDX 1.6 allows.

    A license list holds license objects and SPDX expressions. The model keeps
    any other entry as written when it loads a stored BOM, so that one entry
    does not refuse the component that carries it; a document written for
    other tools must not repeat it. A bare id is written as an expression
    (``"MIT"`` is an SPDX expression), and any other entry is left out. Both
    are counted in ``counts``.

    Models and lists are copied only where something changed, so the BOM given
    in is left as it was.
    """
    if isinstance(value, LicenseChoice):
        kept = []
        for entry in value.root:
            if isinstance(entry, (LicenseEntry, LicenseExpression)):
                kept.append(entry)
            elif isinstance(entry, str):
                kept.append(LicenseExpression(expression=entry))
                counts["expressions"] += 1
            else:
                counts["dropped"] += 1
        unchanged = len(kept) == len(value.root) and all(
            new is old for new, old in zip(kept, value.root)
        )
        return value if unchanged else value.model_copy(update={"root": kept})
    if isinstance(value, BaseModel):
        updates = {}
        for name in value.model_fields_set:
            current = getattr(value, name, None)
            replaced = _conforming_licenses(current, counts)
            if replaced is not current:
                updates[name] = replaced
        return value.model_copy(update=updates) if updates else value
    if isinstance(value, list):
        items = [_conforming_licenses(item, counts) for item in value]
        if any(new is not old for new, old in zip(items, value)):
            return items
    return value


def conforming_bom(report: CycloneDXReport) -> CycloneDXReport:
    """``report`` with every license list reduced to what CycloneDX 1.6 allows.

    Every writer of a CycloneDX document from a stored BOM goes through this
    function, so the ``cyclonedx`` and ``gitlab-cyclonedx`` reporters agree on
    what a license list holds. A bare id is written as an SPDX expression and any
    other entry is left out, with one warning that counts both (see
    :func:`_conforming_licenses`). The BOM given in is left as it was, and is
    returned itself when nothing in it needed a change.
    """
    counts = {"expressions": 0, "dropped": 0}
    bom = _conforming_licenses(report, counts)
    if counts["expressions"] or counts["dropped"]:
        from automated_security_helper.utils.log import ASH_LOGGER

        ASH_LOGGER.warning(
            "CycloneDX 1.6 allows only license objects and SPDX expressions in a "
            "license list. In the SBOM written from this scan, "
            f"{counts['expressions']} bare license id(s) were written as SPDX "
            f"expressions and {counts['dropped']} other entry(ies) were left out; "
            "the stored results are unchanged."
        )
    return bom


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

    A license entry that is not a license object or an SPDX expression (a stored
    results file can hold one; see :func:`_conforming_licenses`) is not
    re-emitted: CycloneDX 1.6 consumers refuse a document that holds one. A bare
    id is written as an expression and any other entry is left out, with one
    warning that counts both.
    """
    bom = conforming_bom(report).model_copy()
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
