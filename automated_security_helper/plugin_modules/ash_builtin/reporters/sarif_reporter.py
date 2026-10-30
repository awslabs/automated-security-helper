# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Callable, Dict, List, Literal, Tuple, TYPE_CHECKING

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
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.severity_ladder import effective_sarif_level
from automated_security_helper.schemas.sarif_schema_model import (
    ReportingDescriptorReference,
    ReportingDescriptorReference1,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
    ToolComponentReference,
)

#: The log written for a results model whose ``sarif`` is None: a valid SARIF
#: 2.1.0 document with no runs. Every field is set explicitly because the
#: reporter dumps with ``exclude_unset``, which would leave a bare ``{}``.
_EMPTY_LOG = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [],
}


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
        """Format ASH model in SARIF, each result referencing its scanner's rule.

        An input a converter did not read is added to the document as an
        invocation of its own, one execution notification per input, so a SARIF
        reader learns which parts of the tree were not scanned
        (``utils/converter_refusals.py``). Added to a copy: the scan's own SARIF,
        which the exit-code gates read, is left as it is.

        A model whose ``sarif`` is None (the field allows it, and a results file
        read back can hold it) is written as a log with no runs, the way the
        other reporters treat a missing SARIF, where this raised AttributeError
        and ``ash.sarif`` was not written at all. A log with no runs that has
        refusals to report gets one run of ASH's own to carry them: dropped, as
        they were, the document said nothing about the inputs that were not
        scanned, and nothing said it was silent.
        """
        sarif = model.sarif
        if sarif is None:
            sarif = SarifReport.model_validate(_EMPTY_LOG)
        invocations = refusal_invocations(model)
        per_project = workspace_converter_invocations(model)
        if invocations or per_project:
            sarif = sarif.model_copy(deep=True)
            if not sarif.runs:
                sarif.runs = [
                    _run_carrying(
                        invocations
                        + [
                            invocation
                            for _, project_invocations in per_project
                            for invocation in project_invocations
                        ]
                    )
                ]
            else:
                if invocations:
                    # A single-directory scan's results carry one run; the
                    # unified workspace model keeps its top-level converter rows
                    # empty, so this is never the arm that reports a project's
                    # converters.
                    run = sarif.runs[0]
                    run.invocations = list(run.invocations or []) + invocations
                for run_index, project_invocations in per_project:
                    if 0 <= run_index < len(sarif.runs):
                        run = sarif.runs[run_index]
                        run.invocations = (
                            list(run.invocations or []) + project_invocations
                        )
        restore = complete_results_for_the_dump(sarif)
        try:
            return sarif.model_dump_json(
                by_alias=True, exclude_none=True, exclude_unset=True
            )
        finally:
            restore()


def _run_carrying(invocations: List[Any]) -> Run:
    """A run of ASH's own, with no results, carrying *invocations*.

    For a log that has no run to attach a converter's refusals to. The driver is
    ASH, which is what ran the converters; a reader sees which inputs were not
    scanned without a scanner's run to find them on.
    """
    return Run(
        tool=Tool(
            driver=ToolComponent(
                name="AWS Labs - Automated Security Helper",
                version=get_ash_version(),
                organization="Amazon Web Services",
            )
        ),
        results=[],
        invocations=list(invocations),
    )


def workspace_converter_invocations(
    model: "AshAggregatedResults",
) -> List[Tuple[int, List[Any]]]:
    """Each project's converter shortfalls as invocations on that project's run.

    The unified workspace model carries no top-level converter rows (its
    ``converter_results`` is empty, because converter paths are relative to one
    project's tree), so :func:`refusal_invocations` found nothing and the
    workspace-level ``ash.sarif`` said nothing about a converter that lost
    coverage in any project. What the model does carry is each project's
    ``incomplete_converters`` (converter name to reason) and its
    ``sarif_run_index``, so this adds to each project's own run one invocation
    per converter that did not complete there, ``executionSuccessful`` false,
    with one error-level notification naming the converter and the reason. The
    per-input records a single-directory ``ash.sarif`` carries are not in the
    unified model, so a workspace document names the converter and not the
    inputs; the project's own ``projects/<key>/reports/ash.sarif`` has them.

    Returns ``(run index, invocations)`` pairs; empty for a model that is not a
    workspace scan, so the single-directory document is unchanged.
    """
    from automated_security_helper.schemas.sarif_schema_model import (
        Invocation,
        Level,
        Message,
        Message1,
        Notification,
        PropertyBag,
        ReportingDescriptorReference,
        ReportingDescriptorReference3,
    )
    from automated_security_helper.utils.converter_refusals import (
        REFUSED_INPUT_NOTIFICATION_ID,
    )

    workspace = getattr(model, "workspace", None)
    projects = getattr(workspace, "projects", None)
    if not isinstance(projects, list):
        return []

    pairs: List[Tuple[int, List[Any]]] = []
    for project in projects:
        run_index = getattr(project, "sarif_run_index", None)
        rows = getattr(project, "incomplete_converters", None)
        if not isinstance(run_index, int) or not isinstance(rows, dict) or not rows:
            continue
        key = getattr(project, "project", None)
        invocations = []
        for converter, reason in sorted(rows.items()):
            invocations.append(
                Invocation(
                    executionSuccessful=False,
                    toolExecutionNotifications=[
                        Notification(
                            level=Level.error,
                            message=Message(
                                root=Message1(
                                    text=(
                                        f"{converter}: inputs of project "
                                        f"'{key}' were not scanned: {reason}"
                                    )
                                )
                            ),
                            descriptor=ReportingDescriptorReference(
                                root=ReportingDescriptorReference3(
                                    id=REFUSED_INPUT_NOTIFICATION_ID
                                )
                            ),
                        )
                    ],
                    properties=PropertyBag.model_validate(
                        {"ash_converter": str(converter), "workspace_project": key}
                    ),
                )
            )
        pairs.append((run_index, invocations))
    return pairs


def complete_results_for_the_dump(sarif: Any) -> Callable[[], None]:
    """State each result's level, and point it at its rule in its scanner's extension.

    The level first. ``ash.sarif`` is dumped with ``exclude_unset``, so a result
    whose level was never set would be written without one, while the results model
    reads it as its default, and the gate, which reads the file, would grade it
    differently from every report. So each result's level is written, as
    ``effective_sarif_level`` reads it, and the file and memory agree.

    ASH writes one run (per project) whose ``tool.driver`` is ASH and whose
    ``tool.extensions`` are the scanners, each with its own name, version and
    rules. A result named its rule only by ``ruleId``, and without
    ``rule.toolComponent`` a reader looks the rule up in ``tool.driver.rules``,
    which is empty. SARIF 2.1.0 3.27.7: "If theDescriptor occurs in
    theTool.extensions (3.18.3), then rule SHOULD be present", since "ruleIndex
    alone does not specify which extension contains theDescriptor".

    For a result whose ``properties.scanner_name`` names an extension that
    defines its ``ruleId``, ``rule`` becomes ``{id, index, toolComponent: {name,
    index}}``: ``id`` equal to ``ruleId`` (3.27.5), ``index`` the rule's position
    in that extension's ``rules`` and ``toolComponent.index`` the extension's
    position in ``tool.extensions``. Same-named extensions (the merge keeps them
    apart when fullName or organization differ) are tried in order. A result
    whose rule no extension defines is left alone: 3.27.7 says ``rule`` SHALL NOT
    be present without a descriptor. ``ruleIndex``, which would have to equal
    ``rule.index`` (3.27.6), is only updated where a result already has one.

    The references are set on the model itself, built with ``model_construct``,
    so the reporter dumps the document once and validates nothing a second
    time; an earlier version dumped, parsed and re-validated the whole document,
    which took about 15 times as long on 20,000 results. Returns the function
    that puts back every field it set, and whether the field was set, so the
    results model, and the ``ash_aggregated_results.json`` written from it, keep
    no extension indices that a later merge could reorder.
    """
    changed: List[Tuple[Any, str, Any, bool]] = []

    def assign(result: Any, field: str, value: Any) -> None:
        changed.append(
            (result, field, getattr(result, field), field in result.model_fields_set)
        )
        setattr(result, field, value)

    for run in getattr(sarif, "runs", None) or []:
        tool = getattr(run, "tool", None)
        components: Dict[Any, List[Tuple[Any, Dict[Any, int]]]] = {}
        for component_index, extension in enumerate(
            getattr(tool, "extensions", None) or []
        ):
            rule_positions: Dict[Any, int] = {}
            for rule_index, rule in enumerate(extension.rules or []):
                rule_positions.setdefault(rule.id, rule_index)
            component_reference = ToolComponentReference.model_construct(
                name=extension.name, index=component_index
            )
            components.setdefault(extension.name, []).append(
                (component_reference, rule_positions)
            )
        for result in run.results or []:
            if "level" not in result.model_fields_set:
                assign(result, "level", effective_sarif_level(result))
        if not components:
            continue
        # One reference per (extension, rule) for results whose existing rule
        # carries nothing else; the dump does not care that they are shared.
        shared: Dict[Tuple[Any, Any], Any] = {}
        for result in run.results or []:
            scanner = getattr(result.properties, "scanner_name", None)
            existing = result.rule.root if result.rule is not None else None
            rule_id = result.ruleId or getattr(existing, "id", None)
            for component, rule_positions in components.get(scanner, []):
                if rule_id not in rule_positions:
                    continue
                carried = {
                    key: getattr(existing, key)
                    for key in (existing.model_fields_set if existing else ())
                    if key not in ("id", "index", "toolComponent")
                }
                key = (component.index, rule_id)
                reference = None if carried else shared.get(key)
                if reference is None:
                    reference = ReportingDescriptorReference.model_construct(
                        root=ReportingDescriptorReference1.model_construct(
                            id=rule_id,
                            index=rule_positions[rule_id],
                            toolComponent=component,
                            **carried,
                        )
                    )
                    if not carried:
                        shared[key] = reference
                assign(result, "rule", reference)
                if (
                    "ruleIndex" in result.model_fields_set
                    and result.ruleIndex is not None
                ):
                    assign(result, "ruleIndex", rule_positions[rule_id])
                break

    def restore() -> None:
        for result, field, value, was_set in reversed(changed):
            setattr(result, field, value)
            if not was_set:
                result.model_fields_set.discard(field)

    return restore
