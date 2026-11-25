# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Annotated, Literal, TYPE_CHECKING, Dict, Any

from pydantic import Field

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.flat_frame import flat_frame
from automated_security_helper.models.workspace import is_workspace_scan
from automated_security_helper.utils.content_db_staleness import (
    content_db_records,
    stale_content_databases,
)
from automated_security_helper.utils.converter_refusals import converter_refusals
from automated_security_helper.utils.finding_clusters import (
    annotate_enabled,
    annotation_values,
    assign_clusters_by_project,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)


class FlatJSONReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Flat JSON reporter."""

    include_scanner_metrics: Annotated[
        bool,
        Field(
            description="When true, the report carries a `scanner_metrics` key with one row per scanner: its finding counts by severity, its result status, and the severity threshold it was judged against. When false, the key is left out."
        ),
    ] = True
    include_summary_metrics: Annotated[
        bool,
        Field(
            description="Accepted for compatibility but not read: the report is written the same whether this is true or false. Use `include_scanner_metrics` and `include_metadata` to choose what the report carries."
        ),
    ] = True
    include_metadata: Annotated[
        bool,
        Field(
            description="When true, the report carries a `metadata` key with the project name, the scan time, the report time, and the ASH version. When false, the key is left out."
        ),
    ] = True


class FlatJSONReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Flat JSON reporter."""

    name: Literal["flat-json"] = "flat-json"
    extension: str = "flat.json"
    enabled: bool = True
    options: FlatJSONReporterConfigOptions = FlatJSONReporterConfigOptions()


@ash_reporter_plugin
class FlatJSONReporter(ReporterPluginBase[FlatJSONReporterConfig]):
    """Formats results as a flattened JSON array of findings.

    Workspace mode: one merged artefact. Each finding carries
    ``workspace_project``, and a ``workspace`` block carries the per-project
    verdicts so a consumer can group without re-deriving anything.

    The per-finding field needs no code here: ``FlatVulnerability`` reads it off
    ``result.properties.workspace_project``, which the aggregator sets on every
    result, and ``model_dump(exclude_none=True)`` omits it for a single-directory
    scan. So this output is unchanged outside workspace mode.

    What is frame work and what is not. The report has no count, group-by, join
    or ranking of its own over the findings: the counts (scanner metrics, top
    hotspots) are the content emitter's, already on frames, and the findings array
    is one JSON object per finding. Each object is that finding's own pydantic
    dump, and which keys it carries differs from finding to finding (a field
    nothing set, or set to ``None``, is left out), so the array has no single
    column schema and a frame cannot hold it; building the objects is row-wise
    serialization of nested models, not algebra over rows. The one value every
    finding carries regardless of what it set, ``is_suppressed``, is read from
    the flat frame's column of that name. The two content-database lists are a
    handful of records each, built from the model's own records, and stay as
    they are.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = FlatJSONReporterConfig()
        return super().model_post_init(context)

    @staticmethod
    def sarif_field_mappings() -> dict[str, str] | None:
        """
        Get mappings from SARIF fields to flat JSON fields.

        Returns:
            Dict[str, str]: Dictionary mapping SARIF field paths to flat JSON fields
        """
        return {
            "runs[].results[].ruleId": "rule_id",
            "runs[].results[].message.text": "description",
            "runs[].results[].level": "severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "file_path",
            "runs[].results[].locations[].physicalLocation.region.startLine": "line_start",
            "runs[].results[].locations[].physicalLocation.region.endLine": "line_end",
            "runs[].tool.driver.name": "scanner",
            "runs[].tool.driver.version": "scanner_version",
            "runs[].results[].properties.tags": "tags",
        }

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as JSON string with comprehensive statistics."""
        # Ensure config is properly typed if it was passed as a dictionary
        if isinstance(self.config, dict):
            self.config = FlatJSONReporterConfig.model_validate(self.config)

        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model)

        # Create the JSON structure
        report_data: Dict[str, Any] = {}

        # Add metadata if enabled
        if self.config.options.include_metadata:
            report_data["metadata"] = emitter.get_metadata()

        # Add scanner metrics if enabled
        if self.config.options.include_scanner_metrics:
            report_data["scanner_metrics"] = emitter.get_scanner_results()

        # Every content database the scan measured, fresh or stale, with its build time, age,
        # bound and whether it failed the scan. Always present (an empty list when no scanner
        # read one), so a consumer can tell "nothing was measured" from an older ASH that did
        # not report it. A stale entry under `content_db_staleness: warn` has stale=true and
        # enforced=false: the scan passed, and this is where a reader of the file learns it
        # passed against an out-of-date database.
        # The notification level is what decided the exit code, so it is what `enforced`
        # reports; the property record carries the policy too, and the two agree for
        # anything ASH wrote.
        # One entry per database and scanner: trivy and trivy-repo each read trivy-db.
        stale = {
            (record.name, record.scanner): record
            for record in stale_content_databases(model)
        }
        databases = []
        for record in content_db_records(model):
            entry = record.to_dict()
            verdict = stale.get((record.name, record.scanner))
            if verdict is not None:
                entry["policy"] = verdict.policy
                entry["enforced"] = verdict.enforced
            databases.append(entry)
        report_data["content_databases"] = databases

        # Every input a converter did not read, with scan_incomplete=true for an
        # archive refused whole for an extraction limit, which is what failed the
        # completeness gate. Always present, like content_databases, so an empty
        # list says nothing was refused.
        report_data["converter_refusals"] = [
            refusal.to_dict() for refusal in converter_refusals(model)
        ]

        # Add top hotspots
        report_data["top_hotspots"] = emitter.get_top_hotspots(10)

        # Add findings. Each carries workspace_project when the scan was a
        # workspace one; exclude_none drops it otherwise, so single-directory
        # output is unchanged.
        flat_vulns = model.to_flat_vulnerabilities()
        # The suppressed flag of every finding is one column of the run's flat
        # frame (models/flat_frame.py, row i = flat_vulns[i]); the rest of each
        # finding stays a row-wise dump (see the class docstring).
        suppressed = flat_frame(flat_vulns)["is_suppressed"].to_list()
        report_data["findings"] = [
            self._finding_dict(vuln, flag)
            for vuln, flag in zip(flat_vulns, suppressed, strict=True)
        ]

        # Opt-in duplicate annotation: a finding in a cluster gains its
        # cluster_id, and a primary or a non-primary member the other columns
        # that apply to it. A finding in no cluster, and every finding with the
        # option off, is exactly as it was (the report omits what is None).
        if annotate_enabled(model):
            for finding, assigned in zip(
                report_data["findings"],
                assign_clusters_by_project(flat_vulns),
                strict=True,
            ):
                finding.update(
                    {
                        key: value
                        for key, value in annotation_values(assigned).items()
                        if value is not None
                    }
                )

        # The per-project verdicts, so a consumer can group and judge without
        # re-deriving anything. Re-deriving would mean applying one threshold to
        # every project, and projects in a workspace are independently
        # configured -- so the consumer's answer would differ from the exit code
        # for the same run, with no rule for which is authoritative.
        if is_workspace_scan(model) and model.workspace is not None:
            report_data["workspace"] = model.workspace.model_dump(mode="json")

        # Return the JSON string
        return json.dumps(report_data, indent=2, default=str)

    @staticmethod
    def _finding_dict(vuln: Any, is_suppressed: bool) -> Dict[str, Any]:
        """One finding as the JSON object this report carries.

        ``exclude_unset`` keeps a single-directory finding free of fields nothing
        set, but it also dropped ``is_suppressed`` from the findings built from a
        scanner's additional report, whose constructor never sets it, while the
        findings built from SARIF results set it on every one. A consumer that
        filtered on the key read those findings as neither suppressed nor open.
        The field is the one value every finding has an answer for, so it is
        written for every finding, with *is_suppressed* (the flat frame's value
        for it) where nothing set it.
        """
        data = vuln.model_dump(exclude_none=True, exclude_unset=True, mode="json")
        data.setdefault("is_suppressed", is_suppressed)
        return data
