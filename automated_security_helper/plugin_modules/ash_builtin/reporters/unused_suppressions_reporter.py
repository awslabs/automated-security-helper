# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter for identifying unused suppressions."""

import json
from typing import Literal, TYPE_CHECKING, Any, ClassVar, Dict, List, Tuple

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.workspace import is_workspace_scan
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.models.core import (
    PACKAGE_SUPPRESSION_FIELDS,
    AshSuppression,
)
from automated_security_helper.utils.suppression_matcher import (
    recorded_suppressions,
    written_suppression_id,
)


def _one_line(text: str | None) -> str:
    """Flatten prose so it survives being interpolated into a markdown bullet.

    A newline in a suppression reason ends its bullet, and the remainder renders
    as loose body text detached from the suppression it describes.

    Collapsing at the point of rendering fixes the report for every existing
    config, with no edit to anyone's file. The config linter also warns about a
    multi-line reason and offers to collapse it, but that only helps someone who
    runs the linter and accepts the fix -- and `ash config lint --fix` re-dumps
    the whole config, dropping every comment in it. A hand-written block-scalar
    reason is a strong signal of a hand-commented config, which is exactly the
    file you least want rewritten.

    str.split() with no argument splits on newlines, carriage returns and tabs,
    so this handles a CRLF config as well as a YAML block scalar.
    """
    return " ".join((text or "").split())


class UnusedSuppressionsReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Unused Suppressions reporter."""

    output_format: str = "both"  # "json", "markdown", or "both"


class UnusedSuppressionsReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Unused Suppressions reporter."""

    name: Literal["unused-suppressions"] = "unused-suppressions"
    extension: str = "unused-suppressions.json"
    enabled: bool = True
    options: UnusedSuppressionsReporterConfigOptions = (
        UnusedSuppressionsReporterConfigOptions()
    )


@ash_reporter_plugin
class UnusedSuppressionsReporter(ReporterPluginBase[UnusedSuppressionsReporterConfig]):
    """Identifies and reports suppressions that were not applied to any findings.

    Workspace mode: ``WORKSPACE_SCOPED``. The per-project artefacts under
    ``projects/<key>/reports/`` answer the per-project question, and the
    workspace-level artefact reports only on *workspace-level* suppressions.

    Not ``MERGED``, and the distinction is the difference between an incomplete
    report and a false one. This reporter subtracts ``model.used_suppressions``
    from the suppressions its own config declares. The unified workspace file
    carries ``used_suppressions: []`` -- suppression matching happened inside each
    project's own scan, against that project's own config -- so a merged run
    would find nothing used and declare *every* suppression unused. An operator
    acting on that would delete suppressions that are load-bearing.

    Not ``PER_PROJECT`` either, because a workspace-level suppression that matched
    nothing in any project is a real thing to report and no per-project file can
    see it: each project only knows its own config.

    In this phase there are no workspace-level suppressions -- workspace-level
    config arrives in Phase 3 -- so the workspace artefact states a count of zero
    and says where the per-project reports are. It says that explicitly rather
    than being absent, because "no file" and "no findings" are the two readings a
    security report must never leave ambiguous, and this is the slot Phase 3 fills
    without changing the contract.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.WORKSPACE_SCOPED

    #: The markdown copy written beside the JSON report when ``output_format`` is
    #: ``both``.
    MARKDOWN_FILE_NAME: ClassVar[str] = "ash.unused-suppressions.md"

    def model_post_init(self, context):
        if self.config is None:
            self.config = UnusedSuppressionsReporterConfig()
        return super().model_post_init(context)

    def companion_file_names(self) -> Tuple[str, ...]:
        """The markdown copy, when ``output_format`` is ``both`` (the default)."""
        config = self.config
        if isinstance(config, dict):
            config = UnusedSuppressionsReporterConfig.model_validate(config)
        output_format = getattr(
            getattr(config, "options", None), "output_format", "both"
        )
        return (self.MARKDOWN_FILE_NAME,) if output_format == "both" else ()

    def report(self, model: "AshAggregatedResults") -> str:
        """Generate a report of unused suppressions."""
        # Ensure config is properly typed if it was passed as a dictionary
        if isinstance(self.config, dict):
            self.config = UnusedSuppressionsReporterConfig.model_validate(self.config)

        # Get all configured suppressions
        all_suppressions = self.context.config.global_settings.suppressions or []

        # Get used suppressions from the model
        used_suppressions = getattr(model, "used_suppressions", set())

        # A use is recorded by the written form's id (written_suppression_id):
        # a field read from the environment is its reference. An entry counts
        # as used by that id, and also by its resolved id, the form a results
        # file written before used ids took the written form recorded, but
        # only when no configured entry has the resolved id as its written id.
        # Without the resolved id, such a file re-rendered reads its env-read
        # entries unused, and `ash config lint --fix-unused` then comments out
        # an entry the scan applies. Without the exclusion, an entry whose
        # environment value is itself reference text (interpolation is one
        # pass) resolves to another entry's written id and reads "used"
        # although nothing applied it.
        recorded = recorded_suppressions(self.context.config)
        written = {
            id(suppression): written_suppression_id(suppression, recorded)
            for suppression in all_suppressions
        }
        written_ids = set(written.values())

        # Identify unused suppressions
        used_ids = set(used_suppressions)
        unused_suppressions = []
        for suppression in all_suppressions:
            if written[id(suppression)] in used_ids:
                continue
            if suppression.id in used_ids and suppression.id not in written_ids:
                continue
            unused_suppressions.append(suppression)

        # Build the report data. "used" counts the configured entries matched,
        # not the recorded ids, so the three numbers always add up: an id that
        # matches no configured entry (one from a config edited since, say) is
        # counted nowhere, where counting the ids read "total 3, used 1,
        # unused 3".
        report_data: Dict[str, Any] = {
            "summary": {
                "total_suppressions": len(all_suppressions),
                "used_suppressions": len(all_suppressions) - len(unused_suppressions),
                "unused_suppressions": len(unused_suppressions),
            },
            "unused_suppressions": [
                self._suppression_to_dict(s, recorded.get(id(s)))
                for s in unused_suppressions
            ],
        }

        # In workspace mode the scope has to be stated, because the numbers above
        # are honest only about workspace-level suppressions. Read as a merge,
        # "unused_suppressions: 0" would mean "nothing unused anywhere in the
        # workspace"; what it means is "no workspace-level suppression went
        # unused", and the per-project answers live in the per-project reports.
        # Leaving that implicit would let an operator conclude their per-project
        # suppressions are all in use on the strength of no evidence at all.
        if is_workspace_scan(model):
            workspace = model.workspace
            report_data["scope"] = "workspace"
            report_data["scope_detail"] = (
                "Counts cover workspace-level suppressions only. Each project's "
                "own suppressions were matched during that project's scan, "
                "against that project's own config, and are reported under "
                "per_project_reports."
            )
            report_data["per_project_reports"] = [
                {
                    "project": project.project,
                    "path": (
                        f"{project.output_path}/reports/ash.{self.config.extension}"
                    ),
                }
                for project in workspace.projects
            ]

        # Check if we should generate both formats
        output_format = getattr(self.config.options, "output_format", "both")

        if output_format == "both":
            # Generate both formats and write markdown separately
            json_output = json.dumps(report_data, indent=2, default=str)
            markdown_output = self._generate_markdown_report(
                report_data, unused_suppressions, recorded
            )

            # Write the markdown file separately
            if hasattr(self.context, "output_dir"):
                from pathlib import Path

                from automated_security_helper.base.reporter_plugin import (
                    write_report_file,
                )

                report_dir = Path(self.context.output_dir) / "reports"
                report_dir.mkdir(parents=True, exist_ok=True)
                write_report_file(report_dir, self.MARKDOWN_FILE_NAME, markdown_output)

            # Return JSON as the primary output
            return json_output
        elif output_format == "markdown":
            return self._generate_markdown_report(
                report_data, unused_suppressions, recorded
            )
        else:
            return json.dumps(report_data, indent=2, default=str)

    @staticmethod
    def _suppression_to_dict(
        suppression: AshSuppression, recorded: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Convert a suppression to a dictionary for JSON serialization.

        Package fields and ``symbol`` are included only when set, so the
        report for a suppression without them is unchanged, and so the config
        linter can rebuild an id from the report that matches the entry.
        ``recorded``, when given, is the suppression as its config file wrote
        the fields it read from the environment (``recorded_suppressions``),
        and each value comes from it. For such an entry the rebuilt id hashes
        the references, not ``AshSuppression.id``'s resolved values, so the
        linter's fixer matches each file entry by its as-written id as well as
        its resolved one (``ConfigLinter.fix_unused_suppressions``).
        """

        def shown(field: str) -> Any:
            if recorded is not None and field in recorded:
                return recorded[field]
            return getattr(suppression, field)

        data: Dict[str, Any] = {
            field: shown(field)
            for field in (
                "path",
                "rule_id",
                "line_start",
                "line_end",
                "reason",
                "expiration",
            )
        }
        for field in (*PACKAGE_SUPPRESSION_FIELDS, "symbol"):
            if getattr(suppression, field) is not None:
                data[field] = shown(field)
        return data

    @staticmethod
    def _generate_markdown_report(
        report_data: Dict[str, Any],
        unused_suppressions: List[AshSuppression],
        recorded: Dict[int, Dict[str, Any]] | None = None,
    ) -> str:
        """Generate a human-readable markdown report.

        ``recorded`` (``recorded_suppressions``) gives the fields shown for a
        suppression, each one the config read from the environment as its
        reference.
        """
        lines = []

        # Title
        lines.append("# Unused Suppressions Report")
        lines.append("")

        # Summary
        summary = report_data["summary"]
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Suppressions**: {summary['total_suppressions']}")
        lines.append(f"- **Used Suppressions**: {summary['used_suppressions']}")
        lines.append(f"- **Unused Suppressions**: {summary['unused_suppressions']}")
        lines.append("")

        # Status indicator
        if summary["unused_suppressions"] == 0:
            lines.append("✅ **All suppressions are being used!**")
            lines.append("")
        else:
            percentage = (
                (summary["unused_suppressions"] / summary["total_suppressions"] * 100)
                if summary["total_suppressions"] > 0
                else 0
            )
            lines.append(f"⚠️  **{percentage:.1f}% of suppressions are unused**")
            lines.append("")

        # Unused suppressions details
        if unused_suppressions:
            lines.append("## Unused Suppressions")
            lines.append("")
            lines.append(
                "The following suppressions are configured but not currently matching any findings:"
            )
            lines.append("")

            for i, suppression in enumerate(unused_suppressions, 1):
                # Each field as recorded: one read from the environment is shown
                # as its reference.
                shown = UnusedSuppressionsReporter._suppression_to_dict(
                    suppression, (recorded or {}).get(id(suppression))
                )
                lines.append(f"### {i}. {shown['path']}")
                lines.append("")
                lines.append(f"- **Rule ID**: `{shown['rule_id'] or 'Any'}`")

                if suppression.line_start is not None:
                    if (
                        suppression.line_end is not None
                        and suppression.line_end != suppression.line_start
                    ):
                        lines.append(
                            f"- **Lines**: {shown['line_start']}-{shown['line_end']}"
                        )
                    else:
                        lines.append(f"- **Line**: {shown['line_start']}")
                else:
                    lines.append("- **Lines**: Any")

                for field, label in (
                    ("package_name", "Package"),
                    ("package_version", "Package version"),
                    ("package_path", "Package path"),
                    ("symbol", "Symbol"),
                ):
                    if field in shown:
                        lines.append(f"- **{label}**: `{shown[field]}`")

                lines.append(f"- **Reason**: {_one_line(shown['reason'])}")

                if suppression.expiration:
                    lines.append(f"- **Expiration**: {shown['expiration']}")

                lines.append("")

            # Recommendations
            lines.append("## Recommendations")
            lines.append("")
            lines.append("Review each unused suppression and consider:")
            lines.append("")
            lines.append(
                "1. **File no longer exists**: Remove the suppression from your configuration"
            )
            lines.append(
                "2. **Finding was fixed**: Remove the suppression as it's no longer needed"
            )
            lines.append(
                "3. **Path/rule/line mismatch**: Update the suppression to match the current code"
            )
            lines.append(
                "4. **Still needed**: Verify the suppression is correctly configured"
            )
            lines.append("")
        else:
            lines.append("## Details")
            lines.append("")
            lines.append(
                "No unused suppressions found. All configured suppressions are actively being applied to findings."
            )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*This report was generated by ASH (Automated Security Helper)*")
        lines.append("")

        return "\n".join(lines)
