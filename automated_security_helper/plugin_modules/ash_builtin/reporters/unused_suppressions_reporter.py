# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter for identifying unused suppressions."""

import json
import re
from typing import Literal, TYPE_CHECKING, Any, ClassVar, Dict, List, Tuple

from pydantic import PrivateAttr, ValidationInfo, field_validator

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    is_workspace_scan,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.models.core import (
    PACKAGE_SUPPRESSION_FIELDS,
    AshSuppression,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.unknown_keys import tolerated_notes
from automated_security_helper.utils.suppression_matcher import (
    recorded_suppressions,
    written_suppression_id,
)


#: The values of ``output_format``.
_OUTPUT_FORMATS = ("json", "markdown", "both")


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
    return " ".join(str(text or "").split())


def _code_span(value: Any) -> str:
    """``value`` as an inline code span on one line.

    A field the config wrote is interpolated as it is, and one that holds a
    newline ends its bullet, and one that holds a backtick ends its span. The
    value is flattened (``_one_line``) and fenced with more backticks than it
    contains in a row, padded by a space when it starts or ends with one.
    """
    text = _one_line(None if value is None else str(value))
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


class UnusedSuppressionsReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Unused Suppressions reporter."""

    output_format: str = "both"  # "json", "markdown", or "both"

    @field_validator("output_format", mode="before")
    @classmethod
    def _output_format_is_one_of_the_three(
        cls, value: Any, info: ValidationInfo
    ) -> Any:
        """Read the case of the name away, and refuse any other.

        ``report`` took every value but ``both`` and ``markdown`` for ``json``,
        so ``md``, ``Both`` and ``MARKDOWN`` were silently the JSON-only report.
        The message names the allowed values and not the one given: it can be a
        value read from the environment.

        The config a results file recorded is read again by every reader of the
        file (``ash report``, ``--existing-results``, ``ash merge``), and a scan
        by an earlier version may have run with a value this refuses. Refusing it
        there would lose the results of a scan nobody is about to run again, so
        under the stored-config tolerance (``utils/unknown_keys``) the value is
        read as the earlier version read it, ``json``, and a note says so
        without naming the value.
        """
        if isinstance(value, str) and value.strip().lower() in _OUTPUT_FORMATS:
            return value.strip().lower()
        notes = tolerated_notes(info)
        if notes is not None:
            notes.append(
                "an unreadable output_format of the unused-suppressions reporter "
                "was read as json"
            )
            return "json"
        raise ValueError("output_format must be one of: json, markdown, both")


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
    #: The extension the report is written under when ``output_format`` is
    #: ``markdown``: the report text is markdown, so the file is named as such.
    #: Left as the JSON extension, the markdown landed in
    #: ``ash.unused-suppressions.json``, which ``ash config lint --fix-unused``
    #: then read as JSON.
    MARKDOWN_EXTENSION: ClassVar[str] = "unused-suppressions.md"

    #: What the report says in place of its counts when the scan ran with
    #: ``--ignore-suppressions``. No suppression was matched against a finding
    #: on such a run, so ``used_suppressions`` is empty by construction and
    #: every configured entry would read as unused. Reported as unused, each
    #: would then be commented out by ``ash config lint --fix-unused``, which
    #: reads this file.
    NOT_EVALUATED: ClassVar[str] = (
        "The scan ran with --ignore-suppressions, so no suppression was matched "
        "against a finding and this report says nothing about which are unused. "
        "Run a scan without --ignore-suppressions to evaluate them."
    )

    #: The ``.json`` file name the markdown-under-a-json-name warning was last
    #: given for. The name is settled twice for a reporter that is built and then
    #: configured (``model_post_init`` and ``configure``), and the same warning
    #: was logged by each.
    _json_name_warned_for: str | None = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = UnusedSuppressionsReporterConfig()
        self._name_the_report_file_by_its_format()
        return super().model_post_init(context)

    def configure(self, config=None) -> None:
        super().configure(config)
        self._name_the_report_file_by_its_format()

    def _name_the_report_file_by_its_format(self) -> None:
        """Under ``output_format: markdown`` the report is markdown, so it is
        written under MARKDOWN_EXTENSION, not the JSON one.

        An extension the operator chose is kept, where chosen means a value
        other than the class default. The first form of this test asked whether
        the field was SET (``model_fields_set``), and the real run never met
        it: the report phase builds a reporter from ``get_plugin_config``,
        which is a full dump of the section, so ``extension`` arrived with the
        default's value, counted as set, and the markdown landed back in
        ``ash.unused-suppressions.json``. An operator who wrote the default's
        own value under ``markdown`` gets the markdown name too. The change
        lands on a copy of the config, so the object the caller handed in (the
        AshConfig's own reporter section, say) is not changed under it.
        """
        if isinstance(self.config, dict):
            self.config = UnusedSuppressionsReporterConfig.model_validate(self.config)
        output_format = getattr(
            getattr(self.config, "options", None), "output_format", "both"
        )
        default_extension = UnusedSuppressionsReporterConfig.model_fields[
            "extension"
        ].default
        if output_format == "markdown" and self.config.extension == default_extension:
            self.config = self.config.model_copy(
                update={"extension": self.MARKDOWN_EXTENSION}
            )
        elif output_format == "markdown" and self.config.extension.lower().endswith(
            ".json"
        ):
            # Kept, as the operator's choice, but said: the text written under it
            # is markdown, and `ash config lint --fix-unused` reads a file of
            # this name as JSON. Once for a name: the reporter settles its name
            # when it is built and again when it is configured.
            if self._json_name_warned_for != self.config.extension:
                self._json_name_warned_for = self.config.extension
                ASH_LOGGER.warning(
                    "The unused-suppressions reporter writes markdown "
                    "(output_format: markdown) under a file name that ends in "
                    ".json; tools that read the report by its name will read "
                    "markdown as JSON."
                )

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

        # The configured suppressions this report is about. In workspace mode
        # those are the workspace-level ones, of which this phase has none (see
        # the class docstring): the context's config is the invoking config,
        # whose suppressions were matched inside each project's own scan and
        # are reported there. Subtracting the unified file's empty
        # used_suppressions from that config listed every one of them unused.
        workspace = is_workspace_scan(model)
        if workspace:
            all_suppressions: List[AshSuppression] = []
        else:
            all_suppressions = self.context.config.global_settings.suppressions or []

        # Under --ignore-suppressions nothing was matched, so the subtraction
        # below has no meaning: the report says so instead of listing every
        # entry as unused (NOT_EVALUATED). The flag is read from this run's
        # context and from the results' own metadata (`suppressions_ignored`,
        # for a scan that recorded it), so a results file re-rendered by a
        # later `ash report`, whose context carries no such flag, reads the
        # same way once the scan records it.
        suppressions_ignored = bool(
            getattr(self.context, "ignore_suppressions", False)
        ) or bool(
            getattr(getattr(model, "metadata", None), "suppressions_ignored", False)
        )

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
            if suppressions_ignored:
                break
            if written[id(suppression)] in used_ids:
                continue
            if suppression.id in used_ids and suppression.id not in written_ids:
                continue
            unused_suppressions.append(suppression)

        # Build the report data. "used" counts the configured entries matched,
        # not the recorded ids, so the three numbers always add up: an id that
        # matches no configured entry (one from a config edited since, say) is
        # counted nowhere, where counting the ids read "total 3, used 1,
        # unused 3". When suppressions were ignored both counts are 0 and
        # "evaluated" says why they add up to nothing: a reader that checks
        # neither key comments nothing out, where "every one unused" would have
        # had it comment out every entry.
        used_count = (
            0
            if suppressions_ignored
            else len(all_suppressions) - len(unused_suppressions)
        )
        report_data: Dict[str, Any] = {
            "summary": {
                "total_suppressions": len(all_suppressions),
                "used_suppressions": used_count,
                "unused_suppressions": len(unused_suppressions),
            },
            "unused_suppressions": [
                self._suppression_to_dict(s, recorded.get(id(s)))
                for s in unused_suppressions
            ],
        }
        if suppressions_ignored:
            report_data["summary"]["evaluated"] = False
            report_data["not_evaluated"] = self.NOT_EVALUATED

        # A suppression is matched against the findings a scanner reports. A
        # scanner that did not run (its tool missing, an error, or excluded for
        # this run) reported none, so a suppression for one of its findings
        # could not be matched and reads as unused here although it is in
        # force. The report names those scanners so the "remove it" reading
        # is qualified; a suppression carries no scanner name, so it cannot
        # say which entries are affected. A scanner that found nothing to scan,
        # or that the configuration turns off, is not named: a later scan of the
        # same tree leaves it out the same way (see _scanners_not_run). Not in
        # workspace mode: this report
        # then covers no suppression (the list above is empty), and each
        # project's own report carries the caveat for that project's scan.
        scanners_not_run = [] if workspace else self._scanners_not_run(model)
        if scanners_not_run and not suppressions_ignored:
            report_data["scanners_not_run"] = scanners_not_run
            report_data["scope_caveat"] = (
                "These scanners did not run on this scan: "
                + ", ".join(scanners_not_run)
                + ". A suppression for a finding one of them would report could "
                "not be matched and may be listed as unused although it is in "
                "force; keep such entries until a scan with the scanner enabled "
                "evaluates them."
            )

        # In workspace mode the scope has to be stated, because the numbers above
        # are honest only about workspace-level suppressions. Read as a merge,
        # "unused_suppressions: 0" would mean "nothing unused anywhere in the
        # workspace"; what it means is "no workspace-level suppression went
        # unused", and the per-project answers live in the per-project reports.
        # Leaving that implicit would let an operator conclude their per-project
        # suppressions are all in use on the strength of no evidence at all.
        if workspace:
            workspace_results = model.workspace
            report_data["scope"] = "workspace"
            report_data["scope_detail"] = (
                "Counts cover workspace-level suppressions only. Each project's "
                "own suppressions were matched during that project's scan, "
                "against that project's own config, and are reported under "
                "per_project_reports."
            )
            # Only a project that completed wrote a report. A skipped or failed
            # one has no file at the path, which a listing here would name.
            report_data["per_project_reports"] = [
                {
                    "project": project.project,
                    "path": (
                        f"{project.output_path}/reports/ash.{self.config.extension}"
                    ),
                }
                for project in workspace_results.projects
                if project.status == ProjectRunStatus.COMPLETED
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
                markdown_path = write_report_file(
                    report_dir, self.MARKDOWN_FILE_NAME, markdown_output
                )
                if markdown_path is None:
                    # write_report_file has said why. What it cannot say is that
                    # a copy an earlier scan left there is not this scan's.
                    ASH_LOGGER.warning(
                        f"The markdown copy of the unused-suppressions report was "
                        f"not written, so {self.MARKDOWN_FILE_NAME} in "
                        f"{report_dir}, if one is there, is from an earlier scan."
                    )

            # Return JSON as the primary output
            return json_output
        elif output_format == "markdown":
            return self._generate_markdown_report(
                report_data, unused_suppressions, recorded
            )
        else:
            return json.dumps(report_data, indent=2, default=str)

    @staticmethod
    def _scanners_not_run(model: "AshAggregatedResults") -> List[str]:
        """The scanners that did not run when a full scan of this configuration
        would have run them: status MISSING or ERROR, a dependency not
        satisfied, or excluded for this run. Sorted by name; empty when every
        recorded scanner ran or was left out for a reason a later scan shares.

        Two kinds of row are not listed, because a later scan of the same tree
        and configuration leaves the scanner out the same way, so a suppression
        for its findings is unused in the same sense as any other:

        - a SKIPPED scanner that was not excluded: it looked and found nothing
          to scan (no lockfile for npm-audit, no template for cdk-nag), so it
          had no finding to match;
        - an excluded scanner whose recorded reason says the configuration
          disabled it (``enabled: false``).

        An exclusion that is the operator's choice for this run alone (a
        ``--scanners`` or ``--exclude-scanners`` selection, a shard split,
        ``--python-only``) stays listed: the next full scan runs the scanner.
        So does an excluded row with no recorded reason, since the cause is then
        unknown.
        """
        from automated_security_helper.core.enums import ScannerStatus

        not_run = []
        for name, info in (getattr(model, "scanner_results", None) or {}).items():
            status = getattr(info, "status", None)
            if status in (ScannerStatus.MISSING, ScannerStatus.ERROR) or not getattr(
                info, "dependencies_satisfied", True
            ):
                not_run.append(str(name))
            elif getattr(info, "excluded", False) and not (
                UnusedSuppressionsReporter._disabled_by_configuration(info)
            ):
                not_run.append(str(name))
        return sorted(not_run)

    #: What the scan phase and the executor write into ``skipped_reason`` for a
    #: scanner the configuration turns off. An unrecognized wording reads as an
    #: exclusion for this run, which is the side that comments nothing out.
    CONFIG_DISABLED_REASON: ClassVar[str] = "disabled in the configuration"

    @staticmethod
    def _disabled_by_configuration(info: Any) -> bool:
        """Whether *info*'s recorded reason says the configuration disabled the
        scanner (alone or beside a selection for this run: a full scan of the
        same configuration leaves it out too)."""
        reason = getattr(info, "skipped_reason", None)
        return (
            isinstance(reason, str)
            and UnusedSuppressionsReporter.CONFIG_DISABLED_REASON in reason
        )

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

        # Status indicator. A report that evaluated nothing says so in place of
        # a judgment, and a workspace-level report names its scope before its
        # counts: "all suppressions are being used" read over a workspace
        # would mean every project's, which this report cannot know.
        if report_data.get("not_evaluated"):
            lines.append(
                f"⚠️  **Suppressions were not evaluated**: {report_data['not_evaluated']}"
            )
            lines.append("")
        elif report_data.get("scope") == "workspace":
            lines.append(f"**Scope**: {report_data.get('scope_detail', '')}")
            lines.append("")
            if summary["unused_suppressions"] == 0:
                lines.append("✅ **No workspace-level suppression is unused.**")
                lines.append("")
        elif summary["total_suppressions"] == 0:
            # Nothing is configured, so nothing is "being used".
            lines.append("**No suppressions are configured.**")
            lines.append("")
        elif summary["unused_suppressions"] == 0:
            lines.append("✅ **All suppressions are being used!**")
            lines.append("")
        if report_data.get("scope_caveat"):
            lines.append(
                f"⚠️  **Scanners that did not run**: {report_data['scope_caveat']}"
            )
            lines.append("")
        if summary["unused_suppressions"] != 0:
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
                lines.append(f"### {i}. {_one_line(shown['path'])}")
                lines.append("")
                lines.append(f"- **Rule ID**: {_code_span(shown['rule_id'] or 'Any')}")

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
                        lines.append(f"- **{label}**: {_code_span(shown[field])}")

                lines.append(f"- **Reason**: {_one_line(shown['reason'])}")

                if suppression.expiration:
                    lines.append(f"- **Expiration**: {_one_line(shown['expiration'])}")

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
        elif report_data.get("not_evaluated"):
            lines.append("## Details")
            lines.append("")
            lines.append(
                "No suppression was evaluated on this run, so none is listed here "
                "as unused."
            )
            lines.append("")
        elif report_data.get("scope") == "workspace":
            lines.append("## Details")
            lines.append("")
            lines.append(
                "No workspace-level suppression is unused. Each project's own "
                "suppressions are reported in that project's report."
            )
            lines.append("")
        elif summary["total_suppressions"] == 0:
            lines.append("## Details")
            lines.append("")
            lines.append("No suppressions are configured, so none can be unused.")
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
