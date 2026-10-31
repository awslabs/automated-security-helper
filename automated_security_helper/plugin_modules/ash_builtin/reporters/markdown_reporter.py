# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import html
import re
from datetime import datetime, timezone
from typing import Any, Dict, Literal, TYPE_CHECKING

from pydantic import field_validator

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.utils.display_text import markdown_code_span
from automated_security_helper.core.unified_metrics import (
    inputs_not_scanned,
)
from automated_security_helper.utils.converter_refusals import (
    converter_refusals,
    markdown_summary_lines,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
    coverage_shortfall_text,
    refuse_negative_limit,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    markdown_workspace_section,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.terminal_text import (
    shown_not_obeyed,
    shown_on_one_line,
)
from automated_security_helper.utils.ui_theme import FOOTER_CREDIT


#: What GitHub acts on without Markdown syntax: an ``@name`` (or ``@org/team``)
#: notifies that user or team, and a bare URL becomes a link. Neither is
#: preceded by a word character, so an e-mail address is left alone. GitHub
#: still links a bare address as a ``mailto:`` link, which notifies nobody and
#: sends nothing until a reader follows it, so that is accepted. A URL
#: stops at whitespace, ``<``, ``>``, a backtick or a pipe, and does not end on
#: the punctuation that closes the sentence or bracket it sits in.
_AUTO_REFERENCE = re.compile(
    r"(?<![\w.+-])@[A-Za-z0-9][A-Za-z0-9_-]*(?:/[A-Za-z0-9_.-]+)?"
    r"|(?:https?|ftp)://[^\s<>|`]*[^\s<>|`.,;:!?)\]}'\"]"
    r"|www\.[^\s<>|`]*[^\s<>|`.,;:!?)\]}'\"]"
)


def _markdown_escaped(text: str) -> str:
    """*text* with ``<``, ``>`` and ``&`` as entities and each Markdown syntax
    character backslash-escaped.

    ``$`` is one of them: GitHub reads a pair of dollar signs as a formula, so
    scanner text such as ``cost $5 and $6`` rendered as math without it.
    """
    return re.sub(r"([\\`*_\[\]{}#|~$])", r"\\\1", html.escape(text, quote=False))


def _text(value) -> str:
    """Keep project and scanner-controlled text literal in GitHub Markdown.

    Escaped once, for Markdown: ``<``, ``>`` and ``&`` become entities, then
    each Markdown syntax character gets a backslash. Quotes are left as
    written. ``html.escape`` with its default quote handling would write ``'``
    as the numeric entity ``&#x27;``, and the backslash pass would turn its
    ``#`` into ``\\#``, which Markdown does not read as an entity, so a reader
    would see the characters ``&#x27;``.

    An ``@name`` and a bare URL are Markdown-neutral text that GitHub still
    acts on where a summary is posted as a comment (it notifies the user and
    links the URL), so each is put in a code span, as the converter refusals
    already are.
    """
    text = str(value or "")
    parts = []
    end = 0
    for match in _AUTO_REFERENCE.finditer(text):
        parts.append(_markdown_escaped(text[end : match.start()]))
        parts.append(markdown_code_span(match.group()))
        end = match.end()
    parts.append(_markdown_escaped(text[end:]))
    return "".join(parts)


#: A reference to an environment variable as a configuration file writes it,
#: ``${NAME}``.
_ENV_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def _reference_text(value) -> str:
    """The project line: ``_text`` that keeps a written ``${NAME}`` reference.

    The configuration records a project name read from the environment as the
    reference it was written as, not the value. Escaping it would show
    ``$\\{NAME\\}`` (or ``NAME`` with its underscores escaped), which is not what
    the file says. A reference is put in a code span, as a mention and a URL
    are: written bare, ``${_X_}`` read as emphasis and ``${ORG}/${REPO}`` as
    math, since the dollar signs delimit a formula on GitHub. Every other
    character is escaped as in ``_text``, and braces stay escaped on every other
    line.

    Pieces that touch are put in one code span. Two code spans back to back
    (``${A}${B}``, or a reference written against a mention or a URL) end and
    open with a run of backticks that Markdown reads as part of one longer span,
    so the reader saw the stray backticks and the text between them as code.
    """
    text = str(value or "")
    # (is_code, text) pieces in order: a reference, a mention or a URL is code,
    # every other stretch is escaped.
    pieces: list[tuple[bool, str]] = []

    def add_plain(stretch: str) -> None:
        stop = 0
        for match in _AUTO_REFERENCE.finditer(stretch):
            pieces.append((False, stretch[stop : match.start()]))
            pieces.append((True, match.group()))
            stop = match.end()
        pieces.append((False, stretch[stop:]))

    end = 0
    for match in _ENV_REFERENCE.finditer(text):
        add_plain(text[end : match.start()])
        pieces.append((True, match.group()))
        end = match.end()
    add_plain(text[end:])

    parts = []
    code = None
    for is_code, piece in pieces:
        if is_code:
            code = piece if code is None else code + piece
            continue
        if not piece:
            # Nothing between two code pieces: they touch.
            continue
        if code is not None:
            parts.append(markdown_code_span(code))
            code = None
        parts.append(_markdown_escaped(piece))
    if code is not None:
        parts.append(markdown_code_span(code))
    return "".join(parts)


def _html_literal(value) -> str:
    """*value* as HTML text, with an ``@name`` and a bare URL in ``<code>``.

    For a line that Markdown does not parse (the collapsible ``<summary>``),
    where GitHub still turns an ``@name`` into a mention and a URL into a link.
    """
    text = str(value or "")
    parts = []
    end = 0
    for match in _AUTO_REFERENCE.finditer(text):
        parts.append(html.escape(text[end : match.start()]))
        parts.append(f"<code>{html.escape(match.group())}</code>")
        end = match.end()
    parts.append(html.escape(text[end:]))
    return "".join(parts)


#: Leading blanks of a line that has text after them, and a line's first
#: character when that starts a list item, a rule or a setext underline once the
#: blanks are gone. A line of blanks alone is a blank line in Markdown and ends
#: the paragraph above it, so it is not matched: written as non-breaking spaces
#: it would be content and would join the paragraphs on either side of it.
_LINE_INDENT = re.compile(r"^[ \t]+(?=[^ \t\r\n])", re.MULTILINE)
_LINE_BLOCK_MARKER = re.compile(r"^(?:([-+=])|(\d+)([.)]))", re.MULTILINE)


def _block_text(value) -> str:
    """Multi-line scanner text kept literal, line starts included.

    :func:`_text` leaves a line break alone, so each line of a multi-line
    description began a Markdown block of its own: four blanks made a code
    block that showed the inserted backslashes, ``-`` or ``1.`` made a list,
    and a ``---`` or ``===`` line made a rule or turned the line above it into
    a heading. Indentation is kept as non-breaking spaces and the marker
    character is backslash-escaped.
    """
    escaped = _text(value)
    escaped = _LINE_INDENT.sub(
        lambda match: "&nbsp;" * len(match.group().expandtabs(4)), escaped
    )
    return _LINE_BLOCK_MARKER.sub(
        lambda match: (
            f"\\{match.group(1)}"
            if match.group(1)
            else f"{match.group(2)}\\{match.group(3)}"
        ),
        escaped,
    )


def _cell(value) -> str:
    return _text(value).replace("\r", "").replace("\n", "<br>")


def _code_block(value: str, language: str = "") -> str:
    # Scanner snippets can contain Markdown fences of their own.
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{value}\n{fence}"


def outcome_markdown(summary: Dict[str, Any]) -> str:
    """The factual outcome shared by standard and generated Markdown reports."""
    alert = {"danger": "CAUTION", "warning": "WARNING", "success": "TIP"}[
        summary["tone"]
    ]
    return "\n".join(
        [
            f"> [!{alert}]",
            f"> **{summary['title']}**",
            ">",
            f"> {summary['description']}",
            ">",
            (
                f"> **{summary['actionable']} actionable** · "
                f"{summary['below_threshold']} below threshold · "
                f"{summary['suppressed']} suppressed · "
                f"{summary['completed']}/{summary['scanners']} scanners completed"
            ),
            ">",
            f"> Next action: {summary['next_step']}\n",
        ]
    )


def coverage_markdown(summary: Dict[str, Any]) -> str:
    """Keep coverage facts visible regardless of report detail options."""
    parts = []
    # A scanner's name can be a results file's text (``ash report`` renders one
    # a repository committed): shown on one line, then kept literal in Markdown.
    if summary["shortfalls"]:
        parts.extend(
            [
                "### Incomplete coverage\n",
                "Targets left unevaluated:\n",
            ]
        )
        for scanner, attempted, failed in summary["shortfalls"]:
            parts.append(
                f"- **{_text(shown_on_one_line(scanner))}**: "
                f"{coverage_shortfall_text(attempted, failed)}"
            )
        parts.append("")
    if summary["unavailable"]:
        parts.append(
            "**Scanners needing attention:** "
            + ", ".join(
                _text(shown_on_one_line(name)) for name in summary["unavailable"]
            )
            + ". Check their dependencies and execution logs.\n"
        )
    if summary["converter_gaps"]:
        parts.extend(
            [
                "### Converters needing attention\n",
                "Inputs not prepared for scanning. Resolve these gaps and scan again:\n",
            ]
        )
        parts.extend(
            # The name and reason come from the tool: shown on one line, then
            # kept literal in Markdown.
            f"- **{_text(shown_on_one_line(name))}**: {_text(shown_on_one_line(reason))}"
            # IncompleteConverter rows carry (name, reason, kinds).
            for name, reason, *_ in summary["converter_gaps"]
        )
        parts.append("")
    if summary["unevaluated_rules"]:
        parts.append(
            "**Rules not evaluated:** "
            + ", ".join(
                _text(shown_on_one_line(rule)) for rule in summary["unevaluated_rules"]
            )
            + ". Review the scanner logs.\n"
        )
    if summary.get("could_not_stop"):
        parts.extend(
            [
                "### Scanner tools not stopped\n",
                (
                    "These tools could not be stopped and may still be writing, so this "
                    "report may not be final. The scan fails for them whatever the "
                    "severity gate says:\n"
                ),
            ]
        )
        parts.extend(
            # The name and the reason come from the run's own record: shown on
            # one line, then kept literal in Markdown.
            f"- **{_text(shown_on_one_line(name))}**: {_text(shown_on_one_line(reason))}"
            for name, reason in summary["could_not_stop"]
        )
        parts.append("")
    if summary["stale"]:
        parts.extend(
            [
                "### Stale content databases\n",
                "Content databases exceeded their declared age limit. Refresh them and scan again:\n",
            ]
        )
        for record in summary["stale"]:
            verdict = "failed the scan" if record.enforced else "warning only"
            parts.append(
                f"- **{_text(shown_on_one_line(record.name))}** "
                f"({_text(shown_on_one_line(record.scanner))}, {verdict}): "
                f"{_text(shown_on_one_line(record.message()))}"
            )
        parts.append("")
    return "\n".join(parts)


def _inputs_not_scanned_markdown(model: "AshAggregatedResults") -> list[str]:
    """The "Inputs not scanned" section as lines, or ``[]`` when there is none."""
    not_scanned = inputs_not_scanned(model)
    if not not_scanned:
        return []
    lines = [
        "### Inputs not scanned",
        "",
        (
            "These scanners found these inputs and did not scan them. That "
            "no finding is reported for one says nothing about it:"
        ),
        "",
    ]
    # The path is the scanned repository's: shown in a code span its own
    # backticks cannot close, with its newlines and other control
    # characters escaped, so it cannot start a line of its own.
    # The scanner's name and the reason are the results file's text
    # too: shown on one line, then kept literal in Markdown.
    for scanner_name, path, reason in not_scanned:
        lines.append(
            f"- **{_text(shown_on_one_line(scanner_name))}**: "
            f"{markdown_code_span(path)}: {_text(shown_on_one_line(reason))}"
        )
    lines.append("")
    return lines


def _converter_refusals_markdown(model: "AshAggregatedResults") -> list[str]:
    """The "Converter inputs not scanned" section as lines, or ``[]``.

    An archive refused for an extraction limit is marked, because it is what
    failed the completeness gate; the rest are reported only.
    """
    refusals = converter_refusals(model)
    if not refusals:
        return []
    return [
        "### Converter inputs not scanned",
        "",
        (
            "These inputs were not read by their converter, so their contents "
            "were not scanned:"
        ),
        "",
        # Each in a code span: a name such as @someone or a URL would
        # otherwise become a mention or a link where the summary is posted.
        *markdown_summary_lines(refusals),
        "",
    ]


class MarkdownReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Markdown reporter."""

    include_summary: bool = True
    include_findings_table: bool = False
    include_detailed_findings: bool = True
    max_detailed_findings: int = 20
    top_hotspots_limit: int = 10
    use_collapsible_details: bool = True
    compact: bool = False

    @field_validator("max_detailed_findings", "top_hotspots_limit")
    @classmethod
    def _limits_are_not_negative(cls, value: int) -> int:
        return refuse_negative_limit(value)


class MarkdownReporterConfig(ReporterPluginConfigBase):
    name: Literal["markdown"] = "markdown"
    extension: str = "summary.md"
    enabled: bool = True
    options: MarkdownReporterConfigOptions = MarkdownReporterConfigOptions()


@ash_reporter_plugin
class MarkdownReporter(ReporterPluginBase[MarkdownReporterConfig]):
    """A triage-first report shared by files, CI summaries, and GitHub comments."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = MarkdownReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        if isinstance(self.config, dict):
            self.config = MarkdownReporterConfig.model_validate(self.config)
        options = self.config.options
        emitter = ReportContentEmitter(model, human_presentation=True)
        metadata = emitter.get_metadata()
        summary = emitter.get_scan_summary()
        parts = [
            "# ASH security scan report\n",
            outcome_markdown(summary),
            (
                # The project name comes from the results file, which a
                # repository can commit: one shown line. The timestamp is
                # validated as one when the file is read.
                f"Project: {_reference_text(shown_on_one_line(str(metadata['project'])))} · "
                f"Scan executed: {_text(metadata['scan_time'])}\n"
            ),
        ]
        # Attribution and skipped-project notices survive compact mode.
        parts.extend(markdown_workspace_section(model))

        if options.include_summary:
            parts.extend(
                [
                    "## Summary\n",
                    "### Scanner results\n",
                    "| Scanner | Suppressed | Critical | High | Medium | Low | Info | Actionable | Result | Threshold |",
                    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
                ]
            )
            shown = 0
            for result in emitter.get_scanner_results():
                if options.compact and (
                    result["status"] == "SKIPPED"
                    or (result["total"] == 0 and result["status"] == "PASSED")
                ):
                    continue
                threshold = f"{result['threshold']} ({result['threshold_source']})"
                parts.append(
                    f"| {_cell(shown_on_one_line(result['scanner_name']))} | {result['suppressed']} | "
                    f"{result['critical']} | {result['high']} | {result['medium']} | "
                    f"{result['low']} | {result['info']} | {result['actionable']} | "
                    f"{_cell(result['status'])} | {_cell(threshold)} |"
                )
                shown += 1
            parts.append("")
            if options.compact:
                parts.append(
                    "Compact view omits disabled scanners and passed scanners with no findings.\n"
                    if shown
                    else "No scanner rows to show in compact view. Completion counts are above; disabled and empty passed rows are omitted.\n"
                )
            else:
                parts.extend(
                    [
                        "<details>",
                        "<summary>How to read scanner results</summary>\n",
                        "**Severity levels:** Critical, High, Medium, Low, Info. Suppressed findings are counted separately.",
                        "",
                        "**Actionable** counts findings at or above each scanner's threshold.",
                        "",
                        "**Result:** PASSED = no actionable findings; FAILED = threshold exceeded; MISSING = dependencies unavailable; SKIPPED = did not run (disabled, or nothing to scan); ERROR = execution error.",
                        "",
                        "**Threshold** shows the minimum severity and its source: `global`, `config`, or `scanner`.",
                        "",
                        "**Statistics calculation:** final aggregated SARIF, with suppressed findings excluded from actionable counts.",
                        "",
                        "</details>\n",
                    ]
                )

        parts.append(coverage_markdown(summary))

        # Inputs no scanner or converter read are coverage facts, as the notices
        # above are: they stay in the report whatever its detail options say.
        # With the summary on they follow the summary's own sections.
        not_scanned_lines = _inputs_not_scanned_markdown(model)
        refusal_lines = _converter_refusals_markdown(model)

        if options.include_summary:
            hotspots = emitter.get_top_hotspots(options.top_hotspots_limit)
            if hotspots:
                parts.extend(
                    [
                        f"### Top {len(hotspots)} hotspots\n",
                        "Files with the most actionable findings.\n",
                        "| Finding count | File location |",
                        "| ---: | --- |",
                    ]
                )
                parts.extend(
                    # A path from the scanned repository: shown on one line.
                    f"| {hotspot['count']} | {_cell(shown_on_one_line(hotspot['location']))} |"
                    for hotspot in hotspots
                )
                parts.append("")

            # See the text reporter: the scan set depends on the ignore files.
            ignore_file_exclusions = model.metadata.ignore_file_exclusions
            if ignore_file_exclusions is not None:
                parts.append(
                    f"- **Ignore files**: {ignore_file_exclusions.summary_text()}"
                )
                parts.append("")

            # A SKIPPED or PASSED row cannot say which input went unexamined
            # (npm-audit's lockfiles offline, for one).
            parts.extend(not_scanned_lines)

            # The stale-content-database section is written once, by
            # coverage_markdown above, which every report carries whatever its
            # detail options and which shows the record's name, scanner and
            # message as literal text. A second copy here wrote the same records
            # again, raw.

            # Same reasoning again: a converter input that was not read never
            # reaches a scanner, so no scanner row can say it went unscanned.
            parts.extend(refusal_lines)
        else:
            parts.extend(not_scanned_lines)
            parts.extend(refusal_lines)

        if options.include_findings_table:
            findings = emitter.get_findings_overview()
            if findings:
                parts.extend(
                    [
                        "## Findings overview\n",
                        "| Severity | Scanner | Rule ID | Title | File |",
                        "| --- | --- | --- | --- | --- |",
                    ]
                )
                for finding in findings:
                    parts.append(
                        "| "
                        + " | ".join(
                            # Each cell is one shown line: the rule ID, title
                            # and path come from the scan.
                            _cell(shown_on_one_line(finding[key]))
                            for key in (
                                "severity",
                                "scanner",
                                "rule_id",
                                "title",
                                "file_path",
                            )
                        )
                        + " |"
                    )
                parts.append("")

        if options.include_detailed_findings:
            findings = emitter.get_detailed_findings(options.max_detailed_findings)
            if findings:
                total = sum(
                    emitter.is_finding_actionable(v) for v in emitter.flat_vulns
                )
                parts.extend(
                    [
                        "## Detailed findings\n",
                        f"Showing {len(findings)} of {total} actionable findings, highest severity first.\n",
                    ]
                )
                for index, finding in enumerate(findings, 1):
                    # The rule ID (the title too), the location, the message
                    # and the snippet come from the scan: shown, not obeyed.
                    # The one-line values stay on their line; the message and
                    # the snippet keep their own lines.
                    if options.use_collapsible_details:
                        # Each is one shown line: a blank line in the summary
                        # would end the HTML block and spill the rest into the
                        # document. A name such as @someone or a URL stays literal.
                        severity = _html_literal(shown_on_one_line(finding["severity"]))
                        rule_id = _html_literal(shown_on_one_line(finding["rule_id"]))
                        location = _html_literal(shown_on_one_line(finding["location"]))
                        parts.extend(
                            [
                                "<details>",
                                (
                                    f"<summary>{index}. {severity} · "
                                    f"{rule_id} · {location}</summary>\n"
                                ),
                            ]
                        )
                    parts.append(
                        f"### Finding {index}: {_text(shown_on_one_line(finding['title']))}\n"
                    )
                    for label, key in (
                        ("Severity", "severity"),
                        ("Scanner", "scanner"),
                        ("Rule ID", "rule_id"),
                        ("Location", "location"),
                        ("CVE", "cve_id"),
                        ("CWE", "cwe_id"),
                    ):
                        if finding.get(key):
                            parts.append(
                                f"- {label}: {_text(shown_on_one_line(finding[key]))}"
                            )
                    parts.append(
                        f"\n{_block_text(shown_not_obeyed(finding['description']))}\n"
                    )
                    if finding.get("code_snippet"):
                        parts.extend(
                            [
                                "Code snippet:\n",
                                _code_block(
                                    str(shown_not_obeyed(finding["code_snippet"]))
                                ),
                                "",
                            ]
                        )
                    if options.use_collapsible_details:
                        parts.append("</details>\n")
                if total > len(findings):
                    parts.append(
                        f"> Showing {len(findings)} of {total} total actionable findings. "
                        "Open the HTML report or use `ash inspect findings` to review the full set. "
                        "Configure `max_detailed_findings` to adjust this limit.\n"
                    )

        if not options.compact:
            parts.extend(
                [
                    "<details>",
                    "<summary>Scan metadata</summary>\n",
                    "## Scan metadata\n",
                    # The project name and tool version come from the results
                    # file: each is one shown line.
                    f"- Project: {_reference_text(shown_on_one_line(str(metadata['project'])))}",
                    f"- Scan executed: {_text(metadata['scan_time'])}",
                    f"- Report generated: {_text(metadata['report_time'])}",
                    f"- ASH version: {_text(shown_on_one_line(str(metadata['tool_version'])))}\n",
                    "</details>\n",
                    (
                        "*Report generated by [Automated Security Helper (ASH)]"
                        "(https://github.com/awslabs/automated-security-helper) at "
                        f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}*"
                    ),
                ]
            )
        parts.extend(["", FOOTER_CREDIT])
        return "\n".join(parts)
