# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Converter inputs a scan did not scan, read back from its results for the reports.

A converter records each input it declines to read in its results row
(``converter_results.<converter>.refused_inputs``): a symlinked or out-of-tree file,
an archive member that is a link, escapes its destination or is itself an archive,
and an archive refused whole for an extraction limit. Before this module those
records reached ``ash.log`` and ``ash_aggregated_results.json`` only, so a reader of
the summary or of a SARIF or flat JSON report could not tell that part of the tree
went unscanned.

Every record is reported. One with ``scan_incomplete`` set (an archive over an
extraction limit, which ``limit`` names, or one that could not be read) is marked
as leaving the scan incomplete: the archive's contents were not scanned at all, and
the completeness
gate (``run_ash_scan.incomplete_converters``) counts it, so under
``fail_on_incomplete_scanners`` the scan exits 1. The others refuse one input or
member that ASH does not read by design, and are reported without failing the
scan.

Where each report puts them:

* the console after the metrics table, and the text and markdown summaries, in a
  section of their own, at most ``SHOWN_IN_SUMMARY`` lines with a count of the rest;
* the flat JSON report under ``converter_refusals``, always present, every record;
* ``ash.sarif`` as one extra invocation per converter, with a
  ``toolExecutionNotifications`` entry per record (level ``error`` when it left the
  scan incomplete, ``warning`` otherwise) located at the input's path. The SARIF
  reporter adds it to the document it writes, not to the scan's in-memory SARIF,
  which the exit-code gates read: ``run_ash_scan.unevaluated_rules`` treats an
  error-level execution notification there as a rule that did not run, and these
  are already counted by the converter gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import Invocation

#: The SARIF notification descriptor id for a refused converter input.
REFUSED_INPUT_NOTIFICATION_ID = "ASH-CONVERTER-INPUT-NOT-SCANNED"

#: How many refusals a summary lists before it gives a count of the rest.
SHOWN_IN_SUMMARY = 20

#: Unicode formatting characters that reorder the text around them when displayed.
_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)


def inert_text(text: str) -> str:
    """``text`` with every control and bidirectional-formatting character escaped.

    For names the scanned tree chose, shown in a terminal or a text report: an
    escape sequence in a member name would otherwise be interpreted by the reader's
    terminal, and a right-to-left override would show the name reordered.
    """
    shown = []
    for char in text:
        code = ord(char)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            shown.append(f"\\x{code:02x}")
        elif char in _BIDI_CONTROLS:
            shown.append(f"\\u{code:04x}")
        else:
            shown.append(char)
    return "".join(shown)


def markdown_code_span(text: str) -> str:
    """``text`` as one inline code span, so markdown, mentions and links stay text.

    The fence is one backtick longer than the longest run in the text, and padded
    with a space on each side, which CommonMark strips.
    """
    text = inert_text(text)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


@dataclass(frozen=True)
class ConverterRefusal:
    """One input a converter did not read, with the converter that recorded it."""

    converter: str
    path: str
    member: Optional[str]
    reason: str
    limit: Optional[str] = None

    unreadable: bool = False
    unlisted_members: Optional[int] = None

    @property
    def scan_incomplete(self) -> bool:
        """Whether this refusal is counted by the completeness gate."""
        return bool(self.limit) or self.unreadable

    def subject(self) -> str:
        if self.unlisted_members is not None:
            return f"{self.unlisted_members} more members of '{self.path}'"
        if self.member:
            return f"member '{self.member}' of '{self.path}'"
        return f"'{self.path}'"

    def message(self) -> str:
        return f"{self.converter}: {self.subject()} was not scanned: {self.reason}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "converter": self.converter,
            "path": self.path,
            "member": self.member,
            "reason": self.reason,
            "limit": self.limit,
            "scan_incomplete": self.scan_incomplete,
            "unlisted_members": self.unlisted_members,
        }


def converter_refusals(model: "AshAggregatedResults") -> List[ConverterRefusal]:
    """Every refused converter input in ``model``, those leaving the scan incomplete first.

    Read with ``getattr`` because a results file written by an older version carries
    rows without ``refused_inputs`` or entries without ``limit``.
    """
    refusals: List[ConverterRefusal] = []
    for name, row in (getattr(model, "converter_results", None) or {}).items():
        for item in getattr(row, "refused_inputs", None) or []:
            refusals.append(
                ConverterRefusal(
                    converter=str(name),
                    path=str(getattr(item, "path", "") or ""),
                    member=getattr(item, "member", None),
                    reason=str(getattr(item, "reason", "") or ""),
                    limit=getattr(item, "limit", None) or None,
                    unreadable=bool(getattr(item, "scan_incomplete", False))
                    and not getattr(item, "limit", None),
                    unlisted_members=getattr(item, "unlisted_members", None),
                )
            )
    refusals.sort(
        key=lambda r: (not r.scan_incomplete, r.converter, r.path, r.member or "")
    )
    return refusals


def summary_lines(
    refusals: List[ConverterRefusal], shown: int = SHOWN_IN_SUMMARY
) -> List[str]:
    """One line per refusal, at most ``shown``, then a line counting the rest."""
    lines = [
        ("[scan incomplete] " if refusal.scan_incomplete else "")
        + inert_text(refusal.message())
        for refusal in refusals[:shown]
    ]
    if len(refusals) > shown:
        lines.append(_more_line(len(refusals) - shown))
    return lines


def markdown_summary_lines(
    refusals: List[ConverterRefusal], shown: int = SHOWN_IN_SUMMARY
) -> List[str]:
    """``summary_lines`` as markdown list items, each refusal inside a code span."""
    lines = [
        "- "
        + ("**scan incomplete**: " if refusal.scan_incomplete else "")
        + markdown_code_span(refusal.message())
        for refusal in refusals[:shown]
    ]
    if len(refusals) > shown:
        lines.append(f"- {_more_line(len(refusals) - shown)}")
    return lines


def _more_line(count: int) -> str:
    return (
        f"... and {count} more; every one is listed under converter_results in "
        "ash_aggregated_results.json and in the flat JSON report"
    )


def refusal_invocations(model: "AshAggregatedResults") -> List["Invocation"]:
    """A SARIF invocation per converter that refused inputs, one notification each."""
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Invocation,
        Level,
        Location,
        Message,
        Message1,
        Notification,
        PhysicalLocation,
        PhysicalLocation2,
        PropertyBag,
        ReportingDescriptorReference,
        ReportingDescriptorReference3,
    )

    by_converter: Dict[str, List[ConverterRefusal]] = {}
    for refusal in converter_refusals(model):
        by_converter.setdefault(refusal.converter, []).append(refusal)

    invocations = []
    for converter, refusals in sorted(by_converter.items()):
        notifications = [
            Notification(
                level=Level.error if refusal.scan_incomplete else Level.warning,
                message=Message(root=Message1(text=refusal.message())),
                descriptor=ReportingDescriptorReference(
                    root=ReportingDescriptorReference3(id=REFUSED_INPUT_NOTIFICATION_ID)
                ),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            root=PhysicalLocation2(
                                artifactLocation=ArtifactLocation(uri=refusal.path)
                            )
                        )
                    )
                ],
                properties=PropertyBag.model_validate(
                    {"refused_input": refusal.to_dict()}
                ),
            )
            for refusal in refusals
        ]
        invocations.append(
            Invocation(
                executionSuccessful=not any(r.scan_incomplete for r in refusals),
                toolExecutionNotifications=notifications,
                properties=PropertyBag.model_validate({"ash_converter": converter}),
            )
        )
    return invocations
