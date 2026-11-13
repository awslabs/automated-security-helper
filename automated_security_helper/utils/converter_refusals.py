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

Every record is reported, and so is every input a converter could not convert
(``converter_results.<converter>.failed_inputs``: an archive that could not be read,
a notebook that could not be converted). Those and an archive over an extraction
limit, which ``limit`` names, are marked as leaving the scan incomplete: their
contents were not scanned at all, and the completeness
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
  scan incomplete, ``warning`` otherwise) located at the input's path, written as
  the URI reference SARIF's ``artifactLocation.uri`` is (percent-encoded, so a
  ``#``, ``?``, ``%`` or space in the name stays part of it). The SARIF
  reporter adds it to the document it writes, not to the scan's in-memory SARIF,
  which the exit-code gates read: ``run_ash_scan.unevaluated_rules`` treats an
  error-level execution notification there as a rule that did not run, and these
  are already counted by the converter gate.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import quote

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

#: Unicode categories of the characters that are escaped besides the controls and
#: _BIDI_CONTROLS: the line and paragraph separators (U+2028 and U+2029, which a
#: terminal or a text viewer breaks the line at, so a name holding one broke a
#: summary line into two) and the other format characters (zero-width joiners
#: and spaces, soft hyphens, tag characters), which show as nothing and can make
#: two different names read as one.
_ESCAPED_CATEGORIES = frozenset({"Zl", "Zp", "Cf"})


def inert_text(text: str) -> str:
    """``text`` with every control, separator and format character escaped.

    For names the scanned tree chose, shown in a terminal or a text report: an
    escape sequence in a member name would otherwise be interpreted by the reader's
    terminal, a right-to-left override would show the name reordered, and a line
    or paragraph separator would break the line the name is shown on.
    """
    shown = []
    for char in text:
        code = ord(char)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            shown.append(f"\\x{code:02x}")
        elif (
            char in _BIDI_CONTROLS or unicodedata.category(char) in _ESCAPED_CATEGORIES
        ):
            shown.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
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

    #: A ``failed_inputs`` record: an input the converter could not convert.
    failed: bool = False
    unlisted_members: Optional[int] = None
    #: A failed input a ``global_settings.suppressions`` entry with rule_id
    #: ``ash-unconverted-input`` accepted (``FailedInputInfo.accepted`` on an
    #: input error; ``waives_gate``). The loss was reviewed: the completeness
    #: gate leaves the record out, and so does ``scan_incomplete`` here.
    accepted: bool = False
    accepted_reason: Optional[str] = None

    @property
    def scan_incomplete(self) -> bool:
        """Whether this record is counted by the completeness gate.

        The gate's own reading (``incomplete_converters``): a refusal that names
        an extraction limit, or a failed input no suppression accepted. A failed
        input a suppression accepted is reported, as the record it is, and not
        as an incomplete scan: the gate waives it, so the reports say so too.
        """
        return bool(self.limit) or (self.failed and not self.accepted)

    def subject(self) -> str:
        if self.unlisted_members is not None:
            return f"{self.unlisted_members} more members of '{self.path}'"
        if self.member:
            return f"member '{self.member}' of '{self.path}'"
        return f"'{self.path}'"

    def message(self) -> str:
        text = f"{self.converter}: {self.subject()} was not scanned: {self.reason}"
        if self.accepted:
            # A record with no stored reason names the acceptance alone, never
            # the word "None".
            if self.accepted_reason:
                text += f" (accepted by a suppression: {self.accepted_reason})"
            else:
                text += " (accepted by a suppression)"
        return text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "converter": self.converter,
            "path": self.path,
            "member": self.member,
            "reason": self.reason,
            "limit": self.limit,
            "scan_incomplete": self.scan_incomplete,
            "unlisted_members": self.unlisted_members,
            "accepted": self.accepted,
            "accepted_reason": self.accepted_reason,
        }


def converter_refusals(model: "AshAggregatedResults") -> List[ConverterRefusal]:
    """Every refused converter input in ``model``, those leaving the scan incomplete first.

    Read with ``getattr`` because a results file written by an older version carries
    rows without ``refused_inputs`` or entries without ``limit``. A failed input is
    marked accepted exactly when the completeness gate waives it (``waives_gate``:
    accepted, and of kind "input"), so the reports and the gate agree.
    """
    from automated_security_helper.models.asharp_model import waives_gate

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
                    unlisted_members=getattr(item, "unlisted_members", None),
                )
            )
        for item in getattr(row, "failed_inputs", None) or []:
            accepted = waives_gate(item)
            accepted_reason = getattr(item, "accepted_reason", None)
            refusals.append(
                ConverterRefusal(
                    converter=str(name),
                    path=str(getattr(item, "path", "") or ""),
                    member=None,
                    reason=str(getattr(item, "reason", "") or ""),
                    failed=True,
                    accepted=accepted,
                    accepted_reason=(
                        None
                        if not accepted or accepted_reason is None
                        else str(accepted_reason)
                    ),
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


def _artifact_uri(path: str) -> str:
    """``path``, a tree-relative path with ``/``, as a SARIF ``artifactLocation.uri``.

    A URI reference, so the path is percent-encoded with ``/`` kept: written as
    it was, a ``#`` started a fragment, a ``?`` a query, a ``%`` an escape and a
    space made the reference invalid, and a reader resolved the notification to
    another file or none. The record's own ``path`` (``properties.refused_input``)
    stays the path as written. A lone surrogate, a name byte that is not UTF-8
    read back from a results file, is encoded as that byte.
    """
    return quote(path.encode("utf-8", "surrogateescape"), safe="/")


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
                                artifactLocation=ArtifactLocation(
                                    uri=_artifact_uri(refusal.path)
                                )
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
