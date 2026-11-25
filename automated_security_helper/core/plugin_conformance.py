# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The conformance harness behind ``ash plugin verify``: the promotion bar, runnable.

Promotion of a scanner from ``alpha`` to ``supported`` is a one-line manifest change
gated on five things. This module evaluates each as a *row* over a scanner's manifest
and its committed transcripts, with no tool run and no network:

1. **Facets over transcripts.** The scanner's recorded transcripts are sound (bytes
   match their digests), fresh (stamped with the pin the manifest declares now), and
   every facet cell of the register agrees with what the transcripts observably carry
   (declared-mapped observed non-empty, declared-N/A empty), judged by
   :func:`~automated_security_helper.base.facet_conformance.judge`, the same function
   the register consistency gate uses.
2. **Operational declarations complete.** The operational register row has no
   unconfirmed cell: honest-ignorance states must be resolved to promote.
3. **Live cell.** The live-tool cell is green on every platform the manifest
   declares. The cell itself runs in CI (Phase B); this row only READS its result, so
   without one it is ``NOT_RUN``, never green.
4. **Provisioning.** The tool is pinned (version and SHA-256 per platform), or declared
   user-installed with its prerequisites stated.
5. **Docs.** Documentation generated from the manifest. No generator exists in this
   tree yet, so the row is ``NOT_RUN`` and says why.

A row is ``GREEN``, ``RED`` or ``NOT_RUN``. ``NOT_RUN`` means the row could not be
evaluated here (it is not a pass, and it is not a defect of the plugin). The report's
verdict is ``fail`` if any row is red, ``pass`` only if all five are green, and
``incomplete`` otherwise; ``ash plugin verify`` exits 1, 0 and 3 for them. Demotion is
the same check read the other way, so a ``supported`` scanner is verified the same way.

The harness reaches a plugin only through its manifest (``resolve_ref``) and imports no
plugin module by name, so the layer order holds. A scanner class is loaded to read its
register rows, the way the kernel will read them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

from pydantic import BaseModel

from automated_security_helper.base.facet_conformance import (
    Verdict,
    judge,
    observed_counts,
)
from automated_security_helper.base.plugin_manifest import (
    PluginTier,
    ScannerManifest,
    resolve_ref,
)
from automated_security_helper.base.plugin_provisioning import tool_versions
from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.base.scanner_operational_facets import (
    LICENSE_NOT_READ,
    OPERATIONAL_FACETS_ATTR,
    RuntimeKind,
)
from automated_security_helper.base.tool_transcript import (
    TRANSCRIPT_FILE_NAME,
    ToolTranscript,
    TranscriptFile,
    load_transcript_file,
    stale_transcripts,
    verify_digests,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

#: The exit codes of ``ash plugin verify``.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCOMPLETE = 3


class RowStatus(str, Enum):
    GREEN = "green"
    RED = "red"
    #: The row could not be evaluated here; not a pass.
    NOT_RUN = "not-run"


@dataclass(frozen=True)
class BarRow:
    number: int
    name: str
    status: RowStatus
    #: One sentence per finding (red) or per reason (not-run); empty for green.
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class BarReport:
    scanner: str
    tier: str
    rows: tuple[BarRow, ...]
    #: Per-cell facet verdicts behind row 1 (for ``--json`` and triage).
    verdicts: tuple[Verdict, ...] = field(default=())

    @property
    def verdict(self) -> str:
        if any(row.status is RowStatus.RED for row in self.rows):
            return "fail"
        if all(row.status is RowStatus.GREEN for row in self.rows):
            return "pass"
        return "incomplete"

    @property
    def exit_code(self) -> int:
        return {"pass": EXIT_PASS, "fail": EXIT_FAIL}.get(self.verdict, EXIT_INCOMPLETE)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "tier": self.tier,
            "verdict": self.verdict,
            "rows": [
                {
                    "row": row.number,
                    "name": row.name,
                    "status": row.status.value,
                    "details": list(row.details),
                }
                for row in self.rows
            ],
        }


# ---------------------------------------------------------------------------
# Transcripts: discovery and the corpus they make.
# ---------------------------------------------------------------------------


def discover_transcript_files(root: Path) -> list[tuple[Path, TranscriptFile]]:
    """Every ``transcripts.json`` under *root*, with its directory, in path order."""
    return [
        (path.parent, load_transcript_file(path))
        for path in sorted(root.rglob(TRANSCRIPT_FILE_NAME))
    ]


def transcripts_of(
    scanner: str, files: list[tuple[Path, TranscriptFile]]
) -> list[tuple[Path, ToolTranscript]]:
    return [
        (base, transcript)
        for base, file in files
        for transcript in file.transcripts
        if scanner in transcript.scanners
    ]


def unrecorded_reasons(
    scanner: str, files: list[tuple[Path, TranscriptFile]]
) -> list[str]:
    return [
        row.reason
        for _base, file in files
        for row in file.unrecorded
        if row.scanner == scanner
    ]


def _load_sarif(path: Path) -> SarifReport:
    return SarifReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


Prep = Callable[
    [ToolTranscript, Path, Path], Iterator[tuple[SarifReport, list[Result]]]
]

_BUILTIN_SCANNERS = "automated_security_helper.plugin_modules.ash_builtin.scanners"


def _prep_cfn_guard(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.cfn_guard_scanner:CfnGuardScanner")
    report = _load_sarif(file)
    yield report, cls.normalize_results(report, "template.yaml")


def _prep_cfn_lint(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.cfn_lint_scanner:CfnLintScanner")
    report = _load_sarif(file)
    # normalize_report reads no instance state: it locates results, maps
    # severities and sorts rules in place.
    cls.normalize_report(None, report)
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_guarddog(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    convert = resolve_ref(
        "automated_security_helper.plugin_modules.ash_guarddog_plugins."
        "guarddog_scanner:convert_guarddog_scan_result"
    )
    ecosystem = file.stem.split("_")[1]
    document = json.loads(file.read_text(encoding="utf-8"))
    converted = convert(
        document, uri_prefix="", ecosystem=ecosystem, include_capabilities=True
    )
    report = SarifReport.model_validate({"version": "2.1.0", "runs": []})
    yield report, list(converted.results)


#: Registered adapter preps: native or adapter-normalized bytes through the adapter's
#: own pure function. A prep never runs a tool. A transcript names one in
#: ``adapter_prep``.
PREPS: Mapping[str, Prep] = {
    "cfn-guard": _prep_cfn_guard,
    "cfn-lint": _prep_cfn_lint,
    "guarddog": _prep_guarddog,
}


def _results_with_runs(
    transcript: ToolTranscript, base: Path
) -> Iterator[tuple[Any, Result]]:
    """``(run or None, result)`` for every result of one transcript's SARIF-bearing files."""
    for entry in transcript.results:
        file = base / entry.path
        if transcript.adapter_prep is not None:
            for report, results in PREPS[transcript.adapter_prep](
                transcript, base, file
            ):
                run = report.runs[0] if report.runs else None
                for result in results:
                    yield run, result
        elif entry.format == "sarif":
            for run in _load_sarif(file).runs or []:
                for result in run.results or []:
                    yield run, result


def observed_frame(
    scanner: str,
    transcripts: list[tuple[Path, ToolTranscript]],
    tool_type: Optional[str] = None,
) -> Optional[dict[str, tuple[int, int]]]:
    """Per facet ``(non_null_count, total_results)`` over the scanner's transcripts, or
    None when none of them can be read as results (native bytes with no registered prep)."""
    readable = [
        (base, t)
        for base, t in transcripts
        if t.observable
        and (t.adapter_prep is not None or any(r.format == "sarif" for r in t.results))
    ]
    if not readable:
        return None
    kind = tool_type or SCANNER_TOOL_TYPES[scanner]
    flats = [
        FlatVulnerability.from_sarif_result(result, scanner, kind, run)
        for base, transcript in readable
        for run, result in _results_with_runs(transcript, base)
    ]
    return observed_counts(flats)


# ---------------------------------------------------------------------------
# The rows.
# ---------------------------------------------------------------------------


def _scanner_class(manifest: ScannerManifest) -> type:
    return resolve_ref(manifest.entry_points.scanner)


def _row_facets(
    manifest: ScannerManifest,
    files: list[tuple[Path, TranscriptFile]],
    pins: Mapping[str, str],
    tool_type: Optional[str],
) -> tuple[BarRow, tuple[Verdict, ...]]:
    name = manifest.name
    problems: list[str] = []
    mine = transcripts_of(name, files)
    if not mine:
        reasons = unrecorded_reasons(name, files)
        problems.append(
            f"{name} has no recorded transcript"
            + (f" ({reasons[0]})" if reasons else "")
            + "; record one (a transcripts.json beside its fixture)"
        )
    for base, transcript in mine:
        problems.extend(verify_digests(transcript, base))
    pinned = {name: pin.tool for pin in manifest.provisioning.tool_pins[:1]}
    problems.extend(stale_transcripts((t for _base, t in mine), pins, pinned))
    if pinned and mine and not any(t.retention == "current" for _b, t in mine):
        problems.append(
            f"{name} pins {pinned[name]} but every recorded transcript is historical; "
            "re-record at the pin (a promotion is judged over a recording of the "
            "tool as shipped)"
        )
    verdicts: list[Verdict] = []
    declared = vars(_scanner_class(manifest)).get(SCANNER_FACETS_ATTR)
    if declared is None:
        problems.append(f"{name}'s scanner class declares no facets register row")
    else:
        frame = observed_frame(name, mine, tool_type) if mine else None
        hint = (
            f"{name}'s transcripts hold no readable results (no SARIF, no registered "
            "adapter prep)"
        )
        for facet in FACET_NAMES:
            state: FacetState = getattr(declared, facet).state
            observed = None if frame is None else frame.get(facet)
            verdict = judge(name, facet, state, observed, corpus_hint=hint)
            verdicts.append(verdict)
            if verdict.outcome == "FAIL":
                problems.append(f"[{name}.{facet}] {verdict.detail}")
    status = RowStatus.RED if problems else RowStatus.GREEN
    return (
        BarRow(1, "facets green over committed transcripts", status, tuple(problems)),
        tuple(verdicts),
    )


def unconfirmed_cells(value: Any, path: str = "") -> Iterator[str]:
    """Every honest-ignorance cell under an operational register row, as ``path: what``."""
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            child = getattr(value, field_name)
            here = f"{path}.{field_name}" if path else field_name
            if field_name == "unconfirmed" and child is not None:
                yield f"{path}: {child}"
            else:
                yield from unconfirmed_cells(child, here)
    elif isinstance(value, (tuple, list)):
        for index, child in enumerate(value):
            yield from unconfirmed_cells(child, f"{path}[{index}]")
    elif isinstance(value, Enum):
        if value.value == "unconfirmed":
            yield f"{path}: unconfirmed"
    elif isinstance(value, str) and value.strip() == LICENSE_NOT_READ:
        yield f"{path}: {LICENSE_NOT_READ}"


def _row_operational(manifest: ScannerManifest) -> BarRow:
    row = getattr(_scanner_class(manifest), OPERATIONAL_FACETS_ATTR, None)
    if row is None:
        return BarRow(
            2,
            "operational declarations complete",
            RowStatus.RED,
            (f"{manifest.name}'s scanner class declares no operational register row",),
        )
    cells = tuple(unconfirmed_cells(row))
    return BarRow(
        2,
        "operational declarations complete, zero unconfirmed",
        RowStatus.RED if cells else RowStatus.GREEN,
        tuple(f"unconfirmed cell {cell}" for cell in cells),
    )


def _row_live(
    manifest: ScannerManifest, live_results: Optional[Mapping[str, bool]]
) -> BarRow:
    operational = getattr(_scanner_class(manifest), OPERATIONAL_FACETS_ATTR, None)
    required = (
        tuple(operational.platforms.provisionable)
        if operational is not None and operational.platforms.provisionable
        else ("host",)
    )
    if live_results is None:
        reason = (
            "no live-cell result was supplied; the live cell runs in CI "
            f"(it must be green on {', '.join(required)})"
        )
        return BarRow(
            3,
            "live-tool cell green on every declared platform",
            RowStatus.NOT_RUN,
            (reason,),
        )
    missing = [p for p in required if p not in live_results]
    red = [p for p in required if p in live_results and not live_results[p]]
    problems = [f"no live-cell result for {p}" for p in missing] + [
        f"the live cell is red on {p}" for p in red
    ]
    return BarRow(
        3,
        "live-tool cell green on every declared platform",
        RowStatus.RED if problems else RowStatus.GREEN,
        tuple(problems),
    )


def _row_provisioning(manifest: ScannerManifest) -> BarRow:
    name = "provisioning pinned, or user-installed with prerequisites"
    cls = _scanner_class(manifest)
    operational = getattr(cls, OPERATIONAL_FACETS_ATTR, None)
    if operational is None:
        return BarRow(
            4,
            name,
            RowStatus.RED,
            ("no operational register row to read the runtime from",),
        )
    runtime = operational.runtime
    if runtime.kind is RuntimeKind.PINNED_BINARY:
        from automated_security_helper.utils.tool_downloads import get_tool_asset

        key = runtime.tool_versions_key or ""
        pinned = {pin.tool for pin in manifest.provisioning.tool_pins}
        problems: list[str] = []
        if key not in pinned:
            problems.append(
                f"the runtime names tool {key!r} but the manifest pins {sorted(pinned)}"
            )
        platforms = operational.platforms.provisionable
        if not platforms:
            problems.append("a pinned binary declares the platforms it provisions on")
        for platform in platforms:
            os_name, _, arch = platform.partition("/")
            try:
                asset = get_tool_asset(key, os_name, arch)
            except Exception as error:  # noqa: BLE001 - reported as the finding
                problems.append(f"{key} on {platform}: {error}")
                continue
            if len(asset.sha256) != 64:
                problems.append(f"{key} on {platform} carries no SHA-256 digest")
        return BarRow(
            4,
            name,
            RowStatus.RED if problems else RowStatus.GREEN,
            tuple(problems),
        )
    if runtime.kind is RuntimeKind.USER_INSTALLED_CLI:
        note = operational.prerequisites.note.strip()
        return BarRow(
            4,
            name,
            RowStatus.GREEN if note else RowStatus.RED,
            () if note else ("a user-installed CLI states its prerequisites",),
        )
    if runtime.kind is RuntimeKind.IN_PROCESS:
        return BarRow(4, name, RowStatus.GREEN, ())
    reason = (
        f"a {runtime.kind.value} tool is pinned by its package lock, which the "
        "manifest does not declare yet; this row cannot read it"
    )
    return BarRow(4, name, RowStatus.NOT_RUN, (reason,))


def _row_docs() -> BarRow:
    return BarRow(
        5,
        "docs generated from the manifest",
        RowStatus.NOT_RUN,
        ("no manifest-to-docs generator exists in this tree yet",),
    )


def verify_plugin(
    manifest: ScannerManifest,
    transcripts_root: Path,
    *,
    live_results: Optional[Mapping[str, bool]] = None,
    pins: Optional[Mapping[str, str]] = None,
    tool_type: Optional[str] = None,
) -> BarReport:
    """Evaluate the promotion bar for *manifest* over the transcripts under
    *transcripts_root*. Runs no tool and touches no network."""
    files = discover_transcript_files(transcripts_root)
    facets_row, verdicts = _row_facets(
        manifest, files, pins if pins is not None else tool_versions(), tool_type
    )
    return BarReport(
        scanner=manifest.name,
        tier=manifest.tier.value
        if isinstance(manifest.tier, PluginTier)
        else str(manifest.tier),
        rows=(
            facets_row,
            _row_operational(manifest),
            _row_live(manifest, live_results),
            _row_provisioning(manifest),
            _row_docs(),
        ),
        verdicts=verdicts,
    )
