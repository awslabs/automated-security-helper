# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The facet conformance verdict: declared facet state against an observed column.

The facets register (``base/scanner_facets.py``) says, per scanner and facet, whether
the native output maps (MAPPED), could map but is discarded today (DROPPED), or cannot
be there (N/A). This module is the pure half of the check that a declaration is not a
lie: :data:`FACET_COLUMNS` says which flat-row column each facet is observed through,
:func:`judge` joins one declared state with the observed counts, and
:func:`observed_counts` reads the counts off flat rows. It holds no corpus, so the
register consistency gate (``tests/unit/plugin_modules``) and the conformance harness
(``core/plugin_conformance``) read the same verdicts over different corpora.

The waiver contract: the register is the only place the truth lives. There is no
suppression list. A failure names the cell and both exits: fix the adapter or the
fixture, or redeclare the cell in the scanner's own register row with its reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from automated_security_helper.base.scanner_facets import FacetState


def text_present(value: Any) -> bool:
    """Whether a text column holds a value (not blank, ``[]``, ``{}`` or ``null``).

    A text column holds a string or nothing. Any other type is a column whose
    type changed under the gate, and reading it as "empty" would let an N/A or
    DROPPED cell pass over a populated column (the contamination direction),
    so it raises instead.
    """
    if value is None:
        return False
    if not isinstance(value, str):
        raise TypeError(
            f"a text facet column holds {type(value).__name__}, not str or None: "
            "the flat row's column type changed, so the observation is unreadable"
        )
    return value.strip() not in ("", "[]", "{}", "null")


def _present(value: Any) -> bool:
    return value is not None


@dataclass(frozen=True)
class Observation:
    """How one facet is read off a flat row.

    ``columns`` are the FlatVulnerability attributes read; ``populated`` is the
    predicate over their values (in column order). ``excluded`` is the declared
    v1 exclusion reason for a facet with no flat column.
    """

    columns: tuple[str, ...] = ()
    populated: Optional[Callable[..., bool]] = None
    excluded: Optional[str] = None


FACET_COLUMNS: Mapping[str, Observation] = {
    "rule_id": Observation(("rule_id",), text_present),
    "severity": Observation(("severity",), text_present),
    "file_path": Observation(("file_path",), text_present),
    "line_range": Observation(
        ("line_start", "line_end"), lambda start, end: _present(start) or _present(end)
    ),
    "column": Observation(
        excluded="the flat row has no column field: the start column is read "
        "only into the finding identity, so it is observed nowhere (G10 shape)"
    ),
    "message": Observation(("description",), text_present),
    "resource_id": Observation(("resource_id",), text_present),
    "resource_type": Observation(("resource_type",), text_present),
    "package_name": Observation(("package_name",), text_present),
    "package_version": Observation(("package_version",), text_present),
    "package_path": Observation(("package_path",), text_present),
    "taxonomy_cve": Observation(("cve_id",), text_present),
    "taxonomy_cwe": Observation(("cwe_id",), text_present),
    # A boolean observation: the id is keyed by a scanner fingerprint.
    "fingerprints": Observation(("has_fingerprint_identity",), bool),
    # False is a written value (the adapter said "no fix"); only None is empty.
    "fix_available": Observation(("fix_available",), _present),
    "remediation_text": Observation(
        excluded="no flat column: remediation text lives only in the SARIF "
        "property bag (G10; add property-bag observation as its own unit)"
    ),
    "snippet": Observation(("code_snippet",), text_present),
    "references": Observation(("references",), text_present),
    "tags": Observation(("tags",), text_present),
    "extras": Observation(
        excluded="no flat column: extras are the property bag itself (G10; "
        "add property-bag observation as its own unit)"
    ),
}

#: The two legal exits, named in every failure so the maintainer never has to
#: guess what "fix" means. There is no third (no skip list; see the module
#: docstring's waiver contract).
EXITS = (
    "Two exits: (1) fix the adapter or the fixture so the observed column "
    "matches the declaration, or (2) redeclare the cell in the scanner's own "
    "register row (the `facets` class attribute) with its reason; that edit "
    "is the reviewed waiver and the only one."
)


@dataclass(frozen=True)
class Verdict:
    scanner: str
    facet: str
    state: str
    non_null: Optional[int]
    total: Optional[int]
    outcome: str  # "ok" | "FAIL" | "excluded" | "owed"
    detail: str

    def row(self) -> str:
        if self.outcome == "excluded":
            counted = "excluded"
        else:
            counted = (
                "no-corpus" if self.total is None else f"{self.non_null}/{self.total}"
            )
        return (
            f"{self.scanner}\t{self.facet}\t{self.state}\t{counted}\t"
            f"{self.outcome}\t{self.detail}"
        )


def judge(
    scanner: str,
    facet: str,
    state: FacetState,
    observed: Optional[tuple[int, int]],
    *,
    corpus_hint: str = "",
) -> Verdict:
    """The verdict for one cell. ``observed`` is (non_null_count, total_results)
    or None when the scanner has no corpus at all."""
    if FACET_COLUMNS[facet].excluded is not None:
        return Verdict(scanner, facet, state.value, None, None, "excluded", "G10")
    non_null, total = observed if observed is not None else (None, None)
    populated = bool(non_null)
    cell = f"{scanner}.{facet} declared {state.value}"
    if state is FacetState.UNCONFIRMED:
        # Neither contamination nor proof: nobody has read a real run for this
        # cell, so whatever the corpus holds proves nothing yet. It is a fixture
        # owed, listed in the table and never failed.
        return Verdict(
            scanner,
            facet,
            state.value,
            non_null,
            total,
            "owed",
            "fixture owed: author or capture the real run that settles the cell, "
            "then redeclare it MAPPED or N/A with the evidence",
        )
    if state not in (FacetState.MAPPED, FacetState.NA, FacetState.DROPPED):
        # A new FacetState member must be judged on purpose. Without this the
        # chain below ends in an "ok" return that every unhandled state reaches,
        # so the next state would pass the gate silently over any column.
        raise AssertionError(f"facet state {state!r} has no judgment in judge()")
    if state is FacetState.MAPPED:
        if observed is None or not total:
            why = (
                "has no corpus to observe: "
                + (corpus_hint or "no committed fixture and no registered prep")
                if observed is None
                else f"its fixtures hold no results ({corpus_hint or 'empty corpus'})"
            )
            return Verdict(
                scanner,
                facet,
                state.value,
                non_null,
                total,
                "FAIL",
                f"{cell} but the scanner {why}. Name the missing fixture "
                f"(author it) or register its prep. {EXITS}",
            )
        if not populated:
            return Verdict(
                scanner,
                facet,
                state.value,
                non_null,
                total,
                "FAIL",
                f"{cell} but the observed column is empty across the corpus "
                f"(0 of {total} results): the tool's output moved or an adapter "
                f"regression dropped the mapping. {EXITS}",
            )
    elif state is FacetState.NA and populated:
        return Verdict(
            scanner,
            facet,
            state.value,
            non_null,
            total,
            "FAIL",
            f"{cell} (cannot be present) but the observed column is populated "
            f"({non_null} of {total} results): a value reached a column the "
            f"register says is impossible. {EXITS}",
        )
    elif state is FacetState.DROPPED and populated:
        return Verdict(
            scanner,
            facet,
            state.value,
            non_null,
            total,
            "FAIL",
            f"{cell} (discarded today) but the observed column is populated "
            f"({non_null} of {total} results): the cell is out of date, "
            f"redeclare it MAPPED with its native field. {EXITS}",
        )
    return Verdict(scanner, facet, state.value, non_null, total, "ok", "")


def observed_counts(flats: Iterable[Any]) -> dict[str, tuple[int, int]]:
    """Per observable facet ``(non_null_count, total_results)`` over flat rows."""
    rows = list(flats)
    counts: dict[str, tuple[int, int]] = {}
    for facet, observation in FACET_COLUMNS.items():
        is_populated = observation.populated
        if observation.excluded is not None or is_populated is None:
            continue
        populated = 0
        for flat in rows:
            values = [getattr(flat, column) for column in observation.columns]
            if is_populated(*values):
                populated += 1
        counts[facet] = (populated, len(rows))
    return counts
