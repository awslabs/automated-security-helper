# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pair each SARIF result with the flattened finding that describes it.

``AshAggregatedResults.to_flat_vulnerabilities`` builds one flattened finding per
SARIF result in ``get_all_results`` order, and its id (``utils/finding_identity``)
is the id every other ASH report gives the finding. The GitLab SAST and OCSF
reporters read that id by position. Position alone is a weak join: a flattening
with more rows than results (a row per location, a row from another source) used
to pass a length check taken after the list was cut to size, and every id after
the first extra row then named a different finding, in the report and in the
identifier GitLab tracks across pipelines. One unreadable id also switched every
finding of the report back to its legacy id, which changed every id between two
pipelines of the same tree.

So the join pairs the SARIF rows of the flattening (the rows that carry no
``source_report``; a scanner's list-form additional report adds rows after them,
and those rows describe no SARIF result) with the results by position, and each
pair has to agree on what the flattening read from the result (its rule id, its
first file and its first line). The two lists are the same length by construction;
when they are not, the rows are walked so that one stray row costs the position it
sits at and no other, instead of the whole report falling back to its legacy ids
(which changed every id between two pipelines of the same tree for one stray row).
"""

from typing import Any, List, Optional

__all__ = ["shared_ids_by_position", "flat_describes_result"]


def shared_ids_by_position(flat: List[Any], results: List[Any]) -> List[Optional[str]]:
    """The shared id of each result, or None where the flattening cannot vouch for it.

    Only the SARIF rows of *flat* take part: a row whose ``source_report`` is set
    was read from a scanner's additional report and describes no SARIF result
    (a row without the attribute is read as a SARIF row). With as many SARIF rows
    as results the two line up by position; otherwise the rows are walked in
    order and each result takes the next row that describes it, so an extra or
    missing row costs the position it sits at alone. None at a position whose row
    carries no usable id or describes another result.
    """
    rows = [item for item in flat if getattr(item, "source_report", None) is None]
    ids: List[Optional[str]] = []
    if len(rows) == len(results):
        for item, result in zip(rows, results):
            ids.append(
                _usable_id(item) if flat_describes_result(item, result) else None
            )
        return ids
    cursor = 0
    for result in results:
        paired = None
        for offset in range(cursor, len(rows)):
            if flat_describes_result(rows[offset], result):
                paired = rows[offset]
                cursor = offset + 1
                break
        ids.append(_usable_id(paired) if paired is not None else None)
    return ids


def _usable_id(item: Any) -> Optional[str]:
    """*item*'s id when it is a non-empty string, else None."""
    identifier = getattr(item, "id", None)
    if isinstance(identifier, str) and identifier:
        return identifier
    return None


def flat_describes_result(item: Any, result: Any) -> bool:
    """Whether flattened finding *item* was read from *result*: same rule, same
    file, same first line.

    Compared the way ``FlatVulnerability.from_sarif_result`` reads them: the
    result's ``ruleId`` (not a ``rule.id`` reference), its first location's
    artifact URI with a ``file://`` scheme stripped, and that location's region
    start line (None on both sides when the result has no region). The line is
    compared because two hits of one rule in one file differ in nothing else a
    row carries, and a flattening that ordered them the other way round swapped
    their ids with no sign. A read that raises is a mismatch, never an exception:
    the caller is deciding which id to print.
    """
    try:
        flat_rule = getattr(item, "rule_id", None) or None
        result_rule = getattr(result, "ruleId", None) or None
        if flat_rule != result_rule:
            return False
        flat_file = getattr(item, "file_path", None) or None
        if flat_file != _first_file_path(result):
            return False
        return getattr(item, "line_start", None) == _first_start_line(result)
    except Exception:  # noqa: BLE001 -- see the docstring
        return False


def _first_start_line(result: Any) -> Optional[int]:
    """The start line of the result's first location's region, as the flattening
    records it; None when the result has no location or no region."""
    locations = getattr(result, "locations", None) or []
    if not locations:
        return None
    physical = getattr(locations[0], "physicalLocation", None)
    root = getattr(physical, "root", None)
    region = getattr(root, "region", None) if root is not None else None
    line = getattr(region, "startLine", None) if region is not None else None
    return int(line) if line is not None else None


def _first_file_path(result: Any) -> Optional[str]:
    """The result's first location's file, as the flattening records it."""
    locations = getattr(result, "locations", None) or []
    if not locations:
        return None
    physical = getattr(locations[0], "physicalLocation", None)
    root = getattr(physical, "root", None)
    if root is None:
        return None
    artifact = getattr(root, "artifactLocation", None)
    uri = getattr(artifact, "uri", None) if artifact is not None else None
    if not uri:
        return None
    text = str(uri)
    if text.startswith("file://"):
        text = text[7:]
        if text.startswith("///"):
            text = text[2:]
    return text or None
