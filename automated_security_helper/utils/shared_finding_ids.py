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

from bisect import bisect_left
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from automated_security_helper.utils.frame_text import ranks, wire

if TYPE_CHECKING:
    import polars as pl

__all__ = [
    "shared_ids_by_position",
    "shared_correlation_ids_by_position",
    "flat_describes_result",
]


def shared_ids_by_position(flat: List[Any], results: List[Any]) -> List[Optional[str]]:
    """The shared id of each result, or None where the flattening cannot vouch for it.

    Only the SARIF rows of *flat* take part: a row whose ``source_report`` is set
    was read from a scanner's additional report and describes no SARIF result
    (a row without the attribute is read as a SARIF row). With as many SARIF rows
    as results the two line up by position; otherwise the rows are walked in
    order and each result takes the next row, at or after the last one taken,
    that describes it: an extra row is skipped and a result with no row gets
    None. The walk never goes back, so a result whose row lies before the last
    one taken (rows and results in different orders) gets None as well. None
    at a position whose row carries no usable id or describes another result.
    """
    return _shared_values_by_position(flat, results, _usable_id)


def shared_correlation_ids_by_position(
    flat: List[Any], results: List[Any]
) -> List[Optional[str]]:
    """The correlation id of each result, or None where there is none to vouch for.

    The same pairing as :func:`shared_ids_by_position`, reading the flattened
    finding's ``correlation_id`` instead of its ``id``, so a reporter that
    carries both reads them off one row. None where the paired row carries none
    (most findings: only the ``secret/`` and ``dep/`` families have one, see
    ``utils/finding_identity``) and where no row can vouch for the result.
    """
    return _shared_values_by_position(flat, results, _usable_correlation_id)


def _shared_values_by_position(
    flat: List[Any], results: List[Any], value_of: Callable[[Any], Optional[str]]
) -> List[Optional[str]]:
    """What *value_of* gives for each result's paired row; see the public wrappers."""
    rows = [item for item in flat if getattr(item, "source_report", None) is None]
    pairs = _describing_pairs(rows, results)
    ids: List[Optional[str]] = []
    if len(rows) == len(results):
        # By position: result ``i`` takes row ``i`` when that pair describes it.
        agreed = {result for result, row in pairs if result == row}
        for position, item in enumerate(rows):
            ids.append(value_of(item) if position in agreed else None)
        return ids
    # Walked: each result takes the first row, at or after the last one taken,
    # that describes it. The frame says which rows describe each result; the
    # cursor, which depends on the answer before it, stays a loop.
    candidates: Dict[int, List[int]] = {}
    for result, row in pairs:
        candidates.setdefault(result, []).append(row)
    cursor = 0
    for position in range(len(results)):
        listed = candidates.get(position, [])
        at = bisect_left(listed, cursor)
        if at < len(listed):
            cursor = listed[at] + 1
            ids.append(value_of(rows[listed[at]]))
        else:
            ids.append(None)
    return ids


# A key cell is text or an object, told apart by its first character, and a missing
# part is the empty string (a part that is present is never empty: ``_stripped``
# turns an empty one into None). A line is a rank, and a missing line is -1.
_MISSING = ""
_NO_LINE = -1


def _cell(value: Any, objects: Dict[Any, int]) -> str:
    """One text part of a pairing key, as a string a polars column can hold.

    Text goes through ``frame_text.wire`` (a lone surrogate is carried, not
    refused). A value that is not text is compared by equality, as the walk
    compared it, so equal values share one code. An unhashable one raises
    ``TypeError``, which the caller reads as "describes nothing".
    """
    if value is None:
        return _MISSING
    if isinstance(value, str):
        return "t" + (wire(value) or "")
    return "o" + str(objects.setdefault(value, len(objects)))


def _line_value(value: Any) -> Optional[int]:
    """*value* as the int it compares equal to, None for no line.

    Raises ``ValueError`` for what equals no int and no None (text, a float with a
    fraction, any other object), so the caller reads it as "describes nothing".
    """
    if value is None:
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise ValueError("not a line")


def _flat_parts(item: Any) -> Optional[Tuple[Any, Any, Optional[int]]]:
    """What the flattened row says about its rule, file and first line."""
    try:
        return (
            _stripped(getattr(item, "rule_id", None)),
            _stripped(getattr(item, "file_path", None)),
            _line_value(getattr(item, "line_start", None)),
        )
    except Exception:  # noqa: BLE001 -- a row that cannot be read describes nothing
        return None


def _result_parts(result: Any) -> Optional[Tuple[Any, Any, Optional[int]]]:
    """What the result says about its rule, file and first line."""
    try:
        return (
            _stripped(getattr(result, "ruleId", None)),
            _stripped(_first_file_path(result)),
            _first_start_line(result),
        )
    except Exception:  # noqa: BLE001 -- a result that cannot be read pairs with nothing
        return None


def _keyed_frame(
    parts: List[Optional[Tuple[Any, Any, Optional[int]]]],
    line_rank: Dict[int, int],
    objects: Dict[Any, int],
    name: str,
) -> "pl.DataFrame":
    """One row per readable item: ``name`` its position, and its rule, file, line."""
    import polars as pl

    index: List[int] = []
    rules: List[str] = []
    files: List[str] = []
    lines: List[int] = []
    for position, part in enumerate(parts):
        if part is None:
            continue
        try:
            rule, path = _cell(part[0], objects), _cell(part[1], objects)
        except TypeError:
            continue
        index.append(position)
        rules.append(rule)
        files.append(path)
        lines.append(_NO_LINE if part[2] is None else line_rank[part[2]])
    return pl.DataFrame(
        {name: index, "rule": rules, "file": files, "line": lines},
        schema={
            name: pl.Int64,
            "rule": pl.String,
            "file": pl.String,
            "line": pl.Int64,
        },
    )


def _describing_pairs(rows: List[Any], results: List[Any]) -> List[Tuple[int, int]]:
    """Every ``(result, row)`` position pair where the row describes the result.

    Reading a row or a result is the host's (they are objects; a read can raise,
    and a read that raises describes nothing). What each said about its rule, file
    and first line becomes a row of a frame, and the pairs are an inner join on
    the three. Sorted by result, then row.
    """
    flat_parts = [_flat_parts(item) for item in rows]
    result_parts = [_result_parts(result) for result in results]
    # The frame column is 64-bit and a line is not, so a line goes in as its rank
    # (equal lines have equal ranks, which is all the join asks).
    line_rank = ranks(
        part[2]
        for parts in (flat_parts, result_parts)
        for part in parts
        if part is not None and part[2] is not None
    )
    objects: Dict[Any, int] = {}
    row_frame = _keyed_frame(flat_parts, line_rank, objects, "row")
    result_frame = _keyed_frame(result_parts, line_rank, objects, "result")
    joined = (
        result_frame.join(row_frame, on=["rule", "file", "line"], how="inner")
        .select("result", "row")
        .sort("result", "row")
    )
    return [(result, row) for result, row in joined.iter_rows()]


def _usable_id(item: Any) -> Optional[str]:
    """*item*'s id when it is a non-empty string, else None."""
    identifier = getattr(item, "id", None)
    if isinstance(identifier, str) and identifier:
        return identifier
    return None


def _usable_correlation_id(item: Any) -> Optional[str]:
    """*item*'s correlation id when it is a non-empty string, else None."""
    value = getattr(item, "correlation_id", None)
    if isinstance(value, str) and value:
        return value
    return None


def flat_describes_result(item: Any, result: Any) -> bool:
    """Whether flattened finding *item* was read from *result*: same rule, same
    file, same first line.

    Compared the way ``FlatVulnerability.from_sarif_result`` reads them: the
    result's ``ruleId`` (not a ``rule.id`` reference), its first location's
    artifact URI reduced to a path (a ``file://`` URI loses its scheme and host
    and is percent-decoded, as the flattening does; any other URI is compared
    as written), and that location's start
    line: the region's, else the context region's (None on both sides when the
    result names no line). The rule id and the path are compared without the
    blanks around them, because the flattening strips every string it records.
    The line is compared because two hits of one rule in
    one file differ in nothing else a row carries, and a flattening that ordered
    them the other way round swapped their ids with no sign. A read that raises
    is a mismatch, never an exception: the caller is deciding which id to print.
    """
    try:
        flat_rule = _stripped(getattr(item, "rule_id", None))
        result_rule = _stripped(getattr(result, "ruleId", None))
        if flat_rule != result_rule:
            return False
        flat_file = _stripped(getattr(item, "file_path", None))
        if flat_file != _stripped(_first_file_path(result)):
            return False
        return getattr(item, "line_start", None) == _first_start_line(result)
    except Exception:  # noqa: BLE001 -- see the docstring
        return False


def _stripped(value: Any) -> Any:
    """*value* without surrounding whitespace when it is text, None when empty.

    ``FlatVulnerability`` strips every string field it holds, so a rule id or a
    path that the result carries with blanks around it is recorded without
    them. Both sides of the comparison are read the same way, or the row of a
    result whose rule id is padded would never pair with it and its report
    would print the legacy id.
    """
    if isinstance(value, str):
        value = value.strip()
    return value or None


def _first_start_line(result: Any) -> Optional[int]:
    """The start line of the result's first location, as the flattening records
    it: the ``region``'s ``startLine``, else the ``contextRegion``'s (the
    flattening's own fallback); None when the result has no location or
    neither region names a line.

    Reading ``region`` alone left a result whose only start line sits in its
    ``contextRegion`` unpaired by the walk: the flattened row carried the
    context line, this read None, and the result fell back to its legacy id.
    """
    locations = getattr(result, "locations", None) or []
    if not locations:
        return None
    physical = getattr(locations[0], "physicalLocation", None)
    root = getattr(physical, "root", None)
    if root is None:
        return None
    for name in ("region", "contextRegion"):
        region = getattr(root, name, None)
        line = getattr(region, "startLine", None) if region is not None else None
        if line is not None:
            return int(line)
    return None


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
        # The reducer the flattening applies to the same URI (it drops a host
        # segment and the slash before a drive letter, and decodes percent
        # escapes), so both sides spell a ``file:`` URI alike. Imported here
        # because sarif_utils imports this module.
        from automated_security_helper.utils.sarif_utils import (
            _file_uri_to_path_text,
        )

        text = _file_uri_to_path_text(text)
    return text or None
