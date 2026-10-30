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

So the join requires the two lists to have the same length, and each pair to agree
on what the flattening read from the result (its rule id and its first file); a
position that does not pair falls back alone.
"""

from typing import Any, List, Optional

__all__ = ["shared_ids_by_position", "flat_describes_result"]


def shared_ids_by_position(flat: List[Any], results: List[Any]) -> List[Optional[str]]:
    """The shared id of each result, or None where the flattening cannot vouch for it.

    None at every position when the two lists differ in length, because then no
    position is known to line up; None at one position when its flattened row
    carries no usable id or describes another result.
    """
    if len(flat) != len(results):
        return [None] * len(results)
    ids: List[Optional[str]] = []
    for item, result in zip(flat, results):
        identifier = getattr(item, "id", None)
        if (
            isinstance(identifier, str)
            and identifier
            and flat_describes_result(item, result)
        ):
            ids.append(identifier)
        else:
            ids.append(None)
    return ids


def flat_describes_result(item: Any, result: Any) -> bool:
    """Whether flattened finding *item* was read from *result*: same rule, same file.

    Compared the way ``FlatVulnerability.from_sarif_result`` reads them: the
    result's ``ruleId`` (not a ``rule.id`` reference) and its first location's
    artifact URI with a ``file://`` scheme stripped. A read that raises is a
    mismatch, never an exception: the caller is deciding which id to print.
    """
    try:
        flat_rule = getattr(item, "rule_id", None) or None
        result_rule = getattr(result, "ruleId", None) or None
        if flat_rule != result_rule:
            return False
        flat_file = getattr(item, "file_path", None) or None
        return flat_file == _first_file_path(result)
    except Exception:  # noqa: BLE001 -- see the docstring
        return False


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
