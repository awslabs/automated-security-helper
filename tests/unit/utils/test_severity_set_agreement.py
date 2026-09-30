# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The five longhand copies of the severity name set must agree.

Why this file exists rather than a refactor
-------------------------------------------
ASH's five severity names are written out by hand in five live places:

* ``utils/severity_ladder.py`` ``SEVERITIES`` -- the source of truth by
  declaration; three modules import it.
* ``core/constants.py`` ``VALID_SEVERITY_VALUES``
* ``models/flat_vulnerability.py`` ``_SEVERITY_ORDER``
* ``utils/sarif_utils.py`` ``_CANONICAL_SEVERITIES``
* ``core/resource_management/result_filters.py`` -- an inline tuple inside
  ``_get_finding_severity``, so it has no name to import and can only be reached
  behaviorally.

Collapsing five call sites is the larger change and it is not the better one
here. These are the SARIF/CVSS names and they have not moved, so the likelihood
of change is low, and ``cli/merge.py`` (line ~1197) already records the project
declining to add a sixth copy for exactly this reason. A cheap test that the
copies agree buys most of the safety of a refactor at a fraction of the risk, so
that is what this is.

The specific failure it guards
------------------------------
``sarif_utils.normalize_sarif_result_severities`` fails OPEN: when a rule carries
no usable score it runs ``continue`` (around lines 364-373) and the result keeps
whatever severity it had. So a partial edit to the severity set -- dropping or
renaming one band in one copy -- produces no error there, just findings quietly
resolving differently. Nothing else in the suite compares the copies, which is
why a silent divergence could land.

What must NOT be collapsed
--------------------------
The SARIF level-to-severity MAP also has three copies, and they are not all the
same table. ``severity_ladder._SARIF_LEVEL_TO_SEVERITY`` and the inline map in
``result_filters._get_finding_severity`` both map ``error`` to CRITICAL and are
genuine duplication. ``flat_vulnerability._LEVEL_TO_SEVERITY`` maps ``error`` to
**HIGH**, and that is a deliberate fork documented in a comment at
``flat_vulnerability.py`` lines 38-40: it preserves the historical
``to_flat_vulnerabilities()`` mapping, and changing it would alter reporter
output for every existing scanner. Deduplicating it would be a behavior change
wearing deduplication's clothes. :func:`test_the_documented_error_to_high_fork_survives`
and :func:`test_the_fork_is_observable_in_flattened_output` pin it so a future
consolidation has to break a test that explains itself rather than silently
shifting every reporter's severities.
"""

from automated_security_helper.core.constants import VALID_SEVERITY_VALUES
from automated_security_helper.core.resource_management.result_filters import (
    _get_finding_severity,
)
from automated_security_helper.models.flat_vulnerability import (
    _LEVEL_TO_SEVERITY,
    _SEVERITY_ORDER,
    _VALID_ISSUE_SEVERITIES,
    FlatVulnerability,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
)
from automated_security_helper.utils.sarif_utils import _CANONICAL_SEVERITIES
from automated_security_helper.utils.severity_ladder import (
    _SARIF_LEVEL_TO_SEVERITY,
    SEVERITIES,
)


def test_named_severity_copies_agree_as_sets():
    """Every named copy holds the same five names as the ladder."""
    expected = set(SEVERITIES)
    copies = {
        "core.constants.VALID_SEVERITY_VALUES": set(VALID_SEVERITY_VALUES),
        "models.flat_vulnerability._SEVERITY_ORDER": set(_SEVERITY_ORDER),
        "models.flat_vulnerability._VALID_ISSUE_SEVERITIES": set(
            _VALID_ISSUE_SEVERITIES
        ),
        "utils.sarif_utils._CANONICAL_SEVERITIES": set(_CANONICAL_SEVERITIES),
    }
    for where, names in copies.items():
        assert names == expected, (
            f"{where} has drifted from utils.severity_ladder.SEVERITIES\n"
            f"  missing: {sorted(expected - names)}\n"
            f"  extra:   {sorted(names - expected)}"
        )


def test_ordered_severity_copies_agree_on_order_too():
    """The ordered copies agree on sequence, not just membership.

    ``_SEVERITY_ORDER`` is named for its order and ``_CANONICAL_SEVERITIES`` is a
    tuple, so a set comparison alone would accept a reordering. Nothing currently
    indexes these by position, but the stronger assertion is free and a name like
    ``_SEVERITY_ORDER`` is a promise to a future reader.
    """
    assert tuple(_SEVERITY_ORDER) == tuple(SEVERITIES)
    assert tuple(_CANONICAL_SEVERITIES) == tuple(SEVERITIES)


def test_the_inline_copy_in_result_filters_accepts_exactly_these_names():
    """The one copy with no name, reached the only way it can be: behaviorally.

    ``result_filters._get_finding_severity`` tests membership against an inline
    tuple. Drop a band from it and that severity stops being honored from
    ``issue_severity`` and silently falls through to the SARIF level mapping --
    a wrong severity, not an error. So each name is asserted to round-trip.
    """
    for name in SEVERITIES:
        got = _get_finding_severity({"properties": {"issue_severity": name}})
        assert got == name, (
            f"issue_severity {name!r} was not honored by result_filters "
            f"(got {got!r}); its inline severity tuple has drifted from "
            "utils.severity_ladder.SEVERITIES"
        )

    # Lower-case input is upper-cased before the membership test, so this is the
    # same tuple being exercised through the path real SARIF takes.
    for name in SEVERITIES:
        assert (
            _get_finding_severity({"properties": {"issue_severity": name.lower()}})
            == name
        )


def test_the_documented_error_to_high_fork_survives():
    """flat_vulnerability maps error->HIGH on purpose; the other two map CRITICAL.

    This asserts the DIVERGENCE, so a well-meaning deduplication that points
    flat_vulnerability at the ladder's table fails here rather than silently
    re-grading every ``error``-level finding from every scanner.
    """
    assert _LEVEL_TO_SEVERITY["error"] == "HIGH", (
        "the documented fork at flat_vulnerability.py:38-40 has been collapsed; "
        "error->HIGH preserves historical to_flat_vulnerabilities() output and "
        "changing it alters reporter output for every existing scanner"
    )
    assert _SARIF_LEVEL_TO_SEVERITY["error"] == "CRITICAL"

    # Everything OTHER than `error` is identical across the two tables, which is
    # what makes `error` a fork rather than two unrelated maps.
    for level in ("warning", "note", "none"):
        assert _LEVEL_TO_SEVERITY[level] == _SARIF_LEVEL_TO_SEVERITY[level]
    assert set(_LEVEL_TO_SEVERITY) == set(_SARIF_LEVEL_TO_SEVERITY)


def test_the_fork_is_observable_in_flattened_output():
    """The fork's consequence, not just its table.

    A constant can be checked and still be unused. This runs an ``error``-level
    result with no ``issue_severity`` through the real factory and pins the
    severity a reporter would actually see.
    """
    flat = FlatVulnerability.from_sarif_result(
        result=Result(
            ruleId="some.rule",
            level="error",
            message=Message(text="an error-level finding with no issue_severity"),
            properties=PropertyBag(tags=["bandit"]),
        ),
        tool_name="bandit",
        tool_type="SAST",
    )
    assert flat.severity == "HIGH", (
        "an error-level SARIF result now flattens to "
        f"{flat.severity!r}; the documented error->HIGH fork has been changed"
    )


def test_result_filters_maps_error_to_critical_not_high():
    """The other side of the fork, asserted behaviorally.

    ``result_filters`` is one of the two copies that DOES map error to CRITICAL.
    Pinning both sides is what makes the fork legible: if a future change unifies
    them, exactly one of these two tests fails and names the direction.
    """
    assert _get_finding_severity({"level": "error"}) == "CRITICAL"
