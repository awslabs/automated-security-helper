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

The level-to-severity map
-------------------------
There is one: ``severity_ladder._SARIF_LEVEL_TO_SEVERITY``, read through
``severity_ladder.result_severity``. ``flat_vulnerability`` and ``result_filters``
call the ladder and keep no copy of their own: a copy mapping ``error`` to HIGH
would grade every flattened ``error`` finding one band below the summary and the
exit code, and a reader triaging from CSV or flat-json could not tell which
findings had failed the scan.
:func:`test_flat_vulnerability_grades_as_the_gate` and
:func:`test_result_filters_grades_as_the_gate` pin the agreement.
"""

from automated_security_helper.core.constants import VALID_SEVERITY_VALUES
from automated_security_helper.core.resource_management.result_filters import (
    _get_finding_severity,
)
from automated_security_helper.models.flat_vulnerability import (
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


def test_flat_vulnerability_grades_as_the_gate():
    """flat_vulnerability reads severities through the ladder, every level."""
    from automated_security_helper.models.flat_vulnerability import _resolve_severity

    for level, severity in _SARIF_LEVEL_TO_SEVERITY.items():
        result = Result(ruleId="r", level=level, message=Message(text="x"))
        assert _resolve_severity(result) == severity, level


def test_an_error_flattens_to_critical():
    """The consequence, not just the table.

    A constant can be checked and still be unused. This runs an ``error``-level
    result with no ``issue_severity`` through the real factory and pins the
    severity a reporter would actually see: CRITICAL, as in the summary.
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
    assert flat.severity == "CRITICAL", (
        "an error-level SARIF result now flattens to "
        f"{flat.severity!r}, which is not the summary's and the gate's CRITICAL"
    )


def test_result_filters_grades_as_the_gate():
    """``result_filters`` (the MCP findings list) agrees too, asserted behaviorally."""
    assert _get_finding_severity({"level": "error"}) == "CRITICAL"
