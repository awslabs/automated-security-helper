# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Single source of truth for the severity-threshold gate.

Why this module exists
----------------------
ASH encoded the same threshold ladder in four places that had already drifted
apart: ``ScanResultsContainer.determine_status`` (severity counts), the
junitxml reporter (SARIF levels, missing two of the five threshold values),
and two tables inside ``run_ash_scan._compute_exit_code``. A finding could
therefore be counted as gate-failing by the exit code and reported as a
passing test in the same run. Everything that answers "does this finding fail
the gate?" now routes through here so those answers cannot disagree.

The direction is counter-intuitive: RAISING the threshold LOOSENS the gate
------------------------------------------------------------------------
The threshold names the *least severe* finding that still fails a scan, so a
higher threshold ignores more:

* ``ALL``      -- everything fails, down to informational findings.
* ``LOW``      -- low, medium, high and critical fail; info is ignored.
* ``MEDIUM``   -- medium and above fail.
* ``HIGH``     -- high and critical fail.
* ``CRITICAL`` -- only critical fails.

So the strictness order, strictest first, is
``ALL < LOW < MEDIUM < HIGH < CRITICAL``, and ``stricter_of`` returns whichever
argument sits earlier in it.

A falsy threshold (``None`` or ``""``) is looser still: nothing fails, not even
a critical finding. That is deliberate and predates this module -- it is how an
operator turns the gate off -- so it is preserved exactly. Note that this makes
the falsy value *not* a synonym for ``CRITICAL``.

Why the workspace field is called ``max_severity_threshold``
-----------------------------------------------------------
Because "max" refers to strictness-permissiveness, not to severity. A
workspace sets the LOOSEST value a project is allowed to configure; a project
may be stricter but not laxer. Combining a workspace ceiling with a project
setting is therefore ``stricter_of(project, workspace_ceiling)``. Naming it
after the severity would invert the meaning for every reader.

Two views of one ladder
-----------------------
``severity_fails_threshold`` works from ASH severity names. SARIF has only four
levels for ASH's five severities, so ``sarif_level_fails_threshold`` maps
``error/warning/note/none`` onto ``CRITICAL/MEDIUM/LOW/INFO`` and reuses the
same comparison. The mapping is lossy in exactly one place, and it is a
limitation of SARIF rather than a choice made here: ``error`` covers both
CRITICAL and HIGH, so under a ``CRITICAL`` threshold a HIGH finding still
qualifies when seen through SARIF levels. Callers that need the distinction
must work from severity counts, not levels.

Failure modes and known limitations
-----------------------------------
* An unrecognised threshold string gates like ``CRITICAL`` -- only critical
  findings fail. This is not a design preference; it is what the historical
  cascade in ``determine_status`` did, because its critical check was
  unconditional while every other check tested membership in a literal tuple.
  Threshold matching is consequently case-SENSITIVE: ``"low"`` is not ``"LOW"``
  and gates like ``CRITICAL``.
* An unrecognised *severity* name fails closed -- it fails every configured
  threshold -- so an unexpected value cannot silently slip past a gate. Both
  in-repo callers pass known names, so this path is defensive only.
* An unrecognised or missing SARIF level is read as ``note``, matching
  ``run_ash_scan``, which defaults a missing level the same way.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

# The ladder, as data. Ordered strictest to loosest -- see the module docstring
# for why that is the opposite of the severity ordering.
SEVERITY_THRESHOLDS: Tuple[str, ...] = ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# ASH severity names, most severe first.
SEVERITIES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Severity rank and the minimum rank each threshold gates on. A finding fails
# when its rank is at or above its threshold's minimum, which is why the two
# tables run in opposite directions.
_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_THRESHOLD_MIN_RANK: Dict[str, int] = {
    "ALL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# An unrecognised threshold gates on critical only, preserving the historical
# cascade where `counts.critical > 0` was checked before any threshold test.
_UNKNOWN_THRESHOLD_MIN_RANK = _THRESHOLD_MIN_RANK["CRITICAL"]

# An unrecognised severity fails closed: it clears every threshold's minimum.
_UNKNOWN_SEVERITY_RANK = _SEVERITY_RANK["CRITICAL"]

# SARIF's four levels onto ASH's five severities. `error` maps to CRITICAL
# rather than HIGH so that a threshold of CRITICAL still gates on it, matching
# the qualifying-level table in run_ash_scan._compute_exit_code.
_SARIF_LEVEL_TO_SEVERITY: Dict[str, str] = {
    "error": "CRITICAL",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

# A missing or unrecognised level is read as `note`, matching run_ash_scan.
_DEFAULT_SARIF_LEVEL = "note"


def _strictness_key(threshold: Optional[str]) -> Tuple[int, str]:
    """Sort key for threshold strictness; a lower key is stricter.

    The three tiers keep the ordering total and independent of argument order:
    recognised thresholds first (ordered by the ladder), then unrecognised
    values, then the absence of a threshold. Unrecognised values sort after
    ``CRITICAL`` even though they gate identically, so that a real ``CRITICAL``
    always wins the comparison rather than the tie being decided by which
    argument came first.
    """
    if not threshold:
        return (2, "")
    if threshold in _THRESHOLD_MIN_RANK:
        return (0, f"{SEVERITY_THRESHOLDS.index(threshold):02d}")
    return (1, threshold)


def stricter_of(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return whichever of *a* and *b* gates more findings.

    Total and commutative over every input, including ``None`` and ``""``.
    Returns ``None`` when neither side configures a threshold, which is why the
    return type is optional: the absence of a threshold is a value in the
    domain, so it has to be a value in the range too.

    Used to combine a workspace-level ceiling with a project-level setting: the
    project may tighten the gate but never loosen it.
    """
    if not a and not b:
        return None
    return a if _strictness_key(a) <= _strictness_key(b) else b


def severity_fails_threshold(severity: str, threshold: Optional[str]) -> bool:
    """Return True when a finding of *severity* fails the gate at *threshold*.

    Args:
        severity: An ASH severity name, e.g. ``"HIGH"``. Case-insensitive.
        threshold: A configured threshold, or ``None``/``""`` for no gate at
            all. Case-SENSITIVE, for the reason given in the module docstring.

    Returns:
        True if the finding should fail the scan.
    """
    if not threshold:
        return False
    rank = _SEVERITY_RANK.get(severity.upper(), _UNKNOWN_SEVERITY_RANK)
    return rank >= _THRESHOLD_MIN_RANK.get(threshold, _UNKNOWN_THRESHOLD_MIN_RANK)


def sarif_level_fails_threshold(level: Optional[str], threshold: Optional[str]) -> bool:
    """Return True when a SARIF result at *level* fails the gate at *threshold*.

    The SARIF-level view of :func:`severity_fails_threshold`, for callers that
    only have a SARIF ``result.level`` to work from. Remember that ``error``
    covers both CRITICAL and HIGH, so this cannot distinguish the two.

    Args:
        level: A SARIF level -- ``error``, ``warning``, ``note`` or ``none``.
            Case-insensitive. A missing or unrecognised value is read as
            ``note``. Accepts the str-backed ``Level`` enum as well as a plain
            string.
        threshold: As for :func:`severity_fails_threshold`.

    Returns:
        True if the finding should be treated as actionable.
    """
    if not threshold:
        return False
    # Read `.value` first: str(Level.error) is "Level.error" on Python 3.11+,
    # because Level is a (str, Enum) mixin rather than a StrEnum.
    raw = getattr(level, "value", level)
    normalized = str(raw).lower() if raw else _DEFAULT_SARIF_LEVEL
    severity = _SARIF_LEVEL_TO_SEVERITY.get(
        normalized, _SARIF_LEVEL_TO_SEVERITY[_DEFAULT_SARIF_LEVEL]
    )
    return severity_fails_threshold(severity, threshold)
