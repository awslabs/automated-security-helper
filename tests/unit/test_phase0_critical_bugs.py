# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Phase 0 critical bug regression tests (TDD).

These tests are written BEFORE the fixes — they should all fail today and
pass once each bug is corrected. One test per bug:

  - Bug 1: Non-deterministic vulnerability IDs (PYTHONHASHSEED-randomized hash())
           in FlatVulnerability.from_sarif_result.
  - Bug 2: Lost dict mutation in AshAggregatedResults._apply_suppression_side_effects
           when scanner_results[key] is a plain dict.
  - Bug 3: Swallowed exceptions in ExecutionEngine.execute_phases — `return` lives
           inside a `finally` block, which discards any in-flight exception.
"""

from __future__ import annotations

import hashlib
import inspect
import re

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    Result,
)


# -----------------------------------------------------------------------------
# Bug 1: Non-deterministic vulnerability IDs
# -----------------------------------------------------------------------------


def test_phase0_bug1_flat_vulnerability_id_is_stable_hash_not_pythonhash():
    """Bug 1: FlatVulnerability ids must be derived from a stable hash.

    Today, ``from_sarif_result`` builds the id with
    ``f"{scanner}-{ruleId}-{hash(description) % 10000}"``. Python's ``hash()``
    is randomized per process via PYTHONHASHSEED, so the same SARIF result
    yields different ids across runs/processes — breaking dedup downstream.

    The fix is to use a deterministic hash (e.g. ``hashlib.sha256`` of the
    description bytes, taking the first 8 hex chars). After the fix, the id
    suffix is a function of the description alone and matches the sha256 prefix.
    Today this assertion fails because the suffix is a 4-digit decimal from
    Python's randomized ``hash()``.
    """
    description = "test vulnerability description abc"
    expected_suffix = hashlib.sha256(description.encode()).hexdigest()[:8]

    result = Result(
        ruleId="RULE001",
        message=Message(root=Message1(text=description)),
    )

    vuln = FlatVulnerability.from_sarif_result(result, "bandit", "SAST")

    # The id should END with the deterministic sha256 prefix once the fix
    # lands. Today the suffix is `hash(description) % 10000` — 0-4 decimal
    # digits with no overlap with a hex sha256 prefix (which is 8 chars and
    # almost certainly contains a-f).
    assert vuln.id.endswith(expected_suffix), (
        f"Expected id to end with stable sha256 prefix {expected_suffix!r} but "
        f"got id={vuln.id!r}. The id likely uses Python's randomized hash() "
        f"instead of a deterministic hash, breaking cross-process dedup."
    )


# -----------------------------------------------------------------------------
# Bug 2: Lost dict mutation in _apply_suppression_side_effects
# -----------------------------------------------------------------------------


def test_phase0_bug2_apply_suppression_side_effects_persists_dict_mutation():
    """Bug 2: dict-typed scanner_results entries lose suppression bumps.

    In ``AshAggregatedResults._apply_suppression_side_effects``, when
    ``scanner_results[key]`` is a plain dict, the code does::

        target_info = ScannerTargetStatusInfo.model_validate(target_info)
        ...
        target_info.suppressed_finding_count = ...

    but never writes ``target_info`` back to ``scanner_results[key]``. The
    mutations happen on the local rebound variable and are discarded — the
    dict in ``scanner_results`` stays a dict with its original counts.

    After the fix, the entry should be a ``ScannerTargetStatusInfo`` instance
    with ``suppressed_finding_count == 1`` and ``severity_counts.suppressed
    == 1`` reflecting the bump.
    """
    results = AshAggregatedResults()
    # Seed scanner_results with a literal dict, mimicking how legacy data
    # may flow in before model coercion.
    results.scanner_results = {
        "bandit": {
            "status": "PASSED",
            "dependencies_satisfied": True,
            "excluded": False,
            "severity_counts": {
                "suppressed": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "finding_count": 0,
            "actionable_finding_count": 0,
            "suppressed_finding_count": None,
            "exit_code": 0,
            "duration": 0.0,
        }
    }

    results._apply_suppression_side_effects("bandit")

    persisted = results.scanner_results["bandit"]

    # After the fix, the dict has been replaced by a coerced model with the
    # bumped suppression count. Today, the dict is still a dict and the
    # local mutation is lost.
    assert isinstance(persisted, ScannerTargetStatusInfo), (
        f"scanner_results['bandit'] should be a ScannerTargetStatusInfo after "
        f"side effects run, but got {type(persisted).__name__}. Local dict "
        f"mutation was lost — see _apply_suppression_side_effects."
    )
    assert persisted.suppressed_finding_count == 1, (
        f"suppressed_finding_count should be 1 after one suppression bump, "
        f"got {persisted.suppressed_finding_count!r}."
    )
    assert isinstance(persisted.severity_counts, ScannerSeverityCount)
    assert persisted.severity_counts.suppressed == 1, (
        f"severity_counts.suppressed should be 1 after one suppression bump, "
        f"got {persisted.severity_counts.suppressed!r}."
    )


# -----------------------------------------------------------------------------
# Bug 3: Swallowed exceptions in execute_phases
# -----------------------------------------------------------------------------


def test_phase0_bug3_execute_phases_does_not_return_inside_finally():
    """Bug 3: ``return`` in ``finally`` swallows exceptions from execute_phases.

    The ``execute_phases`` method has structure::

        try:
            ...  # phase loop, may raise
        except Exception:
            ...
            raise
        finally:
            ...
            return self._results   # <-- swallows in-flight exception

    Per Python semantics, a ``return`` inside ``finally`` discards any
    exception currently propagating from ``try`` (or from a re-``raise`` in
    ``except``). Callers therefore see partial/empty results on phase failure
    instead of an exception.

    Approach B (source inspection): assert that no ``return`` statement
    appears inside a ``finally`` block of ``execute_phases``. Approach A
    (monkeypatch a phase to raise and assert it propagates) requires
    instantiating an ExecutionEngine with a full PluginContext, scanner
    registrations, and progress display — too brittle for a regression test.
    Source inspection is direct: it pins down the structural fix without
    requiring a working engine.

    After the fix, ``return self._results`` will live AFTER the
    ``try/except/finally`` block, not inside ``finally``. This test passes
    once that move happens.
    """
    from automated_security_helper.core.execution_engine import (
        ScanExecutionEngine,
    )

    source = inspect.getsource(ScanExecutionEngine.execute_phases)
    lines = source.splitlines()

    # Find the column where ``finally:`` starts. We expect at least one such
    # line in the current source — the bug lives inside it.
    finally_indents: list[int] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("finally:") or stripped == "finally:":
            finally_indents.append(len(line) - len(stripped))

    assert finally_indents, (
        "execute_phases no longer contains a 'finally:' block — the test's "
        "assumption about the method structure is stale."
    )

    return_pattern = re.compile(r"^\s*return\b")

    # Walk each finally block and assert no `return` lives inside it. A
    # finally block ends when we encounter a non-blank line at or below the
    # finally's own indent (i.e. at the same level as `try:`).
    in_finally = False
    finally_indent = -1
    offending_lines: list[tuple[int, str]] = []

    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if stripped.startswith("finally:"):
            in_finally = True
            finally_indent = indent
            continue

        if not in_finally:
            continue

        # Skip blank or comment-only lines for indent-tracking purposes.
        if not stripped or stripped.startswith("#"):
            continue

        # We've left the finally block when indent drops back to (or below)
        # the finally header's own indent.
        if indent <= finally_indent:
            in_finally = False
            finally_indent = -1
            # Re-check this same line in case it's another `finally:` opener.
            if stripped.startswith("finally:"):
                in_finally = True
                finally_indent = indent
            continue

        if return_pattern.match(line):
            offending_lines.append((idx + 1, line.rstrip()))

    assert not offending_lines, (
        "execute_phases contains a `return` statement inside a `finally:` "
        "block, which swallows exceptions propagating from the try body. "
        "Move the return outside the try/except/finally so phase failures "
        f"surface to the caller. Offending lines: {offending_lines}"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-x", "--tb=short", "--no-cov"])
