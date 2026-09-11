# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every OCI runner ASH will try must have a CI leg, or a reasoned exclusion.

Why this file exists
--------------------
``_OCI_RUNNER_CANDIDATES`` in ``automated_security_helper/interactions/
run_ash_container.py`` is the list ASH walks when no ``--oci-runner`` was given: the
first one on PATH becomes the runtime for the whole scan. A runner on that list with
no CI leg is a documented, reachable code path that nothing exercises -- and it is
reached by *default*, on whichever machine happens to have that binary installed.

``.github/actions/validate-container/action.yml`` already asserts the converse. Its
``case`` guard fails closed for a runtime it has no scan leg for, so a runner cannot be
added to the matrix and quietly get a build-only job. That is a good check and it
answers the opposite question to this one: it says "this runtime is one I cover", never
"I cover every runtime ASH will try". Nothing could see a candidate that was in neither
the matrix nor the guard, because nothing read the candidate list.

Where a runner may be covered
-----------------------------
Two matrices in ``ash-unified-ci.yml``, and both count:

* ``install-validation`` -- its ``method`` axis carries ``podman``, ``finch`` and
  ``nerdctl``, each routed to ``validate-container``, which builds the image with that
  runtime and then scans with it.
* ``scan-validation`` -- its ``include`` entries carry an ``oci-runner`` key, and that
  is where ``docker`` lives. Reading only the install-methods matrix would report
  docker as uncovered, which is wrong: docker has seven scan-validation cells across
  x86 and ARM, including the offline one.

Coverage is computed from the EFFECTIVE matrix -- the axis product minus ``exclude``
entries -- not from the raw axis lists. A runner named on an axis and then excluded on
every OS and Python combination has no leg at all, and the raw list cannot tell that
from full coverage. ``nerdctl`` is the case that makes this matter: it is excluded on
Windows, on ARM, on both macOS runners and on three of four Python versions, and what
is left is one cell.

The pattern this follows
------------------------
``EXPECTED_UPSTREAM_JOBS`` in ``ash-unified-ci.yml``'s ``required-checks`` job, and
``assert-coverage-completeness.mjs``, which takes its file census from ``git ls-files``
rather than from the coverage report. Both exist because a list nobody re-checks drifts
from the thing it describes. The census here is the candidate list in the source, which
is the only authority on what ASH will actually try.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

import yaml

from automated_security_helper.interactions.run_ash_container import (
    _OCI_RUNNER_CANDIDATES,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
VALIDATE_CONTAINER = (
    REPO_ROOT / ".github" / "actions" / "validate-container" / "action.yml"
)

# A runner ASH will try that deliberately has no CI leg, mapped to the reason. Empty
# today, and that is the point: all four candidates are covered, so nothing needs
# excusing. Kept as a mechanism rather than omitted because the alternative when a
# runner genuinely cannot be tested on a hosted runner is to delete this test.
#
# An entry here is a runner this repository ships support for and does not test. State
# what makes it untestable, not that it is inconvenient.
_EXCLUSIONS: dict[str, str] = {}

# Floor for the positive control. Four candidates today.
_MINIMUM_CANDIDATES = 3


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))


def _effective_matrix(job: dict[str, Any]) -> list[dict[str, Any]]:
    """The cells a job actually runs: axis product minus excludes, plus includes.

    ``include`` entries that only add keys to existing cells (the ``arch`` labels on
    the unit-test job) versus ones that define whole cells (scan-validation) are not
    distinguished here, because for this file's purpose -- does any cell name this
    runner -- over-counting an include is harmless and under-counting is not.
    """
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    cells: list[dict[str, Any]] = []
    if axes:
        cells = [dict(zip(axes, combo)) for combo in itertools.product(*axes.values())]
        for excluded in matrix.get("exclude") or []:
            cells = [
                cell
                for cell in cells
                if not all(cell.get(k) == v for k, v in excluded.items())
            ]
    cells.extend(matrix.get("include") or [])
    return cells


def _covered_runners() -> set[str]:
    """Every runner named by a cell that actually runs, from either matrix."""
    jobs = _workflow()["jobs"]
    covered: set[str] = set()

    for cell in _effective_matrix(jobs["install-validation"]):
        method = cell.get("method")
        if isinstance(method, str) and method in _OCI_RUNNER_CANDIDATES:
            covered.add(method)

    for cell in _effective_matrix(jobs["scan-validation"]):
        runner = cell.get("oci-runner")
        # "" is python-local: a scan with no container at all, so it names no runner.
        if isinstance(runner, str) and runner:
            covered.add(runner)

    return covered


def _runtimes_routed_to_validate_container() -> set[str]:
    """The methods install-validation hands to the validate-container action.

    Read from the step's ``if:`` expression rather than hardcoded, so the two lists
    this test compares are both derived and neither is a third copy.
    """
    for step in _workflow()["jobs"]["install-validation"]["steps"]:
        if step.get("uses") == "./.github/actions/validate-container":
            return set(re.findall(r"'([^']+)'", step.get("if", "")))
    return set()


def _runtimes_with_a_scan_leg() -> set[str]:
    """The runtimes validate-container's own guard says it covers.

    Parsed from the shell ``case`` pattern in the "Assert this runtime has a scan leg"
    step. A regex over shell is not lovely, but the alternative is a fourth hand-kept
    copy of the list, and the guard itself is the thing whose agreement with the matrix
    is worth checking.
    """
    text = VALIDATE_CONTAINER.read_text(encoding="utf-8")
    match = re.search(r"^\s*([a-z0-9|\s\-]+?)\)\s*;;\s*$", text, re.MULTILINE)
    if not match:
        return set()
    return {part.strip() for part in match.group(1).split("|") if part.strip()}


class TestEveryRunnerASHWillTryIsTested:
    def test_every_candidate_has_a_ci_leg_or_a_reason(self):
        covered = _covered_runners()
        untested = [
            runner
            for runner in _OCI_RUNNER_CANDIDATES
            if runner not in covered and runner not in _EXCLUSIONS
        ]

        assert not untested, (
            f"These OCI runners are in _OCI_RUNNER_CANDIDATES but no CI cell exercises "
            f"them: {untested}.\n\n"
            "ASH picks the first candidate found on PATH when --oci-runner is not "
            "given, so an untested candidate is the default on any machine that has "
            "that binary. Add a cell -- an install-validation `method` routed to "
            ".github/actions/validate-container, or a scan-validation include with "
            "`oci-runner:` set -- or add the runner to _EXCLUSIONS in this file with "
            "the reason it cannot be tested on a hosted runner.\n"
            f"Currently covered: {sorted(covered)}"
        )

    def test_the_matrices_were_actually_read(self):
        """Positive control. The assertion above passes if `covered` is everything.

        It is a subset test, so a parse that returned a set containing every candidate
        for the wrong reason -- or a `_OCI_RUNNER_CANDIDATES` that had become empty --
        would read as success. Both halves are pinned.
        """
        assert len(_OCI_RUNNER_CANDIDATES) >= _MINIMUM_CANDIDATES, (
            f"_OCI_RUNNER_CANDIDATES holds {len(_OCI_RUNNER_CANDIDATES)} entries, below "
            f"the floor of {_MINIMUM_CANDIDATES}. With an empty list the check above is "
            "vacuous: it iterates nothing and passes."
        )

        covered = _covered_runners()
        assert covered, (
            "No runner was found in either matrix. ash-unified-ci.yml parsed, so this "
            "is a restructure -- a renamed job, a `method` axis that moved into "
            "`include`, or an `oci-runner` key that changed name -- and the check above "
            "would now report every candidate as untested. Fix the readers in this "
            "file."
        )

        # Both readers must contribute. docker comes only from scan-validation and
        # nerdctl only from install-validation, so if either reader silently stopped
        # working the other would still make `covered` non-empty.
        jobs = _workflow()["jobs"]
        from_install = {
            cell.get("method")
            for cell in _effective_matrix(jobs["install-validation"])
            if cell.get("method") in _OCI_RUNNER_CANDIDATES
        }
        from_scan = {
            cell.get("oci-runner")
            for cell in _effective_matrix(jobs["scan-validation"])
            if cell.get("oci-runner")
        }
        assert from_install, "the install-validation reader found no runner at all"
        assert from_scan, "the scan-validation reader found no runner at all"

    def test_no_exclusion_is_stale(self):
        """Exclusions must still be true: not covered, and still a real candidate.

        Same discipline as .github/typescript-coverage-exclusions.json, whose entries
        carry a kind so the kind can select a staleness test. An excuse for a runner
        that has since gained a leg, or that ASH no longer tries, is a false statement
        in the tree.

        Deliberately NOT parametrized over ``_EXCLUSIONS``. Parametrizing an empty
        collection yields a SKIPPED test, and a permanently skipped test reads as "not
        run" in every report -- the same shape as a check that was silently disabled.
        This loops instead, so it executes on every run and starts asserting the moment
        an entry is added.
        """
        covered = _covered_runners()
        problems = []
        for runner, reason in sorted(_EXCLUSIONS.items()):
            if runner in covered:
                problems.append(
                    f"  {runner!r} is excused ({reason}) but a CI cell now covers it; "
                    "remove the entry."
                )
            if runner not in _OCI_RUNNER_CANDIDATES:
                problems.append(
                    f"  {runner!r} is excused but is not in _OCI_RUNNER_CANDIDATES; "
                    "ASH will never try it, so there is nothing to excuse."
                )

        assert not problems, "Stale _EXCLUSIONS entries:\n" + "\n".join(problems)


class TestTheContainerActionAndTheMatrixAgree:
    """The routing condition and the action's own guard must name the same runtimes.

    The guard fails closed at run time, so a mismatch is caught eventually -- but only
    on the leg that runs, and only after an image build. Comparing the two lists here
    turns a mid-job failure forty minutes in into a unit-test failure.
    """

    def test_the_action_covers_every_runtime_routed_to_it(self):
        routed = _runtimes_routed_to_validate_container()
        with_leg = _runtimes_with_a_scan_leg()

        assert routed, (
            "No validate-container step was found in install-validation, or its `if:` "
            "names no method. This reader has gone stale."
        )
        assert with_leg, (
            "The scan-leg `case` pattern was not found in "
            ".github/actions/validate-container/action.yml. This reader has gone stale."
        )

        missing = sorted(routed - with_leg)
        assert not missing, (
            f"install-validation routes {missing} to validate-container, but that "
            "action's scan-leg guard does not name them, so the job would fail at the "
            "guard. Add the runtime to the `case` pattern along with its install, "
            "verify and build steps."
        )

    def test_every_runtime_with_a_leg_is_actually_routed_to_it(self):
        """The other direction: a leg nothing routes to is dead code in the action."""
        routed = _runtimes_routed_to_validate_container()
        with_leg = _runtimes_with_a_scan_leg()

        orphaned = sorted(with_leg - routed)
        assert not orphaned, (
            f"validate-container claims a scan leg for {orphaned}, but "
            "install-validation never routes those runtimes to it, so the leg never "
            "runs. Either add the method to the matrix and the routing `if:`, or drop "
            "the leg."
        )
