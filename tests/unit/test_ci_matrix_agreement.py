# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI matrices and the things that consume them must agree, and be derived.

Why this file exists
--------------------
Four defects in ``.github/`` shared one shape: a value that is derivable from another was
instead restated by hand, and a wrong restatement produced a GREEN check rather than a
red one. This file is the enforcement for the three of them that a unit test can hold.
(The fourth, the ``required-checks`` job census, lives in
``tests/unit/test_required_checks_census.py`` because it is enforcement for a script the
gate itself runs.)

* **Routing with no else.** Both install-validation jobs -- ``install-validation`` in
  ``ash-unified-ci.yml`` and ``validate`` in ``ash-install-methods.yml`` -- end in
  mutually exclusive ``if:`` steps with no default. A ``method`` satisfying none of them
  ran setup-python, did nothing, and exited 0; ``required-checks`` counted that as a
  success, so an entirely unvalidated install method read as validated on every pull
  request. Each job now carries a fail-closed ``case`` guard, and this file reconciles
  the guard's arms against the routing conditions AND against the ``method`` axis, so no
  one of the three can drift from the other two.

* **Derivable matrix values.** ``scan-validation`` carried a ``platform`` key that was a
  pure function of ``os``, restated on 24 rows, consumed only by log lines -- and already
  wrong, because ``macos-latest`` moved to Apple silicon and the rows still said
  ``darwin/amd64``. ``unit-test`` carried a five-row ``arch`` table with the same
  problem, and that one was not cosmetic: ``run-unit-tests`` selected the single leg that
  renders the coverage summary by comparing the arch LABEL, so a mislabelled Linux row
  would have dropped the step from every leg silently. Both are now derived from
  ``runner.os``/``runner.arch`` inside the composite actions, and this file asserts the
  restatements cannot come back.

* **Two install matrices with nothing tying them together.** The comment on
  ``install-validation`` states the discipline -- "Keep the ``python-version`` axes of
  the two identical, deliberately" -- and nothing enforced it. No test read
  ``ash-install-methods.yml`` at all.

The model
---------
``tests/unit/test_oci_runner_ci_coverage.py``. Coverage is computed from the EFFECTIVE
matrix -- the axis product minus ``exclude`` entries -- because a raw axis list cannot
tell full coverage from a method excluded on every cell. Every check carries a positive
control, because a test that parses a workflow and finds nothing to check passes
silently, and that is the dominant failure mode for guards of exactly this shape.

What this file deliberately does not do
---------------------------------------
It does not assert the excludes themselves, their count, or their shape. It asserts that
the two matrices AGREE, which is a property that survives legs being added to both. A
test pinning 113 and 117 would break on every legitimate matrix change and would teach
people to edit the test rather than read it.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
ACTIONS = REPO_ROOT / ".github" / "actions"

UNIFIED_CI = WORKFLOWS / "ash-unified-ci.yml"
INSTALL_METHODS = WORKFLOWS / "ash-install-methods.yml"
RUN_SCAN_TEST = ACTIONS / "run-scan-test" / "action.yml"
RUN_UNIT_TESTS = ACTIONS / "run-unit-tests" / "action.yml"

# The two install-validation surfaces, as (label, workflow path, job key). Both are
# checked by everything in TestInstallMethodRoutingIsClosed; a check that ran on only one
# of them would leave the other exactly as exposed as it was.
INSTALL_SURFACES = [
    pytest.param(
        "ash-unified-ci.yml install-validation",
        UNIFIED_CI,
        "install-validation",
        id="unified-ci",
    ),
    pytest.param(
        "ash-install-methods.yml validate",
        INSTALL_METHODS,
        "validate",
        id="install-methods",
    ),
]

# A method carried by one install surface and not the other, mapped to the reason. This
# is the one legitimate difference between the two matrices, and naming it here is what
# lets the leg-by-leg comparison below be exact rather than approximate.
#
# An entry states why the method belongs on that surface only. "It was added there first"
# is not a reason -- that is drift, which is what this file exists to catch.
_METHOD_ONLY_IN: dict[str, str] = {
    "nix": (
        "ash-install-methods.yml only. It is path-filtered, and the nix toolchain "
        "validation is slow enough that the unconditional surface -- the one "
        "required-checks gates -- deliberately does not carry it."
    ),
    # The six below are ONE fact, not six. ash-unified-ci.yml folded pip, pipx, uvx,
    # pre-commit and mcp into a single `bundle` method run as five steps;
    # ash-install-methods.yml still carries them as five separate methods. So each of
    # those five names is now on one surface only, and `bundle` -- the value that
    # replaced them -- is on the other.
    #
    # This is a deliberate split rather than drift, and no coverage is lost: all five
    # still run on both surfaces, as steps here and as legs there. What differs is the
    # granularity of the leg, which is what the collapse was for.
    #
    # WHAT IT DOES COST, STATED SO IT IS NOT REDISCOVERED
    #
    # test_the_shared_methods_run_exactly_the_same_legs_on_both_surfaces iterates the
    # INTERSECTION of the two method sets, so it can no longer cover these five. A
    # python-version or an OS added to one surface and not the other is still caught for
    # `homebrew` and the three container runtimes, and is NOT caught for pip, pipx, uvx,
    # pre-commit or mcp. test_the_axes_are_identical is what still covers them, since
    # both surfaces draw their os and python-version from axes that must match.
    #
    # If that residual gap ever matters, the fix is to compare the unified surface's
    # bundle STEP conditions against the install-methods legs, not to un-collapse the
    # matrix.
    "bundle": (
        "ash-unified-ci.yml only. Not an install method but five of them run as steps in "
        "one leg -- pip, pipx, uvx, pre-commit and mcp. ash-install-methods.yml keeps "
        "those five as separate legs, so the two surfaces express the same coverage at "
        "different granularity."
    ),
    "pip": (
        "ash-install-methods.yml only as a METHOD. ash-unified-ci.yml runs it as a step "
        "inside the `bundle` leg, so the coverage is on both surfaces and only the leg "
        "granularity differs."
    ),
    "pipx": (
        "ash-install-methods.yml only as a METHOD; a step inside `bundle` on "
        "ash-unified-ci.yml. See the pip entry."
    ),
    "uvx": (
        "ash-install-methods.yml only as a METHOD; a step inside `bundle` on "
        "ash-unified-ci.yml, conditioned to 3.12 there because uvx brings its own "
        "interpreter. See the pip entry."
    ),
    "pre-commit": (
        "ash-install-methods.yml only as a METHOD; a step inside `bundle` on "
        "ash-unified-ci.yml. See the pip entry."
    ),
    "mcp": (
        "ash-install-methods.yml only as a METHOD; a step inside `bundle` on "
        "ash-unified-ci.yml, routed to validate-mcp there. See the pip entry."
    ),
}

# Floors for the positive controls. Deliberately far below the current values (24
# scan-validation rows, 9 install methods) so a legitimate matrix change does not touch
# this file, while a matrix that collapsed to nothing does.
#
# _MINIMUM_INSTALL_LEGS was 40, derived from the 113 and 117 effective legs the two
# surfaces carried when this file was written. Folding pip, pipx, uvx, pre-commit and mcp
# into a single `bundle` method took ash-unified-ci.yml from 113 legs to 33 -- so a number
# chosen as "far below the current value" ended up ABOVE it, and a positive control became
# a ceiling. The check it guards then failed for a reason that had nothing to do with what
# it measures.
#
# 15 restores the original intent against the lower of the two surfaces: comfortably under
# 33, and still tripped by a matrix that collapsed to nothing or to the handful of cells a
# broken axis would yield. It is deliberately not 30 -- a floor one leg under the current
# value is a tripwire on ordinary matrix edits, which is what teaches people to edit the
# constant instead of reading it.
#
# Current values, for whoever moves this next: ash-unified-ci.yml 33 effective legs,
# ash-install-methods.yml 117. Re-derive rather than trusting these; the check is the
# expansion, not the comment.
_MINIMUM_INSTALL_LEGS = 15
_MINIMUM_INSTALL_METHODS = 5
_MINIMUM_SCAN_ROWS = 10


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _job(path: Path, key: str) -> dict[str, Any]:
    return _load(path)["jobs"][key]


def _matrix(job: dict[str, Any]) -> dict[str, Any]:
    return (job.get("strategy") or {}).get("matrix") or {}


def _axes(job: dict[str, Any]) -> dict[str, list[Any]]:
    return {k: v for k, v in _matrix(job).items() if k not in ("include", "exclude")}


def _effective_matrix(job: dict[str, Any]) -> list[dict[str, Any]]:
    """The cells a job actually runs: axis product minus excludes, plus includes.

    Same computation as ``tests/unit/test_oci_runner_ci_coverage.py``. An ``include``
    entry that only adds keys to matching cells and one that defines a whole cell are not
    distinguished, because no check here is a count -- over-counting an include would
    only make an agreement test stricter, never looser.
    """
    matrix = _matrix(job)
    axes = _axes(job)
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


def _validator_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    """Steps that route to one of the .github/actions validators."""
    return [
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("./.github/actions/validate-")
    ]


def _routed_methods(job: dict[str, Any]) -> set[str]:
    """Every method literal named by a validator step's ``if:`` expression.

    Read from the conditions rather than hardcoded, so the sets this file compares are
    all derived and none of them is yet another copy of the list.

    Anchored on ``matrix.method ==`` rather than matching every quoted literal in the
    expression. A bare quoted-string match was correct only while every validator step's
    condition mentioned nothing but the method. Collapsing the cheap install methods into
    one ``bundle`` leg gave the uvx step a second clause --
    ``matrix.method == 'bundle' && matrix.python-version == '3.12'`` -- and this reader
    began reporting ``3.12`` as a routed "method". No ``case`` arm can ever name a Python
    version, so ``arms == routed`` became unsatisfiable rather than merely wrong. That is
    the more dangerous shape: a test that cannot be made to pass creates pressure to
    delete it, and deleting this one would remove the only check that the guard and the
    routing are one statement.
    """
    methods: set[str] = set()
    for step in _validator_steps(job):
        methods.update(
            re.findall(r"matrix\.method\s*==\s*'([^']+)'", str(step.get("if", "")))
        )
    return methods


def _guard_script(job: dict[str, Any]) -> str:
    for step in job["steps"]:
        if "routed to a validator" in str(step.get("name", "")):
            return str(step.get("run", ""))
    return ""


def _case_arms(script: str) -> set[str]:
    """The method patterns the fail-closed ``case`` guard accepts.

    Parsed from shell, which is not lovely -- the same trade-off
    ``test_oci_runner_ci_coverage.py`` records for validate-container's guard. The
    alternative is another hand-kept copy of the list, and the guard is the thing whose
    agreement with the matrix is worth checking.
    """
    arms: set[str] = set()
    for line in script.splitlines():
        stripped = line.strip()
        match = re.match(r"^([a-z0-9|\s\-]+?)\)\s*;;\s*$", stripped)
        if match:
            arms.update(
                part.strip() for part in match.group(1).split("|") if part.strip()
            )
    return arms


def _has_fail_closed_default(script: str) -> bool:
    """A ``*)`` arm that exits non-zero, rather than one that logs and continues."""
    tail = script.split("*)", 1)
    if len(tail) != 2:
        return False
    return bool(re.search(r"^\s*exit\s+[1-9]", tail[1], re.MULTILINE))


class TestInstallMethodRoutingIsClosed:
    """Every method on the axis reaches a validator, and the guard says so too."""

    @pytest.mark.parametrize("label,path,key", INSTALL_SURFACES)
    def test_every_method_on_the_axis_is_routed_to_a_validator(self, label, path, key):
        job = _job(path, key)
        axis = set(_axes(job).get("method") or [])
        routed = _routed_methods(job)
        unrouted = sorted(axis - routed)
        assert not unrouted, (
            f"{label}: the `method` axis carries {unrouted}, and no validator step's "
            "`if:` condition names them. Those legs would run setup-python, validate "
            "nothing, and exit 0 -- green over no work at all. Route them to a "
            f"composite action.\nRouted today: {sorted(routed)}"
        )

    @pytest.mark.parametrize("label,path,key", INSTALL_SURFACES)
    def test_the_guard_exists_and_fails_closed(self, label, path, key):
        script = _guard_script(_job(path, key))
        assert script, (
            f"{label}: no step named '... routed to a validator' was found. Without the "
            "guard, a method in none of the routing conditions is a silent no-op that "
            "reports success."
        )
        assert _has_fail_closed_default(script), (
            f"{label}: the guard has no `*)` arm that exits non-zero, so an unrouted "
            "method would fall through it and the leg would still pass."
        )

    @pytest.mark.parametrize("label,path,key", INSTALL_SURFACES)
    def test_the_guard_arms_and_the_routing_conditions_name_the_same_methods(
        self, label, path, key
    ):
        job = _job(path, key)
        arms = _case_arms(_guard_script(job))
        routed = _routed_methods(job)

        assert arms == routed, (
            f"{label}: the fail-closed guard accepts {sorted(arms)} but the validator "
            f"steps route {sorted(routed)}.\n"
            "A method the guard accepts and nothing routes is a silent no-op the guard "
            "was meant to catch. A method the guard rejects and something routes fails "
            "every leg of a method that is actually validated. Either way the two lists "
            "have to be one statement."
        )

    @pytest.mark.parametrize("label,path,key", INSTALL_SURFACES)
    def test_the_guard_runs_before_any_validator(self, label, path, key):
        """A guard after the work it guards reports on a leg that already ran."""
        steps = _job(path, key)["steps"]
        guard_at = [
            i
            for i, s in enumerate(steps)
            if "routed to a validator" in str(s.get("name", ""))
        ]
        validators_at = [
            i
            for i, s in enumerate(steps)
            if str(s.get("uses", "")).startswith("./.github/actions/validate-")
        ]
        assert guard_at, f"{label}: guard step not found"
        assert validators_at, f"{label}: no validator steps found"
        assert guard_at[0] < min(validators_at), (
            f"{label}: the routing guard is at step {guard_at[0]} but a validator runs "
            f"at step {min(validators_at)}. The guard must fail the leg before it spends "
            "a checkout and an interpreter install on work it will not do."
        )

    @pytest.mark.parametrize("label,path,key", INSTALL_SURFACES)
    def test_the_readers_found_something(self, label, path, key):
        """Positive control. Every assertion above is satisfied by two empty sets."""
        job = _job(path, key)
        axis = _axes(job).get("method") or []
        assert len(axis) >= _MINIMUM_INSTALL_METHODS, (
            f"{label}: the `method` axis holds {len(axis)} entries, below the floor of "
            f"{_MINIMUM_INSTALL_METHODS}. With an empty axis the routing check above "
            "iterates nothing and passes."
        )
        assert _routed_methods(job), (
            f"{label}: the routing reader found no method literal in any validator "
            "step's `if:`. Either the steps were restructured or the reader is stale, "
            "and the subset check above would now pass for the wrong reason."
        )
        assert _case_arms(_guard_script(job)), (
            f"{label}: the guard reader found no case arms. The equality check above "
            "would then be comparing two empty sets."
        )
        assert len(_validator_steps(job)) >= 2, (
            f"{label}: fewer than two validator steps were found, so the routing table "
            "this file exists to reconcile is not being read."
        )


class TestTheTwoInstallMatricesAgree:
    """The discipline the comment states, enforced.

    ``ash-unified-ci.yml``'s ``install-validation`` is unconditional and is what
    ``required-checks`` gates on. ``ash-install-methods.yml`` is path-filtered and adds
    ``nix``. A version, an OS or an exclusion added to one and not the other leaves a
    supported configuration untested on whichever surface was missed, and nothing said so
    -- no test read ``ash-install-methods.yml`` at all.
    """

    def _cells(self, path: Path, key: str) -> list[dict[str, Any]]:
        return _effective_matrix(_job(path, key))

    def _legs(self, path: Path, key: str) -> set[tuple[str, str, str]]:
        return {
            (c["os"], str(c["python-version"]), c["method"])
            for c in self._cells(path, key)
        }

    @pytest.mark.parametrize("axis", ["python-version", "os"])
    def test_the_axes_are_identical(self, axis):
        unified = _axes(_job(UNIFIED_CI, "install-validation")).get(axis) or []
        other = _axes(_job(INSTALL_METHODS, "validate")).get(axis) or []
        assert unified, f"ash-unified-ci.yml install-validation has no `{axis}` axis"
        assert other, f"ash-install-methods.yml validate has no `{axis}` axis"
        assert [str(v) for v in unified] == [str(v) for v in other], (
            f"the `{axis}` axes of the two install matrices differ:\n"
            f"  ash-unified-ci.yml      : {unified}\n"
            f"  ash-install-methods.yml : {other}\n"
            "Keeping them identical is the stated discipline on both jobs. A value "
            "present on one surface only is a supported configuration that goes "
            "untested whenever the other surface is the one that runs."
        )

    def test_the_methods_carried_by_only_one_surface_are_named_with_a_reason(self):
        unified = set(_axes(_job(UNIFIED_CI, "install-validation")).get("method") or [])
        other = set(_axes(_job(INSTALL_METHODS, "validate")).get("method") or [])

        unexplained = sorted((unified ^ other) - set(_METHOD_ONLY_IN))
        assert not unexplained, (
            f"these install methods are on one surface and not the other: {unexplained}.\n"
            "That is either drift -- a method added to one matrix and forgotten on the "
            "second -- or a deliberate split. If it is deliberate, add it to "
            "_METHOD_ONLY_IN in this file with the reason it belongs on one surface "
            "only.\n"
            f"  ash-unified-ci.yml only      : {sorted(unified - other)}\n"
            f"  ash-install-methods.yml only : {sorted(other - unified)}"
        )

    def test_no_method_only_in_entry_is_stale(self):
        """An excuse for a method now on both surfaces, or on neither, is a false claim.

        Deliberately a loop rather than a parametrization: parametrizing a collection
        that may become empty yields a SKIPPED test, and a permanently skipped test reads
        as "not run" in every report -- the same shape as a check that was quietly
        disabled.
        """
        unified = set(_axes(_job(UNIFIED_CI, "install-validation")).get("method") or [])
        other = set(_axes(_job(INSTALL_METHODS, "validate")).get("method") or [])

        problems = []
        for method, reason in sorted(_METHOD_ONLY_IN.items()):
            on = [
                name
                for name, axis in (("unified", unified), ("install-methods", other))
                if method in axis
            ]
            if len(on) == 2:
                problems.append(
                    f"  {method!r} is excused ({reason}) but both surfaces now carry it; "
                    "remove the entry so the leg-by-leg comparison covers it."
                )
            if not on:
                problems.append(
                    f"  {method!r} is excused but neither surface carries it. There is "
                    "nothing to excuse; remove the entry."
                )
        assert not problems, "Stale _METHOD_ONLY_IN entries:\n" + "\n".join(problems)

    def test_the_shared_methods_run_exactly_the_same_legs_on_both_surfaces(self):
        """The check the 64 and 81 hand-written excludes never had.

        Compared leg by leg over the EFFECTIVE matrix, not by comparing exclude lists.
        The two exclude lists are not identical and are not meant to be -- one workflow
        has an extra method to exclude -- so the only comparison that means anything is
        the set of cells that actually run.
        """
        shared = set(
            _axes(_job(UNIFIED_CI, "install-validation")).get("method") or []
        ) & set(_axes(_job(INSTALL_METHODS, "validate")).get("method") or [])
        unified = {
            leg
            for leg in self._legs(UNIFIED_CI, "install-validation")
            if leg[2] in shared
        }
        other = {
            leg for leg in self._legs(INSTALL_METHODS, "validate") if leg[2] in shared
        }

        only_unified = sorted(unified - other)
        only_other = sorted(other - unified)
        assert not only_unified and not only_other, (
            "the two install matrices disagree on which legs they run for the methods "
            "they share:\n"
            f"  only ash-unified-ci.yml      ({len(only_unified)}): {only_unified}\n"
            f"  only ash-install-methods.yml ({len(only_other)}): {only_other}\n"
            "An exclusion added to one matrix and not the other silently drops a "
            "configuration from whichever surface excluded it, and the other surface is "
            "path-filtered so it may not even run."
        )

    def test_both_matrices_were_actually_expanded(self):
        """Positive control, in two parts.

        Empty leg sets satisfy every comparison above. And a comparison that ignored the
        excludes -- comparing raw axis products -- would also pass while missing the
        entire class of defect this test exists for, so the effective matrix is asserted
        to be strictly smaller than the product.
        """
        for label, path, key in (
            ("ash-unified-ci.yml", UNIFIED_CI, "install-validation"),
            ("ash-install-methods.yml", INSTALL_METHODS, "validate"),
        ):
            job = _job(path, key)
            axes = _axes(job)
            product = 1
            for values in axes.values():
                product *= len(values)
            effective = len(_effective_matrix(job))

            assert effective >= _MINIMUM_INSTALL_LEGS, (
                f"{label}: {effective} effective leg(s), below the floor of "
                f"{_MINIMUM_INSTALL_LEGS}. With no legs the comparisons above are "
                "vacuous."
            )
            assert effective < product, (
                f"{label}: the effective matrix ({effective}) is not smaller than the "
                f"axis product ({product}), so the `exclude` list removed nothing. "
                "Either the excludes stopped matching any cell -- which is itself the "
                "bug, since every one of them is there to drop a configuration that "
                "cannot work -- or this file's matrix expansion has gone stale and is "
                "comparing raw axes."
            )


class TestScanValidationValuesAreDerived:
    """No row of scan-validation restates a fact the runner already knows."""

    def _rows(self) -> list[dict[str, Any]]:
        return _matrix(_job(UNIFIED_CI, "scan-validation")).get("include") or []

    def test_the_rows_were_read(self):
        """Positive control for every absence asserted below."""
        rows = self._rows()
        assert len(rows) >= _MINIMUM_SCAN_ROWS, (
            f"scan-validation has {len(rows)} include row(s), below the floor of "
            f"{_MINIMUM_SCAN_ROWS}. Every check in this class asserts that something is "
            "absent from the rows, and an empty row list satisfies all of them."
        )
        methods = {row.get("method") for row in rows}
        assert "python-local" in methods and len(methods) >= 3, (
            f"scan-validation's methods are {sorted(m for m in methods if m)}; the "
            "oci-runner invariant below needs both a python-local row and a container "
            "row to have anything to distinguish."
        )

    def test_no_row_restates_the_platform(self):
        offenders = [row for row in self._rows() if "platform" in row]
        assert not offenders, (
            f"{len(offenders)} scan-validation row(s) carry a `platform` key. It is a "
            "pure function of `os`, its only consumers are log lines, and the "
            "hand-written values had already gone wrong -- macos-latest moved to Apple "
            "silicon while the rows still said darwin/amd64, so the log lied and the "
            "leg stayed green. run-scan-test derives it from runner.os and runner.arch; "
            "delete the key rather than restating it."
        )

    def test_oci_runner_is_named_exactly_when_the_method_uses_one(self):
        """`oci-runner` was `""` on precisely the python-local rows, so it was derivable.

        Asserted in both directions: a python-local row that acquires a runner, and a
        container row that loses one, are both silent changes of what a leg tests.
        """
        wrong = []
        for row in self._rows():
            method = row.get("method")
            runner = row.get("oci-runner")
            if method == "python-local" and runner is not None:
                wrong.append(
                    f"  {row}: python-local names oci-runner {runner!r}. python-local "
                    "runs no container, so the key is meaningless there; an empty string "
                    "was the old way of saying that and an absent key says it without "
                    "restating it."
                )
            if method != "python-local" and not runner:
                wrong.append(
                    f"  {row}: method {method!r} runs a container but names no "
                    "oci-runner, so the action would fall back to its default and the "
                    "row would not test what it claims to."
                )
        assert not wrong, (
            "scan-validation rows disagree with their own method:\n" + "\n".join(wrong)
        )

    def test_run_scan_test_derives_the_platform_from_the_runner(self):
        action = _load(RUN_SCAN_TEST)
        assert "platform" not in (action.get("inputs") or {}), (
            "run-scan-test still declares a `platform` input. While it exists, a caller "
            "can pass a hand-written value again and the log can go back to disagreeing "
            "with the machine that printed it."
        )

        text = RUN_SCAN_TEST.read_text(encoding="utf-8")
        assert "inputs.platform" not in text, (
            "run-scan-test still reads ${{ inputs.platform }} somewhere, which now "
            "expands to the empty string."
        )

        derive = [
            step for step in action["runs"]["steps"] if step.get("id") == "platform"
        ]
        assert derive, (
            "run-scan-test has no step with id `platform`, so nothing derives the label "
            "the log lines now reference."
        )
        script = str(derive[0].get("run", ""))
        assert "RUNNER_OS" in script and "RUNNER_ARCH" in script, (
            "the derivation does not read the runner's own os and arch, which is the "
            "whole point of moving it out of the matrix."
        )
        assert _has_fail_closed_default(script), (
            "the derivation has no `*)` arm that exits non-zero. An unrecognised "
            "runner.os or runner.arch would then interpolate an empty string into the "
            "log -- the same silent wrongness, one level down."
        )

        # Every log line that used to read the input must read the derived value, or the
        # removal above would have left them expanding to nothing. Asserted per line
        # rather than as a total: there were five such lines, one per scan method, and
        # the `bash` method's went with the root ./ash script the Python CLI absorbed,
        # so a fixed count would be stale the next time a method is added or removed.
        log_lines = [line for line in text.splitlines() if "Testing ASH using" in line]
        assert len(log_lines) >= 4, (
            f"only {len(log_lines)} 'Testing ASH using' log line(s) were found; one per "
            "scan method (python-container, python-local on each os family, powershell) "
            "is expected, so the census below would be checking too little."
        )
        unreferenced = [
            line.strip()
            for line in log_lines
            if "steps.platform.outputs.platform" not in line
        ]
        assert not unreferenced, (
            "these log lines do not read the derived platform: " + repr(unreferenced)
        )


class TestUnitTestArchIsDerived:
    """The arch label was not merely cosmetic, so its removal is asserted harder."""

    def test_the_matrix_carries_no_hand_written_arch_table(self):
        job = _job(UNIFIED_CI, "unit-test")
        rows = _matrix(job).get("include") or []
        offenders = [row for row in rows if "arch" in row]
        assert not offenders, (
            f"{len(offenders)} unit-test include row(s) carry an `arch` label. Those "
            "labels are not read from the runner and one had already gone wrong: "
            "macos-latest was labelled x86_64 after GitHub moved it to Apple silicon. "
            "run-unit-tests derives the label from runner.arch instead."
        )

    def test_the_matrix_still_expands_to_the_same_legs(self):
        """Positive control on the removal: dropping an include must not drop legs.

        The removed entries each matched an existing `os` axis value and only added a
        key, so the effective matrix is the axis product either way. If a future edit
        turns an include into a cell-defining one, this catches the leg count moving for
        a reason nobody intended.
        """
        job = _job(UNIFIED_CI, "unit-test")
        axes = _axes(job)
        product = 1
        for values in axes.values():
            product *= len(values)
        assert product >= 20, (
            f"unit-test's axis product is {product}, too small for this comparison to "
            "mean anything -- the matrix has been gutted."
        )
        assert len(_effective_matrix(job)) == product, (
            f"unit-test's effective matrix ({len(_effective_matrix(job))}) no longer "
            f"equals its axis product ({product}). An `include` or an `exclude` has "
            "appeared on the job. Either changes the leg count, and that count is what "
            "the comment on required-checks reconciles against measured run data -- so a "
            "matrix edit that moves it needs a new measurement rather than arithmetic. "
            "Note this file's matrix expansion appends every `include` entry rather than "
            "merging the key-only ones, so a re-added label table trips this too, which "
            "is the intent."
        )

    def test_run_unit_tests_derives_the_arch_label_from_the_runner(self):
        action = _load(RUN_UNIT_TESTS)
        assert "arch" not in (action.get("inputs") or {}), (
            "run-unit-tests still declares an `arch` input, so a caller can pass a "
            "hand-written label again."
        )

        text = RUN_UNIT_TESTS.read_text(encoding="utf-8")
        assert "inputs.arch" not in text, (
            "run-unit-tests still reads ${{ inputs.arch }}, which now expands to the "
            "empty string -- and it appears in an artifact name, so several legs would "
            "upload under one name."
        )

        derive = [s for s in action["runs"]["steps"] if s.get("id") == "runner-arch"]
        assert derive, "run-unit-tests has no step with id `runner-arch`"
        script = str(derive[0].get("run", ""))
        assert "RUNNER_ARCH" in script, (
            "the derivation does not read runner.arch, which is the runner's own "
            "statement about itself and the only authority here."
        )
        assert _has_fail_closed_default(script), (
            "the derivation has no `*)` arm that exits non-zero, so an unrecognised "
            "runner.arch would put an empty label into an artifact name."
        )

    def test_the_coverage_summary_selects_its_leg_from_the_runner_context(self):
        """The half of defect 4 that was not cosmetic.

        This step renders the coverage summary on exactly one of the 25 legs. It used to
        select that leg by comparing the arch LABEL, so a mislabelled Linux row would
        have dropped the step from every leg at once -- nothing renders it and nothing
        reports it missing. The condition must now be composed of runner-context terms
        and the python-version input, with no hand-written label in it.
        """
        action = _load(RUN_UNIT_TESTS)
        steps = [
            s
            for s in action["runs"]["steps"]
            if s.get("name") == "Code coverage summary"
        ]
        assert steps, "the 'Code coverage summary' step was not found"
        condition = str(steps[0].get("if", ""))
        assert condition, (
            "the coverage summary step has no `if:`, so it runs on every leg"
        )

        assert "runner.arch" in condition, (
            f"the condition is {condition!r} and does not name runner.arch. Selecting on "
            "anything other than what the runner reports is how this step came to be "
            "selectable by a wrong label."
        )
        assert "inputs.arch" not in condition and "matrix." not in condition, (
            f"the condition is {condition!r} and still selects on a matrix-supplied "
            "label."
        )
        # runner.os and the python version are the other two terms; naming them keeps the
        # selection at exactly one leg rather than one per Linux architecture.
        assert "runner.os" in condition and "python-version" in condition, (
            f"the condition is {condition!r}; it needs the OS and the interpreter "
            "version too, or it selects more than one leg and the summary is rendered "
            "several times."
        )
