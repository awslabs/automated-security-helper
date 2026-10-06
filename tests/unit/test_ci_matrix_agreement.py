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
  ``ash-unified-ci.yml`` and the nix-only ``validate`` in ``ash-install-methods.yml`` -- end in
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
  ``install-validation`` stated a discipline -- "Keep the ``python-version`` axes of
  the two identical, deliberately" -- and nothing enforced it. No test read
  ``ash-install-methods.yml`` at all. That second matrix has since been cut to its nix
  legs, because every other cell it ran was a cell the unified job already ran
  (TestTheNixSurfaceCarriesOnlyNix). What is enforced now is the premise of that cut:
  the unified job still carries every method the removed legs did, and the nix surface
  carries nothing else.

The model
---------
``tests/unit/test_oci_runner_ci_coverage.py``. Coverage is computed from the EFFECTIVE
matrix -- the axis product minus ``exclude`` entries -- because a raw axis list cannot
tell full coverage from a method excluded on every cell. Every check carries a positive
control, because a test that parses a workflow and finds nothing to check passes
silently, and that is the dominant failure mode for guards of exactly this shape.

What this file deliberately does not do
---------------------------------------
It does not assert the excludes themselves, their count, or their shape. A test pinning
leg counts would break on every legitimate matrix change and would teach people to edit
the test rather than read it.
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

# The two install-validation surfaces, as (label, workflow path, job key, minimum
# methods on the axis, minimum validator steps). Both are checked by everything in
# TestInstallMethodRoutingIsClosed; a check that ran on only one of them would leave the
# other exactly as exposed as it was. The floors differ because the nix surface carries
# one method routed to one validator, and a floor above that would be a tripwire on the
# shape it is supposed to have.
INSTALL_SURFACES = [
    pytest.param(
        "ash-unified-ci.yml install-validation",
        UNIFIED_CI,
        "install-validation",
        5,
        2,
        id="unified-ci",
    ),
    pytest.param(
        "ash-install-methods.yml validate",
        INSTALL_METHODS,
        "validate",
        1,
        1,
        id="install-methods",
    ),
]

# What ash-unified-ci.yml's install-validation must keep carrying, because removing the
# per-method legs from ash-install-methods.yml was justified by it carrying them. The five
# cheap methods run as steps inside the `bundle` leg; the rest are `method` values.
_BUNDLED_STEPS = ("pip", "pipx", "uvx", "pre-commit", "mcp")
_UNIFIED_METHODS = ("bundle", "homebrew", "podman", "finch", "nerdctl")

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
# Current value, for whoever moves this next: ash-unified-ci.yml 33 effective legs.
# Re-derive rather than trusting it; the check is the expansion, not the comment.
_MINIMUM_INSTALL_LEGS = 15
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

    @pytest.mark.parametrize(
        "label,path,key,min_methods,min_validators", INSTALL_SURFACES
    )
    def test_every_method_on_the_axis_is_routed_to_a_validator(
        self, label, path, key, min_methods, min_validators
    ):
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

    @pytest.mark.parametrize(
        "label,path,key,min_methods,min_validators", INSTALL_SURFACES
    )
    def test_the_guard_exists_and_fails_closed(
        self, label, path, key, min_methods, min_validators
    ):
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

    @pytest.mark.parametrize(
        "label,path,key,min_methods,min_validators", INSTALL_SURFACES
    )
    def test_the_guard_arms_and_the_routing_conditions_name_the_same_methods(
        self, label, path, key, min_methods, min_validators
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

    @pytest.mark.parametrize(
        "label,path,key,min_methods,min_validators", INSTALL_SURFACES
    )
    def test_the_guard_runs_before_any_validator(
        self, label, path, key, min_methods, min_validators
    ):
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

    @pytest.mark.parametrize(
        "label,path,key,min_methods,min_validators", INSTALL_SURFACES
    )
    def test_the_readers_found_something(
        self, label, path, key, min_methods, min_validators
    ):
        """Positive control. Every assertion above is satisfied by two empty sets."""
        job = _job(path, key)
        axis = _axes(job).get("method") or []
        assert len(axis) >= min_methods, (
            f"{label}: the `method` axis holds {len(axis)} entries, below the floor of "
            f"{min_methods}. With an empty axis the routing check above "
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
        assert len(_validator_steps(job)) >= min_validators, (
            f"{label}: fewer than {min_validators} validator step(s) were found, so the routing table "
            "this file exists to reconcile is not being read."
        )


class TestTheNixSurfaceCarriesOnlyNix:
    """ash-install-methods.yml is nix and nothing else, and the unified job covers the rest.

    It used to repeat every pip, pipx, uvx, pre-commit, mcp, homebrew, podman, finch and
    nerdctl cell of ``install-validation`` as a leg of its own -- 113 legs, each one a
    cell the unified job, unconditional and gated by ``required-checks``, already ran.
    Those legs were removed on that premise, so the premise is what is asserted here: if
    the unified job stops carrying a method, or this surface grows a non-nix method back,
    the reason for the cut no longer holds and something here goes red.
    """

    def test_install_methods_carries_nix_only(self):
        job = _job(INSTALL_METHODS, "validate")
        cells = _effective_matrix(job)
        assert cells, "ash-install-methods.yml validate expands to no legs"
        methods = sorted({c["method"] for c in cells})
        assert methods == ["nix"], (
            f"ash-install-methods.yml validate runs {methods}. Every method other than "
            "nix is already run by ash-unified-ci.yml install-validation on the same "
            "cells, so a non-nix leg here is a duplicate queued for a runner. Add the "
            "coverage to install-validation instead."
        )

    def test_unified_does_not_carry_nix(self):
        """If it ever does, this workflow has nothing left to do and should go."""
        methods = _axes(_job(UNIFIED_CI, "install-validation")).get("method") or []
        assert "nix" not in methods

    @pytest.mark.parametrize("axis", ["python-version", "os"])
    def test_nix_runs_on_cells_the_unified_job_also_runs(self, axis):
        unified = {
            str(v)
            for v in _axes(_job(UNIFIED_CI, "install-validation")).get(axis) or []
        }
        nix = {
            str(c[axis]) for c in _effective_matrix(_job(INSTALL_METHODS, "validate"))
        }
        assert unified and nix
        assert nix <= unified, (
            f"the nix legs run on {axis} {sorted(nix - unified)}, which "
            "ash-unified-ci.yml install-validation does not carry. A configuration "
            "supported on one surface only is untested by the other."
        )

    def test_the_unified_job_still_carries_every_removed_method(self):
        job = _job(UNIFIED_CI, "install-validation")
        methods = set(_axes(job).get("method") or [])
        missing = sorted(set(_UNIFIED_METHODS) - methods)
        assert not missing, (
            f"install-validation no longer carries {missing}. The per-method legs were "
            "removed from ash-install-methods.yml because this job ran them; restore "
            "the method here, or the coverage is gone from both surfaces."
        )

        bundle_steps = {
            str(step.get("name")): str(step.get("if", ""))
            for step in job["steps"]
            if "matrix.method == 'bundle'" in str(step.get("if", ""))
            and str(step.get("uses", "")).startswith("./.github/actions/validate-")
        }
        missing_steps = sorted(set(_BUNDLED_STEPS) - set(bundle_steps))
        assert not missing_steps, (
            f"the `bundle` leg no longer runs {missing_steps} as validator steps. Those "
            "methods have no other surface since ash-install-methods.yml was cut to nix."
        )

    def test_the_unified_matrix_was_actually_expanded(self):
        """Positive control.

        Empty leg sets satisfy every comparison above. And a comparison that ignored the
        excludes -- comparing raw axis products -- would also pass while missing the
        class of defect the excludes exist for, so the effective matrix is asserted to be
        strictly smaller than the product.
        """
        job = _job(UNIFIED_CI, "install-validation")
        product = 1
        for values in _axes(job).values():
            product *= len(values)
        effective = len(_effective_matrix(job))
        assert effective >= _MINIMUM_INSTALL_LEGS, (
            f"install-validation: {effective} effective leg(s), below the floor of "
            f"{_MINIMUM_INSTALL_LEGS}. With no legs the comparisons above are vacuous."
        )
        assert effective < product, (
            f"install-validation: the effective matrix ({effective}) is not smaller than "
            f"the axis product ({product}), so the `exclude` list removed nothing."
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
        # removal above would have left them expanding to nothing.
        referenced = text.count("steps.platform.outputs.platform")
        assert referenced >= 5, (
            f"only {referenced} reference(s) to the derived platform were found; the "
            "five log lines that named the old input should each read it now."
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
