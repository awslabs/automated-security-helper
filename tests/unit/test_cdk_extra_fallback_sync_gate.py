# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/sync_cdk_extra_fallback.py`` -- the repair for a drifting constant.

Why this file exists
--------------------
``_CDK_EXTRA_FALLBACK_REQUIREMENTS`` in ``cdk_nag_scanner.py`` duplicates
``[project.optional-dependencies] cdk``. ``test_fallback_matches_installed_metadata``
already *detects* the drift and does it well, but detection was the whole story:
every dependabot bump broke that test and a human repaired the constant by hand.
The script under test is the repair, so it has to be trustworthy in both
directions -- it must fix a real drift, and it must refuse rather than guess when
it cannot find what it owns.

What could go wrong, and is therefore asserted here
---------------------------------------------------
A generator that writes to the wrong place is worse than no generator. The
dangerous failure is not "it did not fix the drift", which is loud; it is "it
rewrote something else", or "it reported success having changed nothing". So the
refusal paths get as much coverage as the happy path: a reformatted anchor, a
missing closing bracket, a renamed extra. In each case the script must exit
non-zero **and leave the file untouched**, and both halves are asserted, because
a refusal that still wrote is the exact shape of the damage.

The anti-vacuity control is ``test_fix_is_not_satisfied_by_emptying_the_list``.
An easy way to make ``--check`` pass forever is to produce an empty list on both
sides; that would leave the scanner with no fallback at all while every gate went
green. Asserted rather than assumed because it is the cheapest wrong fix
available to anyone who edits this later.

Constraints
-----------
Nothing here touches the real repository files. Each test copies ``pyproject.toml``
and the scanner module into ``tmp_path`` and repoints the script's module-level
``PYPROJECT``/``SCANNER`` at the copies, so a failing test cannot leave the
checkout modified -- which matters more than usual for a script whose job is to
rewrite tracked source.

Known limitation
----------------
The round-trip test proves ``--fix`` reproduces the committed file byte for byte
*today*. If ruff-format's list style ever changes, that assertion is what fails,
and the fix is to update ``render()`` rather than to relax the assertion.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "sync_cdk_extra_fallback.py"
REAL_PYPROJECT = REPO_ROOT / "pyproject.toml"
REAL_SCANNER = (
    REPO_ROOT
    / "automated_security_helper"
    / "plugin_modules"
    / "ash_builtin"
    / "scanners"
    / "cdk_nag_scanner.py"
)

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="the script needs tomllib; it runs in pre-commit and CI, not inside ASH",
)


def _load_script():
    """Import the script by path; ``scripts/`` is not a package.

    Registered under its own name in ``sys.modules`` so no other worker picks up a
    half-initialised module, matching ``test_scanners_completed_gate.py``.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_sync_cdk_extra_fallback", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """The script, pointed at copies of the two real files."""
    script = _load_script()
    pyproject = tmp_path / "pyproject.toml"
    scanner = tmp_path / "cdk_nag_scanner.py"
    shutil.copyfile(REAL_PYPROJECT, pyproject)
    shutil.copyfile(REAL_SCANNER, scanner)
    monkeypatch.setattr(script, "PYPROJECT", pyproject)
    monkeypatch.setattr(script, "SCANNER", scanner)
    monkeypatch.setattr(sys, "argv", ["sync_cdk_extra_fallback.py"])
    return script, pyproject, scanner


def _bump(pyproject: Path, frm: str, to: str) -> None:
    text = pyproject.read_text(encoding="utf-8")
    assert frm in text, f"{frm!r} not in pyproject; the fixture drifted"
    pyproject.write_text(text.replace(frm, to, 1), encoding="utf-8")


class TestTheCommittedStateIsClean:
    def test_check_passes_on_the_real_files(self):
        """The gate this adds must be green on main before it is added to CI."""
        script = _load_script()
        assert (
            script.committed_requirements(
                script.SCANNER.read_text(encoding="utf-8").splitlines()
            )
            == script.declared_requirements()
        )

    def test_check_exits_zero_in_the_sandbox(self, sandbox, monkeypatch):
        script, _, _ = sandbox
        monkeypatch.setattr(sys, "argv", ["x"])
        assert script.main() == 0


class TestADependabotBumpIsCaughtAndRepaired:
    """The measured case: pyproject moves, the constant does not."""

    def test_check_fails_and_changes_nothing(self, sandbox, monkeypatch):
        script, pyproject, scanner = sandbox
        before = scanner.read_bytes()
        _bump(pyproject, "aws-cdk-lib>=2.269.0,<3.0.0", "aws-cdk-lib>=2.270.0,<3.0.0")
        monkeypatch.setattr(sys, "argv", ["x"])

        assert script.main() == 1
        assert scanner.read_bytes() == before, "--check wrote to the scanner"

    def test_fix_repairs_the_constant(self, sandbox, monkeypatch):
        script, pyproject, scanner = sandbox
        _bump(pyproject, "aws-cdk-lib>=2.269.0,<3.0.0", "aws-cdk-lib>=2.270.0,<3.0.0")
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])

        assert script.main() == 0
        assert (
            script.committed_requirements(
                scanner.read_text(encoding="utf-8").splitlines()
            )
            == script.declared_requirements()
        )
        assert "aws-cdk-lib>=2.270.0,<3.0.0" in scanner.read_text(encoding="utf-8")

    def test_fix_round_trips_to_the_committed_bytes(self, sandbox, monkeypatch):
        """``--fix`` on an already-correct file must be a no-op, byte for byte.

        If it is not, every bump would produce a spurious formatting diff and the
        gate would be teaching people to ignore it.
        """
        script, _, scanner = sandbox
        before = scanner.read_bytes()
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])

        assert script.main() == 0
        assert scanner.read_bytes() == before

    @pytest.mark.parametrize(
        "frm,to",
        [
            ("cdk-nag>=3.0,<4.0.0", "cdk-nag>=4.0,<5.0.0"),
            ("constructs>=10.8,<11.0.0", "constructs>=11.0,<12.0.0"),
            ("aws-cdk-lib>=2.269.0,<3.0.0", "aws-cdk-lib>=2.269.0"),
        ],
    )
    def test_any_requirement_moving_is_caught(self, sandbox, monkeypatch, frm, to):
        """Not just the aws-cdk-lib floor, which is the only one seen so far."""
        script, pyproject, _ = sandbox
        _bump(pyproject, frm, to)
        monkeypatch.setattr(sys, "argv", ["x"])
        assert script.main() == 1

    def test_a_requirement_added_to_the_extra_is_caught(self, sandbox, monkeypatch):
        script, pyproject, _ = sandbox
        _bump(
            pyproject,
            '    "constructs>=10.8,<11.0.0",',
            '    "constructs>=10.8,<11.0.0",\n    "some-new-dep>=1.0,<2.0.0",',
        )
        monkeypatch.setattr(sys, "argv", ["x"])
        assert script.main() == 1


class TestItRefusesRatherThanGuessing:
    """A generator that writes to the wrong place is worse than no generator."""

    def test_a_reformatted_anchor_is_refused_without_writing(
        self, sandbox, monkeypatch
    ):
        script, _, scanner = sandbox
        text = scanner.read_text(encoding="utf-8")
        # A plausible future edit: drop the type annotation.
        scanner.write_text(
            text.replace(
                "_CDK_EXTRA_FALLBACK_REQUIREMENTS: List[str] = [",
                "_CDK_EXTRA_FALLBACK_REQUIREMENTS = [",
            ),
            encoding="utf-8",
        )
        before = scanner.read_bytes()
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])

        with pytest.raises(SystemExit) as excinfo:
            script.main()

        assert "ANCHOR" in str(excinfo.value)
        assert scanner.read_bytes() == before, "refused but wrote anyway"

    def test_a_missing_closing_bracket_is_refused_without_writing(
        self, sandbox, monkeypatch
    ):
        script, _, scanner = sandbox
        lines = scanner.read_text(encoding="utf-8").splitlines()
        _first, closer = script.locate_block(lines)
        del lines[closer]
        scanner.write_text("\n".join(lines) + "\n", encoding="utf-8")
        before = scanner.read_bytes()
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])

        with pytest.raises(SystemExit) as excinfo:
            script.main()

        assert "closing" in str(excinfo.value)
        assert scanner.read_bytes() == before

    def test_a_duplicated_anchor_is_refused(self, sandbox, monkeypatch):
        """Two candidate blocks means the script cannot know which it owns."""
        script, _, scanner = sandbox
        text = scanner.read_text(encoding="utf-8")
        scanner.write_text(
            text + "\n_CDK_EXTRA_FALLBACK_REQUIREMENTS: List[str] = [\n]\n",
            encoding="utf-8",
        )
        before = scanner.read_bytes()
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])

        with pytest.raises(SystemExit):
            script.main()

        assert scanner.read_bytes() == before

    def test_a_renamed_extra_is_refused(self, sandbox, monkeypatch):
        """Removing the extra is a human decision, not something to generate."""
        script, pyproject, _ = sandbox
        pyproject.write_text(
            pyproject.read_text(encoding="utf-8").replace(
                "[project.optional-dependencies]\ncdk = [",
                "[project.optional-dependencies]\ncdk-renamed = [",
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])

        with pytest.raises(SystemExit) as excinfo:
            script.main()

        assert "optional-dependencies" in str(excinfo.value)


class TestTheGateCannotPassVacuously:
    """The control. A gate that checks nothing is worse than the hand edit."""

    def test_fix_is_not_satisfied_by_emptying_the_list(self, sandbox, monkeypatch):
        """An empty extra must not produce a silently empty fallback.

        The cheapest wrong way to make this gate permanently green is for both
        sides to be empty. The scanner would then have no fallback at all, and
        ``_cdk_extra_requirements`` would hand an empty install list to pip, which
        reports success having installed nothing.
        """
        script, _, scanner = sandbox
        monkeypatch.setattr(sys, "argv", ["x", "--fix"])
        script.main()

        after = script.committed_requirements(
            scanner.read_text(encoding="utf-8").splitlines()
        )
        assert after, "--fix produced an empty fallback list"
        assert len(after) == 3, after
        assert {requirement.split(">")[0].split("<")[0] for requirement in after} == {
            "aws-cdk-lib",
            "cdk-nag",
            "constructs",
        }

    def test_the_comparison_is_against_pyproject_and_not_itself(
        self, sandbox, monkeypatch
    ):
        """Perturb pyproject and the read-back constant must not follow.

        If ``declared_requirements`` were secretly reading the scanner, the two
        sides would agree for every value and ``--check`` could never fail. Same
        shape as ``test_the_comparison_is_not_against_the_constant_itself`` next
        to the test this script exists to stop breaking.
        """
        script, pyproject, scanner = sandbox
        _bump(pyproject, "aws-cdk-lib>=2.269.0,<3.0.0", "aws-cdk-lib>=2.271.0,<3.0.0")

        declared = script.declared_requirements()
        committed = script.committed_requirements(
            scanner.read_text(encoding="utf-8").splitlines()
        )

        assert declared != committed
        assert any("2.271.0" in requirement for requirement in declared)
        assert not any("2.271.0" in requirement for requirement in committed)
