"""``scripts/sync_alpha_extra.py`` -- the repair for a drifting ``alpha`` extra.

Why this file exists
--------------------
``[project.optional-dependencies] alpha`` in pyproject.toml and the ``alpha-extra`` group
in .github/dependabot.yml restate what the provisioning register
(``base/plugin_provisioning.py``) says about which PyPI pins are members of the extra.
The script under test writes both from the register and fails a check when either
disagrees, so it has to be trustworthy in both directions: it must repair a real drift,
and it must refuse, writing nothing, when it cannot find what it owns.

What could go wrong, and is therefore asserted here
---------------------------------------------------
A generator that writes to the wrong place is worse than none. So the refusals get as
much coverage as the happy path, and each is asserted in two halves, because a refusal
that still wrote is the exact shape of the damage: the exit status is the refusing one,
and both files are byte-identical afterwards (compared by content, before and after).
Refusal is all or nothing: a refusal found in one file leaves the other file unrepaired.

The anti-vacuity controls are the ones that matter most. An easy way to make a check pass
forever is to render nothing on both sides. So an array emptied while the register holds
members is not accepted, and no ``alpha`` key is written (or kept) while no pin is a member.
The comparison is made against the register: the register is changed and the files are
not, and the check fails.

Constraints
-----------
Nothing here touches the real repository files except the tests that name them. Each test
points the script's module-level ``PYPROJECT``, ``DEPENDABOT`` and ``load_register`` at
throwaway files and a planted register. The expectations are spelled out rather than read
from the script, so a mutant of the renderer cannot make its own test agree with it.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
import types
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base import plugin_provisioning as prov

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "sync_alpha_extra.py"
REAL_PYPROJECT = REPO_ROOT / "pyproject.toml"
REAL_DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
PRE_COMMIT_CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
DRIFT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-alpha-extra-drift.yml"
AUTO_MERGE_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "ash-dependabot-auto-merge.yml"
)

EXTRA = "alpha"
BEGIN = "# BEGIN generated: alpha-extra-group (scripts/sync_alpha_extra.py)"
END = "# END generated: alpha-extra-group"


def _load_script():
    """Import the script by path; ``scripts/`` is not a package.

    Registered under its own name in ``sys.modules`` so no other worker picks up a
    half-initialized module, as the cdk sync gate does.
    """
    spec = importlib.util.spec_from_file_location("ash_sync_alpha_extra", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# The files the script edits, and a register to edit them from
# ---------------------------------------------------------------------------

PYPROJECT_TEXT = """\
[project]
name = "fixture"
dependencies = [
 "left-pad>=1,<2",
]
[project.optional-dependencies]
cdk = [
    # a comment in a neighboring array, which the script never touches
    "aws-cdk-lib>=2.0,<3.0.0",
]
symbols = [
    "tree-sitter>=0.26,<0.27",
]

[[project.authors]]
name = "A Person"
"""

DEPENDABOT_TEXT = f"""\
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    groups:
      actions:
        patterns:
          - "*"
  - package-ecosystem: "uv"
    directory: "/"
    groups:
      scanner-minor:
        patterns:
          - "cdk-nag*"
        update-types:
          - "minor"
      {BEGIN}
      {END}
      engine-minor:
        patterns:
          - "*"
        update-types:
          - "minor"
"""


def _pin(distribution: str, specifier: str, runtime: str = "uv-tool", **changes):
    return prov.PypiPin(distribution, specifier, runtime, **changes)


FERRET = _pin("ferret-scan", ">=2.4.5,<2.7.0", "ash-environment", extra=EXTRA)
GUARDDOG = _pin(
    "guarddog",
    "==3.2.0",
    python_marker="python_version < '3.14'",
    platform_marker="sys_platform != 'win32'",
    extra=EXTRA,
)
NEEDS_PLUGGY = _pin(
    "needs-pluggy-tool",
    "==1.0.0",
    with_requirements=("pluggy<1.7",),
    platform_marker="sys_platform == 'linux'",
    extra=EXTRA,
)
#: Excluded from the extra, so it appears in neither file.
HELD = _pin(
    "scancode-toolkit",
    "==32.5.0",
    with_requirements=("pluggy<1.7",),
    excluded=prov.Exclusion(
        prov.ExclusionReason.NO_WHEELS, "a detail", "a measurement"
    ),
)

#: guarddog as the register holds it today: out of the extra, with the reason recorded.
GUARDDOG_HELD = _pin(
    "guarddog",
    "==3.2.0",
    excluded=prov.Exclusion(
        prov.ExclusionReason.OWNER_HOLD, "a detail", "a measurement"
    ),
)

#: A register whose pins are all excluded: no member, so no extra and no group.
NO_MEMBERS = {"scancode": [HELD]}
#: Three members and one exclusion. The scanner names carry no meaning.
ALL_PINS = {
    "ferret-scan": [FERRET],
    "guarddog": [GUARDDOG],
    "needs-pluggy-tool": [NEEDS_PLUGGY],
    "scancode": [HELD],
}

#: What the three members render to, sorted by distribution: each with-requirement is a
#: line of its own under its member's marker.
REQUIREMENTS = [
    "ferret-scan>=2.4.5,<2.7.0",
    "guarddog==3.2.0; python_version < '3.14' and sys_platform != 'win32'",
    "needs-pluggy-tool==1.0.0; sys_platform == 'linux'",
    "pluggy<1.7; sys_platform == 'linux'",
]
PATTERNS = ["ferret-scan*", "guarddog*", "needs-pluggy-tool*", "pluggy*"]


def _array_line(requirement: str) -> str:
    return f'    "{requirement}",\n'


ALPHA_BODY = "".join(_array_line(requirement) for requirement in REQUIREMENTS)
ALPHA_ARRAY = f"alpha = [\n{ALPHA_BODY}]\n"
EXPECTED_PYPROJECT = PYPROJECT_TEXT.replace(
    "]\n\n[[project.authors]]", f"]\n{ALPHA_ARRAY}\n[[project.authors]]"
)
GROUP = "".join(
    [
        "      alpha-extra:\n",
        "        patterns:\n",
        *(f'          - "{pattern}"\n' for pattern in PATTERNS),
    ]
)
EXPECTED_DEPENDABOT = DEPENDABOT_TEXT.replace(
    f"      {BEGIN}\n", f"      {BEGIN}\n{GROUP}"
)


class Sandbox:
    """The script, pointed at two throwaway files and a planted register."""

    def __init__(self, script, pyproject: Path, dependabot: Path, monkeypatch):
        self.script = script
        self.pyproject = pyproject
        self.dependabot = dependabot
        self._monkeypatch = monkeypatch

    def plant(self, pins_by_scanner: dict) -> None:
        provisioning = {
            scanner: prov.Provisioning(pypi_pins=tuple(pins))
            for scanner, pins in pins_by_scanner.items()
        }
        register = types.SimpleNamespace(PROVISIONING=provisioning)
        self._monkeypatch.setattr(self.script, "load_register", lambda: register)

    def run(self, *argv: str) -> int:
        return self.script.main(list(argv))

    def snapshot(self) -> tuple[bytes, bytes]:
        return self.pyproject.read_bytes(), self.dependabot.read_bytes()

    def edit(self, path: Path, old: str, new: str) -> None:
        """Replace ``old`` with ``new`` once. Written as bytes so no platform adds a
        carriage return, and asserted to change something so a case that stopped
        matching the fixture cannot pass by planting nothing."""
        text = path.read_bytes().decode("utf-8")
        assert old in text, f"{old!r} is not in {path.name}; the fixture drifted"
        path.write_bytes(text.replace(old, new, 1).encode("utf-8"))

    def synced(self) -> Sandbox:
        """Plant the three members and let ``--fix`` write both files."""
        self.plant(ALL_PINS)
        assert self.run("--fix") == 0
        return self


@pytest.fixture
def sandbox(tmp_path, monkeypatch) -> Sandbox:
    script = _load_script()
    pyproject = tmp_path / "pyproject.toml"
    dependabot = tmp_path / "dependabot.yml"
    pyproject.write_bytes(PYPROJECT_TEXT.encode("utf-8"))
    dependabot.write_bytes(DEPENDABOT_TEXT.encode("utf-8"))
    monkeypatch.setattr(script, "PYPROJECT", pyproject)
    monkeypatch.setattr(script, "DEPENDABOT", dependabot)
    box = Sandbox(script, pyproject, dependabot, monkeypatch)
    box.plant(NO_MEMBERS)
    return box


def _extras(path: Path) -> dict:
    return tomllib.loads(path.read_bytes().decode("utf-8"))["project"][
        "optional-dependencies"
    ]


# ---------------------------------------------------------------------------
# The committed state is clean
# ---------------------------------------------------------------------------


class TestTheCommittedStateIsClean:
    def test_check_exits_zero_on_the_real_files(self, capsys):
        """The gate this adds must be green on main before it is added to CI."""
        assert _load_script().main(["--check"]) == 0
        assert capsys.readouterr().out.startswith("ok:")

    def test_the_command_line_exits_zero_on_the_real_files(self):
        done = subprocess.run(
            [sys.executable, "-I", str(SCRIPT_PATH), "--check"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
        assert done.returncode == 0, (done.stdout, done.stderr)
        assert done.stdout.startswith("ok:")

    def test_the_real_pyproject_has_an_alpha_key_exactly_when_a_pin_is_a_member(self):
        """Read without the script: the register through the package, the extra through
        tomllib. It holds today with no member and no key, and after a member goes in
        with its key, so it survives that change."""
        members = [
            pin
            for block in prov.PROVISIONING.values()
            for pin in block.pypi_pins
            if pin.extra == EXTRA
        ]
        extras = tomllib.loads(REAL_PYPROJECT.read_text(encoding="utf-8"))["project"][
            "optional-dependencies"
        ]

        assert (EXTRA in extras) == bool(members)

    def test_a_register_with_no_member_and_files_with_no_key_are_in_sync(
        self, sandbox, capsys
    ):
        before = sandbox.snapshot()

        assert sandbox.run("--check") == 0

        assert capsys.readouterr().out.startswith("ok: no pin is a member")
        assert sandbox.snapshot() == before

    def test_the_default_mode_reports_and_writes_nothing(self, sandbox, capsys):
        sandbox.plant(ALL_PINS)
        before = sandbox.snapshot()

        assert sandbox.run() == 1
        assert sandbox.snapshot() == before
        assert capsys.readouterr().err.startswith("drift:")

    def test_check_and_fix_cannot_be_asked_for_together(self, sandbox):
        with pytest.raises(SystemExit) as excinfo:
            sandbox.run("--check", "--fix")

        assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# --fix writes what the register says, and nothing else
# ---------------------------------------------------------------------------


class TestFixWritesTheRegistersMembers:
    def test_fix_writes_the_extra_and_the_group(self, sandbox, capsys):
        sandbox.plant(ALL_PINS)

        assert sandbox.run("--fix") == 0

        assert sandbox.pyproject.read_bytes() == EXPECTED_PYPROJECT.encode("utf-8")
        assert sandbox.dependabot.read_bytes() == EXPECTED_DEPENDABOT.encode("utf-8")
        out = capsys.readouterr().out
        assert out.count("fixed:") == 2
        assert "uv lock" in out

    def test_an_excluded_pin_appears_in_neither_file(self, sandbox):
        sandbox.synced()

        assert "scancode" not in sandbox.pyproject.read_bytes().decode("utf-8")
        assert "scancode" not in sandbox.dependabot.read_bytes().decode("utf-8")

    def test_the_written_extra_is_the_members_requirements_and_nothing_less(
        self, sandbox
    ):
        sandbox.synced()

        assert _extras(sandbox.pyproject)[EXTRA] == REQUIREMENTS

    def test_fix_is_idempotent(self, sandbox, capsys):
        sandbox.synced()
        once = sandbox.snapshot()
        capsys.readouterr()

        assert sandbox.run("--fix") == 0

        assert sandbox.snapshot() == once
        assert "fixed:" not in capsys.readouterr().out
        assert sandbox.run("--check") == 0

    def test_fix_changes_nothing_outside_the_array_and_the_markers(self, sandbox):
        sandbox.synced()

        wrote = sandbox.pyproject.read_bytes().decode("utf-8")
        assert wrote.count(ALPHA_ARRAY) == 1
        assert wrote.replace(ALPHA_ARRAY, "") == PYPROJECT_TEXT
        head, _, rest = sandbox.dependabot.read_bytes().decode("utf-8").partition(BEGIN)
        _, _, tail = rest.partition(END)
        want_head, _, want_rest = DEPENDABOT_TEXT.partition(BEGIN)
        _, _, want_tail = want_rest.partition(END)
        assert (head, tail) == (want_head, want_tail)

    def test_a_member_leaving_restores_the_original_bytes(self, sandbox):
        original = sandbox.snapshot()
        sandbox.synced()
        assert sandbox.snapshot() != original

        sandbox.plant(NO_MEMBERS)

        assert sandbox.run("--fix") == 0
        assert sandbox.snapshot() == original

    def test_the_extra_goes_at_the_end_of_its_table(self, sandbox):
        sandbox.synced()

        text = sandbox.pyproject.read_bytes().decode("utf-8")
        table = text.index("[project.optional-dependencies]")
        authors = text.index("[[project.authors]]")
        assert table < text.index("symbols = [") < text.index("alpha = [") < authors

    def test_a_comment_block_at_the_end_of_the_table_ends_up_above_the_array(
        self, sandbox
    ):
        note = "# How the alpha extra is edited, written by hand.\n"
        sandbox.edit(
            sandbox.pyproject,
            "]\n\n[[project.authors]]",
            f"]\n{note}\n[[project.authors]]",
        )
        with_note = sandbox.pyproject.read_bytes()
        sandbox.plant(ALL_PINS)

        assert sandbox.run("--fix") == 0

        text = sandbox.pyproject.read_bytes().decode("utf-8")
        assert f"{note}{ALPHA_ARRAY}\n[[project.authors]]" in text
        sandbox.plant(NO_MEMBERS)
        assert sandbox.run("--fix") == 0
        assert sandbox.pyproject.read_bytes() == with_note

    def test_crlf_files_are_written_with_crlf_and_left_alone_when_in_sync(
        self, sandbox
    ):
        crlf = (
            PYPROJECT_TEXT.replace("\n", "\r\n"),
            DEPENDABOT_TEXT.replace("\n", "\r\n"),
        )
        sandbox.pyproject.write_bytes(crlf[0].encode("utf-8"))
        sandbox.dependabot.write_bytes(crlf[1].encode("utf-8"))
        sandbox.plant(ALL_PINS)

        assert sandbox.run("--fix") == 0

        assert sandbox.pyproject.read_bytes() == EXPECTED_PYPROJECT.replace(
            "\n", "\r\n"
        ).encode("utf-8")
        assert sandbox.dependabot.read_bytes() == EXPECTED_DEPENDABOT.replace(
            "\n", "\r\n"
        ).encode("utf-8")
        once = sandbox.snapshot()
        assert sandbox.run("--check") == 0
        assert sandbox.run("--fix") == 0
        assert sandbox.snapshot() == once


# ---------------------------------------------------------------------------
# Drift is caught by --check, and repaired by --fix
# ---------------------------------------------------------------------------

_GUARDDOG_LINE = _array_line(REQUIREMENTS[1])
_FERRET_LINE = _array_line(REQUIREMENTS[0])

#: case -> (file, text to replace, replacement)
_DRIFTS = {
    "a requirement's specifier moved": (
        "pyproject",
        "guarddog==3.2.0",
        "guarddog==3.3.0",
    ),
    "a requirement was dropped": (
        "pyproject",
        _array_line(REQUIREMENTS[3]),
        "",
    ),
    "a requirement was added": (
        "pyproject",
        _FERRET_LINE,
        _FERRET_LINE + _array_line("stowaway>=1"),
    ),
    "a marker was edited": (
        "pyproject",
        "sys_platform != 'win32'",
        "sys_platform == 'linux'",
    ),
    "two requirements swapped places": (
        "pyproject",
        _FERRET_LINE + _GUARDDOG_LINE,
        _GUARDDOG_LINE + _FERRET_LINE,
    ),
    "a pattern was dropped from the group": (
        "dependabot",
        '          - "guarddog*"\n',
        "",
    ),
    "a pattern was added to the group": (
        "dependabot",
        '          - "guarddog*"\n',
        '          - "guarddog*"\n          - "stowaway*"\n',
    ),
    "the group was removed": ("dependabot", GROUP, ""),
    "a hand-written line sits between the markers": (
        "dependabot",
        f"      {END}",
        f"      note: written by hand\n      {END}",
    ),
}


def _target(box: Sandbox, which: str) -> Path:
    return box.pyproject if which == "pyproject" else box.dependabot


class TestDriftIsCaughtAndRepaired:
    @pytest.mark.parametrize("case", sorted(_DRIFTS))
    def test_check_reports_the_drift_and_writes_nothing(self, sandbox, capsys, case):
        box = sandbox.synced()
        which, old, new = _DRIFTS[case]
        box.edit(_target(box, which), old, new)
        before = box.snapshot()
        capsys.readouterr()

        assert box.run("--check") == 1

        err = capsys.readouterr().err
        assert err.startswith("drift:"), err
        assert "sync_alpha_extra.py --fix" in err
        assert "--no-project" in err
        assert box.snapshot() == before

    @pytest.mark.parametrize("case", sorted(_DRIFTS))
    def test_fix_repairs_it_to_the_bytes_the_register_calls_for(self, sandbox, case):
        box = sandbox.synced()
        synced = box.snapshot()
        which, old, new = _DRIFTS[case]
        box.edit(_target(box, which), old, new)

        assert box.run("--fix") == 0

        assert box.snapshot() == synced

    def test_a_pyproject_drift_asks_for_a_relock_and_a_group_drift_does_not(
        self, sandbox, capsys
    ):
        box = sandbox.synced()
        box.edit(box.pyproject, "guarddog==3.2.0", "guarddog==3.3.0")
        capsys.readouterr()
        assert box.run("--check") == 1
        pyproject_advice = capsys.readouterr().err
        box.run("--fix")
        box.edit(box.dependabot, '          - "guarddog*"\n', "")
        capsys.readouterr()
        assert box.run("--check") == 1
        group_advice = capsys.readouterr().err

        assert "[project.optional-dependencies] alpha differs" in pyproject_advice
        assert "uv lock" in pyproject_advice
        assert "alpha-extra-group markers differs" in group_advice
        assert "[project.optional-dependencies] alpha differs" not in group_advice
        assert "uv lock" not in group_advice

    def test_the_advice_says_to_move_the_register_before_running_fix(
        self, sandbox, capsys
    ):
        """After a dependency bump edits pyproject.toml, --fix alone writes the old pin
        back over it, so the message has to say which side to change first."""
        box = sandbox.synced()
        box.edit(box.pyproject, "guarddog==3.2.0", "guarddog==3.3.0")
        capsys.readouterr()

        box.run("--check")

        err = capsys.readouterr().err
        assert "plugin_provisioning.py" in err
        assert "bump" in err


# ---------------------------------------------------------------------------
# The controls: the check cannot pass vacuously
# ---------------------------------------------------------------------------


class TestTheGateCannotPassVacuously:
    def test_an_emptied_array_is_not_accepted_while_the_register_has_members(
        self, sandbox
    ):
        box = sandbox.synced()
        box.edit(box.pyproject, ALPHA_BODY, "")
        assert _extras(box.pyproject)[EXTRA] == [], "the fixture must empty the array"

        assert box.run("--check") == 1
        assert box.run("--fix") == 0

        assert _extras(box.pyproject)[EXTRA] == REQUIREMENTS

    def test_fix_never_leaves_fewer_lines_than_there_are_members(self, sandbox):
        sandbox.synced()

        written = _extras(sandbox.pyproject)[EXTRA]
        assert len(written) >= len(
            [pin for pins in ALL_PINS.values() for pin in pins if pin.extra == EXTRA]
        )
        for member in (FERRET, GUARDDOG, NEEDS_PLUGGY):
            assert any(line.startswith(member.distribution) for line in written)

    def test_no_alpha_key_is_written_while_no_member_is_in(self, sandbox):
        before = sandbox.snapshot()

        assert sandbox.run("--fix") == 0

        assert sandbox.snapshot() == before
        assert EXTRA not in _extras(sandbox.pyproject)

    def test_an_empty_alpha_array_is_removed_when_no_member_is_in(self, sandbox):
        sandbox.edit(
            sandbox.pyproject,
            "]\n\n[[project.authors]]",
            "]\nalpha = [\n]\n\n[[project.authors]]",
        )
        assert _extras(sandbox.pyproject)[EXTRA] == []

        assert sandbox.run("--check") == 1
        assert sandbox.run("--fix") == 0

        assert sandbox.pyproject.read_bytes() == PYPROJECT_TEXT.encode("utf-8")
        assert EXTRA not in _extras(sandbox.pyproject)

    def test_the_comparison_is_against_the_register_and_not_the_files(self, sandbox):
        """Change the register and nothing else. If the check read the files on both
        sides it would still pass."""
        box = sandbox.synced()
        moved = _pin(
            "guarddog",
            "==3.3.0",
            python_marker="python_version < '3.14'",
            platform_marker="sys_platform != 'win32'",
            extra=EXTRA,
        )

        box.plant({**ALL_PINS, "guarddog": [moved]})

        assert box.run("--check") == 1

    def test_a_pin_that_leaves_the_extra_takes_its_lines_with_it(self, sandbox):
        box = sandbox.synced()
        box.plant({**ALL_PINS, "guarddog": [GUARDDOG_HELD]})

        assert box.run("--fix") == 0

        written = _extras(box.pyproject)[EXTRA]
        assert not any(line.startswith("guarddog") for line in written)
        assert "guarddog*" not in box.dependabot.read_bytes().decode("utf-8")


# ---------------------------------------------------------------------------
# Refusals: a nonzero exit, and both files byte-identical
# ---------------------------------------------------------------------------


def _repoint_table(box: Sandbox) -> None:
    box.edit(box.pyproject, "[project.optional-dependencies]", "[project.extras]")


def _repeat_table(box: Sandbox) -> None:
    box.edit(
        box.pyproject,
        "[[project.authors]]",
        "[project.optional-dependencies]\n\n[[project.authors]]",
    )


def _repeat_opener(box: Sandbox) -> None:
    box.edit(
        box.pyproject, "\n[[project.authors]]", "alpha = [\n]\n\n[[project.authors]]"
    )


def _leave_the_array_open(box: Sandbox) -> None:
    box.edit(
        box.pyproject,
        _array_line(REQUIREMENTS[3]) + "]\n",
        _array_line(REQUIREMENTS[3]),
    )


def _write_the_array_on_one_line(box: Sandbox) -> None:
    box.edit(box.pyproject, ALPHA_ARRAY, 'alpha = ["ferret-scan>=2.4.5,<2.7.0"]\n')


def _break_the_toml(box: Sandbox) -> None:
    box.pyproject.write_bytes(box.pyproject.read_bytes() + b"= =\n")


def _lose_the_begin_marker(box: Sandbox) -> None:
    box.edit(box.dependabot, f"      {BEGIN}\n", "")


def _lose_the_end_marker(box: Sandbox) -> None:
    box.edit(box.dependabot, f"      {END}\n", "")


def _repeat_the_begin_marker(box: Sandbox) -> None:
    box.edit(box.dependabot, f"      {BEGIN}\n", f"      {BEGIN}\n      {BEGIN}\n")


def _unindent_the_begin_marker(box: Sandbox) -> None:
    box.edit(box.dependabot, f"      {BEGIN}\n", f"{BEGIN}\n")


def _swap_the_markers(box: Sandbox) -> None:
    box.edit(
        box.dependabot,
        f"      {BEGIN}\n{GROUP}      {END}\n",
        f"      {END}\n{GROUP}      {BEGIN}\n",
    )


def _a_member_in_another_extra(box: Sandbox) -> None:
    box.plant({**ALL_PINS, "other": [_pin("other-tool", "==1", extra="cdk")]})


def _a_requirement_that_cannot_be_written(box: Sandbox) -> None:
    box.plant({**ALL_PINS, "other": [_pin("other-tool", '=="1"', extra=EXTRA)]})


def _a_with_requirement_with_its_own_marker(box: Sandbox) -> None:
    pin = _pin(
        "other-tool",
        "==1",
        with_requirements=("pluggy<1.7; python_version < '3.13'",),
        extra=EXTRA,
    )
    box.plant({**ALL_PINS, "other": [pin]})


_BOTH = ("--check", "--fix")

#: case -> (what to break, a fragment of the refusal, the modes that refuse). The array
#: shape is only refused by --fix, which is the one that would drop what it holds.
_REFUSALS = {
    "the table is gone": (
        _repoint_table,
        "no [project.optional-dependencies] table",
        _BOTH,
    ),
    "the table is repeated": (
        _repeat_table,
        "2 [project.optional-dependencies] lines",
        _BOTH,
    ),
    "the opener is repeated": (_repeat_opener, "2 `alpha = [` lines", _BOTH),
    "the array never closes": (_leave_the_array_open, "never closes", _BOTH),
    "the array is written on one line": (
        _write_the_array_on_one_line,
        "not as `alpha = [`",
        _BOTH,
    ),
    "the file is not TOML": (_break_the_toml, "not valid TOML", _BOTH),
    "the begin marker is gone": (_lose_the_begin_marker, "expected exactly one", _BOTH),
    "the end marker is gone": (_lose_the_end_marker, "expected exactly one", _BOTH),
    "the begin marker is repeated": (
        _repeat_the_begin_marker,
        "expected exactly one",
        _BOTH,
    ),
    "the markers are out of order": (_swap_the_markers, "must come before", _BOTH),
    "the begin marker is not indented": (
        _unindent_the_begin_marker,
        "must be indented",
        _BOTH,
    ),
    "a member is in an extra the script does not render": (
        _a_member_in_another_extra,
        "renders only 'alpha'",
        _BOTH,
    ),
    "a requirement cannot be written as a TOML string": (
        _a_requirement_that_cannot_be_written,
        "cannot be written as one double-quoted",
        _BOTH,
    ),
    "a with-requirement carries a marker of its own": (
        _a_with_requirement_with_its_own_marker,
        "carries a marker of its own",
        _BOTH,
    ),
}


class TestItRefusesRatherThanGuessing:
    """A generator that writes to the wrong place is worse than no generator."""

    @pytest.mark.parametrize(
        ("case", "mode"),
        [(case, mode) for case in sorted(_REFUSALS) for mode in _REFUSALS[case][2]],
    )
    def test_a_refusal_exits_nonzero_and_writes_nothing(
        self, sandbox, capsys, case, mode
    ):
        arrange, fragment, _ = _REFUSALS[case]
        box = sandbox.synced()
        arrange(box)
        before = box.snapshot()
        capsys.readouterr()

        assert box.run(mode) == 2

        err = capsys.readouterr().err
        assert err.startswith("refused:"), err
        assert fragment in err, err
        assert box.snapshot() == before, "refused but wrote anyway"

    def test_a_refusal_in_one_file_leaves_the_other_unrepaired(self, sandbox):
        """All or nothing: the group could be repaired, but not while the extra cannot."""
        box = sandbox.synced()
        box.edit(box.pyproject, "guarddog==3.2.0", "guarddog==3.3.0")
        box.edit(box.pyproject, _FERRET_LINE, "    # kept by hand\n" + _FERRET_LINE)
        box.edit(box.dependabot, '          - "guarddog*"\n', "")
        before = box.snapshot()

        assert box.run("--fix") == 2

        assert box.snapshot() == before

    def test_a_register_that_cannot_be_loaded_is_refused(
        self, tmp_path, monkeypatch, capsys
    ):
        script = _load_script()
        broken = tmp_path / "plugin_provisioning.py"
        broken.write_bytes(b"raise RuntimeError('the register contradicts itself')\n")
        pyproject = tmp_path / "pyproject.toml"
        dependabot = tmp_path / "dependabot.yml"
        pyproject.write_bytes(PYPROJECT_TEXT.encode("utf-8"))
        dependabot.write_bytes(DEPENDABOT_TEXT.encode("utf-8"))
        monkeypatch.setattr(script, "PYPROJECT", pyproject)
        monkeypatch.setattr(script, "DEPENDABOT", dependabot)
        monkeypatch.setattr(script, "PROVISIONING_MODULE", broken)

        assert script.main(["--fix"]) == 2

        err = capsys.readouterr().err
        assert "could not be loaded" in err
        assert "the register contradicts itself" in err
        assert pyproject.read_bytes() == PYPROJECT_TEXT.encode("utf-8")
        assert dependabot.read_bytes() == DEPENDABOT_TEXT.encode("utf-8")

    def test_a_register_file_that_is_missing_is_refused(
        self, sandbox, tmp_path, monkeypatch, capsys
    ):
        script = _load_script()
        monkeypatch.setattr(script, "PYPROJECT", sandbox.pyproject)
        monkeypatch.setattr(script, "DEPENDABOT", sandbox.dependabot)
        monkeypatch.setattr(script, "PROVISIONING_MODULE", tmp_path / "missing.py")
        before = sandbox.snapshot()

        assert script.main(["--check"]) == 2

        assert "could not be loaded" in capsys.readouterr().err
        assert sandbox.snapshot() == before

    def test_a_file_that_cannot_be_read_is_refused(self, sandbox, capsys):
        sandbox.pyproject.unlink()

        assert sandbox.run("--check") == 2

        assert "cannot read" in capsys.readouterr().err

    def test_a_failed_write_names_what_was_already_written_and_the_next_run_finishes(
        self, sandbox, monkeypatch, capsys
    ):
        """The two writes are not atomic, and the message says where it stopped."""
        sandbox.plant(ALL_PINS)
        real_write = sandbox.script.write_text
        attempts: list[str] = []

        def second_write_fails(path, text):
            attempts.append(path.name)
            if len(attempts) == 2:
                raise OSError("disk full")
            real_write(path, text)

        monkeypatch.setattr(sandbox.script, "write_text", second_write_fails)

        assert sandbox.run("--fix") == 2

        err = capsys.readouterr().err
        assert err.startswith("error:"), err
        assert "disk full" in err
        assert "Already written: pyproject.toml" in err
        assert sandbox.pyproject.read_bytes() == EXPECTED_PYPROJECT.encode("utf-8")
        assert sandbox.dependabot.read_bytes() == DEPENDABOT_TEXT.encode("utf-8")
        monkeypatch.setattr(sandbox.script, "write_text", real_write)
        assert sandbox.run("--fix") == 0
        assert sandbox.dependabot.read_bytes() == EXPECTED_DEPENDABOT.encode("utf-8")


class TestTheArrayShape:
    """``--fix`` replaces every line of the array, so it refuses what it would drop.
    ``--check`` reads past it with the TOML parser and reports drift as usual."""

    def _drifted_with(self, box: Sandbox, old: str, new: str) -> None:
        box.synced()
        box.edit(box.pyproject, "guarddog==3.2.0", "guarddog==3.3.0")
        box.edit(box.pyproject, old, new)

    @pytest.mark.parametrize(
        ("case", "old", "new"),
        [
            (
                "a whole-line comment",
                _FERRET_LINE,
                "    # kept by hand\n" + _FERRET_LINE,
            ),
            (
                "a comment after an element",
                _FERRET_LINE,
                '    "ferret-scan>=2.4.5,<2.7.0",  # kept by hand\n',
            ),
            (
                "two requirements on one line",
                _FERRET_LINE,
                '    "ferret-scan>=2.4.5,<2.7.0", "stowaway>=1",\n',
            ),
            (
                "a single-quoted requirement",
                _FERRET_LINE,
                "    'ferret-scan>=2.4.5,<2.7.0',\n",
            ),
        ],
    )
    def test_fix_refuses_what_it_would_drop_and_check_reports_drift(
        self, sandbox, capsys, case, old, new
    ):
        self._drifted_with(sandbox, old, new)
        before = sandbox.snapshot()
        capsys.readouterr()

        assert sandbox.run("--check") == 1
        capsys.readouterr()
        assert sandbox.run("--fix") == 2

        err = capsys.readouterr().err
        assert "is not one double-quoted requirement" in err, case
        assert sandbox.snapshot() == before

    def test_removing_an_array_that_holds_a_comment_is_refused(self, sandbox, capsys):
        box = sandbox.synced()
        box.edit(box.pyproject, _FERRET_LINE, "    # kept by hand\n" + _FERRET_LINE)
        box.plant(NO_MEMBERS)
        before = box.snapshot()
        capsys.readouterr()

        assert box.run("--check") == 1
        capsys.readouterr()
        assert box.run("--fix") == 2

        assert "is not one double-quoted requirement" in capsys.readouterr().err
        assert box.snapshot() == before

    def test_a_comment_in_an_array_that_is_in_sync_is_left_alone(self, sandbox):
        box = sandbox.synced()
        box.edit(box.pyproject, _FERRET_LINE, "    # kept by hand\n" + _FERRET_LINE)
        before = box.snapshot()

        assert box.run("--check") == 0
        assert box.run("--fix") == 0

        assert box.snapshot() == before

    def test_blank_lines_in_the_array_are_normalized_away(self, sandbox):
        box = sandbox.synced()
        box.edit(box.pyproject, _GUARDDOG_LINE, "\n" + _GUARDDOG_LINE)
        box.edit(box.pyproject, "guarddog==3.2.0", "guarddog==3.3.0")

        assert box.run("--fix") == 0

        assert box.pyproject.read_bytes() == EXPECTED_PYPROJECT.encode("utf-8")


# ---------------------------------------------------------------------------
# The rendering
# ---------------------------------------------------------------------------


class TestTheRendering:
    def test_requirements_sort_by_normalized_name_and_keep_their_spelling(
        self, sandbox
    ):
        pins = [
            _pin("Zeta_Tool", "==2", extra=EXTRA),
            _pin("alpha.tool", "==1", extra=EXTRA),
        ]

        assert sandbox.script.requirement_lines(pins) == [
            "alpha.tool==1",
            "Zeta_Tool==2",
        ]

    def test_two_markers_join_with_and_and_a_marker_holding_or_is_parenthesized(
        self, sandbox
    ):
        pin = _pin(
            "t",
            "==1",
            python_marker="python_version < '3.14'",
            platform_marker="sys_platform == 'linux' or sys_platform == 'darwin'",
            extra=EXTRA,
        )

        assert sandbox.script.requirement_lines([pin]) == [
            "t==1; python_version < '3.14' and "
            "(sys_platform == 'linux' or sys_platform == 'darwin')"
        ]

    def test_a_with_requirement_sits_under_its_members_marker(self, sandbox):
        assert sandbox.script.requirement_lines([NEEDS_PLUGGY]) == [
            "needs-pluggy-tool==1.0.0; sys_platform == 'linux'",
            "pluggy<1.7; sys_platform == 'linux'",
        ]

    def test_a_line_two_members_share_is_written_once(self, sandbox):
        first = _pin("a-tool", "==1", with_requirements=("pluggy<1.7",), extra=EXTRA)
        second = _pin("b-tool", "==1", with_requirements=("pluggy<1.7",), extra=EXTRA)

        lines = sandbox.script.requirement_lines([first, second])

        assert lines.count("pluggy<1.7") == 1

    def test_the_same_requirement_under_two_markers_is_two_lines(self, sandbox):
        bare = _pin("a-tool", "==1", with_requirements=("pluggy<1.7",), extra=EXTRA)

        lines = sandbox.script.requirement_lines([bare, NEEDS_PLUGGY])

        assert "pluggy<1.7" in lines
        assert "pluggy<1.7; sys_platform == 'linux'" in lines

    def test_patterns_name_each_member_and_each_with_requirement_once(self, sandbox):
        first = _pin("a-tool", "==1", with_requirements=("pluggy<1.7",), extra=EXTRA)
        second = _pin("B_Tool", "==1", with_requirements=("pluggy<1.7",), extra=EXTRA)

        assert sandbox.script.group_patterns([first, second]) == [
            "a-tool*",
            "b-tool*",
            "pluggy*",
        ]

    @pytest.mark.parametrize(
        "name", ["Zeta_Tool", "alpha.tool", "A--b__c..d", "ferret-scan"]
    )
    def test_patterns_are_normalized_the_way_the_register_normalizes(
        self, sandbox, name
    ):
        pin = _pin(name, "==1", extra=EXTRA)

        assert sandbox.script.group_patterns([pin]) == [
            f"{prov.normalize_distribution(name)}*"
        ]

    def test_with_no_member_there_is_nothing_to_render(self, sandbox):
        pins = sandbox.script.member_pins(
            {
                name: prov.Provisioning(pypi_pins=tuple(planted))
                for name, planted in NO_MEMBERS.items()
            }
        )

        assert pins == []
        assert sandbox.script.requirement_lines(pins) == []
        assert sandbox.script.group_patterns(pins) == []
        assert sandbox.script.dependabot_body([]) == []

    def test_members_come_back_in_distribution_order_whatever_the_scanner_order(
        self, sandbox
    ):
        provisioning = {
            "z-scanner": prov.Provisioning(pypi_pins=(GUARDDOG,)),
            "a-scanner": prov.Provisioning(pypi_pins=(FERRET, HELD)),
        }

        pins = sandbox.script.member_pins(provisioning)

        assert [pin.distribution for pin in pins] == ["ferret-scan", "guarddog"]


# ---------------------------------------------------------------------------
# The Dependabot block, in the real file
# ---------------------------------------------------------------------------


def _root_uv_groups(text: str) -> dict:
    config = yaml.safe_load(text)
    (entry,) = [
        update
        for update in config["updates"]
        if update["package-ecosystem"] == "uv" and update["directory"] == "/"
    ]
    return entry["groups"]


def _outside_the_markers(text: str) -> tuple[str, str]:
    head, _, rest = text.partition(BEGIN)
    _, _, tail = rest.partition(END)
    return head, tail


class TestTheDependabotBlock:
    def test_the_real_file_carries_each_marker_once_before_the_engine_groups(self):
        text = REAL_DEPENDABOT.read_text(encoding="utf-8")

        assert text.count(BEGIN) == 1
        assert text.count(END) == 1
        assert (
            text.index("scanner-minor:")
            < text.index(BEGIN)
            < text.index(END)
            < text.index("engine-major-upgrade:")
        )

    def test_the_empty_form_is_no_group_at_all(self, sandbox):
        shutil.copyfile(REAL_DEPENDABOT, sandbox.dependabot)

        assert sandbox.run("--check") == 0

        groups = _root_uv_groups(sandbox.dependabot.read_text(encoding="utf-8"))
        assert "alpha-extra" not in groups

    def test_with_members_the_group_lands_in_the_root_entry_before_the_engine_groups(
        self, sandbox
    ):
        shutil.copyfile(REAL_DEPENDABOT, sandbox.dependabot)
        before_text = sandbox.dependabot.read_bytes().decode("utf-8")
        before = _root_uv_groups(before_text)
        sandbox.plant(ALL_PINS)

        assert sandbox.run("--fix") == 0

        after_text = sandbox.dependabot.read_bytes().decode("utf-8")
        groups = _root_uv_groups(after_text)
        names = list(groups)
        assert groups["alpha-extra"] == {"patterns": PATTERNS}
        assert names.index("alpha-extra") < names.index("engine-major-upgrade")
        assert names.index("alpha-extra") < names.index("engine-minor")
        assert {k: v for k, v in groups.items() if k != "alpha-extra"} == before
        assert _outside_the_markers(after_text) == _outside_the_markers(before_text)

    def test_the_group_takes_every_update_type_so_a_major_stays_out_of_the_engine_group(
        self, sandbox
    ):
        shutil.copyfile(REAL_DEPENDABOT, sandbox.dependabot)
        sandbox.plant(ALL_PINS)
        sandbox.run("--fix")

        group = _root_uv_groups(sandbox.dependabot.read_text(encoding="utf-8"))[
            "alpha-extra"
        ]

        assert "update-types" not in group

    def test_nothing_ignores_a_pin_the_register_declares(self):
        """``ignore`` also suppresses security updates, so it stays off for every
        distribution the register pins, members and exclusions alike."""
        config = yaml.safe_load(REAL_DEPENDABOT.read_text(encoding="utf-8"))
        ignored = {
            re.sub(r"[-_.]+", "-", str(rule["dependency-name"])).lower()
            for update in config["updates"]
            for rule in update.get("ignore", [])
        }
        pinned = {
            re.sub(r"[-_.]+", "-", pin.distribution).lower()
            for block in prov.PROVISIONING.values()
            for pin in block.pypi_pins
        }

        assert pinned, "the register pins nothing, so this check reads nothing"
        assert not ignored & pinned, sorted(ignored & pinned)


# ---------------------------------------------------------------------------
# What runs the script: the hook, the workflow, and the script's own promises
# ---------------------------------------------------------------------------


def _local_hooks() -> list[dict]:
    config = yaml.safe_load(PRE_COMMIT_CONFIG.read_text(encoding="utf-8"))
    return [
        hook
        for repo in config["repos"]
        if repo["repo"] == "local"
        for hook in repo["hooks"]
    ]


def _triggers(workflow: dict) -> dict:
    # PyYAML reads the bare key ``on`` as the boolean True.
    return workflow.get("on", workflow.get(True))


class TestTheWiring:
    def test_the_hook_runs_the_script_in_fix_mode_outside_the_project(self):
        (hook,) = [h for h in _local_hooks() if h["id"] == "sync-alpha-extra"]
        argv = shlex.split(hook["entry"])

        assert argv[:3] == ["uv", "run", "--no-project"], argv
        assert argv[argv.index("--python") + 1] == "3.13", argv
        assert argv[-2:] == ["scripts/sync_alpha_extra.py", "--fix"], argv
        assert hook["language"] == "system"
        assert hook["pass_filenames"] is False

    @pytest.mark.parametrize(
        ("path", "fires"),
        [
            ("pyproject.toml", True),
            ("automated_security_helper/base/plugin_provisioning.py", True),
            (".github/dependabot.yml", True),
            ("scripts/sync_alpha_extra.py", True),
            ("uv.lock", False),
            ("README.md", False),
            ("docs/pyproject.toml", False),
            ("scripts/sync_cdk_extra_fallback.py", False),
            ("automated_security_helper/base/plugin_manifest.py", False),
            ("tests/unit/test_alpha_extra_sync_gate.py", False),
        ],
    )
    def test_the_hook_fires_on_what_the_script_reads_and_writes(self, path, fires):
        (hook,) = [h for h in _local_hooks() if h["id"] == "sync-alpha-extra"]

        assert bool(re.search(hook["files"], path)) is fires

    def test_the_drift_workflow_checks_and_never_repairs(self):
        workflow = yaml.safe_load(DRIFT_WORKFLOW.read_text(encoding="utf-8"))
        steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
        runs = [
            shlex.split(step["run"])
            for step in steps
            if "sync_alpha_extra.py" in str(step.get("run", ""))
        ]

        assert workflow["name"] == "Alpha Extra Drift"
        assert runs == [
            [
                "uv",
                "run",
                "--no-project",
                "--python",
                "3.13",
                "python",
                "scripts/sync_alpha_extra.py",
                "--check",
            ]
        ]

    def test_the_drift_workflow_runs_on_the_queue_and_on_what_the_script_reads(self):
        workflow = yaml.safe_load(DRIFT_WORKFLOW.read_text(encoding="utf-8"))
        triggers = _triggers(workflow)
        wanted = {
            "pyproject.toml",
            "automated_security_helper/base/plugin_provisioning.py",
            ".github/dependabot.yml",
            "scripts/sync_alpha_extra.py",
            ".github/workflows/ash-alpha-extra-drift.yml",
        }

        assert set(triggers) == {
            "push",
            "pull_request",
            "merge_group",
            "workflow_dispatch",
        }
        assert set(triggers["push"]["paths"]) == wanted
        assert set(triggers["pull_request"]["paths"]) == wanted
        assert "tags" not in triggers["push"]
        # GitHub scopes ``paths`` to push and pull_request, so a filter here would
        # be inert at best, and would keep a required check from ever reporting.
        assert "paths" not in (triggers["merge_group"] or {})
        assert (triggers["merge_group"] or {}).get("types") == ["checks_requested"]

    def test_the_drift_workflow_reads_only_and_pins_every_action_by_sha(self):
        workflow = yaml.safe_load(DRIFT_WORKFLOW.read_text(encoding="utf-8"))
        (job,) = workflow["jobs"].values()
        uses = [step["uses"] for step in job["steps"] if "uses" in step]

        assert workflow["permissions"] == {"contents": "read"}
        assert job["permissions"] == {"contents": "read"}
        assert {use.split("@")[0] for use in uses} == {
            "actions/checkout",
            "astral-sh/setup-uv",
        }
        for use in uses:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use), use
        assert not [use for use in uses if use.startswith("actions/cache")]

    def test_the_auto_merge_waits_for_the_drift_workflow(self):
        """A dependabot bump of a member is what this gate is for; the auto-merge only
        approves once the workflows it listens for have all finished green."""
        workflow = yaml.safe_load(AUTO_MERGE_WORKFLOW.read_text(encoding="utf-8"))
        listened = _triggers(workflow)["workflow_run"]["workflows"]

        assert "Alpha Extra Drift" in listened

    def test_the_script_needs_only_the_standard_library(self):
        """What makes --no-project safe: outside the project nothing else is importable,
        and it promises no fallback for a missing import."""
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Try):
                for statement in node.body:
                    assert not any(
                        isinstance(inner, (ast.Import, ast.ImportFrom))
                        for inner in ast.walk(statement)
                    ), "an import guarded by try promises a fallback that nothing tests"
        outside = sorted(imported - set(sys.stdlib_module_names) - {"__future__"})

        assert imported, "parsed the wrong script"
        assert not outside, f"{SCRIPT_PATH.name} imports {outside}"
        assert "automated_security_helper" not in imported

    def test_the_commands_the_script_prints_keep_the_project_environment(self):
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        advice = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "uv run" in node.value
        ]

        assert advice, "the script no longer prints a uv command; update this test"
        assert not [text for text in advice if "--no-project" not in text], advice
