# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-nag's native build on Windows depends on where a step sits, not just on it existing.

Why this file exists
--------------------
``cfn_nag_scanner.py`` refuses to declare an install command on Windows unless
``RI_DEVKIT`` is set. Nothing in the ``windows-latest`` image sets it, so for as
long as the scan action skipped ``ruby/setup-ruby`` on Windows, the gate declined
every time and cfn-nag was reported ``NO INSTALL PATH`` there. That is a real
measurement, from ``scan (python-local, windows-latest)`` on 756d15f9::

    WARNING  cfn-nag cannot be installed here: no Ruby DevKit (RI_DEVKIT is unset)
    No install path on this platform: cfn-nag, detect-secrets, npm-audit

The step that fixes it is ``ruby/setup-ruby``, whose default ``windows-toolchain``
unpacks the ucrt64 gcc bundle and runs ``ridk enable``; ``ridk enable`` is what
exports ``RI_DEVKIT`` (rubyinstaller2,
``lib/ruby_installer/build/msys2_installation.rb``).

What was tried and rejected
---------------------------
Running that step where the Unix one runs, near the top of the action. setup-ruby
prepends its MSYS2 directories to ``PATH``, and the runner resolves ``shell: bash``
through ``PATH`` (actions/runner, ``src/Runner.Worker/Handlers/ScriptHandler.cs``
calls ``WhichUtil.Which("bash", ..., prependPath)``), so MSYS2's ``bash.EXE`` became
the shell for "Validate ASH config files", which then exited 2 in 176ms.

Installing a libyaml package was also considered and is not the problem. psych
3.3.4 vendors libyaml under ``ext/psych/yaml`` and its ``extconf.rb`` falls back to
that copy, which is what happened on 18e5cba9 -- "checking for yaml.h... yes",
"creating Makefile". The build died afterwards, in make::

    make: *** No rule to make target
    '/C/hostedtoolcache/windows/Ruby/3.3.12/x64/include/ruby-3.3.0/ruby.h',
    needed by 'api.o'.  Stop.

an MSYS-translated path handed to a make from a different tree. The requirement is
one coherent MSYS2 environment, not an extra package.

So the ordering below is the fix, and ordering is exactly what a later edit can
undo without any test noticing. Hence these assertions.

Constraints and limitations
---------------------------
This asserts the wiring, not the build. Whether psych actually compiles can only
be settled by a Windows run; what proves it there is cfn-nag moving off the "No
install path on this platform" line and reporting a real scanner state. These
tests cannot see that, and passing them is not evidence the gem built.

The window between the setup-ruby step and the precedence restore must contain no
``shell: bash`` step, because any such step would get MSYS2 bash. That invariant is
asserted directly rather than left to review.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"

SETUP_RUBY = "ruby/setup-ruby@"
WINDOWS_TOOLCHAIN_STEP = "Set up Ruby and MSYS2 toolchain for cfn-nag (Windows)"
RESTORE_STEP = "Restore Git Bash precedence after the Ruby toolchain (Windows)"
CONFIG_VALIDATE_STEP = "Validate ASH config files"
WINDOWS_SCAN_STEP = "Validate ASH using Python Local (Windows)"


@pytest.fixture(scope="module")
def steps() -> list:
    """The action's step list.

    Parsing is itself an assertion: GitHub rejects a malformed composite action by
    failing every job that uses it.
    """
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]


def _index(steps: list, name: str) -> int:
    for i, step in enumerate(steps):
        if step.get("name") == name:
            return i
    raise AssertionError(f"no step named {name!r} in {ACTION}")


def test_windows_gets_a_ruby_toolchain_step(steps):
    step = steps[_index(steps, WINDOWS_TOOLCHAIN_STEP)]
    assert SETUP_RUBY in step.get("uses", ""), (
        "the Windows toolchain step no longer uses ruby/setup-ruby, so nothing "
        "runs `ridk enable` and RI_DEVKIT stays unset -- cfn-nag will silently go "
        "back to reporting NO INSTALL PATH on windows-latest."
    )
    assert "runner.os == 'Windows'" in step["if"]
    # windows-toolchain must stay at its default: 'none' adds Ruby to PATH and
    # installs no build tools, which is the one setting that would leave the gem
    # unbuildable while this step still appears to be doing its job.
    assert step.get("with", {}).get("windows-toolchain", "default") != "none"


def test_the_toolchain_step_is_pinned_to_a_full_sha(steps):
    """A floating tag turns the repo's action-pin gate red."""
    ref = steps[_index(steps, WINDOWS_TOOLCHAIN_STEP)]["uses"].split("@", 1)[1]
    assert len(ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in ref), (
        f"{ref!r} is not a 40-character commit SHA."
    )


def test_the_toolchain_lands_after_config_validation(steps):
    """The documented breakage: MSYS2 bash shadowing Git Bash for that step."""
    assert _index(steps, CONFIG_VALIDATE_STEP) < _index(
        steps, WINDOWS_TOOLCHAIN_STEP
    ), (
        f"{WINDOWS_TOOLCHAIN_STEP!r} moved ahead of {CONFIG_VALIDATE_STEP!r}. "
        "setup-ruby prepends MSYS2 to PATH, so that step would run under MSYS2 "
        "bash, which is how it exited 2 in 176ms before."
    )


def test_the_toolchain_lands_before_the_windows_install(steps):
    assert _index(steps, WINDOWS_TOOLCHAIN_STEP) < _index(steps, WINDOWS_SCAN_STEP), (
        f"{WINDOWS_SCAN_STEP!r} runs `ash dependencies install`, so the toolchain "
        "has to be in place before it or the gate declines."
    )


def test_git_bash_precedence_is_restored_after_the_windows_scan(steps):
    restore = _index(steps, RESTORE_STEP)
    assert _index(steps, WINDOWS_SCAN_STEP) < restore, (
        "precedence is restored before the Windows scan, so psych would build "
        "with Git's sh against another tree's make -- the 18e5cba9 failure."
    )
    step = steps[restore]
    assert "GITHUB_PATH" in step["run"], (
        "the restore step no longer writes GITHUB_PATH, so MSYS2 bash stays first "
        "on PATH for every later `shell: bash` step."
    )


def _runs_on_python_local(step: dict) -> bool:
    """Whether this step can execute on the ``python-local`` leg.

    Only ``inputs.method`` is interpreted, because that is the input the window is
    reasoned about. A step pinned to some other method cannot run alongside the
    Windows toolchain step and is therefore not in scope; anything else is treated
    as in scope, so an unrecognized condition fails safe rather than being excused.
    """
    condition = str(step.get("if", ""))
    for method in ("python-container", "bash", "powershell"):
        if f"inputs.method == '{method}'" in condition:
            return False
    return True


def test_no_bash_step_sits_inside_the_msys2_window(steps):
    """Any bash step between the two would resolve to MSYS2 bash.

    Scoped to steps that can actually run on this leg: the two ``python-container``
    bash steps sit inside the window textually but are excluded by their own ``if``.
    """
    lo = _index(steps, WINDOWS_TOOLCHAIN_STEP)
    hi = _index(steps, RESTORE_STEP)
    window = steps[lo + 1 : hi]
    # Control: the window must not be empty, or this test would pass by measuring
    # nothing -- which is what it would do if either anchor step were renamed and
    # the two ended up adjacent.
    assert window, (
        f"nothing sits between {WINDOWS_TOOLCHAIN_STEP!r} and {RESTORE_STEP!r}, so "
        "the Windows install step is no longer inside the toolchain window."
    )
    offenders = [
        s.get("name")
        for s in window
        if s.get("shell") == "bash" and _runs_on_python_local(s)
    ]
    assert not offenders, (
        f"these steps run between {WINDOWS_TOOLCHAIN_STEP!r} and {RESTORE_STEP!r} "
        f"with `shell: bash` on the python-local leg, so they would get MSYS2 "
        f"bash: {offenders}"
    )


def test_the_unix_setup_ruby_step_still_excludes_windows(steps):
    """Two steps, one per platform; the Unix one must not also fire on Windows.

    If it did, it would run at its original early position on Windows too and
    reintroduce exactly the shadowing this arrangement exists to avoid.
    """
    unix = [
        s
        for s in steps
        if SETUP_RUBY in s.get("uses", "") and s.get("name") != WINDOWS_TOOLCHAIN_STEP
    ]
    assert len(unix) == 1, f"expected one non-Windows setup-ruby step, got {len(unix)}"
    assert "runner.os != 'Windows'" in unix[0]["if"]
