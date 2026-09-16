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

The second name MSYS2 shadows, and why bash was only half the problem
--------------------------------------------------------------------
The arrangement above was reasoned about entirely in terms of ``bash``, on the
stated grounds that everything inside the window is ``shell: pwsh`` and therefore
"does not care which bash is first". True of bash, and it missed that MSYS2's
``usr/bin`` also contains an executable named ``ash`` -- the Almquist shell -- and
that the two pwsh steps inside the window invoke ``ash`` six times between them.
Git for Windows ships the same shell, being MSYS2-derived, so promoting Git Bash
is not a fix either.

Measured on ``scan (python-local, windows-latest)`` at 1c492f28, and identically
on the ``- Community Plugins`` cell, which is itself the evidence that the cause
is environmental rather than config-specific::

    .../msys64/usr/bin/ash: 0: Illegal option --          <- ash --version
    .../msys64/usr/bin/ash: 0: Illegal option --          <- ash --help
    .../msys64/usr/bin/ash: 0: cannot open dependencies   <- ash dependencies install
    .../msys64/usr/bin/ash: 0: cannot open config         <- ash config get
    .../msys64/usr/bin/ash: 0: Illegal option --          <- ash --mode local ...

Five invocations, five errors, in order, and the step ended in 543ms having run no
scanner. The reason it read as something else entirely: nothing wrote
``.ash/ash_output``, so the artifact upload found no files and "Verify scan
completed" was SKIPPED rather than failed. The visible symptom was a missing
artifact four steps downstream, not a shadowed binary.

``setup-ash`` puts ASH's console scripts on ``PATH`` via ``GITHUB_PATH`` before
this action runs, and setup-ruby adds MSYS2 later; since the runner reverses the
accumulated list, later wins. So the fix is to re-add ASH's scripts directory
after setup-ruby, which promotes it above MSYS2 without evicting MSYS2 -- sh, make
and gcc keep coming from the one coherent tree psych needs. Promoting Git Bash
there instead would break the gem build for the 18e5cba9 reason, which is what
``test_git_bash_precedence_is_restored_after_the_windows_scan`` already forbids.
"""

import re
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
PROMOTE_STEP = "Put ASH's entry point ahead of the MSYS2 toolchain (Windows)"

# A command invocation of `ash`, anchored at the start of a line so that a path
# argument such as `--config .ash/.ash_community_plugins.yaml` is not counted, and
# allowing pwsh's call operator so `& ash report` is.
ASH_INVOCATION = re.compile(r"^\s*(?:&\s*)?ash\s", re.MULTILINE)


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


def _runs_on_windows_python_local(step: dict) -> bool:
    """Whether this step can execute on the ``windows-latest`` python-local leg.

    Narrower than ``_runs_on_python_local``: it also drops steps pinned to
    non-Windows runners. Anything whose condition is not recognized is treated as
    in scope, so a new condition fails safe rather than being excused.
    """
    if not _runs_on_python_local(step):
        return False
    return "runner.os != 'Windows'" not in str(step.get("if", ""))


def test_ash_entry_point_is_promoted_inside_the_msys2_window(steps):
    """The promote step has to sit after setup-ruby and before anything reads ``ash``.

    Before setup-ruby it would be pointless -- MSYS2 is not on ``PATH`` yet, so
    there is nothing to outrank, and setup-ruby would then add MSYS2 after it and
    win. After the scan step it is too late, which is the state that produced the
    five-error log in this module's docstring.
    """
    promote = _index(steps, PROMOTE_STEP)
    assert _index(steps, WINDOWS_TOOLCHAIN_STEP) < promote, (
        f"{PROMOTE_STEP!r} runs before setup-ruby, so it promotes ASH's scripts "
        "directory and setup-ruby then puts MSYS2 ahead of it again. GITHUB_PATH "
        "entries are reversed before joining, so the last one added wins."
    )
    assert promote < _index(steps, WINDOWS_SCAN_STEP), (
        f"{PROMOTE_STEP!r} runs after {WINDOWS_SCAN_STEP!r}, so every `ash` in "
        "that step resolves to MSYS2's Almquist shell and the scan does nothing."
    )


def test_every_windows_ash_invocation_follows_the_promotion(steps):
    """The general invariant, rather than naming the two steps that exist today.

    A new pwsh step that calls ``ash`` and is added above the promotion would
    reintroduce this silently, and naming today's two steps would not catch it.
    """
    promote = _index(steps, PROMOTE_STEP)
    offenders = [
        step.get("name")
        for i, step in enumerate(steps)
        if i < promote
        and i > _index(steps, WINDOWS_TOOLCHAIN_STEP)
        and _runs_on_windows_python_local(step)
        and ASH_INVOCATION.search(str(step.get("run", "")))
    ]
    assert not offenders, (
        f"these steps invoke `ash` between {WINDOWS_TOOLCHAIN_STEP!r} and "
        f"{PROMOTE_STEP!r}, where MSYS2's Almquist shell outranks it: {offenders}"
    )
    # Control: the steps this is protecting must actually be found by the same
    # detector, or the test above would pass by matching nothing at all. Both
    # in-window pwsh steps call `ash`, so the count is two.
    callers = [
        step.get("name")
        for step in steps[promote + 1 : _index(steps, RESTORE_STEP)]
        if _runs_on_windows_python_local(step)
        and ASH_INVOCATION.search(str(step.get("run", "")))
    ]
    assert len(callers) == 2, (
        "expected the two in-window pwsh steps that call `ash` to be detected, "
        f"found {callers}. If this is zero the detector stopped matching and the "
        "assertion above is vacuous."
    )


def test_the_promotion_does_not_hand_precedence_to_git_bash(steps):
    """Promoting Git Bash here is the plausible wrong fix, and it is two bugs.

    It does not work -- Git's ``bin`` ships no ``ash``, so MSYS2 still wins, and
    Git's ``usr/bin`` ships the same Almquist shell, so winning would only change
    which wrong ``ash`` ran. And it breaks the gem build, because
    ``ash dependencies install`` inside the next step compiles psych's C extension
    and needs MSYS2's sh rather than Git's. That is the 18e5cba9 failure.
    """
    body = steps[_index(steps, PROMOTE_STEP)]["run"]
    assert "Git" not in body, (
        f"{PROMOTE_STEP!r} mentions Git, so it is likely promoting Git Bash. That "
        "leaves MSYS2's `ash` first and puts Git's sh ahead of MSYS2's for the "
        "psych compile in the next step."
    )
    assert "GITHUB_PATH" in body, (
        f"{PROMOTE_STEP!r} no longer writes GITHUB_PATH, so it changes no PATH "
        "for the steps that follow it and the promotion silently does nothing."
    )


def test_the_promotion_fails_loudly_when_it_cannot_find_the_entry_point(steps):
    """A promotion that finds nothing must not pass quietly.

    Its whole job is to put one directory first. If no candidate contains
    ``ash.exe`` then the assumption behind the step is wrong, and continuing would
    hand the next step the same shadowed shell with nothing said about why.
    """
    body = steps[_index(steps, PROMOTE_STEP)]["run"]
    assert "::error::" in body and "exit 1" in body, (
        f"{PROMOTE_STEP!r} does not fail with an ::error:: annotation when it "
        "finds no ash.exe, so a wrong assumption about where pip installs console "
        "scripts would surface as the same five confusing shell errors."
    )


def test_the_windows_scan_asserts_that_ash_is_ash(steps):
    """The guard that names the cause, since the failure otherwise misdirects.

    Untreated, this step fails as a run of "Illegal option --" and "cannot open"
    errors, and the artifact it never writes is what a reader notices four steps
    later. One resolved path in the log is the difference between that and a named
    cause.
    """
    body = steps[_index(steps, WINDOWS_SCAN_STEP)]["run"]
    assert "Get-Command ash" in body, (
        f"{WINDOWS_SCAN_STEP!r} no longer resolves `ash` before using it, so a "
        "shadowed binary is diagnosed from five downstream shell errors again."
    )
    assert "::error::" in body and "exit 1" in body, (
        "the guard warns instead of failing, so a shadowed `ash` would still "
        "produce an empty scan -- and an empty scan skips `Verify scan completed` "
        "rather than failing it."
    )
    guard, _, remainder = body.partition("Get-Command ash")
    assert not ASH_INVOCATION.search(guard), (
        "an `ash` invocation precedes the guard, so the step would already have "
        "run a shell before checking what `ash` is."
    )
    assert ASH_INVOCATION.search(remainder), (
        "no `ash` invocation follows the guard, so the guard protects nothing and "
        "this test would pass against a step that stopped scanning."
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
