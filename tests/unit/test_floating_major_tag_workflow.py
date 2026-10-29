# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The floating tag a release moves must match that release's major version.

Why this file exists
--------------------
``.github/workflows/ash-tag-on-merge.yml`` fires on any pull request that closes
against ``main`` with ``merged == true`` and a title starting ``chore(release):``. It
holds ``contents: write``. Its last step force-moved a tag named by the literal string
``v3``::

    gh api "repos/${GITHUB_REPOSITORY}/git/refs/tags/v3" -X PATCH \\
      --field sha="$MAIN_SHA" --field force=true

There was no ``if:`` on the step and no reference to the version being released, so
*every* release moved ``v3`` -- including a 4.x one, which would have left ``v3``
pointing at a 4.0 commit.

That is worse than a mislabeled tag, because ``v3`` is a documented interface.
``README.md`` offers it as the deliberate alternative to a pinned release:

    **Floating tag `v3`**: We also maintain a `v3` floating tag that always points to
    the latest stable v3.x release. You can use `@v3` instead of `@v3.7.0` to stay up
    to date automatically.

and nine further places under ``docs/`` repeat the offer, one of them an install
command a user pastes (``docs/content/docs/troubleshooting.md``). So everyone who took
the documented advice would have received 4.0 on their next install, with no tag name
changing to hint at it. Nothing about the failure is visible from the release itself:
the step exits 0, having done exactly what it was told.

What this asserts
-----------------
One invariant: the floating tag the workflow touches is ``v<major>`` of the version
being released. ``3.8.0`` moves ``v3``; ``4.0.0`` moves ``v4`` and leaves ``v3`` alone.

It asserts that by *running the workflow's own shell*, extracted from the YAML, with
``gh`` and ``git`` replaced by stubs that record their argv. The script is not copied
into this file -- a copy would let the workflow and the test disagree while the test
stayed green, which is the same class of drift
``tests/unit/test_version_template_round_trip.py`` exists to catch between a doc and
its template.

What it deliberately does not check
-----------------------------------
It does not check that a release happens at all, that the job's ``if:`` gate is
correct, or that the preceding ``gh release create`` step works. Those need Actions
itself. A pass here means "given a version, the right floating tag is the one that
gets written", not "the release workflow is correct".

A ``4.0.0rc1`` release resolves to ``v4``. Whether a prerelease should move a floating
tag at all is a separate question from the one the defect posed, and the workflow still
lets one move it. What this file does assert about prereleases is the backward guard:
a prerelease is older than the stable release with the same core, so a re-run of the
``4.0.0rc1`` job after ``v4.0.0`` exists moves nothing; a prerelease is also older than
a later prerelease of its own core, so a re-run of the ``4.1.0rc1`` job after
``v4.1.0rc2`` moved the tag moves nothing either; and a prerelease that is the newest
of its core, with no stable release at or past that core, still moves the tag.

Failure mode of this harness itself
-----------------------------------
Three ways it could report success over nothing. All three are controlled for, and the
third was found the hard way.

The first is a locator that finds no step. The step is found by content -- the only
step in the job whose ``run`` touches ``git/refs/tags`` -- rather than by name, because
the name changed with this fix and a name-matched locator would have silently stopped
finding anything. ``test_exactly_one_step_writes_a_tag_ref`` fails if the count is not
one.

The second, and the one that makes the rest of the file mean something, is a harness
that cannot distinguish right from wrong. ``FROZEN_PREFIX_SCRIPT`` is the verbatim
pre-fix script, and ``test_the_harness_rejects_the_pre_fix_script`` requires the same
assertions to FAIL against it -- a ``4.0.0`` release must be caught moving ``v3``. That
control was run against the real file before the fix landed and did fail there; it is
frozen here so it keeps failing after the working tree stops containing the bug.

The third is an assertion satisfied by a harness that never ran, and it is not
hypothetical: the first version of this file shipped nine of them. On run 35877713374
every ``windows-latest`` leg resolved ``bash`` to the WSL launcher stub, so the step
never executed -- exit 1, no ``gh`` calls, a UTF-16 error about missing distributions --
and nine tests reported PASSED anyway. They were the ones phrased as absences:
``test_a_later_major_never_touches_v3`` asserted ``"v3" not in []``, and all six
``TestAMalformedVersionWritesNothing`` cases asserted "wrote no ref and exited
non-zero", which is precisely the signature of a harness that cannot start.

The lesson is narrow and worth stating, because the Windows skip below does not fix it
-- it only hides it on one platform. An assertion about what the step did NOT do needs a
companion assertion that the step ran at all. So the nine now require positive evidence
first: a ref actually written, or the step's own ``::error::`` annotation proving control
reached the version guard. Verified by pointing the harness at a fake ``bash`` that exits
1 like the stub: against the pre-fix assertions those nine pass, and against the current
ones all nine fail.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# Applied to the tests that execute the step's shell, and only to those -- the locator
# control in TestTheHarnessCanFail parses YAML and must keep running everywhere.
#
# The mechanism and both conditions are taken from
# tests/unit/test_ash_bash_entrypoint_build_failure.py rather than invented here, so
# there is one skip idiom for this reason instead of two that can drift. That file
# records why a which("bash") guard alone is not enough: on a GitHub Windows runner
# `bash` resolves to C:\Windows\System32\bash.exe, the WSL launcher stub, which is on
# PATH whether or not a distribution is installed. Measured on run 35877713374, this
# harness hit exactly that -- exit 1, no gh calls, and "Windows Subsystem for Linux has
# no installed distributions" printed as UTF-16 -- on all five windows-latest legs.
#
# Skipping is the honest answer rather than a portability fix. The step under test is a
# `run:` block in a job with `runs-on: ubuntu-latest`, whose shell is `bash -e {0}`. It
# will never execute on Windows. Git Bash does exist on the runner and the harness could
# be pointed at it, but that would exercise the step under a shell it never runs on: a
# pass would be evidence about a configuration that does not exist, and a failure would
# be a false alarm. It would also couple this file to the runner image's install layout
# for no added signal.
_REQUIRES_BASH = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; the step under test runs on ubuntu-latest",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the step under test is a bash script"
    ),
]


def _requires_bash(func):
    """Apply _REQUIRES_BASH to a single test, for classes that are not wholly skipped."""
    for mark in reversed(_REQUIRES_BASH):
        func = mark(func)
    return func


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-tag-on-merge.yml"
JOB = "tag-and-release"

# Any sha; the harness only needs to see it arrive at the API call unchanged.
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
FAKE_REPO = "awslabs/automated-security-helper"

# Records argv and answers the existence probe. The workflow distinguishes the probe
# from the mutation only by the absence of `-X`, so the stub does the same.
GH_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GH_CALL_LOG"
for arg in "$@"; do
  if [ "$arg" = "-X" ]; then exit 0; fi
done
[ "${STUB_TAG_EXISTS:-0}" = "1" ]
"""

# The step resolves the floating tag's target from the release tag: a fetch of that tag,
# then `git rev-list -n1` on it, which answers FAKE_SHA. `git rev-parse HEAD` answers a
# different sha, standing in for whatever main is at run time, so a step that reads HEAD
# is visible at the API call. Anything else is a change this harness has not been taught
# about, and reads better as a loud failure than as a stubbed success.
HEAD_SHA = "fedcba9876543210fedcba9876543210fedcba98"  # pragma: allowlist secret
#
# `rev-list` answers for a release tag only after the stub has recorded a fetch of exactly
# that tag, as the real repository would: the tag is created server-side after the
# checkout, so a local `rev-list` without the fetch finds nothing. Without this a step
# that dropped the fetch line would still read FAKE_SHA and pass. `ls-remote` lists the
# tags named in STUB_REMOTE_TAGS, one per word, standing in for the remote's tags --
# but only those that match the ref pattern it was given (the last argument), as the
# real command does. Without that filter a cell could pass on a listing a real
# `git ls-remote origin "refs/tags/v4.*"` can never return, such as a lone v3.9.9
# answered to a 4.x run.
GIT_STUB = f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GIT_CALL_LOG"
if [ "$1" = "rev-parse" ]; then echo "{HEAD_SHA}"; exit 0; fi
if [ "$1" = "fetch" ]; then exit 0; fi
if [ "$1" = "ls-remote" ]; then
  if [ "${{STUB_LS_REMOTE_FAILS:-0}}" = "1" ]; then
    echo "harness: ls-remote fails like an unreachable remote" >&2; exit 2
  fi
  pattern="${{@: -1}}"
  for t in ${{STUB_REMOTE_TAGS:-}}; do
    case "refs/tags/$t" in
      $pattern) printf '%s\\trefs/tags/%s\\n' "{FAKE_SHA}" "$t";;
    esac
  done
  exit 0
fi
if [ "$1" = "rev-list" ] && [ "$2" = "-n1" ]; then
  case "$3" in refs/tags/v*)
    tag="${{3#refs/tags/}}"
    if grep -qxF "fetch --no-tags origin refs/tags/$tag:refs/tags/$tag" "$GIT_CALL_LOG"; then
      echo "{FAKE_SHA}"; exit 0
    fi
    echo "harness: rev-list of $3 before any fetch of it" >&2; exit 1;;
  esac
fi
echo "harness: unexpected git invocation: $*" >&2
exit 1
"""

# The step compares versions with `uv run python`, which runs the interpreter of the
# project environment that `uv sync` built. This stub stands in for it: `uv run python
# <args>` runs the interpreter that runs these tests, which has `packaging`. Any other
# uv invocation fails loudly, so a change to the step's uv use is not stubbed away.
UV_STUB = f"""#!/usr/bin/env bash
if [ "$1" = "run" ] && [ "$2" = "python" ]; then
  shift 2
  exec "{sys.executable}" "$@"
fi
echo "harness: unexpected uv invocation: $*" >&2
exit 1
"""

# The pre-fix step, verbatim from ash-tag-on-merge.yml at 1fdf17e2b0. Frozen on
# purpose: see "failure mode of this harness itself".
FROZEN_PREFIX_SCRIPT = """MAIN_SHA=$(git rev-parse HEAD)

if gh api "repos/${GITHUB_REPOSITORY}/git/refs/tags/v3" >/dev/null 2>&1; then
  gh api "repos/${GITHUB_REPOSITORY}/git/refs/tags/v3" \\
    -X PATCH \\
    --field sha="$MAIN_SHA" \\
    --field force=true
  echo "Moved v3 tag to $MAIN_SHA (v${VERSION})"
else
  gh api "repos/${GITHUB_REPOSITORY}/git/refs" \\
    -X POST \\
    --field ref="refs/tags/v3" \\
    --field sha="$MAIN_SHA"
  echo "Created v3 tag at $MAIN_SHA (v${VERSION})"
fi
"""

_PATCH_REF = re.compile(r"git/refs/tags/(?P<ref>[^\s\"']+)")
_POST_REF = re.compile(r"--field\s+ref=(?:\"|')?refs/tags/(?P<ref>[^\s\"']+)")


def _tag_writing_steps() -> list[dict]:
    """Every step in the release job whose shell writes a git ref."""
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = doc["jobs"][JOB]["steps"]
    return [
        step
        for step in steps
        if isinstance(step, dict) and "git/refs" in (step.get("run") or "")
    ]


def _floating_tag_script() -> str:
    steps = _tag_writing_steps()
    assert len(steps) == 1, (
        f"expected exactly one ref-writing step in job {JOB}, found {len(steps)}. "
        "The locator below resolves the step by content; see TestTheHarnessCanFail."
    )
    return steps[0]["run"]


class Result:
    """What the step did: its exit status, and the gh calls it made."""

    def __init__(
        self,
        proc: subprocess.CompletedProcess,
        calls: list[str],
        git_calls: list[str] | None = None,
    ):
        self.proc = proc
        self.calls = calls
        self.git_calls = git_calls or []

    @property
    def ok(self) -> bool:
        return self.proc.returncode == 0

    @property
    def mutations(self) -> list[tuple[str, str]]:
        """``[(verb, ref)]`` for each call that wrote a ref."""
        out = []
        for call in self.calls:
            if "-X PATCH" in call:
                match = _PATCH_REF.search(call)
                out.append(("PATCH", match.group("ref") if match else "?"))
            elif "-X POST" in call:
                match = _POST_REF.search(call)
                out.append(("POST", match.group("ref") if match else "?"))
        return out

    @property
    def refs_written(self) -> list[str]:
        return [ref for _verb, ref in self.mutations]

    def describe(self) -> str:
        return (
            f"exit={self.proc.returncode}\n"
            f"gh calls:\n  " + ("\n  ".join(self.calls) or "(none)") + "\n"
            "git calls:\n  " + ("\n  ".join(self.git_calls) or "(none)") + "\n"
            f"stdout: {self.proc.stdout.strip()}\n"
            f"stderr: {self.proc.stderr.strip()}"
        )


def _run(
    script: str,
    version: str,
    tmp_path: Path,
    tag_exists: bool = True,
    remote_tags: str | None = None,
    ls_remote_fails: bool = False,
) -> Result:
    """Run the step's shell with gh and git stubbed, and report what it touched.

    ``remote_tags`` is the space-separated list of tags the stubbed remote reports. Left
    as None it lists the release tag of ``version`` alone, as the real remote does once
    the release step has created that tag. ``ls_remote_fails`` makes ``git ls-remote``
    exit non-zero, as it does when the remote cannot be reached.
    """
    if remote_tags is None:
        remote_tags = f"v{version}"
    assert "${{" not in script, (
        "the step's run block contains an Actions expression, which this harness does "
        "not expand -- it would be running a template rather than the real script"
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "gh-calls.log"
    log.write_text("", encoding="utf-8")
    git_log = tmp_path / "git-calls.log"
    git_log.write_text("", encoding="utf-8")

    for name, body in (("gh", GH_STUB), ("git", GIT_STUB), ("uv", UV_STUB)):
        path = bin_dir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    script_path = tmp_path / "step.sh"
    script_path.write_text(script, encoding="utf-8")

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "VERSION": version,
        "GITHUB_REPOSITORY": FAKE_REPO,
        "GH_TOKEN": "stub-token",
        "GH_CALL_LOG": str(log),
        "STUB_TAG_EXISTS": "1" if tag_exists else "0",
        "GIT_CALL_LOG": str(git_log),
        "STUB_REMOTE_TAGS": remote_tags,
        "STUB_LS_REMOTE_FAILS": "1" if ls_remote_fails else "0",
    }
    # `bash -e {0}` is the default shell Actions gives a `run:` block on ubuntu-latest,
    # and this workflow does not override it.
    proc = subprocess.run(
        ["bash", "-e", str(script_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    calls = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    git_calls = [
        line for line in git_log.read_text(encoding="utf-8").splitlines() if line
    ]
    return Result(proc, calls, git_calls)


@pytest.mark.integration
class TestTheFloatingTagMatchesTheReleasedMajor:
    """The invariant, one case per release shape so a failure names the version."""

    pytestmark = _REQUIRES_BASH

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("3.7.1", "v3"),
            ("3.8.0", "v3"),
            ("4.0.0", "v4"),
            ("4.1.2", "v4"),
            ("10.0.0", "v10"),
            ("4.0.0rc1", "v4"),
            ("3.0.0-beta-20250528", "v3"),
        ],
    )
    def test_the_released_major_is_the_tag_that_moves(
        self, version: str, expected: str, tmp_path: Path
    ):
        result = _run(_floating_tag_script(), version, tmp_path, tag_exists=True)

        assert result.ok, (
            f"the step failed on a valid version {version}\n{result.describe()}"
        )
        assert result.refs_written == [expected], (
            f"releasing {version} must move {expected} and nothing else, but the step "
            f"wrote {result.refs_written}\n{result.describe()}"
        )

    @pytest.mark.parametrize("version", ["4.0.0", "4.1.2", "10.0.0"])
    def test_a_later_major_never_touches_v3(self, version: str, tmp_path: Path):
        """The defect, stated as its own case.

        Kept separate from the parametrized test above because this is the assertion
        whose failure was going to reach users: `v3` is the ref the README tells people
        to install from, and a 4.x release moving it is silent at every layer.
        """
        result = _run(_floating_tag_script(), version, tmp_path, tag_exists=True)

        # Liveness first. `v3 not in []` is true, so without this the assertion below
        # passes on a harness that never ran -- which is not hypothetical: it is what
        # these three cases did on all five windows-latest legs of run 35877713374,
        # reporting PASSED while bash was the WSL stub and no gh call was made.
        assert result.refs_written, (
            "the step wrote no ref at all, so the assertion below would hold "
            f"vacuously\n{result.describe()}"
        )
        assert "v3" not in result.refs_written, (
            f"releasing {version} wrote v3. README.md line 112 promises v3 always "
            "points to the latest stable v3.x release, so this hands 4.x to every user "
            f"who followed that advice.\n{result.describe()}"
        )

    def test_the_sha_reaches_the_api_call(self, tmp_path: Path):
        """Otherwise the right ref could be moved to the wrong commit."""
        result = _run(_floating_tag_script(), "3.8.0", tmp_path, tag_exists=True)

        assert any(FAKE_SHA in call for call in result.calls), (
            f"no gh call carried the release tag's commit\n{result.describe()}"
        )


@pytest.mark.integration
class TestTheAbsentTagPath:
    """A floating major tag that does not exist yet is created, not skipped.

    The pre-fix step already had this branch for `v3`, so dropping it would be a
    regression rather than a fix. Generalized, it means the first 4.x release creates
    `v4` -- and the alternative, a step that finds no tag and exits 0 having done
    nothing, is the silent-success shape this repository's other gates exist to reject.
    """

    pytestmark = _REQUIRES_BASH

    def test_an_absent_tag_is_created_at_the_released_major(self, tmp_path: Path):
        result = _run(_floating_tag_script(), "4.0.0", tmp_path, tag_exists=False)

        assert result.ok, f"the create path failed\n{result.describe()}"
        assert result.mutations == [("POST", "v4")], (
            "a 4.0.0 release with no v4 tag must create v4, but the step made "
            f"{result.mutations}\n{result.describe()}"
        )

    def test_the_existing_tag_path_patches_rather_than_creates(self, tmp_path: Path):
        result = _run(_floating_tag_script(), "3.8.0", tmp_path, tag_exists=True)

        assert result.mutations == [("PATCH", "v3")], (
            f"an existing v3 must be moved in place, not recreated\n{result.describe()}"
        )


@pytest.mark.integration
class TestAMalformedVersionWritesNothing:
    """A version the step cannot parse must fail loudly and touch no ref.

    `VERSION` comes from `uv run cz version --project`. If that ever returns something
    unexpected, the pre-fix step did not care -- it wrote the literal `v3` regardless.
    The generalized step derives a ref name from `VERSION`, so an unparsable value must
    stop it rather than produce a ref named from garbage.

    Failing is deliberate rather than skipping. By this point in the job the GitHub
    release already exists, so a skip would leave a published release whose floating
    tag silently never moved, and the run would still be green.

    Note what makes this class hard to assert honestly: "wrote no ref and exited
    non-zero" is also the signature of a harness that could not start bash at all. All
    six cases reported PASSED on every windows-latest leg of run 35877713374 while the
    harness was in exactly that state. So each case additionally requires the step's own
    `::error::` annotation, which only appears if control reached the version guard.
    """

    pytestmark = _REQUIRES_BASH

    @pytest.mark.parametrize(
        "version",
        [
            "",
            "v3.7.1",  # a leading v; VERSION is bare, and `vv3` is not a tag
            "3.7",  # not three components
            "not-a-version",
            "3.7.1 extra",
            "latest",
        ],
    )
    def test_no_ref_is_written_and_the_step_fails(self, version: str, tmp_path: Path):
        result = _run(_floating_tag_script(), version, tmp_path, tag_exists=True)

        # Liveness first: proves the step ran and rejected this version itself, rather
        # than dying before it got there. Without it the two assertions below are
        # satisfied by any harness that fails to launch.
        assert "::error::" in result.proc.stdout, (
            f"VERSION={version!r} produced no ::error:: annotation, so the step did not "
            "reach its own version guard -- the assertions below would hold for a "
            f"harness that never started\n{result.describe()}"
        )
        assert result.refs_written == [], (
            f"VERSION={version!r} is not a version this step can act on, but it wrote "
            f"{result.refs_written}\n{result.describe()}"
        )
        assert not result.ok, (
            f"VERSION={version!r} wrote no ref but still exited 0, so a release would "
            f"appear to have updated its floating tag\n{result.describe()}"
        )


_VERSION_GUARD = re.compile(r'"\$VERSION"\s+=~\s+(\S+)\s+\]\]')

# The X.Y.Z capture the version guard must open with, verbatim from the step.
_CORE_PART = r"^(([0-9]+)\.[0-9]+\.[0-9]+)"


def _version_guard_suffix() -> str:
    """The suffix subpattern of the step's version guard, as written in the YAML."""
    script = _floating_tag_script()
    match = _VERSION_GUARD.search(script)
    assert match, "the step no longer guards $VERSION with a =~ regex"
    pattern = match.group(1)
    assert pattern.startswith(_CORE_PART) and pattern.endswith("$"), pattern
    return pattern[len(_CORE_PART) : -1]


@pytest.mark.unit
class TestTheVersionGuardSplitsACoreUnambiguously:
    """CORE must be the whole X.Y.Z on every regex engine, so the suffix class is
    asserted on the pattern itself.

    ``[[ =~ ]]`` submatch assignment is engine-dependent. POSIX longest-submatch
    rules (glibc, measured on this platform) read ``3.8.10`` as CORE ``3.8.10``
    even when the suffix class admits digits, so no cell that runs the step's shell
    can tell a digit-admitting suffix class from the current one here. On an engine
    that assigns submatches differently, a digit-admitting class lets ``3.8.10``
    split as CORE ``3.8.1`` with suffix ``0``: a stable release treated as a
    prerelease, whose floating tag silently does not move on a green run. The
    behavioral twin of that shape is the ``3.8.10`` row in
    ``test_the_newest_release_still_moves_the_floating_tag``, which can only fire
    on such an engine; this class fires everywhere.

    The subpattern is extracted from the workflow rather than copied, so the step
    and the assertion cannot drift apart. Both patterns here are plain EREs whose
    meaning is the same under Python's ``re``.
    """

    def test_a_suffix_cannot_start_with_a_digit(self):
        suffix = _version_guard_suffix()

        assert re.fullmatch(suffix, "0") is None, (
            f"the suffix class {suffix!r} admits a digit-led suffix, so an engine "
            "that does not assign longest submatches may read VERSION 3.8.10 as "
            "CORE 3.8.1 with suffix '0'"
        )

    def test_prerelease_suffixes_and_the_empty_suffix_are_admitted(self):
        suffix = _version_guard_suffix()

        for accepted in ("", "rc1", "-beta-20250528", ".dev1", "+build5"):
            assert re.fullmatch(suffix, accepted) is not None, (
                f"the suffix class {suffix!r} no longer admits {accepted!r}, a "
                "release shape this repository has published or the bare stable "
                "shape itself"
            )


class TestTheHarnessCanFail:
    """Positive controls. Every assertion above is satisfiable by a broken harness.

    Deliberately NOT skipped as a class. The locator control below needs no bash and so
    runs on every platform; only the three that execute the shell carry the skip. A
    control that is skipped wherever it might have fired is worse than no control.
    """

    @pytest.mark.unit
    def test_exactly_one_step_writes_a_tag_ref(self):
        """The locator must find the step. Finding none makes everything above vacuous."""
        steps = _tag_writing_steps()

        assert len(steps) == 1, (
            f"found {len(steps)} ref-writing step(s) in job {JOB}, expected 1. At zero, "
            "every test in this file errors rather than passing -- but a locator matched "
            "on the step NAME would instead have found nothing quietly, which is why "
            "the match is on content."
        )
        assert "refs/tags" in steps[0]["run"]

    @pytest.mark.integration
    @_requires_bash
    def test_the_stub_records_calls_at_all(self, tmp_path: Path):
        """If the gh stub logged nothing, `refs_written == []` would pass everywhere."""
        result = _run(_floating_tag_script(), "3.8.0", tmp_path, tag_exists=True)

        assert result.calls, (
            "the gh stub recorded no calls, so the malformed-version assertions above "
            f"would hold no matter what the step did\n{result.describe()}"
        )

    @pytest.mark.integration
    @_requires_bash
    @pytest.mark.parametrize(
        ("version", "wrong_ref"),
        [("4.0.0", "v3"), ("4.1.2", "v3"), ("10.0.0", "v3")],
    )
    def test_the_harness_rejects_the_pre_fix_script(
        self, version: str, wrong_ref: str, tmp_path: Path
    ):
        """The control that makes this file evidence rather than decoration.

        Run the SAME harness against the pre-fix script and require it to be caught.
        The tests above pass only while the workflow is correct, so the moment they go
        green they stop demonstrating that they could ever have gone red.
        """
        result = _run(FROZEN_PREFIX_SCRIPT, version, tmp_path, tag_exists=True)

        assert result.refs_written == [wrong_ref], (
            "the pre-fix script is expected to move v3 for every version -- that is the "
            f"defect. Releasing {version} against it wrote {result.refs_written}. If "
            "this no longer reproduces, the harness is not measuring what it claims."
        )

    @pytest.mark.integration
    @_requires_bash
    def test_the_pre_fix_script_is_indifferent_to_a_malformed_version(
        self, tmp_path: Path
    ):
        """And it wrote v3 even with no version at all, which is the same root cause."""
        result = _run(FROZEN_PREFIX_SCRIPT, "", tmp_path, tag_exists=True)

        assert result.refs_written == ["v3"], (
            "the pre-fix script ignored VERSION entirely; if it did not, the "
            "malformed-version tests above are guarding against a different mechanism "
            f"than the one that shipped.\n{result.describe()}"
        )


@pytest.mark.integration
class TestTheFloatingTagFollowsTheReleaseTag:
    """The floating tag points at the release tag's commit, never at the checkout's HEAD.

    HEAD is main at run time. A merge whose release already exists, a re-run of an old
    run, or a pull request merged after the release would otherwise move the floating
    tag onto code that was never released.
    """

    pytestmark = _REQUIRES_BASH

    @pytest.mark.parametrize("tag_exists", [True, False])
    def test_the_floating_tag_is_moved_to_the_release_tag_commit(
        self, tag_exists: bool, tmp_path: Path
    ):
        result = _run(_floating_tag_script(), "3.8.0", tmp_path, tag_exists=tag_exists)

        assert result.ok, f"the step failed on a valid version\n{result.describe()}"
        assert any(FAKE_SHA in call for call in result.calls), (
            "no gh call carried the release tag's commit, so the floating tag was "
            f"pointed somewhere else\n{result.describe()}"
        )
        assert not any(HEAD_SHA in call for call in result.calls), (
            "a gh call carried the checkout's HEAD, which is main at run time and not "
            f"necessarily the release commit\n{result.describe()}"
        )


@pytest.mark.integration
class TestTheReleaseTagIsFetchedBeforeItIsResolved:
    """The fetch line is what makes the release tag visible locally.

    The tag is created server-side after the checkout, so `git rev-list` on it finds
    nothing until it is fetched. GIT_STUB answers `rev-list` only after it recorded that
    exact fetch, so deleting the fetch line turns these cells red.
    """

    pytestmark = _REQUIRES_BASH

    def test_the_step_fetches_the_release_tag(self, tmp_path: Path):
        result = _run(_floating_tag_script(), "3.8.0", tmp_path, tag_exists=True)

        assert result.ok, f"the step failed on a valid version\n{result.describe()}"
        assert "fetch --no-tags origin refs/tags/v3.8.0:refs/tags/v3.8.0" in (
            result.git_calls
        ), f"no fetch of the release tag was recorded\n{result.git_calls}"

    def test_the_stub_refuses_a_rev_list_without_the_fetch(self, tmp_path: Path):
        """Control: the stub is what gives the cell above its teeth."""
        result = _run(
            "git rev-list -n1 refs/tags/v3.8.0\n", "3.8.0", tmp_path, tag_exists=True
        )

        assert not result.ok, (
            "the git stub answered rev-list for a tag that was never fetched, so a "
            f"step without the fetch line would pass\n{result.describe()}"
        )
        assert "before any fetch" in result.proc.stderr


@pytest.mark.integration
class TestTheFloatingTagNeverMovesBackward:
    """A re-run of an old release run, or two runs finishing out of order, must not
    point the floating tag at an older release than one that already exists."""

    pytestmark = _REQUIRES_BASH

    @pytest.mark.parametrize(
        ("version", "remote_tags"),
        [
            ("3.7.1", "v3.7.1 v3.8.0"),
            ("3.8.0", "v3.8.0 v3.9.1"),
            ("3.9.0", "v3.9.0 v3.10.0"),  # numeric, not lexical, order
            ("3.0.0-beta-20250528", "v3.0.0-beta-20250528 v3.7.1 v3.8.0"),
            # A prerelease is older than the stable release with the same core, so a
            # re-run of its job after the stable release shipped moves nothing.
            ("4.0.0rc1", "v4.0.0rc1 v4.0.0"),
            ("3.0.0-beta-20250528", "v3.0.0-beta-20250528 v3.0.0"),
            ("3.8.0.dev1", "v3.8.0.dev1 v3.8.0"),
            # One prerelease against another: rc2 of the same core moved the tag, so
            # a re-run of the rc1 job moves nothing. The stable list cannot decide
            # this one -- neither rc is in it.
            ("4.1.0rc1", "v4.0.0 v4.1.0rc1 v4.1.0rc2"),
            ("3.0.0-beta-20250528", "v3.0.0-beta-20250528 v3.0.0-beta-20250601"),
            # PEP 440 order, which sort -V does not follow: a .devN of a prerelease
            # is older than the prerelease, and a post-release is newer than its
            # base, so the base is older than the post-release.
            ("4.1.0rc1.dev1", "v4.1.0rc1.dev1 v4.1.0rc1"),
            ("3.8.0", "v3.8.0 v3.8.0.post1"),
            ("3.8.0", "v3.8.0 v3.8.0+build5"),
        ],
    )
    def test_an_older_release_does_not_move_the_floating_tag(
        self, version: str, remote_tags: str, tmp_path: Path
    ):
        result = _run(
            _floating_tag_script(),
            version,
            tmp_path,
            tag_exists=True,
            remote_tags=remote_tags,
        )

        # Liveness: the step compared against the remote's tags, so an empty result
        # below is the guard's doing and not a step that never started.
        assert any(call.startswith("ls-remote") for call in result.git_calls), (
            f"the step never listed the remote's release tags\n{result.describe()}"
        )
        assert result.ok, (
            f"skipping a backward move is not a failure\n{result.describe()}"
        )
        assert result.refs_written == [], (
            f"releasing {version} moved {result.refs_written} although a newer "
            f"release exists ({remote_tags})\n{result.describe()}"
        )
        assert "::notice::" in result.proc.stdout, result.describe()

    @pytest.mark.parametrize(
        ("version", "remote_tags", "expected"),
        [
            ("3.8.0", "v3.7.1 v3.8.0", [("PATCH", "v3")]),  # newest is itself
            ("3.10.0", "v3.9.0 v3.10.0", [("PATCH", "v3")]),
            # A two-digit patch is one stable version, not a prerelease of the
            # one-digit patch: an engine that read CORE as 3.8.1 with suffix 0
            # would skip this move silently on a green run.
            ("3.8.10", "v3.8.9 v3.8.10", [("PATCH", "v3")]),
            ("3.8.10rc1", "v3.8.10rc1 v3.8.9", [("PATCH", "v3")]),
            ("4.0.0", "v3.9.9 v4.0.0", [("PATCH", "v4")]),  # another major is no rival
            # A prerelease still moves the tag while no stable release of its major
            # has the same or a newer core.
            # No stable tag listed at all, only the run's own prerelease tag --
            # which must be listed, like every run's own tag.
            ("4.0.0rc1", "v4.0.0rc1", [("PATCH", "v4")]),
            ("4.0.0rc1", "v4.0.0rc1 v3.9.9", [("PATCH", "v4")]),
            ("4.1.0rc1", "v4.1.0rc1 v4.0.0", [("PATCH", "v4")]),
            # The newest prerelease of a core is not a backward move over its own
            # earlier prereleases.
            ("4.1.0rc2", "v4.0.0 v4.1.0rc1 v4.1.0rc2", [("PATCH", "v4")]),
            # PEP 440: a post-release and a local version are newer than their base,
            # and rc1 is newer than rc1.dev1, so each is the newest release and moves
            # the tag.
            ("3.8.0.post1", "v3.8.0 v3.8.0.post1", [("PATCH", "v3")]),
            ("3.8.0+build5", "v3.8.0 v3.8.0+build5", [("PATCH", "v3")]),
            ("4.1.0rc1", "v4.1.0rc1 v4.1.0rc1.dev1", [("PATCH", "v4")]),
        ],
    )
    def test_the_newest_release_still_moves_the_floating_tag(
        self,
        version: str,
        remote_tags: str,
        expected: list[tuple[str, str]],
        tmp_path: Path,
    ):
        result = _run(
            _floating_tag_script(),
            version,
            tmp_path,
            tag_exists=True,
            remote_tags=remote_tags,
        )

        assert result.ok, f"the step failed on a valid version\n{result.describe()}"
        assert result.mutations == expected, (
            f"releasing {version} with remote tags [{remote_tags}] should write "
            f"{expected}\n{result.describe()}"
        )


@pytest.mark.integration
class TestTheRemoteTagListMustBeUsable:
    """The guard compares against the remote's tags, so a list it cannot trust stops the
    step. Without this an unreachable remote reads as "no newer release" and the floating
    tag moves unchecked, with nothing in the run to say the comparison never happened."""

    pytestmark = _REQUIRES_BASH

    # Every version now fails on the empty list a hidden failure would leave behind
    # too (its own tag must be in it), so what these rows add is the exit status
    # itself: the stub fails like an unreachable remote, and `bash -e` must stop the
    # step at the assignment rather than go on to read an empty list.
    @pytest.mark.parametrize("version", ["3.8.0", "4.0.0rc1"])
    def test_a_failing_ls_remote_fails_the_step(self, version: str, tmp_path: Path):
        result = _run(
            _floating_tag_script(),
            version,
            tmp_path,
            tag_exists=True,
            ls_remote_fails=True,
        )

        # Liveness: the step reached the remote read, so the absence below is the
        # guard's doing and not a step that never started.
        assert any(call.startswith("ls-remote") for call in result.git_calls), (
            f"the step never listed the remote's release tags\n{result.describe()}"
        )
        assert not result.ok, (
            f"a failing ls-remote was hidden and the step went on\n{result.describe()}"
        )
        assert result.refs_written == [], result.describe()

    @pytest.mark.parametrize(
        ("version", "remote_tags"),
        [
            ("3.8.0", ""),  # the list is empty
            ("3.8.0", "v3.7.1"),  # it lacks this run's own tag
            ("3.8.0", "v3.8.0.dev1"),  # a prerelease tag is not the stable one
        ],
    )
    def test_a_stable_version_missing_from_the_list_fails_the_step(
        self, version: str, remote_tags: str, tmp_path: Path
    ):
        result = _run(
            _floating_tag_script(),
            version,
            tmp_path,
            tag_exists=True,
            remote_tags=remote_tags,
        )

        assert any(call.startswith("ls-remote") for call in result.git_calls), (
            f"the step never listed the remote's release tags\n{result.describe()}"
        )
        assert "::error::" in result.proc.stdout, result.describe()
        assert not result.ok, (
            f"a tag list without v{version} must not be compared against\n"
            f"{result.describe()}"
        )
        assert result.refs_written == [], result.describe()
        self._the_error_names_no_cause_it_cannot_know(result)

    # The step cannot tell an incomplete listing from a release that has no tag:
    # the release step exits 0 once `gh release view` finds a release, and a draft
    # release, or one whose tag was deleted, has none. So the error must name those
    # possibilities and must not direct the operator to move the floating tag by
    # hand -- with no release tag on the remote there is nothing to move it to.
    @staticmethod
    def _the_error_names_no_cause_it_cannot_know(result: Result) -> None:
        assert "draft" in result.proc.stdout, (
            "the error must say what a missing tag can mean (a draft release, or a "
            f"deleted tag)\n{result.describe()}"
        )
        assert "by hand" not in result.proc.stdout, (
            "the error must not direct the operator to move the floating tag by "
            f"hand: there is no release tag to move it to\n{result.describe()}"
        )
        assert "release step created it" not in result.proc.stdout, (
            "the error must not claim this run created the tag; the release step "
            f"exits 0 for a release that has no tag at all\n{result.describe()}"
        )

    def test_a_prerelease_missing_from_the_remote_list_fails_the_step(
        self, tmp_path: Path
    ):
        """A prerelease run's own tag was just created too, so a listing without it
        is as incomplete as a stable run's, and comparing against it is refused the
        same way. The check reads the unfiltered listing: the stable filter would
        drop the prerelease tag before the comparison."""
        result = _run(
            _floating_tag_script(),
            "4.0.0rc1",
            tmp_path,
            tag_exists=True,
            remote_tags="v4.0.0",
        )

        assert any(call.startswith("ls-remote") for call in result.git_calls), (
            f"the step never listed the remote's release tags\n{result.describe()}"
        )
        assert "::error::" in result.proc.stdout, result.describe()
        assert not result.ok, (
            "a tag list without v4.0.0rc1 must not be compared against\n"
            f"{result.describe()}"
        )
        assert result.refs_written == [], result.describe()
        self._the_error_names_no_cause_it_cannot_know(result)

    def test_a_prerelease_listed_on_the_remote_proceeds(self, tmp_path: Path):
        result = _run(
            _floating_tag_script(),
            "4.0.0rc1",
            tmp_path,
            tag_exists=True,
            remote_tags="v4.0.0rc1",
        )

        assert result.ok, result.describe()
        assert result.refs_written == ["v4"], result.describe()
        assert "::error::" not in result.proc.stdout, result.describe()

    def test_the_stub_honors_the_ls_remote_pattern(self, tmp_path: Path):
        """Control: a tag outside the asked-for pattern must not be listed.

        The step asks for `refs/tags/v${MAJOR}.*`. A stub that answers with every
        tag in STUB_REMOTE_TAGS lets cells pass on listings a real remote can never
        return -- a lone v3.9.9 answered to a 4.x run was exactly how the old
        prerelease-absent cell went green.
        """
        result = _run(
            'git ls-remote --tags --refs origin "refs/tags/v4.*"\n',
            "4.0.0",
            tmp_path,
            tag_exists=True,
            remote_tags="v3.9.9 v4.0.0",
        )

        assert result.ok, result.describe()
        assert "refs/tags/v4.0.0" in result.proc.stdout, (
            f"the stub dropped a tag inside the pattern\n{result.describe()}"
        )
        assert "v3.9.9" not in result.proc.stdout, (
            "the git stub listed a tag outside the requested pattern, so cells "
            "could pass on remote listings a real `git ls-remote` can never "
            f"return\n{result.describe()}"
        )


@pytest.mark.unit
class TestReleaseRunsAreSerialized:
    """Two release runs finishing together must not interleave their tag writes."""

    def test_the_job_declares_a_queueing_concurrency_group(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        concurrency = doc["jobs"][JOB].get("concurrency")

        assert isinstance(concurrency, dict), (
            f"job {JOB} has no concurrency block, so release runs can overlap"
        )
        group = concurrency.get("group")
        # The literal, not truthiness: a group built from the pull request number or the
        # version would still be truthy and would turn serialization off.
        assert group == "ash-release-tag", (
            f"the concurrency group is {group!r}; it must be the one literal shared by "
            "every release run, with no ${{ }} expression in it"
        )
        assert "${{" not in group
        assert concurrency.get("cancel-in-progress") is False, (
            "cancel-in-progress must be false: cancelling a running release would "
            "stop it between creating the tag and moving the floating tag"
        )


RELEASE_GH_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GH_CALL_LOG"
# `gh release view` finds no release, so the step goes on to create one.
if [ "$1" = "release" ] && [ "$2" = "view" ]; then exit 1; fi
exit 0
"""


def _release_step_script() -> str:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = [
        step
        for step in doc["jobs"][JOB]["steps"]
        if isinstance(step, dict) and "gh release create" in (step.get("run") or "")
    ]
    assert len(steps) == 1, f"expected one release-creating step, found {len(steps)}"
    return steps[0]["run"]


# Answers the step's read of the release tag on the remote. STUB_TAG_SHA is the commit the
# tag points at; with STUB_TAG_OBJECT set the tag is annotated, so the remote lists the
# tag object first and the commit it peels to on the `^{}` line, as `git ls-remote` does.
# Unset STUB_TAG_SHA means the tag is absent.
RELEASE_GIT_STUB = """#!/usr/bin/env bash
if [ "$1" = "ls-remote" ]; then
  if [ -n "${STUB_TAG_SHA:-}" ]; then
    if [ -n "${STUB_TAG_OBJECT:-}" ]; then
      printf '%s\\trefs/tags/v3.8.0\\n' "$STUB_TAG_OBJECT"
      printf '%s\\trefs/tags/v3.8.0^{}\\n' "$STUB_TAG_SHA"
    else
      printf '%s\\trefs/tags/v3.8.0\\n' "$STUB_TAG_SHA"
    fi
  fi
  exit 0
fi
echo "harness: unexpected git invocation: $*" >&2
exit 1
"""

OTHER_SHA = "89abcdef0123456789abcdef0123456789abcdef"  # pragma: allowlist secret
TAG_OBJECT_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # pragma: allowlist secret


def _run_release_step(
    script: str,
    tmp_path: Path,
    tag_sha: str | None = None,
    tag_object: str | None = None,
    changelog: str = "",
    curated: str | None = None,
) -> Result:
    """Run the release step's shell with gh and git stubbed. ``tag_sha`` is the commit
    the release tag already points at on the remote, or None when the tag does not
    exist. ``changelog`` is the CHANGELOG.md the checkout holds (empty by default), and
    ``curated`` the content of ``.github/release-notes/v3.8.0.md`` when that file
    should exist."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "gh-calls.log"
    log.write_text("", encoding="utf-8")
    for name, body in (("gh", RELEASE_GH_STUB), ("git", RELEASE_GIT_STUB)):
        stub = bin_dir / name
        stub.write_text(body, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    (work / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    if curated is not None:
        notes_dir = work / ".github" / "release-notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "v3.8.0.md").write_text(curated, encoding="utf-8")
    script_path = tmp_path / "release-step.sh"
    script_path.write_text(script, encoding="utf-8")

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "VERSION": "3.8.0",
        "MERGE_SHA": FAKE_SHA,
        "GITHUB_REPOSITORY": FAKE_REPO,
        "GH_TOKEN": "stub-token",
        "GH_CALL_LOG": str(log),
        "RUNNER_TEMP": str(tmp_path),
        "STUB_TAG_SHA": tag_sha or "",
        "STUB_TAG_OBJECT": tag_object or "",
    }
    proc = subprocess.run(
        ["bash", "-e", str(script_path)],
        env=env,
        cwd=work,
        capture_output=True,
        text=True,
        timeout=60,
    )
    calls = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    return Result(proc, calls)


class TestTheReleaseTargetsTheMergeCommit:
    """`--target main` is resolved when the release is created, so a pull request merged
    in between puts the release tag past the release pull request's merge commit."""

    pytestmark = _REQUIRES_BASH

    @pytest.mark.integration
    def test_release_create_targets_the_merge_commit(self, tmp_path: Path):
        result = _run_release_step(_release_step_script(), tmp_path)

        created = [c for c in result.calls if c.startswith("release create")]
        assert created, f"the step never ran `gh release create`\n{result.describe()}"
        assert f"--target {FAKE_SHA}" in created[0], (
            "the release must be created at the pull request's merge commit\n"
            f"{result.describe()}"
        )
        assert "--target main" not in created[0], result.describe()

    @pytest.mark.unit
    def test_the_version_is_read_from_the_merge_commit(self):
        """The checkout the version and changelog are read from is the merge commit.

        Reading them from the tip of main lets the run for an earlier release pull
        request see a later release's version and create that release at the older
        merge commit.
        """
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = doc["jobs"][JOB]["steps"]
        checkout = next(
            s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")
        )
        read_version = next(s for s in steps if s.get("id") == "version")

        assert steps.index(checkout) < steps.index(read_version)
        assert (
            checkout["with"]["ref"]
            == "${{ github.event.pull_request.merge_commit_sha }}"
        )

    @pytest.mark.unit
    def test_the_merge_commit_comes_from_the_event_payload(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        step = next(
            s
            for s in doc["jobs"][JOB]["steps"]
            if isinstance(s, dict) and "gh release create" in (s.get("run") or "")
        )
        assert (
            step["env"]["MERGE_SHA"]
            == "${{ github.event.pull_request.merge_commit_sha }}"
        )


@pytest.mark.integration
class TestAnExistingReleaseTagMustSitAtTheMergeCommit:
    """`gh release create --target` is ignored when the tag already exists, so a tag at
    another commit would publish the release there. The step reads the tag on the remote
    first and refuses unless it is absent or already at the merge commit."""

    pytestmark = _REQUIRES_BASH

    def _created(self, result: Result) -> list[str]:
        return [c for c in result.calls if c.startswith("release create")]

    def test_a_tag_at_another_commit_fails_the_step(self, tmp_path: Path):
        result = _run_release_step(_release_step_script(), tmp_path, tag_sha=OTHER_SHA)

        # Liveness: the step's own annotation, not a harness that failed to start.
        assert "::error::" in result.proc.stdout, result.describe()
        assert OTHER_SHA in result.proc.stdout and FAKE_SHA in result.proc.stdout, (
            f"the error must name both commits\n{result.describe()}"
        )
        assert not result.ok, (
            f"a release tag at another commit must fail the step\n{result.describe()}"
        )
        assert self._created(result) == [], (
            f"the release was created anyway\n{result.describe()}"
        )

    def test_a_tag_at_the_merge_commit_proceeds(self, tmp_path: Path):
        result = _run_release_step(_release_step_script(), tmp_path, tag_sha=FAKE_SHA)

        assert result.ok, result.describe()
        assert len(self._created(result)) == 1, result.describe()

    def test_an_annotated_tag_is_judged_by_the_commit_it_peels_to(self, tmp_path: Path):
        result = _run_release_step(
            _release_step_script(),
            tmp_path,
            tag_sha=FAKE_SHA,
            tag_object=TAG_OBJECT_SHA,
        )

        assert result.ok, result.describe()
        assert len(self._created(result)) == 1, result.describe()

    def test_an_absent_tag_proceeds(self, tmp_path: Path):
        result = _run_release_step(_release_step_script(), tmp_path, tag_sha=None)

        assert result.ok, result.describe()
        assert len(self._created(result)) == 1, result.describe()


@pytest.mark.integration
class TestTheCuratedNotesFailureNamesTheRecovery:
    """The failure's advice must be an action that can change the outcome.

    The checkout is pinned to the pull request's merge commit, and a re-run replays
    the same event payload, so it reads the same CHANGELOG.md and fails identically.
    The one recovery that changes the input is a new chore(release): pull request
    whose regenerated entry includes the curated file, and the error must direct
    there rather than advise the re-run that cannot work.
    """

    pytestmark = _REQUIRES_BASH

    CURATED = "### Breaking behavior changes\n\n- a curated note\n"

    def test_the_error_directs_to_a_new_release_pull_request(self, tmp_path: Path):
        result = _run_release_step(
            _release_step_script(),
            tmp_path,
            changelog="## v3.8.0 (2026-10-02)\n\n### Feat\n\n- something\n",
            curated=self.CURATED,
        )

        # Liveness: the step's own annotation, not a harness that failed to start.
        assert "::error::" in result.proc.stdout, result.describe()
        assert not result.ok, result.describe()
        assert "chore(release)" in result.proc.stdout, (
            "the curated-notes error must direct to a new chore(release): pull "
            f"request, the only recovery that changes the input\n{result.describe()}"
        )
        assert "then rerun this job" not in result.proc.stdout, (
            "a re-run replays the same merge commit and reads the same unfixed "
            f"CHANGELOG.md, so advising one misdirects the operator\n"
            f"{result.describe()}"
        )

    def test_an_entry_that_carries_the_notes_still_publishes(self, tmp_path: Path):
        result = _run_release_step(
            _release_step_script(),
            tmp_path,
            changelog=(
                "## v3.8.0 (2026-10-02)\n\n"
                + self.CURATED
                + "\n### Feat\n\n- something\n"
            ),
            curated=self.CURATED,
        )

        assert result.ok, result.describe()
        created = [c for c in result.calls if c.startswith("release create")]
        assert len(created) == 1, result.describe()


@pytest.mark.unit
class TestEveryLocalWorkflowCallIsCallable:
    """A job that ``uses`` a workflow of this repository makes GitHub read that
    workflow when it loads the caller. If the callee declares no ``workflow_call``
    trigger, the caller fails to load and none of its jobs run, so the release is
    never created."""

    @staticmethod
    def _on(doc: dict) -> dict:
        # PyYAML reads the bare key ``on`` as the boolean True.
        triggers = doc.get("on", doc.get(True))
        return triggers if isinstance(triggers, dict) else {}

    def test_every_local_callee_declares_workflow_call(self):
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        callees = [
            job["uses"]
            for job in doc["jobs"].values()
            if str(job.get("uses", "")).startswith("./")
        ]
        for uses in callees:
            callee = yaml.safe_load((REPO_ROOT / uses[2:]).read_text(encoding="utf-8"))
            assert "workflow_call" in self._on(callee), (
                f"{uses} is called from {WORKFLOW.name} but declares no "
                "workflow_call trigger"
            )

    def test_the_check_can_fail(self):
        """Controls for the helper: a callee with only push and dispatch triggers
        reads as missing, and one that declares the trigger reads as present, under
        both spellings of the ``on`` key."""
        without = yaml.safe_load("on:\n  push: {}\n  workflow_dispatch: {}\n")
        with_call = yaml.safe_load("on:\n  workflow_call:\n    inputs: {}\n")
        assert "workflow_call" not in self._on(without)
        assert "workflow_call" in self._on(with_call)


# The v* tags of a clone of this repository when the comparison was written:
# 63 tags, among them a bare v3, a bare v3.0.0-beta and eleven v3.0.0-beta-YYYYMMDD
# forms. The comparison must parse every one of them, because a tag it refuses fails
# the step.
REAL_TAGS = (
    "v1.3.2 v1.3.3 v1.4.0 v1.4.1 v1.5.0 v1.5.1 v2.0.0 v2.0.1 v3 v3.0.0 v3.0.0-beta "
    "v3.0.0-beta-20250528 v3.0.0-beta-20250602 v3.0.0-beta-20250603 "
    "v3.0.0-beta-20250604 v3.0.0-beta-20250610 v3.0.0-beta-20250614 "
    "v3.0.0-beta-20250708 v3.0.0-beta-20250709 v3.0.0-beta-20250714 "
    "v3.0.0-beta-20250718 v3.0.0-beta-20250722 v3.0.1 v3.0.2 v3.0.3 v3.1.0 v3.1.1 "
    "v3.1.10 v3.1.11 v3.1.12 v3.1.13 v3.1.2 v3.1.3 v3.1.4 v3.1.5 v3.1.6 v3.1.7 "
    "v3.1.8 v3.1.9 v3.2.0 v3.2.1 v3.2.2 v3.2.3 v3.2.4 v3.2.5 v3.2.6 v3.2.7 v3.3.0 "
    "v3.4.0 v3.5.0 v3.5.1 v3.5.2 v3.5.3 v3.5.4 v3.5.5 v3.5.6 v3.5.7 v3.5.8 v3.5.9 "
    "v3.6.0 v3.6.1 v3.7.0 v3.7.1"
)


class TestTheComparisonReadsTheRepositorysRealTags:
    pytestmark = _REQUIRES_BASH

    @pytest.mark.unit
    def test_the_real_tag_list_is_63_tags(self):
        assert len(REAL_TAGS.split()) == 63

    @pytest.mark.integration
    def test_a_new_release_moves_the_tag_over_the_real_history(self, tmp_path: Path):
        result = _run(
            _floating_tag_script(),
            "3.8.0",
            tmp_path,
            remote_tags=f"{REAL_TAGS} v3.8.0",
        )
        assert result.ok, result.describe()
        assert result.mutations == [("PATCH", "v3")], result.describe()

    @pytest.mark.integration
    def test_an_old_beta_rerun_over_the_real_history_moves_nothing(
        self, tmp_path: Path
    ):
        result = _run(
            _floating_tag_script(),
            "3.0.0-beta-20250528",
            tmp_path,
            remote_tags=REAL_TAGS,
        )
        assert result.ok, result.describe()
        assert result.refs_written == [], result.describe()
        assert "::notice::" in result.proc.stdout, result.describe()
