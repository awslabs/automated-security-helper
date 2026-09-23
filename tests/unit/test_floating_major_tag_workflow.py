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

It also does not assert prerelease behavior beyond major extraction. A ``4.0.0rc1``
release resolves to ``v4``, which is the part this file cares about; whether a
prerelease should move a floating tag at all is a separate question from the one the
defect posed, and the workflow's behavior there is unchanged -- a ``3.8.0rc1`` release
moves ``v3`` exactly as it did before.

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
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"
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

# `git rev-parse HEAD` is the only git the step runs. Anything else is a change this
# harness has not been taught about, and reads better as a loud failure than as a
# stubbed success.
GIT_STUB = f"""#!/usr/bin/env bash
if [ "$1" = "rev-parse" ]; then echo "{FAKE_SHA}"; exit 0; fi
echo "harness: unexpected git invocation: $*" >&2
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

    def __init__(self, proc: subprocess.CompletedProcess, calls: list[str]):
        self.proc = proc
        self.calls = calls

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
            f"stdout: {self.proc.stdout.strip()}\n"
            f"stderr: {self.proc.stderr.strip()}"
        )


def _run(script: str, version: str, tmp_path: Path, tag_exists: bool = True) -> Result:
    """Run the step's shell with gh and git stubbed, and report what it touched."""
    assert "${{" not in script, (
        "the step's run block contains an Actions expression, which this harness does "
        "not expand -- it would be running a template rather than the real script"
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "gh-calls.log"
    log.write_text("", encoding="utf-8")

    for name, body in (("gh", GH_STUB), ("git", GIT_STUB)):
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
    return Result(proc, calls)


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
            f"no gh call carried the sha from `git rev-parse HEAD`\n{result.describe()}"
        )


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


class TestTheHarnessCanFail:
    """Positive controls. Every assertion above is satisfiable by a broken harness.

    Deliberately NOT skipped as a class. The locator control below needs no bash and so
    runs on every platform; only the three that execute the shell carry the skip. A
    control that is skipped wherever it might have fired is worse than no control.
    """

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

    @_requires_bash
    def test_the_stub_records_calls_at_all(self, tmp_path: Path):
        """If the gh stub logged nothing, `refs_written == []` would pass everywhere."""
        result = _run(_floating_tag_script(), "3.8.0", tmp_path, tag_exists=True)

        assert result.calls, (
            "the gh stub recorded no calls, so the malformed-version assertions above "
            f"would hold no matter what the step did\n{result.describe()}"
        )

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
