# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every entrypoint that builds the ASH image must honour ASH_BASE_IMAGE_OVERRIDE.

Why this file exists
--------------------
``.github/actions/prepull-base-image`` pulls the Dockerfile's base image once per job so the
container legs do not each hit ECR Public's anonymous quotas at ``FROM ${BASE_IMAGE}``. When
ECR Public refuses, it sources the image from Docker Hub instead -- and then has to tell the
build to ask Docker Hub for it.

Its first attempt did not tell the build anything. It tagged the Docker Hub image locally under
the ECR reference and announced that "the build resolves it from the local store without
touching public.ecr.aws". A build then died at the Dockerfile's first instruction::

    >>> FROM ${BASE_IMAGE} AS uv-reqs
    error: failed to solve: public.ecr.aws/docker/library/python:3.12-slim-bookworm:
    failed to resolve source metadata for ...: 429 Too Many Requests
    toomanyrequests: Data limit exceeded

Whether a local tag is visible to ``FROM`` comes down to one guard in BuildKit's
``sourceresolver/imageresolver.go`` (v0.31.2). The registry is tried first, and the local-store
recovery after a failure is gated on ``rm != resolver.ResolveModeDefault || is.ImageStore ==
nil``. Nothing here passes ``--pull``, so the mode is always the default -- which leaves
``ImageStore`` as the only variable, and that is a property of the worker.
``worker/runc/runc.go`` sets ``ImageStore: nil, // explicitly``; the containerd worker binds it
to a containerd namespace.

So the builders that ignore the tag are the ones on a store-less worker: ``docker buildx build``
on a ``docker-container`` driver, which is a separate container with its own OCI worker and
cannot be configured otherwise from here, and any buildkitd left on its default worker. That
second case was nerdctl's, and it was fixable -- ``scripts/setup-nerdctl-linux.sh`` now writes
the same ``buildkitd.toml`` finch ships. Plain ``docker build``, podman, finch and the
now-configured nerdctl all read the tag.

The docker-container driver is the one that matters most here, because every docker cell runs
it: ``run-scan-test`` sets up ``docker/setup-buildx-action`` (driver defaults to
``docker-container``) and exports ``ACTIONS_RUNTIME_TOKEN``, which switches ASH's build to
``docker buildx build --load``. That is why the override, not the tag, is the mechanism this
file guards.

So the fallback exports ``ASH_BASE_IMAGE_OVERRIDE=<repo>@<pinned digest>`` and each build
entrypoint passes it through as ``--build-arg BASE_IMAGE=``. Changing what ``FROM`` *asks for*
is uniform across every runtime and every builder driver, because no runtime has a say in what
a build-arg names.

What this asserts, and why it is a separate file
-----------------------------------------------
There are three independent build call sites, each with its own argv construction, and all
three are reachable from CI after the pre-pull runs:

* ``run_ash_container.py::_build_image`` -- ``ash build-image`` and ``ash scan --mode
  container``; every ``validate-container`` leg and the ``python-container`` scan legs;
* ``./ash`` -- the ``bash`` scan legs;
* ``utils/ash_helpers.ps1`` -- the ``powershell`` scan legs.

A fix applied to one of them would leave the other two broken in exactly the way that is hard
to see: the pre-pull step still exits 0, the log still says the base image is in place, and the
build fails later at ``FROM`` blaming the registry. This file is the completeness guard for
that -- one place that fails when an entrypoint loses the read, or when a fourth one is added
without it. The per-argv details for ``_build_image`` live with its other argv tests, in
``tests/unit/interactions/test_run_ash_container_helpers_coverage.py``.

Constraints and limitations
---------------------------
The PowerShell entrypoint is asserted as text rather than executed. There is no ``pwsh`` on
the machine this was written on, and ``tests/unit/test_cfn_nag_windows_toolchain.py`` already
establishes text assertions as this repository's answer to that. What that buys is real but
bounded: it catches the read being deleted or reordered, and it cannot catch PowerShell-level
breakage in the line itself. Only a ``powershell`` leg can.

Nothing here measures whether a runtime ignores a local tag. That is a property of BuildKit,
not of this repository; asserting it here would be measuring BuildKit. It was measured out of
band instead, with a Dockerfile whose ``FROM`` names a reference on a ``.invalid`` host that is
present in the local image store. Four runs, one instrument:

* plain ``docker build``, tag present -> PASSES. The instrument can see a local tag.
* plain ``docker build``, tag absent -> FAILS with a DNS error. So the pass above came from
  the tag, and the probe is not vacuous.
* ``docker buildx build`` on a ``docker-container`` builder, tag present -> FAILS at ``FROM``
  with the same DNS error. Same store, same tag, different builder: that is the defect.
* the same buildx build with ``--build-arg BASE_IMAGE=`` naming a reference that resolves ->
  PASSES. That is the fix, run through ``_build_image`` itself.

nerdctl, finch and podman have no binary on the machine that was measured on, so their rows
rest on the CI log and on their sources; only CI closes that.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"
PS1 = REPO_ROOT / "utils" / "ash_helpers.ps1"
PY_BUILD = (
    REPO_ROOT / "automated_security_helper" / "interactions" / "run_ash_container.py"
)
PREPULL = REPO_ROOT / ".github" / "actions" / "prepull-base-image" / "action.yml"

OVERRIDE = "ASH_BASE_IMAGE_OVERRIDE"

# A digest-pinned reference, because that is the shape the pre-pull exports: it verified the
# digest before falling back, so it hands the build content rather than a name.
PINNED_REF = "docker.io/library/python@sha256:" + "b" * 64

_REQUIRES_BASH = [
    # Windows users invoke ASH through utils/ash_helpers.ps1, not ./ash. It also cannot work:
    # on a GitHub Windows runner shutil.which("bash") finds C:\Windows\System32\bash.exe, the
    # WSL launcher stub, which is on PATH whether or not a distribution is installed -- so the
    # which() guard passes and the assertions then fail on its output rather than on ASH.
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; ./ash is the POSIX entrypoint",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the entrypoint under test is bash"
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason="repository ash entrypoint not present (installed-package layout)",
    ),
]

# Records the build's argv and then fails, so the run step is never reached and the test costs
# one process rather than a container. Exiting 0 here would send ./ash on to `run`, which would
# need mounts and a scan.
RECORDING_RUNNER = """#!/bin/bash
if [ "$1" = "build" ]; then
  printf '%s\\n' "$*" > "$ARGV_LOG"
  echo 'fake runner: refusing to build, argv recorded' >&2
  exit 1
fi
echo "FAKE-RUNNER-INVOKED-WITH: $*"
exit 0
"""


@pytest.fixture
def recording_runner(tmp_path):
    runner = tmp_path / "fake-oci-runner"
    runner.write_text(RECORDING_RUNNER, encoding="utf-8")
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return runner


def _build_argv(recording_runner, tmp_path, override: str | None) -> str:
    """Run ``./ash`` far enough to capture the build argv, and return it as one line."""
    source_dir = tmp_path / "src"
    source_dir.mkdir(exist_ok=True)
    argv_log = tmp_path / "argv"

    env = {
        **os.environ,
        "OCI_RUNNER": str(recording_runner),
        "ARGV_LOG": str(argv_log),
    }
    # Set explicitly in both directions rather than inherited: a developer who exported this
    # while debugging the fallback would otherwise flip the negative test.
    env.pop(OVERRIDE, None)
    if override is not None:
        env[OVERRIDE] = override

    proc = subprocess.run(  # nosec B603 B607 — fixed script path, list args, no shell
        [
            "bash",
            str(ASH_SCRIPT),
            "--source-dir",
            str(source_dir),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=180,
        check=False,
    )
    assert argv_log.is_file(), (
        "the fake runner was never asked to build, so there is no argv to assert over -- this "
        f"test would otherwise pass vacuously.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    return argv_log.read_text(encoding="utf-8").strip()


class TestTheBashEntrypoint:
    """``./ash``, which is what the ``bash`` scan legs run."""

    pytestmark = _REQUIRES_BASH

    def test_the_override_reaches_the_build(self, recording_runner, tmp_path):
        argv = _build_argv(recording_runner, tmp_path, PINNED_REF)

        assert f"--build-arg BASE_IMAGE={PINNED_REF}" in argv, (
            "./ash must pass the override through, or the bash legs resolve FROM against the "
            f"registry that just refused. Build argv was:\n{argv}"
        )

    def test_a_digest_suffixed_reference_survives_intact(
        self, recording_runner, tmp_path
    ):
        """``FROM ${BASE_IMAGE}`` accepts a digest; the plumbing must not mangle one.

        This is the property that makes the fallback path more tightly pinned than the primary
        rather than less, so it is worth pinning separately from mere presence: an ``@`` and a
        64-character hex digest surviving word-splitting and quoting is not free in a shell
        that builds argv by unquoted expansion.
        """
        argv = _build_argv(recording_runner, tmp_path, PINNED_REF)

        assert PINNED_REF in argv, f"the digest was altered in transit:\n{argv}"
        assert argv.count(PINNED_REF) == 1, (
            f"the reference must appear exactly once:\n{argv}"
        )

    def test_nothing_redirects_from_when_the_override_is_unset(
        self, recording_runner, tmp_path
    ):
        """ECR Public answers on nearly every run, and then the Dockerfile's default is right.

        Emitting a redirect anyway would add a ``--build-arg BASE_IMAGE=`` to every build and
        make ``ARG BASE_IMAGE`` in the Dockerfile unreachable.
        """
        argv = _build_argv(recording_runner, tmp_path, None)

        assert "BASE_IMAGE=" not in argv, (
            f"the primary path's argv must be what it was before this existed:\n{argv}"
        )

    def test_an_empty_override_is_treated_as_unset(self, recording_runner, tmp_path):
        """Writing an empty value to GITHUB_ENV is how a composite action unsets a variable.

        ``run-scan-test`` already does exactly that to clear the Actions cache credentials
        after the build, so this is a reachable state. ``--build-arg BASE_IMAGE=`` would make
        ``FROM ${BASE_IMAGE}`` empty and fail the build with a parse error well away from the
        cause.
        """
        argv = _build_argv(recording_runner, tmp_path, "")

        assert "BASE_IMAGE=" not in argv, (
            f"an empty override must not be passed through:\n{argv}"
        )


class TestThePowerShellEntrypoint:
    """``utils/ash_helpers.ps1``, which is what the ``powershell`` scan legs run.

    Text assertions, for the reason given in this module's docstring: there is no pwsh here.
    """

    @pytest.fixture
    def body(self) -> str:
        return PS1.read_text(encoding="utf-8")

    def test_the_override_is_read_and_passed_as_a_build_arg(self, body: str):
        assert f"$env:{OVERRIDE}" in body, (
            f"utils/ash_helpers.ps1 must read {OVERRIDE}, or the powershell legs resolve FROM "
            "against the registry that just refused"
        )
        assert f'"--build-arg", "BASE_IMAGE=$($env:{OVERRIDE})"' in body, (
            "the override must be appended as a --build-arg/value pair in the same idiom as "
            "the other build args, so it survives the Invoke-Expression join"
        )

    def test_it_is_emitted_before_the_callers_own_build_args(self, body: str):
        """A duplicate ``--build-arg`` is last-wins, so position decides which value applies.

        Measured on docker 25.0.16: with ``--build-arg WHICH=first --build-arg WHICH=second``
        the build saw ``second``. So a caller who names BASE_IMAGE themselves has to land
        after the CI fallback, not before it.
        """
        override_at = body.index(f"$env:{OVERRIDE}")
        extra_at = body.index("# Add any extra build args")
        assert override_at < extra_at, (
            "the override has to be emitted before $buildArgs, or a caller's explicit "
            "BASE_IMAGE build-arg is silently overridden by the CI fallback"
        )


class TestEveryBuildEntrypointIsCovered:
    """The completeness guard. One entrypoint left out is the failure mode, not a gap.

    Asserted as a list rather than per-file, because what breaks is a *set*: the pre-pull
    exports one variable for every build in the repository, and a build that does not read it
    fails at ``FROM`` with a registry error that names neither the pre-pull nor itself.
    """

    def test_all_three_build_entrypoints_read_the_override(self):
        missing = [
            path.relative_to(REPO_ROOT).as_posix()
            for path in (PY_BUILD, ASH_SCRIPT, PS1)
            if OVERRIDE not in path.read_text(encoding="utf-8")
        ]
        assert missing == [], (
            f"these build entrypoints do not read {OVERRIDE}: {missing}. Each constructs its "
            "own build argv, and each is reachable from CI after the base-image pre-pull runs "
            "-- _build_image for the container and validate-container legs, ./ash for the "
            "bash legs, ash_helpers.ps1 for the powershell legs. One left out is a leg that "
            "still fails at FROM with a registry error, after a pre-pull step that exited 0."
        )

    def test_the_prepull_is_the_only_thing_that_sets_it(self):
        """A reader who greps for the variable has to land on the one place that writes it."""
        action = PREPULL.read_text(encoding="utf-8")
        assert (
            'printf \'%s\\n\' "base-image-override=${override}" >> "${GITHUB_OUTPUT}"'
            in action
        ), (
            "the pre-pull action must be what produces the value; if this moved, the "
            "entrypoints above are reading something nothing sets"
        )
        assert "steps.pull.outputs.base-image-override" in action, (
            "the action exposes the pull step's value as its base-image-override output, "
            "which callers map to the variable in each build step's env; "
            "tests/unit/test_build_handoffs_reach_every_consumer.py checks the mappings"
        )
        assert f"{OVERRIDE}=" not in action, (
            "the action writes the variable itself again; the hand-off is an output now"
        )
