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
There are two independent build call sites, each with its own argv construction, and both
are reachable from CI after the pre-pull runs:

* ``run_ash_container.py::_build_image`` -- ``ash build-image`` and ``ash scan --mode
  container``; every ``validate-container`` leg and the ``python-container`` scan legs;
* ``utils/ash_helpers.ps1`` -- the ``powershell`` scan legs.

There used to be a third, the root ``./ash`` bash script that drove the ``bash`` scan legs. It
was absorbed into the Python CLI, so its build is ``_build_image`` above and its legs are
``python-container`` legs; ``test_the_root_bash_entrypoint_stays_absent`` keeps it from coming
back unguarded.

A fix applied to one of them would leave the other broken in exactly the way that is hard
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

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PS1 = REPO_ROOT / "utils" / "ash_helpers.ps1"
PY_BUILD = (
    REPO_ROOT / "automated_security_helper" / "interactions" / "run_ash_container.py"
)
PREPULL = REPO_ROOT / ".github" / "actions" / "prepull-base-image" / "action.yml"

OVERRIDE = "ASH_BASE_IMAGE_OVERRIDE"

# A digest-pinned reference, because that is the shape the pre-pull exports: it verified the
# digest before falling back, so it hands the build content rather than a name.
PINNED_REF = "docker.io/library/python@sha256:" + "b" * 64


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

    def test_every_build_entrypoint_reads_the_override(self):
        missing = [
            path.relative_to(REPO_ROOT).as_posix()
            for path in (PY_BUILD, PS1)
            if OVERRIDE not in path.read_text(encoding="utf-8")
        ]
        assert missing == [], (
            f"these build entrypoints do not read {OVERRIDE}: {missing}. Each constructs its "
            "own build argv, and each is reachable from CI after the base-image pre-pull runs "
            "-- _build_image for the container and validate-container legs, ash_helpers.ps1 "
            "for the powershell legs. One left out is a leg that "
            "still fails at FROM with a registry error, after a pre-pull step that exited 0."
        )

    def test_the_root_bash_entrypoint_stays_absent(self):
        """The root ``ash`` bash script was absorbed into the Python CLI.

        ``run_ash_container.py::_build_image`` is the build it used to type, so the ``bash``
        scan legs became ``python-container`` legs on the same os and runtime (see
        packaging/RECONCILIATION.md, "The CLI consolidation"). If a root ``ash`` script comes
        back it is a third build entrypoint, and it has to be added to the tuple above rather
        than slip past this guard.
        """
        assert not (REPO_ROOT / "ash").exists(), (
            "a root ./ash entrypoint exists again; add it to this file's completeness guard"
        )

    def test_the_prepull_is_the_only_thing_that_sets_it(self):
        """A reader who greps for the variable has to land on the one place that writes it."""
        action = PREPULL.read_text(encoding="utf-8")
        assert f"{OVERRIDE}=${{override}}" in action, (
            "the pre-pull action must be what exports the variable; if this moved, the "
            "entrypoints above are reading something nothing sets"
        )
        assert "GITHUB_ENV" in action, (
            "the handoff is through GITHUB_ENV, which is what reaches every later step in the "
            "job regardless of which entrypoint the job then uses"
        )
