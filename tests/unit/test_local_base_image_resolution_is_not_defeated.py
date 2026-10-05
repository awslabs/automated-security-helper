# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No build entrypoint may emit a flag that defeats local base-image resolution.

Why this file exists
--------------------
``.github/actions/prepull-base-image`` pulls the Dockerfile's base image once per job so the
container legs do not each hit ECR Public's anonymous quotas at ``FROM ${BASE_IMAGE}``. That
only helps if the build then reads the image out of the local store instead of asking the
registry again. Two of the four runtimes do read it, and both do so *by default* -- which means
neither is protected by anything written down, and a flag added for an unrelated reason would
silently turn the pre-pull back into a no-op.

This file is that missing guard. It asserts an ABSENCE, across every entrypoint that builds the
image, of the small set of flags that are known to defeat local resolution. An absence is worth
a test precisely because nothing else can catch it: adding ``--platform`` to support multi-arch
builds is an obviously reasonable change that would break two runtimes' base-image path without
failing a single existing assertion, and the symptom would be a registry rate-limit error in an
unrelated leg weeks later.

The flags, and what each one breaks
-----------------------------------
``--pull``, ``--pull=true``, ``--pull=always``, ``--pull-always``
    ``podman build`` is buildah, and its default pull policy is ``missing``
    (``pullPolicy := buildahDefine.PullIfMissing``). Under ``missing`` with a local hit,
    ``libimage``'s ``copySingleImageFromRegistry`` returns early -- before short-name resolution
    and before any registry I/O at all, not even a digest check. Any of these spellings replaces
    that with ``always`` and sends every build back to the registry the pre-pull existed to
    avoid. ``--pull=newer`` is the same hazard on podman past the 2025-11-04 fix; on podman
    4.9.3, which Ubuntu noble ships, ``newer`` is silently degraded to ``missing``.

``--platform``, ``--arch``, ``--os``
    Two separate failures. On podman these re-resolve a base image whose declared platform does
    not match, defeating the local hit. On nerdctl they defeat the shared-store path as well:
    ``isImageSharable`` (``pkg/cmd/builder/build.go`` at v2.3.5) requires
    ``isBuildPlatformDefault(platform, parser)`` as one of five conjuncts, so any explicit
    non-native platform forces nerdctl onto ``--output type=docker`` plus a hand-rolled
    ``loadImage`` import instead of letting buildkitd write into containerd's store.

``--all-platforms``
    Resolves base-image manifests independently of the pull policy, so it reaches the registry
    whatever ``--pull`` says.

The one pull flag that is allowed, and only where it is allowed
---------------------------------------------------------------
``--pull=false`` on nerdctl and finch, and only while ``ASH_BASE_OCI_LAYOUT`` names a verified
base-image layout. It is the opposite of the flags above: nerdctl maps it to
``image-resolve-mode=local`` (``pkg/cmd/builder/build.go`` at v2.3.5), which forbids the
registry rather than forcing it. It is never emitted for podman, whose ``--pull=false`` is not
that, and never without the layout. ``TestTheLocalOnlyPullFlag`` pins all three conditions.

What this does NOT assert
-------------------------
It does not assert that any runtime honours a local tag -- that is a property of buildah and of
BuildKit, not of this repository, and asserting it here would be measuring them. It also does
not stop a *user* from passing these flags. ``_build_image`` honours ``--custom-build-arg``; a caller who asks for ``--platform`` is
entitled to it and accepts the consequence. What is guarded is only what ASH adds on its own,
unasked, to every build.

The PowerShell entrypoint is asserted as text rather than executed, for the reason
``test_base_image_override_reaches_every_build_entrypoint.py`` gives: there is no ``pwsh`` on
the machine this was written on, and ``test_cfn_nag_windows_toolchain.py`` already establishes
text assertions as this repository's answer to that.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import _build_image

REPO_ROOT = Path(__file__).resolve().parents[2]
PS1 = REPO_ROOT / "utils" / "ash_helpers.ps1"

# Exact argv tokens that must never appear. Kept as whole tokens rather than substrings so that
# a legitimate value which merely contains one of these words -- an image tag called
# "multi-platform", a build-arg named OS -- cannot trip the assertion.
#
# `--pull` covers the bare form; the `=`-suffixed forms are checked separately by prefix,
# because `--pull=always` is one argv element and `--pull always` is two.
FORBIDDEN_EXACT = frozenset(
    {
        "--pull",
        "--pull-always",
        "--all-platforms",
        "--platform",
        "--arch",
        "--os",
    }
)
FORBIDDEN_PREFIXES = ("--pull=", "--platform=", "--arch=", "--os=")

# The single exception, and the conditions it is allowed under; see the module docstring.
LOCAL_ONLY_PULL = "--pull=false"
LAYOUT_VALUE = "/runner/temp/ash-base-image-oci@sha256:" + "c" * 64


def _offending_tokens(argv: List[str]) -> List[str]:
    """Return every token in ``argv`` that would defeat local base-image resolution."""
    return [
        token
        for token in argv
        if token in FORBIDDEN_EXACT or token.startswith(FORBIDDEN_PREFIXES)
    ]


@pytest.fixture
def recorded_commands(monkeypatch):
    """Capture the command lists ``run_cmd_direct`` would have executed."""
    calls: List[List[str]] = []

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
        recorded = [str(item) for item in cmd_list if item is not None]
        calls.append(recorded)

        class _Result:
            returncode = 0
            args = recorded

        return _Result()

    monkeypatch.setattr(rac, "run_cmd_direct", fake_run_cmd_direct)
    return calls


def _build_image_kwargs(dockerfile: Path, **overrides: Any) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "podman",
        "dockerfile_path": dockerfile,
        "image_name": "ash:test",
        "build_target": "non-root",
        "container_uid": "1000",
        "container_gid": "1000",
        "resolved_revision": "LOCAL",
        "offline": False,
        "offline_semgrep_rulesets": "p/ci",
        "force": False,
        "quiet": False,
        "custom_build_arg": [],
        "debug": False,
    }
    kwargs.update(overrides)
    return kwargs


class TestThePythonEntrypoint:
    """``_build_image`` -- ``ashx build-image`` and ``ashx scan --mode container``."""

    @pytest.fixture
    def dockerfile(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM scratch\n", encoding="utf-8")
        return path

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        """Pin the environment this argv depends on, so the result is not machine-dependent."""
        monkeypatch.delenv("ASH_BASE_IMAGE_OVERRIDE", raising=False)
        monkeypatch.delenv("ASH_BASE_OCI_LAYOUT", raising=False)
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({}, id="plain"),
            pytest.param({"force": True, "quiet": True}, id="force-and-quiet"),
            pytest.param({"offline": True}, id="offline"),
            pytest.param({"build_target": "ci"}, id="ci-target"),
        ],
        # Every configuration, not just the default one: the flags guarded here would most
        # plausibly arrive inside one of the conditional branches (`extra_args`, the cache
        # branch), which a single-configuration test would walk straight past.
    )
    def test_no_configuration_adds_a_flag_that_defeats_local_resolution(
        self, recorded_commands, dockerfile, overrides
    ):
        _build_image(**_build_image_kwargs(dockerfile, **overrides))

        argv = recorded_commands[0]
        offending = _offending_tokens(argv)
        assert offending == [], (
            f"_build_image added {offending} to the build argv. podman resolves "
            "`FROM ${BASE_IMAGE}` out of its local store only while its default --pull=missing "
            "policy is intact, and nerdctl only writes into containerd's shared store while the "
            "build platform is the default one. Either flag sends the build back to the "
            "registry that .github/actions/prepull-base-image exists to avoid.\n"
            f"argv was:\n{argv}"
        )

    def test_the_buildx_cache_configuration_is_also_clean(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """The CI shape, which takes the other branch of the buildx/cache decision.

        ``run-scan-test`` exports ``ACTIONS_RUNTIME_TOKEN``, which switches the argv to
        ``buildx build --load`` with ``type=gha`` cache arguments. That is a different code path
        through ``_build_image`` and is the one every docker scan leg actually runs, so a flag
        added there would not be caught by the plain-build cases above.
        """
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache")
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        monkeypatch.setattr(rac, "_runner_supports_buildx", lambda runner: True)

        _build_image(
            **_build_image_kwargs(
                dockerfile, resolved_oci_runner="docker", build_target="ci"
            )
        )

        argv = recorded_commands[0]
        # Guard against the test passing because the branch was not taken at all.
        assert "buildx" in argv, (
            f"this test means to exercise the buildx path and did not reach it:\n{argv}"
        )
        assert _offending_tokens(argv) == [], (
            f"the buildx/cache path added {_offending_tokens(argv)}:\n{argv}"
        )

    def test_a_caller_asking_for_a_platform_is_still_allowed(
        self, recorded_commands, dockerfile
    ):
        """The guard is on what ASH adds unasked, not on what a caller may request.

        Without this, the assertion above could be "satisfied" by a future change that strips
        caller-supplied build arguments -- which would be a worse bug than the one being
        prevented, and would look like a pass.
        """
        _build_image(
            **_build_image_kwargs(
                dockerfile, custom_build_arg=["TARGETPLATFORM=linux/arm64"]
            )
        )

        argv = recorded_commands[0]
        assert "TARGETPLATFORM=linux/arm64" in argv, (
            f"a caller's own build-arg must survive:\n{argv}"
        )


class TestTheLocalOnlyPullFlag:
    """``--pull=false`` appears on nerdctl and finch with a verified layout, and nowhere else.

    Asserted in ``_build_image`` directly. The same three conditions for ``ash_helpers.ps1``
    are pinned in ``test_base_oci_layout_reaches_every_build_entrypoint.py``, which reads the
    PowerShell branch.
    """

    @pytest.fixture
    def dockerfile(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM scratch\n", encoding="utf-8")
        return path

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        monkeypatch.delenv("ASH_BASE_IMAGE_OVERRIDE", raising=False)
        monkeypatch.delenv("ASH_BASE_OCI_LAYOUT", raising=False)
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)

    @pytest.mark.parametrize("runner", ["nerdctl", "finch"])
    def test_it_is_the_only_pull_flag_on_nerdctl_and_finch_with_a_layout(
        self, monkeypatch, recorded_commands, dockerfile, runner
    ):
        monkeypatch.setenv("ASH_BASE_OCI_LAYOUT", LAYOUT_VALUE)
        _build_image(**_build_image_kwargs(dockerfile, resolved_oci_runner=runner))

        argv = recorded_commands[0]
        assert argv.count(LOCAL_ONLY_PULL) == 1, argv
        others = [t for t in _offending_tokens(argv) if t != LOCAL_ONLY_PULL]
        assert others == [], f"only {LOCAL_ONLY_PULL} is allowed here, found {others}"

    @pytest.mark.parametrize("runner", ["podman", "docker"])
    def test_it_is_never_emitted_for_podman_or_docker(
        self, monkeypatch, recorded_commands, dockerfile, runner
    ):
        monkeypatch.setenv("ASH_BASE_OCI_LAYOUT", LAYOUT_VALUE)
        _build_image(**_build_image_kwargs(dockerfile, resolved_oci_runner=runner))

        assert _offending_tokens(recorded_commands[0]) == [], recorded_commands[0]

    @pytest.mark.parametrize("runner", ["nerdctl", "finch"])
    def test_it_is_never_emitted_without_a_layout(
        self, recorded_commands, dockerfile, runner
    ):
        _build_image(**_build_image_kwargs(dockerfile, resolved_oci_runner=runner))

        assert _offending_tokens(recorded_commands[0]) == [], recorded_commands[0]


class TestThePowerShellEntrypoint:
    """``utils/ash_helpers.ps1``, asserted as text -- there is no pwsh here."""

    def test_no_pull_or_platform_flag_is_appended_to_the_build(self):
        body = PS1.read_text(encoding="utf-8")

        # Only the build command's own construction matters. The literal strings are checked in
        # the quoted argv idiom the file uses ("--flag", ...), so prose in a comment mentioning
        # --platform does not trip this.
        offending = [
            literal
            for literal in (
                '"--pull"',
                '"--pull-always"',
                '"--platform"',
                '"--all-platforms"',
                '"--arch"',
                '"--os"',
            )
            if literal in body
        ]
        assert offending == [], (
            f"utils/ash_helpers.ps1 appends {offending} to a build command. The powershell scan "
            "legs run podman and finch, both of which resolve the pre-pulled base image locally "
            "only while these flags are absent."
        )

    def test_the_local_only_pull_flag_sits_inside_the_nerdctl_finch_layout_branch(self):
        """``"--pull=false"`` is the one pull flag allowed, and only in that branch.

        Text, like the check above: the literal must appear exactly once, after the
        ``ASH_BASE_OCI_LAYOUT`` test and the nerdctl/finch test, and before the else-branch that
        handles every other runtime.
        """
        body = PS1.read_text(encoding="utf-8")
        assert body.count(f'"{LOCAL_ONLY_PULL}"') == 1, (
            "expected exactly one --pull=false"
        )
        at = body.index(f'"{LOCAL_ONLY_PULL}"')
        layout_at = body.index("if ($env:ASH_BASE_OCI_LAYOUT)")
        runner_at = body.index("if ($ociRunnerName -in @('nerdctl', 'finch'))")
        else_at = body.index("else", runner_at)
        assert layout_at < runner_at < at < else_at, (
            "--pull=false must only be appended inside the nerdctl/finch branch of the "
            "ASH_BASE_OCI_LAYOUT block"
        )


class TestEveryBuildEntrypointIsCovered:
    """The completeness guard, in the same shape as the override test's.

    One entrypoint left out of this file is the failure mode, not a gap: the pre-pull runs once
    per job and every entrypoint reachable afterwards has to keep the local store usable.
    """

    def test_this_file_covers_the_same_entrypoints_as_the_override_guard(self):
        override_guard = (
            REPO_ROOT
            / "tests"
            / "unit"
            / "test_base_image_override_reaches_every_build_entrypoint.py"
        )
        assert override_guard.is_file(), (
            "the companion guard is gone; these two files are meant to cover the same set of "
            "build entrypoints from two directions (what must be passed, what must not be)"
        )
        covered = {
            "TestThePythonEntrypoint",
            "TestThePowerShellEntrypoint",
        }
        body = Path(__file__).read_text(encoding="utf-8")
        missing = sorted(name for name in covered if f"class {name}" not in body)
        assert missing == [], (
            f"these entrypoint classes went missing from this file: {missing}"
        )
