# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A branch build re-runs the Dockerfile's clone step; a tag or a commit id does not.

Why this file exists
--------------------
A non-LOCAL image build clones ASH at ``INSTALL_ASH_REVISION`` in the Dockerfile's
``uv-reqs`` stage. A branch (``--ash-revision-to-install main``) moves, but the
clone step is the same command on every build, so the build cache would serve the
branch's first clone to every later build unless --force was given: nothing in the
step changes when the branch does.

So a branch build passes ASH_CLONE_DATE_EPOCH=<now>, which the Dockerfile declares
directly above the clone step. Docker passes an ARG to every later RUN of its stage
as an environment variable, so a new value is a cache miss for each of them ("Impact
on build caching" in the Dockerfile reference); the steps above the ARG stay cached.
LOCAL, a release tag (v3.7.0, v3.0.0-beta) and a full commit id clone the same tree
every time and pass none, so their clone stays cached, and so does a build whose
context is ASH's own source tree, which the clone step builds without cloning (./ash
is always one). Whether a name is a branch is
decided from its shape, without asking the remote: anything that is not LOCAL, a
release-shaped tag or a full commit id is treated as a branch, which includes the
floating v3 tag, which does move.

Not asserted, because it needs a container runtime: the cache behavior itself. It
rests on the documented rule above.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    CLONE_DATE_BUILD_ARG,
    _build_image,
)
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.unit.interactions.test_container_image_revision import (
    _clone_step,
    _instructions,
    _stage,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMIT_ID = "0123456789abcdef0123456789abcdef01234567"
BRANCHES = ["main", "beta", "feature/scan-cache", "v3", "abc1234"]
FIXED = ["LOCAL", "v3.7.0", "v3.0.0-beta", "v3.0.0-beta-20250528", COMMIT_ID]


def _build_args(argv: List[str]) -> List[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--build-arg"]


def _build_image_argv(
    revision: str, tmp_path: Path, calls: List[List[str]], ash_tree: bool = False
) -> List[str]:
    """``ash_tree``: the Dockerfile's directory, the build context, is ASH's tree."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    if ash_tree:
        tmp_path.joinpath("pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
    _build_image(
        oci_command_prefix=[],
        resolved_oci_runner="docker",
        dockerfile_path=dockerfile,
        image_name="ash:test",
        build_target="non-root",
        container_uid="1000",
        container_gid="1000",
        resolved_revision=revision,
        offline=False,
        offline_semgrep_rulesets="p/ci",
        force=False,
        quiet=False,
        custom_build_arg=[],
        debug=False,
    )
    return calls[-1]


def _clone_dates(argv: List[str]) -> List[str]:
    return [
        value.partition("=")[2]
        for value in _build_args(argv)
        if value.startswith(f"{CLONE_DATE_BUILD_ARG}=")
    ]


@pytest.fixture
def recorded_builds(monkeypatch) -> List[List[str]]:
    calls: List[List[str]] = []

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
        calls.append([str(item) for item in cmd_list])
        return create_completed_process(args=list(cmd_list), returncode=0)

    monkeypatch.setattr(rac, "run_cmd_direct", fake_run_cmd_direct)
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    for name in (
        "ACTIONS_RUNTIME_TOKEN",
        "ASH_BASE_IMAGE_OVERRIDE",
        "ASH_BASE_OCI_LAYOUT",
    ):
        monkeypatch.delenv(name, raising=False)
    return calls


class _Clock:
    """datetime stand-in whose now() advances a second on every call.

    Takes now()'s tz argument as datetime does: the build-date argument is read with
    ``datetime.now(timezone.utc)`` on the same builds.
    """

    _now = datetime(2026, 10, 11, 8, 0, 0)

    @classmethod
    def now(cls, tz=None):
        cls._now = cls._now.replace(second=(cls._now.second + 1) % 60)
        return cls._now if tz is None else cls._now.replace(tzinfo=tz)


class TestTheCloneDateBuildArg:
    @pytest.mark.parametrize("branch", BRANCHES)
    def test_a_branch_build_passes_a_new_clone_date(
        self, monkeypatch, recorded_builds, tmp_path, branch
    ):
        """v3 is the floating major-version tag and moves; a short id cannot be fetched."""
        monkeypatch.setattr(rac, "datetime", _Clock)

        first = _clone_dates(_build_image_argv(branch, tmp_path, recorded_builds))
        second = _clone_dates(_build_image_argv(branch, tmp_path, recorded_builds))

        assert len(first) == 1 and len(second) == 1
        assert first != second
        assert all(int(value) > 0 for value in first + second)

    @pytest.mark.parametrize("branch", ["main", "v3"])
    def test_a_branch_build_of_an_ash_tree_context_passes_none(
        self, recorded_builds, tmp_path, branch
    ):
        """The clone step builds such a context without cloning; nothing to re-run."""
        argv = _build_image_argv(branch, tmp_path, recorded_builds, ash_tree=True)

        assert _clone_dates(argv) == []

    @pytest.mark.parametrize("revision", FIXED)
    def test_a_fixed_revision_passes_none(self, recorded_builds, tmp_path, revision):
        argv = _build_image_argv(revision, tmp_path, recorded_builds)

        assert _clone_dates(argv) == []
        assert f"INSTALL_ASH_REVISION={revision}" in _build_args(argv)


# ---------------------------------------------------------------------------
# The Dockerfile side
# ---------------------------------------------------------------------------


class TestTheDockerfile:
    def test_the_clone_date_is_declared_directly_above_the_clone(self):
        instructions = _instructions(_stage("uv-reqs"))
        clone = instructions.index(_clone_step())
        declared = [
            i
            for i, instruction in enumerate(instructions)
            if instruction.startswith(f"ARG {CLONE_DATE_BUILD_ARG}=")
        ]

        assert len(declared) == 1, "the clone date ARG is not declared in uv-reqs"
        assert declared[0] < clone
        between = instructions[declared[0] + 1 : clone]
        assert not [i for i in between if i.startswith("RUN ")], (
            f"a RUN between the ARG and the clone re-runs on every branch build: {between}"
        )
        before = instructions[: declared[0]]
        assert any("install-pinned-tool uv" in i for i in before), (
            "the ARG must come after the uv install, or that install re-runs too"
        )

    def test_the_dockerfile_and_the_build_agree_on_a_commit_id(self):
        """The shell test for a commit id is the whole value: 40 characters, none of
        them outside lowercase hex, which is _COMMIT_ID_PATTERN read with
        fullmatch. test_container_clone_step_runs.py runs both on the same values."""
        step = _clone_step()
        assert '[ "${#INSTALL_ASH_REVISION}" -eq 40 ]' in step
        assert (
            'case "${INSTALL_ASH_REVISION}" in *[!0123456789abcdef]*) false ;;' in step
        )
        assert rac._COMMIT_ID_PATTERN.pattern == "^[0-9a-f]{40}$"
