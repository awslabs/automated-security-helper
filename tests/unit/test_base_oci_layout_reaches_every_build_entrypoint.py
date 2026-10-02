# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every entrypoint that builds the ASH image must translate ASH_BASE_OCI_LAYOUT correctly.

Why this file exists
--------------------
On a cache hit, ``.github/actions/prepull-base-image`` verifies the restored base-image OCI
layout against the Dockerfile's pinned digest and exports
``ASH_BASE_OCI_LAYOUT=<layout dir>@<arch manifest digest>``. The build then has to read the base
image from that layout, or from where the action placed it, and make no registry call. What that
takes differs per runtime and per builder, and the action's header carries the measurements:

* ``docker buildx build`` (docker-container builder, blind to the engine's store):
  ``--build-context ash-base-image=oci-layout://DIR@DIGEST --build-arg BASE_IMAGE=ash-base-image``;
* plain ``docker build`` (docker driver): nothing -- measured, that driver turns an oci-layout
  context into a registry lookup, so the action loads the layout into the engine instead;
* nerdctl and finch: ``--build-context ash-base-image=oci-layout://DIR`` (no digest: nerdctl
  treats the rest of the value as the path and reads the image from index.json),
  ``--build-arg BASE_IMAGE=ash-base-image`` and ``--pull=false``;
* podman: nothing -- it has no oci-layout context; the action imports the layout into its store.

There are two build call sites with their own argv construction, as for
``ASH_BASE_IMAGE_OVERRIDE``: ``run_ash_container.py::_build_image`` and
``utils/ash_helpers.ps1``. (The root ``./ash`` bash script was a third until the Python CLI
absorbed it; its nerdctl/finch/docker/podman cases are the Python class's cases now.) This file
mirrors ``test_base_image_override_reaches_every_build_entrypoint.py`` for the new variable: one
class per entrypoint, and a completeness guard over both.

Limitations
-----------
PowerShell is asserted as text, for the reason the override test gives: there is no ``pwsh``
here. Whether each runtime really makes no registry call with these arguments is not something a
unit test can see; the pre-pull action proves that in CI by pointing the registry hosts at
0.0.0.0 on every warm leg, so a build that reached a registry would fail.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    BASE_OCI_LAYOUT_CONTEXT,
    _build_image,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PS1 = REPO_ROOT / "utils" / "ash_helpers.ps1"
PY_BUILD = (
    REPO_ROOT / "automated_security_helper" / "interactions" / "run_ash_container.py"
)
ACTION_DIR = REPO_ROOT / ".github" / "actions" / "prepull-base-image"

VAR = "ASH_BASE_OCI_LAYOUT"
LAYOUT_DIR = "/home/runner/work/_temp/ash-base-image-oci"
DIGEST = "sha256:" + "d" * 64
VALUE = f"{LAYOUT_DIR}@{DIGEST}"
OVERRIDE_REF = "docker.io/library/python@sha256:" + "b" * 64

CONTEXT_WITH_DIGEST = f"{BASE_OCI_LAYOUT_CONTEXT}=oci-layout://{LAYOUT_DIR}@{DIGEST}"
CONTEXT_NO_DIGEST = f"{BASE_OCI_LAYOUT_CONTEXT}=oci-layout://{LAYOUT_DIR}"
BASE_ARG = f"BASE_IMAGE={BASE_OCI_LAYOUT_CONTEXT}"


def test_the_context_name_is_the_one_every_entrypoint_uses():
    """One name, three files. A mismatch would point FROM at a context nobody attached."""
    assert BASE_OCI_LAYOUT_CONTEXT == "ash-base-image"
    for path in (PY_BUILD, PS1):
        body = path.read_text(encoding="utf-8")
        assert "ash-base-image=oci-layout://" in body, path
        assert "BASE_IMAGE=ash-base-image" in body, path


# --------------------------------------------------------------------------- python


@pytest.fixture
def recorded_commands(monkeypatch):
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


def _kwargs(dockerfile: Path, **overrides: Any) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "dockerfile_path": dockerfile,
        "image_name": "ash:test",
        "build_target": "ci",
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


def _pairs(argv: List[str], flag: str) -> List[str]:
    return [argv[i + 1] for i, token in enumerate(argv[:-1]) if token == flag]


class TestThePythonEntrypoint:
    """``_build_image``: the python-container legs and every validate-container leg."""

    @pytest.fixture
    def dockerfile(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM scratch\n", encoding="utf-8")
        return path

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        for name in (VAR, "ASH_BASE_IMAGE_OVERRIDE", "ACTIONS_RUNTIME_TOKEN"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv("ACTIONS_CACHE_URL", raising=False)
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)

    @pytest.fixture
    def buildx(self, monkeypatch):
        """The CI shape of the docker python-container legs: `docker buildx build --load`."""
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache")
        monkeypatch.setattr(rac, "_runner_supports_buildx", lambda runner: True)

    def test_buildx_gets_the_layout_as_a_digest_addressed_context(
        self, monkeypatch, buildx, recorded_commands, dockerfile
    ):
        monkeypatch.setenv(VAR, VALUE)
        _build_image(**_kwargs(dockerfile))

        argv = recorded_commands[0]
        assert "buildx" in argv, f"this case means the buildx branch:\n{argv}"
        assert _pairs(argv, "--build-context") == [CONTEXT_WITH_DIGEST], argv
        assert BASE_ARG in _pairs(argv, "--build-arg"), argv
        assert "--pull=false" not in argv, argv

    def test_plain_docker_build_gets_nothing(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """The docker driver turns an oci-layout context into a registry lookup (measured)."""
        monkeypatch.setenv(VAR, VALUE)
        _build_image(**_kwargs(dockerfile))

        argv = recorded_commands[0]
        assert "buildx" not in argv, argv
        assert "--build-context" not in argv, argv
        assert not any(a.startswith("BASE_IMAGE=") for a in argv), argv

    @pytest.mark.parametrize("runner", ["nerdctl", "/usr/local/bin/nerdctl", "finch"])
    def test_nerdctl_and_finch_get_the_path_only_context_and_pull_false(
        self, monkeypatch, recorded_commands, dockerfile, runner
    ):
        monkeypatch.setenv(VAR, VALUE)
        _build_image(**_kwargs(dockerfile, resolved_oci_runner=runner))

        argv = recorded_commands[0]
        assert _pairs(argv, "--build-context") == [CONTEXT_NO_DIGEST], (
            "nerdctl reads everything after oci-layout:// as the path; a @digest suffix would "
            f"name a directory that does not exist\n{argv}"
        )
        assert BASE_ARG in _pairs(argv, "--build-arg"), argv
        assert argv.count("--pull=false") == 1, argv

    def test_podman_gets_nothing(self, monkeypatch, recorded_commands, dockerfile):
        monkeypatch.setenv(VAR, VALUE)
        _build_image(**_kwargs(dockerfile, resolved_oci_runner="podman"))

        argv = recorded_commands[0]
        assert "--build-context" not in argv, argv
        assert not any(a.startswith("BASE_IMAGE=") for a in argv), argv

    def test_the_layout_replaces_the_override_where_it_applies(
        self, monkeypatch, buildx, recorded_commands, dockerfile
    ):
        monkeypatch.setenv(VAR, VALUE)
        monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", OVERRIDE_REF)
        _build_image(**_kwargs(dockerfile))

        base_args = [
            a
            for a in _pairs(recorded_commands[0], "--build-arg")
            if a.startswith("BASE_IMAGE=")
        ]
        assert base_args == [BASE_ARG], base_args

    def test_the_override_still_applies_where_the_layout_does_not(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        monkeypatch.setenv(VAR, VALUE)
        monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", OVERRIDE_REF)
        _build_image(**_kwargs(dockerfile, resolved_oci_runner="podman"))

        assert f"BASE_IMAGE={OVERRIDE_REF}" in recorded_commands[0]

    def test_a_callers_own_base_image_still_wins(
        self, monkeypatch, buildx, recorded_commands, dockerfile
    ):
        """Emitted before custom_build_arg, like the override, so last-wins favours the caller."""
        monkeypatch.setenv(VAR, VALUE)
        _build_image(**_kwargs(dockerfile, custom_build_arg=["BASE_IMAGE=mine:1"]))

        base_args = [
            a
            for a in _pairs(recorded_commands[0], "--build-arg")
            if a.startswith("BASE_IMAGE=")
        ]
        assert base_args == [BASE_ARG, "BASE_IMAGE=mine:1"], base_args

    @pytest.mark.parametrize("value", ["", "   "])
    def test_an_empty_value_is_unset(
        self, monkeypatch, buildx, recorded_commands, dockerfile, value
    ):
        monkeypatch.setenv(VAR, value)
        _build_image(**_kwargs(dockerfile))

        assert "--build-context" not in recorded_commands[0]

    @pytest.mark.parametrize(
        "value",
        [
            LAYOUT_DIR,
            f"{LAYOUT_DIR}@sha256:short",
            f"{LAYOUT_DIR}@sha512:{'d' * 64}",
            f"@{DIGEST}",
            f"{LAYOUT_DIR}@{DIGEST.upper()}",
        ],
    )
    def test_a_malformed_value_is_refused(
        self, monkeypatch, buildx, recorded_commands, dockerfile, value
    ):
        monkeypatch.setenv(VAR, value)
        with pytest.raises(ValueError, match=VAR):
            _build_image(**_kwargs(dockerfile))
        assert recorded_commands == [], (
            "nothing may be built on a value that was refused"
        )


# --------------------------------------------------------------------------- powershell


class TestThePowerShellEntrypoint:
    """``utils/ash_helpers.ps1``: the powershell scan legs. Text assertions; no pwsh here."""

    @pytest.fixture
    def body(self) -> str:
        return PS1.read_text(encoding="utf-8")

    def test_the_variable_is_read_and_validated(self, body):
        assert f"$env:{VAR}" in body
        assert "-notmatch '^(?<dir>.+)@(?<digest>sha256:[0-9a-f]{64})$'" in body, (
            "the value must be validated with the same shape as the other two entrypoints"
        )

    def test_nerdctl_and_finch_get_the_context_arg_and_pull_false(self, body):
        branch_at = body.index("if ($ociRunnerName -in @('nerdctl', 'finch'))")
        else_at = body.index("else", branch_at)
        branch = body[branch_at:else_at]
        assert (
            '"--build-context", "`"ash-base-image=oci-layout://$baseLayoutDir`""'
            in branch
        )
        assert '"--build-arg", "BASE_IMAGE=ash-base-image"' in branch
        assert '"--pull=false"' in branch

    def test_the_runner_name_ignores_path_and_extension(self, body):
        """Windows resolves `docker.exe`; a bare string compare would never match."""
        assert (
            "[System.IO.Path]::GetFileNameWithoutExtension($RESOLVED_OCI_RUNNER)"
            in body
        )

    def test_it_is_emitted_before_the_callers_own_build_args(self, body):
        assert body.index(f"$env:{VAR}") < body.index("# Add any extra build args")

    def test_the_override_is_the_else_branch(self, body):
        """Layout and override are one decision, so they cannot both emit BASE_IMAGE."""
        assert "elseif ($env:ASH_BASE_IMAGE_OVERRIDE)" in body


# --------------------------------------------------------------------------- completeness


class TestEveryBuildEntrypointIsCovered:
    def test_every_build_entrypoint_reads_the_variable(self):
        missing = [
            path.relative_to(REPO_ROOT).as_posix()
            for path in (PY_BUILD, PS1)
            if VAR not in path.read_text(encoding="utf-8")
        ]
        assert missing == [], (
            f"these build entrypoints do not read {VAR}: {missing}. Each is reachable from a "
            "warm CI leg, and one that ignores it goes back to the registry."
        )

    def test_this_file_covers_every_entrypoint(self):
        body = Path(__file__).read_text(encoding="utf-8")
        for name in (
            "TestThePythonEntrypoint",
            "TestThePowerShellEntrypoint",
        ):
            assert f"class {name}" in body

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

    def test_only_the_prepull_action_sets_it(self):
        writer = (ACTION_DIR / "use_cached_layout.sh").read_text(encoding="utf-8")
        assert f"{VAR}=${{LAYOUT_DIR}}@${{manifest}}" in writer
        assert "GITHUB_ENV" in writer
        # An assignment from a shell expansion, which is what a writer looks like; the prose in
        # the action's header names the variable as `VAR=<layout dir>@...` and is not one.
        workflows = REPO_ROOT / ".github"
        setters = [
            p.relative_to(REPO_ROOT).as_posix()
            for p in workflows.rglob("*")
            if p.is_file()
            and f"{VAR}=${{" in p.read_text(encoding="utf-8", errors="ignore")
        ]
        assert setters == [".github/actions/prepull-base-image/use_cached_layout.sh"], (
            setters
        )
