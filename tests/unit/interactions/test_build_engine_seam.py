"""Which program builds ASH's image, which runs the scan in it, and when each is found.

Container mode asks a container tool for two jobs: building ASH's image, and running
the scan inside it. One program does both today, the container runner that
``_resolve_oci_runner`` finds. ``run_ash_container`` takes a ``build_engine`` naming
the program for the first job (``runner``, the default, is that same container
runner), and ``_resolve_engines`` finds the programs a call needs. These tests pin:

* The commands the default engine starts are the commands container mode started
  before there was a build engine. Each case below writes out one build in full and
  runs it three ways: with no ``build_engine``, with the member, and with its value.
* The runner is looked up once per call, after every refusal that needs no program,
  and a host with none still fails when nothing is asked of it. The helpers that
  build take the build engine's path and the run phase takes the run engine's path.
  The default engine gives both jobs one path, so those two are told apart with a
  lookup that answers with two different programs.
* ``ScanOptions.build_engine`` reaches ``run_ash_container``, and ``run_ash_scan``, the
  library entry point, takes the same ``build_engine`` and builds its ``ScanOptions``
  with it.

No container tool runs. ``run_cmd_direct`` is the one call that starts a program, and
a recorder takes its place.
"""

from __future__ import annotations

import inspect
import os
import re
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from automated_security_helper.core.enums import BuildEngine, BuildTarget, RunMode
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

#: Where the stand-in container tools sit. Nothing is installed there.
PROGRAMS = "/nonexistent/ash-test"

#: What ``BUILD_DATE_EPOCH`` reads in every command.
BUILD_DATE_EPOCH = 1700000000

#: The ``<layout dir>@<digest>`` value of ASH_BASE_OCI_LAYOUT, and its digest.
LAYOUT_DIGEST = "sha256:" + "b" * 64
LAYOUT = f"/layout@{LAYOUT_DIGEST}"

#: An ASH_BASE_IMAGE_OVERRIDE value: a digest-pinned image reference.
BASE_OVERRIDE = "registry.example/ash-base@sha256:" + "a" * 64

#: The Actions variables that turn the layer cache on for docker with buildx.
ACTIONS_CACHE = {
    "ACTIONS_RUNTIME_TOKEN": "token",
    "ACTIONS_RESULTS_URL": "https://results.example/",
}

#: The source tree this suite imports ASH from. A LOCAL revision builds its Dockerfile.
ASH_SOURCE_ROOT = Path(rac.__file__).resolve().parents[2]

#: Environment that would change the commands under test if the suite itself runs in
#: a job that exported it.
_SCRUBBED_ENV = (
    "CI",
    "IsCI",
    "ISCI",
    "CODEBUILD_BUILD_ID",
    "ASH_CONFIG",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_CACHE_URL",
    "ACTIONS_RESULTS_URL",
    "ASH_DISABLE_GHA_BUILD_CACHE",
    "ASH_GHA_BUILD_CACHE_EXPORT",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@pytest.fixture
def installed() -> set[str]:
    """The container tools this test's host has: docker, until a test says otherwise."""
    return {"docker"}


@pytest.fixture
def commands(monkeypatch, tmp_path, installed) -> List[List[str]]:
    """Every command ASH would start, recorded instead of started; each one exits 0."""
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    def find(name: str) -> str | None:
        return f"{PROGRAMS}/{name}" if name in installed else None

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", find)
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "_build_date_epoch", lambda: BUILD_DATE_EPOCH)
    monkeypatch.setattr(rac, "_host_is_windows", lambda: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    monkeypatch.setattr(rac.platform, "machine", lambda: "x86_64")
    for name in _SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.fixture
def packaged(monkeypatch, tmp_path) -> Path:
    """The directory of the Dockerfile a pinned revision builds."""
    assets = tmp_path / "packaged-assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text(
        "FROM scratch AS ci\nFROM scratch AS non-root\n", encoding="utf-8"
    )
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    return assets


@pytest.fixture
def lookups(commands, monkeypatch) -> List[Any]:
    """The runner each lookup was asked for (None: any of the usual ones), in order.

    The lookup still answers from the host's installed tools.
    """
    asked: List[Any] = []
    answer = rac._resolve_oci_runner

    def spy(oci_runner, quiet=False):
        asked.append(oci_runner)
        return answer(oci_runner, quiet)

    monkeypatch.setattr(rac, "_resolve_oci_runner", spy)
    return asked


def _argv(line: str) -> List[str]:
    """A command written the way a shell would write it: one word per space.

    ``@name`` stands for the stand-in tool of that name.
    """
    return [
        f"{PROGRAMS}/{word[1:]}" if word.startswith("@") else word
        for word in line.split()
    ]


def _shown(cmd: List[str], **places: Path) -> List[str]:
    """``cmd`` with each place's path as ``<name>``, and a moving date as ``<now>``."""
    shown = []
    for word in cmd:
        text = re.sub(r"^(ASH_CLONE_DATE_EPOCH=)\d+$", r"\1<now>", word)
        if os.path.isabs(word):
            resolved = Path(word).resolve()
            for name, root in places.items():
                root = root.resolve()
                if resolved == root or root in resolved.parents:
                    inside = resolved.relative_to(root).as_posix()
                    text = f"<{name}>" if inside == "." else f"<{name}>/{inside}"
                    break
        shown.append(text)
    return shown


# ---------------------------------------------------------------------------
# The commands of the default engine, one build at a time
# ---------------------------------------------------------------------------

_DEFAULT_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <assets>"
)

_CI_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:ci --target ci "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <assets>"
)

_OFFLINE_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=YES --build-arg OFFLINE_SEMGREP_RULESETS=p/custom "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <assets>"
)

_FORCED_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 --no-cache <assets>"
)

_QUIET_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 -q <assets>"
)

_FORCED_QUIET_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 --no-cache -q <assets>"
)

_IMAGE_WITH_THE_CALLERS_ARGS = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 "
    "--build-arg FOO=bar --build-arg UID=2000 <assets>"
)

_BRANCH_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--build-arg ASH_CLONE_DATE_EPOCH=<now> "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=main "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <assets>"
)

_LOCAL_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <source>/Dockerfile --build-arg INSTALL_ASH_REVISION=LOCAL "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <source>"
)

_REDIRECTED_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 "
    f"--build-arg BASE_IMAGE={BASE_OVERRIDE} <assets>"
)

_REDIRECTED_IMAGE_WITH_THE_CALLERS_BASE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 "
    f"--build-arg BASE_IMAGE={BASE_OVERRIDE} --build-arg BASE_IMAGE=mine:1 <assets>"
)

_NERDCTL_IMAGE_FROM_THE_LAYOUT = (
    "@nerdctl build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 "
    "--build-context ash-base-image=oci-layout:///layout "
    "--build-arg BASE_IMAGE=ash-base-image --pull=false <assets>"
)

_FINCH_IMAGE_FROM_THE_LAYOUT = _NERDCTL_IMAGE_FROM_THE_LAYOUT.replace(
    "@nerdctl", "@finch"
)

_PODMAN_IMAGE = _DEFAULT_IMAGE.replace("@docker", "@podman")

_FINCH_IMAGE = _DEFAULT_IMAGE.replace("@docker", "@finch")

_PODMAN_IMAGE_REDIRECTED = _REDIRECTED_IMAGE.replace("@docker", "@podman")

_ACTIONS_CACHED_IMAGE = (
    "@docker buildx build --load "
    "--cache-from type=gha,version=2,scope=ash-non-root-x86_64-online "
    "--cache-to type=gha,version=2,mode=min,ignore-error=true,"
    "scope=ash-non-root-x86_64-online "
    "--build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <assets>"
)

_ACTIONS_CACHED_IMAGE_FROM_THE_LAYOUT = (
    "@docker buildx build --load "
    "--cache-from type=gha,version=2,scope=ash-non-root-x86_64-online "
    "--cache-to type=gha,version=2,mode=min,ignore-error=true,"
    "scope=ash-non-root-x86_64-online "
    "--build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:non-root --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 "
    f"--build-context ash-base-image=oci-layout:///layout@{LAYOUT_DIGEST} "
    "--build-arg BASE_IMAGE=ash-base-image <assets>"
)

_CUSTOM_IMAGE = (
    "@docker build --tag automated-security-helper:custom "
    "--file <custom>/Containerfile "
    "--build-arg ASH_BASE_IMAGE=automated-security-helper:ci <custom>"
)

_CI_IMAGE_FORCED_QUIET = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag automated-security-helper:ci --target ci "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 --no-cache -q <assets>"
)

_CUSTOM_IMAGE_STAGE_FORCED_QUIET = (
    "@docker build --tag automated-security-helper:custom "
    "--file <custom>/Containerfile "
    "--build-arg ASH_BASE_IMAGE=automated-security-helper:ci "
    "--target non-root --no-cache -q <custom>"
)

_NAMED_IMAGE = (
    "@docker build --build-arg UID=1000 --build-arg GID=1000 "
    "--tag registry.example/ash:test --target non-root "
    "--file <assets>/Dockerfile --build-arg INSTALL_ASH_REVISION=v3.7.0 "
    "--build-arg OFFLINE=NO --build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
    "--build-arg BUILD_DATE_EPOCH=1700000000 <assets>"
)


def _build_case(
    case_id: str,
    *expected: str,
    kwargs: Dict[str, Any] | None = None,
    env: Dict[str, str] | None = None,
    tools: tuple[str, ...] = ("docker",),
    buildx: bool = False,
    containerfile: str | None = None,
):
    """One build: what is asked, the host it runs on, and each command it starts."""
    return pytest.param(
        kwargs or {},
        env or {},
        tools,
        buildx,
        containerfile,
        [_argv(line) for line in expected],
        id=case_id,
    )


_STAGES = "FROM scratch AS non-root\n"

BUILD_CASES = [
    _build_case("the-default-image", _DEFAULT_IMAGE),
    _build_case(
        "the-ci-stage",
        _CI_IMAGE,
        kwargs={"build_target": BuildTarget.CI},
    ),
    _build_case(
        "offline-with-its-own-rulesets",
        _OFFLINE_IMAGE,
        kwargs={"offline": True, "offline_semgrep_rulesets": "p/custom"},
    ),
    _build_case(
        "force-builds-without-the-cache",
        _FORCED_IMAGE,
        kwargs={"force": True},
    ),
    _build_case("quiet", _QUIET_IMAGE, kwargs={"quiet": True}),
    _build_case(
        "force-and-quiet",
        _FORCED_QUIET_IMAGE,
        kwargs={"force": True, "quiet": True},
    ),
    _build_case(
        "the-callers-build-arguments-come-last",
        _IMAGE_WITH_THE_CALLERS_ARGS,
        kwargs={"custom_build_arg": ["FOO=bar", "UID=2000"]},
    ),
    _build_case(
        "a-branch-carries-the-clone-date",
        _BRANCH_IMAGE,
        kwargs={"ash_revision_to_install": "main"},
    ),
    _build_case(
        "a-local-revision-builds-ashs-own-tree",
        _LOCAL_IMAGE,
        kwargs={"ash_revision_to_install": "LOCAL"},
    ),
    _build_case(
        "the-base-image-override",
        _REDIRECTED_IMAGE,
        env={"ASH_BASE_IMAGE_OVERRIDE": BASE_OVERRIDE},
    ),
    _build_case(
        "the-override-comes-before-the-callers-arguments",
        _REDIRECTED_IMAGE_WITH_THE_CALLERS_BASE,
        kwargs={"custom_build_arg": ["BASE_IMAGE=mine:1"]},
        env={"ASH_BASE_IMAGE_OVERRIDE": BASE_OVERRIDE},
    ),
    _build_case(
        "a-layout-is-no-use-to-docker-without-buildx",
        _DEFAULT_IMAGE,
        env={"ASH_BASE_OCI_LAYOUT": LAYOUT},
    ),
    _build_case(
        "nerdctl-takes-the-layout-as-a-build-context",
        _NERDCTL_IMAGE_FROM_THE_LAYOUT,
        env={"ASH_BASE_OCI_LAYOUT": LAYOUT},
        tools=("nerdctl",),
    ),
    _build_case(
        "finch-takes-the-layout-as-a-build-context",
        _FINCH_IMAGE_FROM_THE_LAYOUT,
        env={"ASH_BASE_OCI_LAYOUT": LAYOUT},
        tools=("finch",),
    ),
    _build_case(
        "podman-has-the-layout-in-its-store-already",
        _PODMAN_IMAGE,
        env={"ASH_BASE_OCI_LAYOUT": LAYOUT},
        tools=("podman",),
    ),
    _build_case(
        "the-layout-wins-over-the-override-where-the-runtime-can-take-it",
        _NERDCTL_IMAGE_FROM_THE_LAYOUT,
        env={"ASH_BASE_OCI_LAYOUT": LAYOUT, "ASH_BASE_IMAGE_OVERRIDE": BASE_OVERRIDE},
        tools=("nerdctl",),
    ),
    _build_case(
        "the-override-applies-where-the-runtime-cannot-take-the-layout",
        _PODMAN_IMAGE_REDIRECTED,
        env={"ASH_BASE_OCI_LAYOUT": LAYOUT, "ASH_BASE_IMAGE_OVERRIDE": BASE_OVERRIDE},
        tools=("podman",),
    ),
    _build_case(
        "docker-with-buildx-in-actions-uses-the-actions-cache",
        _ACTIONS_CACHED_IMAGE,
        env=ACTIONS_CACHE,
        buildx=True,
    ),
    _build_case(
        "force-leaves-the-actions-cache-alone",
        _FORCED_IMAGE,
        kwargs={"force": True},
        env=ACTIONS_CACHE,
        buildx=True,
    ),
    _build_case(
        "buildx-takes-the-layout-as-a-build-context",
        _ACTIONS_CACHED_IMAGE_FROM_THE_LAYOUT,
        env={**ACTIONS_CACHE, "ASH_BASE_OCI_LAYOUT": LAYOUT},
        buildx=True,
    ),
    _build_case(
        "a-custom-containerfile-is-built-on-the-ci-stage",
        _CI_IMAGE,
        _CUSTOM_IMAGE,
        containerfile=_STAGES,
    ),
    _build_case(
        "a-custom-containerfile-stage-force-and-quiet",
        _CI_IMAGE_FORCED_QUIET,
        _CUSTOM_IMAGE_STAGE_FORCED_QUIET,
        kwargs={"build_target": BuildTarget.NON_ROOT, "force": True, "quiet": True},
        containerfile=_STAGES,
    ),
    _build_case(
        "a-wrapper-prefixes-every-command",
        f"sudo -E {_CI_IMAGE}",
        f"sudo -E {_CUSTOM_IMAGE}",
        env={"OCI_RUNNER_WRAPPER": "sudo -E"},
        containerfile=_STAGES,
    ),
    _build_case(
        "the-runner-the-caller-names",
        _PODMAN_IMAGE,
        kwargs={"oci_runner": "podman"},
        tools=("docker", "podman"),
    ),
    _build_case(
        "finch-is-found-first",
        _FINCH_IMAGE,
        tools=("podman", "docker", "finch"),
    ),
    _build_case(
        "the-image-name-from-the-environment",
        _NAMED_IMAGE,
        env={"ASH_IMAGE_NAME": "registry.example/ash:test"},
    ),
]

#: The three ways a caller can say which build engine it means.
SPELLINGS = [
    pytest.param({}, id="no-engine-given"),
    pytest.param({"build_engine": BuildEngine.RUNNER}, id="the-member"),
    pytest.param({"build_engine": "runner"}, id="its-value"),
]


@pytest.mark.parametrize("spelling", SPELLINGS)
@pytest.mark.parametrize(
    "kwargs, env, tools, buildx, containerfile, expected", BUILD_CASES
)
def test_the_default_engine_starts_the_commands_container_mode_always_started(
    kwargs,
    env,
    tools,
    buildx,
    containerfile,
    expected,
    spelling,
    commands,
    installed,
    packaged,
    monkeypatch,
    tmp_path,
):
    installed.clear()
    installed.update(tools)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: buildx)
    custom = tmp_path / "custom"
    if containerfile is not None:
        custom.mkdir()
        (custom / "Containerfile").write_text(containerfile, encoding="utf-8")
        kwargs = {**kwargs, "custom_containerfile": str(custom / "Containerfile")}
    kwargs = {"ash_revision_to_install": "v3.7.0", **kwargs}

    result = rac.run_ash_container(build=True, run=False, **kwargs, **spelling)

    assert result.returncode == 0, result.stderr
    shown = [
        _shown(cmd, assets=packaged, source=ASH_SOURCE_ROOT, custom=custom)
        for cmd in commands
    ]
    assert shown == expected


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_build_and_a_run_are_started_with_one_program(spelling, commands, packaged):
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        build=True,
        run=True,
        ash_revision_to_install="v3.7.0",
        **spelling,
    )

    assert result.returncode == 0, result.stderr
    docker = f"{PROGRAMS}/docker"
    assert [cmd[:2] for cmd in commands] == [[docker, "build"], [docker, "run"]]
    assert commands[1][2:4] == ["--rm", "--name"]


# ---------------------------------------------------------------------------
# The runner is looked up once per call, and only after the refusals that need none
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "build, run",
    [
        pytest.param(True, True, id="build-and-run"),
        pytest.param(True, False, id="build-alone"),
        pytest.param(False, True, id="run-alone"),
        pytest.param(False, False, id="neither"),
    ],
)
def test_one_lookup_serves_the_whole_call(build, run, lookups, commands, packaged):
    rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        build=build,
        run=run,
        ash_revision_to_install="v3.7.0",
    )

    assert lookups == [None]


def test_the_runner_the_caller_names_is_the_one_looked_up(
    lookups, commands, installed, packaged
):
    installed.add("podman")

    rac.run_ash_container(
        build=True, run=False, oci_runner="podman", ash_revision_to_install="v3.7.0"
    )

    assert lookups == ["podman"]
    assert commands[0][0] == f"{PROGRAMS}/podman"


def test_a_host_with_no_runner_fails_even_when_nothing_is_asked_of_it(
    lookups, commands, installed
):
    installed.clear()

    result = rac.run_ash_container(build=False, run=False)

    assert result.returncode == 1
    assert result.stderr == "Unable to resolve an OCI runner"
    assert lookups == [None]
    assert commands == []


REFUSALS_THAT_NEED_NO_PROGRAM = [
    pytest.param(
        {"container_uid": "root"},
        3,
        "Container UID must be a numeric value",
        id="a-uid-that-is-not-a-number",
    ),
    pytest.param(
        {"container_gid": "wheel"},
        3,
        "Container GID must be a numeric value",
        id="a-gid-that-is-not-a-number",
    ),
    pytest.param(
        {"ash_revision_to_install": "v1.0.0; touch pwned"},
        1,
        "Invalid ASH revision value",
        id="a-revision-the-build-cannot-take",
    ),
    pytest.param(
        {"container_uid": "0"},
        3,
        "creates a user with UID 0",
        id="the-non-root-stage-as-uid-0",
    ),
    pytest.param(
        {"container_gid": "0"},
        3,
        "gives its user GID 0",
        id="the-non-root-stage-as-gid-0",
    ),
    pytest.param(
        {"config": "missing.yaml", "run": True},
        3,
        "Config file not found: missing.yaml",
        id="a-config-that-is-not-there",
    ),
]


@pytest.mark.parametrize("kwargs, code, text", REFUSALS_THAT_NEED_NO_PROGRAM)
def test_a_refusal_that_needs_no_program_comes_before_any_lookup(
    kwargs, code, text, lookups, commands, packaged
):
    kwargs = {
        "build": True,
        "run": False,
        "ash_revision_to_install": "v3.7.0",
        **kwargs,
    }

    result = rac.run_ash_container(source_dir="src", output_dir="out", **kwargs)

    assert result.returncode == code, result.stderr
    assert text in result.stderr
    assert lookups == []
    assert commands == []


def test_host_ids_that_cannot_be_read_stop_the_call_before_any_lookup(
    lookups, commands, monkeypatch
):
    def unreadable():
        raise OSError("id -u unavailable")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", unreadable)

    result = rac.run_ash_container(build=True, run=False)

    assert result.returncode == 1
    assert "id -u unavailable" in result.stderr
    assert lookups == []
    assert commands == []


def test_a_host_with_no_runner_is_told_so_before_a_bad_wrapper_is_refused(
    lookups, commands, installed, monkeypatch, packaged
):
    installed.clear()
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo")

    result = rac.run_ash_container(
        build=True, run=False, ash_revision_to_install="v3.7.0"
    )

    assert result.returncode == 1
    assert result.stderr == "Unable to resolve an OCI runner"
    assert lookups == [None]
    assert commands == []


def test_a_bad_wrapper_is_refused_once_the_runner_is_found(
    lookups, commands, monkeypatch, packaged
):
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo")

    result = rac.run_ash_container(
        build=True, run=False, ash_revision_to_install="v3.7.0"
    )

    assert result.returncode == 3
    assert "OCI_RUNNER_WRAPPER" in result.stderr
    assert lookups == [None]
    assert commands == []


# ---------------------------------------------------------------------------
# _resolve_engines
# ---------------------------------------------------------------------------


class TestResolveEngines:
    def test_the_runner_builds_and_runs(self, lookups, commands):
        engines = rac._resolve_engines(BuildEngine.RUNNER, None, build=True, run=True)

        runner = f"{PROGRAMS}/docker"
        assert engines == rac.ResolvedEngines(
            build_path=runner, build_kind=BuildEngine.RUNNER, run_path=runner
        )
        assert lookups == [None]

    @pytest.mark.parametrize("build", [True, False])
    @pytest.mark.parametrize("run", [True, False])
    def test_a_step_the_call_does_not_take_has_no_path(
        self, build, run, lookups, commands
    ):
        engines = rac._resolve_engines(BuildEngine.RUNNER, None, build=build, run=run)

        assert (engines.build_path is not None) is build
        assert (engines.run_path is not None) is run
        assert lookups == [None]

    def test_the_runner_the_caller_names_is_passed_to_the_lookup(
        self, lookups, commands, installed
    ):
        installed.add("nerdctl")

        engines = rac._resolve_engines("runner", "nerdctl", build=True, run=True)

        assert lookups == ["nerdctl"]
        assert engines.build_path == f"{PROGRAMS}/nerdctl"

    def test_the_value_of_an_engine_is_taken_for_the_engine(self, commands):
        engines = rac._resolve_engines("runner", None, build=True, run=False)

        assert engines.build_kind is BuildEngine.RUNNER

    def test_a_name_that_is_not_an_engine_is_refused_before_any_lookup(
        self, lookups, commands
    ):
        with pytest.raises(ValueError):
            rac._resolve_engines("no-such-engine", None, build=True, run=True)

        assert lookups == []

    def test_a_host_with_no_runner_raises_the_error_callers_print(
        self, commands, installed
    ):
        installed.clear()

        with pytest.raises(RuntimeError, match="Unable to resolve an OCI runner"):
            rac._resolve_engines(BuildEngine.RUNNER, None, build=True, run=True)

    def test_the_lookup_is_called_with_the_runner_name_alone(self, monkeypatch):
        """Callers replace the lookup with a function of that one argument."""
        monkeypatch.setattr(rac, "_resolve_oci_runner", lambda oci_runner: "/stub/run")

        engines = rac._resolve_engines(BuildEngine.RUNNER, None, build=True, run=True)

        assert engines.build_path == engines.run_path == "/stub/run"

    def test_the_program_of_a_step_the_call_does_not_take_is_an_error(self, commands):
        engines = rac._resolve_engines(BuildEngine.RUNNER, None, build=False, run=False)

        with pytest.raises(RuntimeError, match="build engine"):
            _ = engines.build_program
        with pytest.raises(RuntimeError, match="run engine"):
            _ = engines.run_program

    def test_the_program_of_a_step_the_call_takes_is_its_path(self, commands):
        engines = rac._resolve_engines(BuildEngine.RUNNER, None, build=True, run=True)

        assert engines.build_program == engines.build_path
        assert engines.run_program == engines.run_path


# ---------------------------------------------------------------------------
# Each job gets its own program
# ---------------------------------------------------------------------------


@pytest.fixture
def distinct(monkeypatch):
    """Make the lookup answer with a builder and a runner that are different programs.

    The default engine gives both jobs one program, so a helper handed the wrong one
    could not be told apart. Returns a function taking the two tools' names; what it
    returns is the list of what each call asked the lookup.
    """

    def use(builder: str, runner: str) -> List[Any]:
        asked: List[Any] = []

        def resolve(build_engine, oci_runner, *, build, run):
            asked.append((build_engine, oci_runner, build, run))
            return rac.ResolvedEngines(
                build_path=f"{PROGRAMS}/{builder}" if build else None,
                build_kind=BuildEngine.RUNNER,
                run_path=f"{PROGRAMS}/{runner}" if run else None,
            )

        monkeypatch.setattr(rac, "_resolve_engines", resolve)
        return asked

    return use


class TestEachJobGetsItsOwnProgram:
    def test_the_images_are_built_by_the_build_engine_and_the_scan_run_by_the_other(
        self, distinct, commands, packaged, tmp_path
    ):
        asked = distinct("nerdctl", "podman")
        containerfile = tmp_path / "Containerfile"
        containerfile.write_text(_STAGES, encoding="utf-8")

        rac.run_ash_container(
            source_dir="src",
            output_dir="out",
            build=True,
            run=True,
            ash_revision_to_install="v3.7.0",
            custom_containerfile=str(containerfile),
        )

        assert [cmd[:2] for cmd in commands] == [
            [f"{PROGRAMS}/nerdctl", "build"],
            [f"{PROGRAMS}/nerdctl", "build"],
            [f"{PROGRAMS}/podman", "run"],
        ]
        assert asked == [(BuildEngine.RUNNER, None, True, True)]

    @pytest.mark.parametrize(
        "build, run",
        [(True, False), (False, True), (True, True), (False, False)],
    )
    def test_the_lookup_is_told_which_steps_the_call_takes(
        self, build, run, distinct, commands, packaged
    ):
        asked = distinct("docker", "docker")

        rac.run_ash_container(
            source_dir="src",
            output_dir="out",
            build=build,
            run=run,
            ash_revision_to_install="v3.7.0",
            oci_runner="podman",
        )

        assert asked == [(BuildEngine.RUNNER, "podman", build, run)]

    @pytest.mark.parametrize(
        "builder, runner, layout",
        [
            pytest.param("nerdctl", "podman", True, id="nerdctl-builds"),
            pytest.param("podman", "nerdctl", False, id="podman-builds"),
        ],
    )
    def test_the_base_image_handoff_is_the_build_engines_to_make(
        self, builder, runner, layout, distinct, commands, packaged, monkeypatch
    ):
        distinct(builder, runner)
        monkeypatch.setenv("ASH_BASE_OCI_LAYOUT", LAYOUT)

        rac.run_ash_container(build=True, run=False, ash_revision_to_install="v3.7.0")

        assert ("--build-context" in commands[0]) is layout

    @pytest.mark.parametrize(
        "builder, runner, caches",
        [
            pytest.param("docker", "podman", True, id="docker-builds"),
            pytest.param("podman", "docker", False, id="podman-builds"),
        ],
    )
    def test_the_layer_cache_is_the_build_engines_to_use(
        self, builder, runner, caches, distinct, commands, packaged, monkeypatch
    ):
        distinct(builder, runner)
        for name, value in ACTIONS_CACHE.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: True)

        rac.run_ash_container(build=True, run=False, ash_revision_to_install="v3.7.0")

        assert ("buildx" in commands[0]) is caches
        assert ("--cache-from" in commands[0]) is caches

    @pytest.mark.parametrize("build", [False, True])
    def test_the_leftover_record_names_the_run_engine(
        self, build, distinct, commands, packaged, monkeypatch
    ):
        # A call that builds and runs holds both programs; a record that took the build
        # engine's would name the wrong one.
        distinct("nerdctl", "podman")
        recorded: List[List[str]] = []
        monkeypatch.setattr(
            rac,
            "record_container",
            lambda name, argv: recorded.append(list(argv)) or "record",
        )
        monkeypatch.setattr(rac, "discard_record", lambda record: None)

        rac.run_ash_container(
            source_dir="src",
            output_dir="out",
            build=build,
            run=True,
            ash_revision_to_install="v3.7.0",
        )

        assert recorded == [[f"{PROGRAMS}/podman"]]


# ---------------------------------------------------------------------------
# _ash_build_args
# ---------------------------------------------------------------------------


class TestAshBuildArgs:
    @pytest.fixture(autouse=True)
    def _a_fixed_build_date(self, monkeypatch):
        monkeypatch.setattr(rac, "_build_date_epoch", lambda: BUILD_DATE_EPOCH)
        monkeypatch.delenv("ASH_BASE_IMAGE_OVERRIDE", raising=False)

    @staticmethod
    def _words(dockerfile: Path, **settings: Any) -> List[str]:
        arguments: Dict[str, Any] = {
            "dockerfile_path": dockerfile,
            "image_name": "ash:test",
            "build_target": "ci",
            "container_uid": "1000",
            "container_gid": "1001",
            "resolved_revision": "v3.7.0",
            "offline": False,
            "offline_semgrep_rulesets": "p/ci",
        }
        return rac._ash_build_args(**{**arguments, **settings})

    @pytest.mark.parametrize(
        "folder", ["docker", "docker files"], ids=["no-space", "a-space"]
    )
    def test_the_words_of_a_pinned_revision(self, folder, tmp_path):
        dockerfile = tmp_path / folder / "Dockerfile"

        words = self._words(dockerfile, offline=True)

        # The file is one word whatever the path holds: written with forward slashes
        # on every host, and not split at a space in the temporary directory.
        assert words == [
            *_argv(
                "--build-arg UID=1000 --build-arg GID=1001 "
                "--tag ash:test --target ci --file"
            ),
            dockerfile.as_posix(),
            *_argv(
                "--build-arg INSTALL_ASH_REVISION=v3.7.0 --build-arg OFFLINE=YES "
                "--build-arg OFFLINE_SEMGREP_RULESETS=p/ci "
                "--build-arg BUILD_DATE_EPOCH=1700000000"
            ),
        ]

    def test_a_branch_carries_the_clone_date_right_after_the_ids(self, tmp_path):
        words = self._words(tmp_path / "Dockerfile", resolved_revision="main")

        assert words[:4] == ["--build-arg", "UID=1000", "--build-arg", "GID=1001"]
        assert words[4] == "--build-arg"
        assert re.fullmatch(r"ASH_CLONE_DATE_EPOCH=\d+", words[5]), words[5]
        assert words[6] == "--tag"

    @pytest.mark.parametrize(
        "revision", ["v3.7.0", "a" * 40, "LOCAL"], ids=["tag", "commit", "local"]
    )
    def test_a_revision_that_never_moves_carries_no_clone_date(
        self, revision, tmp_path
    ):
        words = self._words(tmp_path / "Dockerfile", resolved_revision=revision)

        assert not [word for word in words if "ASH_CLONE_DATE_EPOCH" in word]

    def test_a_branch_built_from_ashs_own_tree_carries_no_clone_date(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )

        words = self._words(tmp_path / "Dockerfile", resolved_revision="main")

        assert not [word for word in words if "ASH_CLONE_DATE_EPOCH" in word]

    def test_what_the_environment_or_the_engine_decides_is_not_in_it(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", BASE_OVERRIDE)
        monkeypatch.setenv("ASH_BASE_OCI_LAYOUT", LAYOUT)

        words = self._words(tmp_path / "Dockerfile")

        assert not [word for word in words if word.startswith("BASE_IMAGE=")]
        assert "--build-context" not in words
        assert "--no-cache" not in words
        assert "-q" not in words
        assert words[-1] == "BUILD_DATE_EPOCH=1700000000"


# ---------------------------------------------------------------------------
# The option
# ---------------------------------------------------------------------------


@pytest.fixture
def handed_over(monkeypatch) -> Dict[str, Any]:
    """What a scan hands the container run; nothing is started."""
    seen: Dict[str, Any] = {}

    def fake_run_ash_container(**kwargs):
        seen.update(kwargs)
        return rac._not_started(create_completed_process(args=[], returncode=4))

    monkeypatch.setattr(ras, "run_ash_container", fake_run_ash_container)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return seen


class TestTheOptionReachesTheContainerRun:
    def test_the_options_default_to_the_runner(self):
        options = ras.ScanOptions(source_dir=".", output_dir=".")

        assert options.build_engine is BuildEngine.RUNNER

    def test_the_value_of_an_engine_is_taken_for_the_engine(self):
        options = ras.ScanOptions(source_dir=".", output_dir=".", build_engine="runner")

        assert options.build_engine is BuildEngine.RUNNER

    def test_a_name_that_is_not_an_engine_is_refused(self):
        with pytest.raises(ValidationError, match="build_engine"):
            ras.ScanOptions(source_dir=".", output_dir=".", build_engine="no-such")

    def test_the_container_run_defaults_to_the_runner(self):
        default = inspect.signature(rac.run_ash_container).parameters["build_engine"]

        assert default.default is BuildEngine.RUNNER

    def test_a_scan_hands_the_container_run_the_engine_of_its_options(
        self, handed_over, tmp_path
    ):
        (tmp_path / "src").mkdir()
        options = ras.ScanOptions(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            mode=RunMode.container,
            build=True,
            run=False,
            progress=False,
            show_summary=False,
        )
        # A value no member has: what the run is handed is then the options' own.
        options.build_engine = "named-by-this-test"

        with pytest.raises(SystemExit):
            ras._run_container_mode(options, MagicMock())

        assert handed_over["build_engine"] == "named-by-this-test"

    def test_a_scan_with_no_engine_named_hands_the_runner(self, handed_over, tmp_path):
        (tmp_path / "src").mkdir()

        with pytest.raises(SystemExit):
            ras.run_ash_scan(
                source_dir=str(tmp_path / "src"),
                output_dir=str(tmp_path / "out"),
                mode=RunMode.container,
            )

        assert handed_over["build_engine"] is BuildEngine.RUNNER


# ---------------------------------------------------------------------------
# The library entry point takes the option
# ---------------------------------------------------------------------------

#: How a library caller names the engine to ``run_ash_scan``: not at all, which means
#: the default, and each engine as the member and as its value.
NAMED_TO_THE_SCAN = [
    pytest.param({}, BuildEngine.RUNNER, id="no-engine-given"),
    *[
        pytest.param({"build_engine": named}, engine, id=f"{engine.value}-{how}")
        for engine in BuildEngine
        for how, named in (("member", engine), ("value", engine.value))
    ],
]


@pytest.fixture
def scan_options(monkeypatch, handed_over) -> List[Any]:
    """An ``(arguments, options)`` pair for each ScanOptions a scan call builds.

    ``arguments`` is what the call gave ``ScanOptions``. With one engine to name, the
    options read the same whether the call handed its engine on or dropped it (the
    default is that engine), so only the arguments tell the two apart. The scan goes
    as far as one can with ``handed_over``'s stand-in for the container run: nothing
    is built or started, and no container tool is looked for.
    """
    built: List[Any] = []

    class Recording(ras.ScanOptions):
        def __init__(self, **arguments: Any) -> None:
            super().__init__(**arguments)
            built.append((arguments, self))

    monkeypatch.setattr(ras, "ScanOptions", Recording)
    return built


def _scan_in_a_container(tmp_path: Path, **named: Any) -> None:
    """``run_ash_scan`` in container mode; the stand-in container run exits it."""
    (tmp_path / "src").mkdir(exist_ok=True)
    with pytest.raises(SystemExit):
        ras.run_ash_scan(
            source_dir=str(tmp_path / "src"),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.container,
            **named,
        )


class TestTheScanEntryPointTakesTheOption:
    def test_its_default_is_the_runner_like_the_options_and_the_container_run(self):
        entry = inspect.signature(ras.run_ash_scan).parameters
        assert "build_engine" in entry, "run_ash_scan takes no build_engine"
        container = inspect.signature(rac.run_ash_container).parameters
        field = ras.ScanOptions.model_fields["build_engine"]

        assert entry["build_engine"].default is BuildEngine.RUNNER
        assert container["build_engine"].default is BuildEngine.RUNNER
        assert field.default is BuildEngine.RUNNER

    @pytest.mark.parametrize("named, engine", NAMED_TO_THE_SCAN)
    def test_the_engine_reaches_the_options_the_call_builds(
        self, named, engine, scan_options, tmp_path
    ):
        meant = named.get("build_engine", BuildEngine.RUNNER)

        _scan_in_a_container(tmp_path, **named)

        [(arguments, options)] = scan_options
        assert arguments["build_engine"] is meant
        assert options.build_engine is engine

    @pytest.mark.parametrize("named, engine", NAMED_TO_THE_SCAN)
    def test_the_engine_reaches_the_container_run(
        self, named, engine, handed_over, tmp_path
    ):
        _scan_in_a_container(tmp_path, **named)

        assert handed_over["build_engine"] is engine
