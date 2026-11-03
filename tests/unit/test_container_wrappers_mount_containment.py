# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The bash and PowerShell wrappers share the host as ``ash --mode container`` does.

docs/content/docs/cli-reference.md ("Running a scan in a container") gives the three
entry points one mount table: ``/src`` read-only, ``/out`` read-write, and a config
file outside the source directory read-only under ``/ash-config``. This file holds
``./ash`` and ``utils/ash_helpers.ps1`` to it, and checks that ``./ash`` and the
Python launcher reach the same decision for the same config layouts:

- the source directory is mounted at ``/src`` read-only under its own name, also
  when the name holds spaces, shell punctuation or glob characters;
- the arguments before the image name are the ones the wrapper means to pass, and
  nothing from the environment adds a mount or another runner option;
- a config outside the source directory with an ``extends`` entry is refused, in
  every spelling ASH reads as one, because the wrapper mounts that file alone;
- for a config inside the source, outside the checkout, elsewhere in the checkout,
  or linked out of the checkout, ``./ash`` and ``_assemble_run_command`` agree on
  the refusal, the inner ``--config`` path and the repository flag.

``./ash`` runs against a fake OCI runner that records each invocation. The
PowerShell checks read the script's text, so they run without ``pwsh``.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404 - running the wrapper script is the point
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from automated_security_helper.config.config_sources import read_config_file
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from tests.utils.helpers import mark_git_checkout

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"
PS1_SCRIPT = REPO_ROOT / "utils" / "ash_helpers.ps1"

needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or not ASH_SCRIPT.is_file(),
    reason=(
        "./ash needs bash and a checkout: on Windows bash is the WSL launcher stub and "
        "users run utils/ash_helpers.ps1, and an installed-package layout has no ./ash"
    ),
)

FAKE_RUNNER = """#!/bin/bash
count=$(find "$FAKE_RUNNER_LOG_DIR" -type f | wc -l)
printf '%s\\0' "$@" > "$FAKE_RUNNER_LOG_DIR/$(printf '%03d' "$count")"
exit 0
"""

_SCRUBBED_ENV = (
    "CI",
    "IsCI",
    "ISCI",
    "CODEBUILD_BUILD_ID",
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "DOCKER_EXTRA_ARGS",
    "ASH_CONFIG",
    "MOUNT_OUTPUT_DIR",
)

#: The same names test_container_mount_containment.py gives the Python launcher.
UNUSUAL_NAMES = [
    pytest.param("plain", id="plain"),
    pytest.param("with space", id="space"),
    pytest.param("dollar$HOME", id="dollar"),
    pytest.param("glob*?[ab]", id="glob"),
    pytest.param("semi;colon&amp", id="shell-punctuation"),
    pytest.param("quote'single", id="single-quote"),
    pytest.param("uniéü", id="non-ascii"),
    pytest.param("eq=sign", id="equals"),
    pytest.param("-leading-dash", id="leading-dash"),
    pytest.param("back\\slash", id="backslash"),
    pytest.param("tab\there", id="tab"),
]


@pytest.fixture
def fake_runner(tmp_path):
    runner = tmp_path / "bin" / "fake-oci-runner"
    runner.parent.mkdir()
    runner.write_text(FAKE_RUNNER)
    runner.chmod(runner.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    log_dir = tmp_path / "runner-calls"
    log_dir.mkdir()
    return runner, log_dir


def _run_ash(
    fake_runner, cwd: Path, args: List[str], extra_env: Optional[Dict[str, str]] = None
) -> Tuple[int, str, List[List[str]]]:
    """Run ./ash against the fake runner: (returncode, stdout and stderr, calls)."""
    runner, log_dir = fake_runner
    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV}
    env.update({"OCI_RUNNER": str(runner), "FAKE_RUNNER_LOG_DIR": str(log_dir)})
    env.update(extra_env or {})
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        ["bash", str(ASH_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env,
        timeout=180,
        check=False,
    )
    calls = [
        record.read_bytes().decode().split("\0")[:-1]
        for record in sorted(log_dir.iterdir())
    ]
    return result.returncode, result.stdout + result.stderr, calls


def _only_run(calls: List[List[str]]) -> List[str]:
    runs = [call for call in calls if call and call[0] == "run"]
    assert len(runs) == 1, f"expected one `run` call, got {calls}"
    return runs[0]


def _mounts(call: List[str]) -> Dict[str, Dict[str, object]]:
    found: Dict[str, Dict[str, object]] = {}
    for i, arg in enumerate(call[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, object] = {}
        for part in call[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else True
        destination = str(options.get("destination"))
        assert destination not in found, f"two mounts at {destination}: {call}"
        found[destination] = options
    return found


def _inner_args(call: List[str]) -> List[str]:
    return call[call.index("ash") + 1 :]


def _flag(args: List[str], flag: str) -> Optional[str]:
    values = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == flag]
    assert len(values) <= 1, f"more than one {flag} in {args}"
    return values[0] if values else None


# ---------------------------------------------------------------------------
# ./ash: the source is read-only at /src under its own name
# ---------------------------------------------------------------------------


@pytest.mark.integration
@needs_bash
@pytest.mark.parametrize("name", UNUSUAL_NAMES)
class TestTheBashWrapperMountsTheSourceReadOnly:
    def test_the_source_and_output_are_mounted_under_their_own_names(
        self, name, fake_runner, tmp_path
    ):
        source = tmp_path / f"project {name}"
        source.mkdir()
        output = tmp_path / f"out {name}"

        rc, output_text, calls = _run_ash(
            fake_runner,
            tmp_path,
            ["--no-build", "--source-dir", str(source), "--output-dir", str(output)],
        )

        assert rc == 0, output_text
        mounts = _mounts(_only_run(calls))
        assert set(mounts) == {"/src", "/out"}
        assert Path(str(mounts["/src"]["source"])).resolve() == source.resolve()
        assert mounts["/src"].get("readonly") is True
        assert Path(str(mounts["/out"]["source"])).resolve() == output.resolve()

    def test_a_config_outside_the_source_is_mounted_read_only_by_its_real_path(
        self, name, fake_runner, tmp_path
    ):
        source = tmp_path / "project"
        source.mkdir()
        operator = tmp_path / f"operator {name}"
        operator.mkdir()
        config = operator / f"ash {name}.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        rc, output_text, calls = _run_ash(
            fake_runner,
            source,
            [
                "--no-build",
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                str(config),
            ],
        )

        assert rc == 0, output_text
        run = _only_run(calls)
        inner = _flag(_inner_args(run), "--config")
        assert inner == f"/ash-config/ash {name}.yaml"
        mounts = _mounts(run)
        assert set(mounts) == {"/src", "/out", inner}
        assert Path(str(mounts[inner]["source"])) == config.resolve()
        assert mounts[inner].get("readonly") is True


# ---------------------------------------------------------------------------
# ./ash: only the arguments the wrapper means to pass reach the runner
# ---------------------------------------------------------------------------

#: Options the wrapper passes ``<runner> run`` itself, before the image name. -i is
#: not among them for a scan: the wrapper keeps the container's stdin open only for
#: the subcommands its ASH_READS_STDIN list names (and for a run given
#: ``--cli-json-input -``; tests/unit/test_ash_bash_entrypoint_subcommand_args.py
#: checks the list against the CLI's readers), and these cases run the default scan,
#: whose stdin a container must never consume.
_RUN_OPTIONS_WITHOUT_VALUE = {"--rm", "-t", "--network=none"}
_RUN_ENV_KEYS = {
    "ASH_ACTUAL_SOURCE_DIR",
    "ASH_ACTUAL_OUTPUT_DIR",
    "ASH_DEBUG",
    # The mounted paths as the scan inside reads them: ./ash hands them over as
    # variables, so a subcommand that takes no --source-dir still runs.
    "ASH_SOURCE_DIR",
    "ASH_OUTPUT_DIR",
    "ASH_OUTPUT_FORMAT",
    "COLUMNS",
    "LINES",
}


def _runner_options(run: List[str], image: str) -> List[str]:
    """The arguments between ``run`` and the image name."""
    assert image in run, f"the image name {image!r} is not one argument in {run}"
    return run[1 : run.index(image)]


def _assert_only_the_wrappers_own_options(options: List[str]) -> None:
    i = 0
    while i < len(options):
        option = options[i]
        if option in _RUN_OPTIONS_WITHOUT_VALUE:
            i += 1
        elif option == "-e":
            key = options[i + 1].partition("=")[0]
            assert key in _RUN_ENV_KEYS, f"an unexpected variable: {options[i + 1]}"
            i += 2
        elif option == "--mount":
            fields = dict(
                part.partition("=")[::2] for part in options[i + 1].split(",")
            )
            destination = fields.get("destination", "")
            assert destination in ("/src", "/out") or destination.startswith(
                "/ash-config/"
            ), f"an unexpected mount: {options[i + 1]}"
            i += 2
        else:
            raise AssertionError(
                f"an unexpected runner option: {option!r} in {options}"
            )


@pytest.mark.integration
@pytest.mark.parametrize(
    "extra_env",
    [
        pytest.param({}, id="clean-environment"),
        pytest.param({"ASH_IMAGE_NAME": "registry.example/ash:1"}, id="image-name"),
        # A variable the wrapper does not set adds nothing to the command.
        pytest.param(
            {"MOUNT_OUTPUT_DIR": "--mount type=bind,source=/,destination=/host"},
            id="MOUNT_OUTPUT_DIR",
        ),
        # An image name is one argument to the runner, so one with a space would
        # split into runner options of its own, and one starting with '-' reads as
        # an option however it is quoted: ./ash refuses it, as ash --mode container
        # and Invoke-ASH do, before anything is built or run.
        pytest.param(
            {"ASH_IMAGE_NAME": "--privileged registry.example/ash:1"},
            id="image-name-with-a-space",
        ),
    ],
)
@pytest.mark.parametrize("flags", [[], ["--offline"]], ids=["online", "offline"])
@needs_bash
def test_the_bash_wrapper_passes_the_runner_only_its_own_options(
    extra_env, flags, fake_runner, tmp_path
):
    source = tmp_path / "project"
    source.mkdir()
    image = extra_env.get("ASH_IMAGE_NAME", "automated-security-helper:non-root")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), *flags],
        extra_env,
    )

    if image.startswith("-") or " " in image:
        # Refused with 3 and no runner call: no word of the name reaches the runner.
        assert rc == 3, output_text
        assert calls == [], f"the runner was called: {calls}"
        assert f"The image name '{image}' starts with '-'" in output_text, output_text
        return
    assert rc == 0, output_text
    _assert_only_the_wrappers_own_options(_runner_options(_only_run(calls), image))


# ---------------------------------------------------------------------------
# ./ash: an outside config with an extends entry is refused in every spelling
# ---------------------------------------------------------------------------

#: (id, file name, text): spellings ASH reads as an ``extends`` entry.
_EXTENDS_SPELLING_TABLE = [
    ("yaml", "ash.yaml", "extends: base.yaml\n"),
    ("json", "ash.json", '{"extends": "base.json"}\n'),
    ("toml", "ash.toml", 'extends = "base.toml"\n'),
    (
        "json-key-and-colon-on-two-lines",
        "ash.json",
        '{\n  "extends"\n  : "base.json"\n}\n',
    ),
    ("yaml-escaped-key", "ash.yaml", '"ext\\x65nds": base.yaml\n'),
    ("yaml-complex-key", "ash.yaml", "? extends\n: base.yaml\n"),
]

#: The spellings the bash wrapper test below runs: all of them.
_REFUSED_BY_THE_BASH_WRAPPER = tuple(id_ for id_, _, _ in _EXTENDS_SPELLING_TABLE)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "text"),
    [pytest.param(name, text, id=id_) for id_, name, text in _EXTENDS_SPELLING_TABLE],
)
def test_the_spelling_is_an_extends_entry_to_ash(name, text, tmp_path):
    """The precondition for the wrapper test below: ASH reads each one as ``extends``."""
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    assert "extends" in read_config_file(config)


@pytest.mark.integration
@needs_bash
@pytest.mark.parametrize(
    ("name", "text"),
    [
        pytest.param(name, text, id=id_)
        for id_, name, text in _EXTENDS_SPELLING_TABLE
        if id_ in _REFUSED_BY_THE_BASH_WRAPPER
    ],
)
def test_the_bash_wrapper_refuses_an_outside_config_that_extends(
    name, text, fake_runner, tmp_path
):
    source = tmp_path / "project"
    source.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config = operator / name
    config.write_text(text, encoding="utf-8")

    rc, output_text, calls = _run_ash(
        fake_runner,
        source,
        ["--no-build", "--output-dir", str(tmp_path / "out"), "--config", str(config)],
    )

    assert rc == 3, output_text
    assert calls == [], f"the runner was called: {calls}"
    assert "extends" in output_text


# ---------------------------------------------------------------------------
# ./ash and the Python launcher reach the same decision for the same layout
# ---------------------------------------------------------------------------


def _assemble(source_dir: Path, output_dir: Path, config: str) -> List[str]:
    return rac._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name="automated-security-helper:non-root",
        source_dir=source_dir,
        output_dir=output_dir,
        offline=False,
        debug=False,
        color=False,
        quiet=True,
        progress=False,
        verbose=False,
        simple=True,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[ExecutionPhase.SCAN],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=config,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=ExecutionStrategy.PARALLEL,
        ctx=None,
    )


def _decision(run: List[str], inner: List[str], flag_present: bool):
    mounts = _mounts(run)
    return {
        "refused": False,
        "config": _flag(inner, "--config"),
        "from_repository": flag_present,
        "src": (
            Path(str(mounts["/src"]["source"])).resolve(),
            mounts["/src"].get("readonly"),
        ),
        "config_sources": sorted(
            str(Path(str(options["source"])).resolve())
            for destination, options in mounts.items()
            if destination not in ("/src", "/out")
        ),
    }


def _python_decision(source: Path, output: Path, config: Path) -> Dict[str, object]:
    """``run_ash_container`` resolves the source directory before it builds this."""
    try:
        cmd = _assemble(source.resolve(), output.resolve(), str(config))
    except rac.ContainerInputError:
        return {"refused": True}
    inner = cmd[cmd.index("automated-security-helper:non-root") + 2 :]
    return _decision(cmd, inner, rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in inner)


def _bash_decision(fake_runner, source: Path, output: Path, config: Path, cwd: Path):
    rc, output_text, calls = _run_ash(
        fake_runner,
        cwd,
        [
            "--no-build",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config),
        ],
    )
    if rc == 3 and not calls:
        return {"refused": True}
    assert rc == 0, output_text
    run = _only_run(calls)
    inner = _inner_args(run)
    return _decision(run, inner, "--config-from-scanned-repository" in inner)


@pytest.mark.integration
@pytest.mark.parametrize(
    "layout",
    [
        "inside-the-source",
        "link-inside-the-source-to-inside",
        "outside-the-checkout",
        "elsewhere-in-the-checkout",
        "link-in-the-source-out-of-the-checkout",
        "directory-link-out-of-the-checkout",
        "link-elsewhere-in-the-checkout-out-of-it",
        "elsewhere-in-the-checkout-source-named-through-a-link",
    ],
)
@needs_bash
def test_the_bash_wrapper_and_the_launcher_agree(layout, fake_runner, tmp_path):
    checkout = tmp_path / "repo"
    # A git-shaped .git, one holding HEAD: a bare empty directory is no checkout
    # boundary to the launcher (sandbox_grants._git_shaped), so it marks nothing.
    mark_git_checkout(checkout)
    source = checkout / "services" / "api"
    (source / ".ash").mkdir(parents=True)
    (checkout / "ci").mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "ash.yaml").write_text("project_name: operator\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    if layout == "inside-the-source":
        config = source / ".ash" / "strict.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
    elif layout == "link-inside-the-source-to-inside":
        (source / "real.yaml").write_text("project_name: p\n", encoding="utf-8")
        config = source / ".ash" / "strict.yaml"
        config.symlink_to(source / "real.yaml")
    elif layout == "outside-the-checkout":
        config = operator / "ash.yaml"
    elif layout == "elsewhere-in-the-checkout":
        config = checkout / "ci" / "ash.yaml"
        config.write_text("project_name: ci\n", encoding="utf-8")
    elif layout == "link-in-the-source-out-of-the-checkout":
        config = source / ".ash" / "strict.yaml"
        config.symlink_to(operator / "ash.yaml")
    elif layout == "directory-link-out-of-the-checkout":
        (source / "conf").symlink_to(operator, target_is_directory=True)
        config = source / "conf" / "ash.yaml"
    elif layout == "link-elsewhere-in-the-checkout-out-of-it":
        config = checkout / "ci" / "ash.yaml"
        config.symlink_to(operator / "ash.yaml")
    else:
        # The checkout is found from the source's real path as well as its name.
        config = checkout / "ci" / "ash.yaml"
        config.write_text("project_name: ci\n", encoding="utf-8")
        named = tmp_path / "alias"
        named.symlink_to(source, target_is_directory=True)
        source = named

    python = _python_decision(source, output, config)
    bash = _bash_decision(fake_runner, source, output, config, tmp_path)

    assert bash == python
    if not python["refused"]:
        assert python["src"] == (source.resolve(), True)
    if layout.startswith("elsewhere-in-the-checkout"):
        assert python["from_repository"] is True
    if "out-of" in layout:
        assert python["refused"] is True


# ---------------------------------------------------------------------------
# utils/ash_helpers.ps1, read as text: the run command's mounts
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ps1() -> str:
    if not PS1_SCRIPT.is_file():
        pytest.skip("utils/ash_helpers.ps1 is not in this tree")
    return PS1_SCRIPT.read_text(encoding="utf-8")


def _mount_literals(text: str) -> List[str]:
    """Every ``--mount`` value the script writes, as written: the pair the run
    command takes (``"--mount", "..."``) and the pair the extra run arguments
    take (``$runArgs.Add('--mount')``, then ``$runArgs.Add("...")``)."""
    paired = re.findall(r'"--mount",\s*"([^"]*)"', text)
    added = re.findall(
        r"\$runArgs\.Add\('--mount'\)\s*\$runArgs\.Add\(\"([^\"]*)\"\)", text
    )
    return paired + added


@pytest.mark.unit
def test_the_powershell_wrapper_mounts_the_source_read_only(ps1):
    literals = [m for m in _mount_literals(ps1) if "destination=/src," in m]
    assert literals == ["type=bind,source=$sourceDirFull,destination=/src,readonly"]


@pytest.mark.unit
def test_the_powershell_wrapper_mounts_only_the_documented_destinations(ps1):
    destinations = sorted(
        re.search(r"destination=([^,]*)", m).group(1) for m in _mount_literals(ps1)
    )
    assert destinations == ["$envConfigInner", "/out", "/src"]
    config = [m for m in _mount_literals(ps1) if "destination=$envConfigInner" in m]
    assert config == [
        "type=bind,source=$envConfigReal,destination=$envConfigInner,readonly"
    ]
    # The config's container path is under /src or /ash-env-config, nowhere else.
    assigned = re.findall(r"\$envConfigInner\s*=\s*(['\"])([^'\"]*)\1", ps1)
    assert assigned and all(
        value.startswith(("/src/", "/ash-env-config/")) for _, value in assigned
    ), assigned


@pytest.mark.unit
def test_the_powershell_wrapper_reads_source_and_output_paths_literally(ps1):
    """-Path takes '[', ']', '*' and '?' as wildcards (about_Wildcards), so a source
    directory named 'src[1]' would resolve to 'src1' when that exists. Read on the
    code alone: a comment may name the wildcard reading it rules out."""
    code = "\n".join(
        line for line in ps1.splitlines() if not line.strip().startswith("#")
    )
    by_path = re.findall(
        r"\b(?:Get-Item|Test-Path|New-Item)\s+(?!-LiteralPath)\$(?:_|SourceDir|OutputDir)\b",
        code,
    )
    assert by_path == [], by_path
