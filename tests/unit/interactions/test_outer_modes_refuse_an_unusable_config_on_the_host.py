# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container and nix mode refuse a config file that cannot be used before anything starts.

``ash scan --mode container`` and ``--mode nix`` run a second ASH, inside an image or
a Nix shell, and that ASH refuses a config file that does not load with exit 3. It
did so only after the image was built and started (or the shell entered), and after
the previous run's output was cleared. Now the host judges the file first, with the
loader and the message a local scan uses, and refuses with exit 3 before any runner
or ``nix`` command and before the output directory is touched.

What the host judges: a file that is missing, a directory, unreadable, a FIFO, not
UTF-8, not valid YAML (aliases included), or not a valid config, whether it is named
with ``--config``, named by ``ASH_CONFIG``, or found by discovery, and a discovered
name that is a link to nothing. Options of a plugin the image may hold and the host
does not are left to the scan inside, as before. So is the model's refusal of the
file ``ASH_CONFIG`` names in container mode without a build: the image's ASH may
carry another schema, so parse and confinement stay the host's and the schema is
the scan inside's to judge (``run_ash_scan._image_schema_may_differ``); the host
starts the container and carries the inner refusal's exit 3.

The runners are stand-ins first on PATH (``docker``, ``podman``, ``finch``,
``nerdctl``, ``nix``) that record each call and exit 97, so nothing real starts.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.utils import subprocess_utils
from tests.unit.config.test_config_file_reads import _returns_promptly

RUNNERS = ("docker", "podman", "finch", "nerdctl", "nix")
MODES = ["container", "nix"]

needs_fifo = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX file type"
)
needs_permissions = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions that root ignores",
)


class Stage:
    def __init__(self, root: Path):
        self.root = root
        self.source = root / "src"
        self.output = root / "out"
        self.runner_log = root / "runner.log"
        self.named = root / "cfg" / "ash.yaml"
        self.discovered = self.source / ".ash.yaml"
        self.env = root / "env" / "environment-config.yaml"

    def runner_calls(self) -> List[str]:
        if not self.runner_log.exists():
            return []
        return self.runner_log.read_text(encoding="utf-8").splitlines()

    def inner_run_refuses(self, code: int = 3) -> None:
        """Make the stand-in runners exit as the scan inside does when it refuses
        its config: 3, ASH's invalid-config status, instead of the 97 that marks a
        runner that should never have been reached."""
        for name in RUNNERS:
            stub = self.root / "bin" / name
            stub.write_text(
                f'#!/bin/sh\necho "{name} $*" >> "{self.runner_log}"\nexit {code}\n',
                encoding="utf-8",
            )

    def output_snapshot(self) -> Dict[str, bytes]:
        return {
            path.relative_to(self.output).as_posix(): (
                path.read_bytes() if path.is_file() else b"<dir>"
            )
            for path in sorted(self.output.rglob("*"))
        }


@pytest.fixture
def stage(tmp_path, monkeypatch) -> Stage:
    stage = Stage(tmp_path)
    stage.source.mkdir()
    (stage.source / "app.py").write_text("x = 1\n", encoding="utf-8")
    stage.named.parent.mkdir()
    stage.env.parent.mkdir()
    # The previous run's output, which a refused scan leaves as it was.
    (stage.output / "reports").mkdir(parents=True)
    (stage.output / "ash_aggregated_results.json").write_text(
        '{"previous": "run"}\n', encoding="utf-8"
    )
    (stage.output / "reports" / "ash.sarif").write_text(
        '{"previous": "sarif"}\n', encoding="utf-8"
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in RUNNERS:
        stub = bin_dir / name
        stub.write_text(
            f'#!/bin/sh\necho "{name} $*" >> "{stage.runner_log}"\nexit 97\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    for name in (
        "ASH_CONFIG",
        "ASH_IMAGE_NAME",
        "ASH_IN_CONTAINER",
        "ASH_IN_NIX",
        "ASH_NIX_FLAKE_REF",
        "CI",
        "OCI_RUNNER",
        "OCI_RUNNER_WRAPPER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.chdir(tmp_path)
    yield stage
    for path in (stage.named, stage.discovered, stage.env):
        if path.exists() and not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)


def _make_missing(path: Path) -> None:
    pass


def _make_directory(path: Path) -> None:
    path.mkdir()


def _make_unreadable(path: Path) -> None:
    path.write_text("project_name: locked\n", encoding="utf-8")
    path.chmod(0)


def _make_fifo(path: Path) -> None:
    os.mkfifo(path)


def _make_not_utf8(path: Path) -> None:
    path.write_bytes(b"project_name: \xff\xfe\n")


def _make_unparsable(path: Path) -> None:
    path.write_text("project_name: [unclosed\n", encoding="utf-8")


def _make_alias(path: Path) -> None:
    path.write_text("project_name: &n x\ndescription: *n\n", encoding="utf-8")


def _make_model_violation(path: Path) -> None:
    path.write_text("project_name: x\nglobal_settings: 7\n", encoding="utf-8")


REASONS = [
    pytest.param(_make_missing, id="missing"),
    pytest.param(_make_directory, id="directory"),
    pytest.param(_make_unreadable, id="unreadable", marks=needs_permissions),
    pytest.param(_make_fifo, id="fifo", marks=needs_fifo),
    pytest.param(_make_not_utf8, id="not-utf8"),
    pytest.param(_make_unparsable, id="unparsable"),
    pytest.param(_make_alias, id="yaml-alias"),
    pytest.param(_make_model_violation, id="not-a-valid-config"),
]
# A discovered name that is missing is no config at all: that is a control below.
DISCOVERED_REASONS = [reason for reason in REASONS if reason.id != "missing"]


def _cli(stage: Stage, mode: str, *extra: str, env: Dict[str, str] | None = None):
    from automated_security_helper.cli.main import app

    args = [
        "scan",
        "--mode",
        mode,
        "--no-progress",
        "--source-dir",
        str(stage.source),
        "--output-dir",
        str(stage.output),
        *(["--no-build"] if mode == "container" else []),
        *extra,
    ]
    return CliRunner().invoke(app, args, env=env)


def _api(stage: Stage, mode: str, config: Path | None = None):
    """run_ash_scan as an API caller drives it, with *config* named, or none."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    with pytest.raises(SystemExit) as excinfo:
        run_ash_scan(
            source_dir=stage.source,
            output_dir=stage.output,
            mode=RunMode(mode),
            build=False,
            progress=False,
            show_summary=False,
            **({"config": str(config)} if config is not None else {}),
        )
    return excinfo.value.code


def _promptly(make: Callable[[Path], None], path: Path, call: Callable[[], object]):
    """Run ``call``, bounded by a deadline when ``path`` is a FIFO a read could block on."""
    if make is _make_fifo:
        outcome: dict = {}

        def run() -> None:
            outcome["value"] = call()

        error = _returns_promptly(run, path)
        if error is not None:
            raise error
        return outcome["value"]
    return call()


# How the host words a config refusal, by which check refuses the file: the
# loader's refusal of a file that does not parse or load ("Invalid
# configuration:", run_ash_scan._printed_config_refusal); container mode's
# hand-over check of --config (run_ash_container._unreadable_config); and the
# check of the file ASH_CONFIG names (config/default_config.py
# refuse_unless_ash_config_names_a_file).
REFUSAL_WORDINGS = (
    "Invalid configuration:",
    "Config file not found:",
    "Config file cannot be read:",
    "ASH_CONFIG names ",
    "Configuration validation failed for ",
)


def _assert_refused_on_the_host(stage: Stage, before: Dict[str, bytes], code, output):
    assert code == 3, output
    assert stage.runner_calls() == [], stage.runner_calls()
    assert stage.output_snapshot() == before
    assert any(wording in output for wording in REFUSAL_WORDINGS), output


def _printed(capsys) -> str:
    """What an API caller's refusal printed: the hand-over check writes to
    stderr, the loader's refusal to stdout."""
    captured = capsys.readouterr()
    return captured.out + captured.err


def _left_to_the_scan_inside(mode: str, make: Callable[[Path], None]) -> bool:
    """Whether the host leaves the file ``ASH_CONFIG`` names to the scan inside.

    Only a model refusal, and only in container mode without a build, where the
    image's ASH may carry another schema (``run_ash_scan._image_schema_may_differ``).
    A file that does not parse, is not a file or cannot be read is the host's in
    every mode, and so is a named ``--config`` the model refuses.
    """
    return mode == "container" and make is _make_model_violation


def _assert_left_to_the_scan_inside(stage: Stage, code, output):
    """The host started the container, did not refuse the file itself, and
    carried the inner refusal's exit 3 with the line that names it."""
    calls = stage.runner_calls()
    assert any(call.split()[1:2] == ["run"] for call in calls), (calls, output)
    assert code == 3, output
    flat = " ".join(output.split())
    assert "The container exited with 3 (invalid config or refused input)" in flat, (
        output
    )
    assert "Invalid configuration" not in output, output


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("make", REASONS)
def test_a_named_config(stage, mode, make):
    make(stage.named)
    before = stage.output_snapshot()

    result = _promptly(
        make, stage.named, lambda: _cli(stage, mode, "--config", str(stage.named))
    )

    _assert_refused_on_the_host(stage, before, result.exit_code, result.output)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("make", REASONS)
def test_the_file_ash_config_names(stage, mode, make):
    make(stage.named)
    before = stage.output_snapshot()
    if _left_to_the_scan_inside(mode, make):
        stage.inner_run_refuses()

    result = _promptly(
        make,
        stage.named,
        lambda: _cli(stage, mode, env={"ASH_CONFIG": str(stage.named)}),
    )

    if _left_to_the_scan_inside(mode, make):
        _assert_left_to_the_scan_inside(stage, result.exit_code, result.output)
    else:
        _assert_refused_on_the_host(stage, before, result.exit_code, result.output)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("make", REASONS)
def test_ash_config_when_an_api_caller_names_no_config(
    stage, mode, make, monkeypatch, capsys
):
    """The fallback a local scan takes when it finds no config in the directory."""
    make(stage.named)
    monkeypatch.setenv("ASH_CONFIG", str(stage.named))
    before = stage.output_snapshot()
    if _left_to_the_scan_inside(mode, make):
        stage.inner_run_refuses()

    code = _promptly(make, stage.named, lambda: _api(stage, mode))

    if _left_to_the_scan_inside(mode, make):
        _assert_left_to_the_scan_inside(stage, code, _printed(capsys))
    else:
        _assert_refused_on_the_host(stage, before, code, _printed(capsys))


@pytest.mark.parametrize("entry", ["cli", "api"])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("make", REASONS)
def test_ash_config_beside_a_valid_named_config(
    stage, mode, make, entry, monkeypatch, capsys
):
    """A local scan reads the file ASH_CONFIG names first, as its base, whatever
    else names the config (default_config.get_default_config), and refuses it
    with a valid --config too. So does the host here, before anything starts."""
    make(stage.env)
    stage.named.write_text("project_name: fine\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(stage.env))
    before = stage.output_snapshot()
    if _left_to_the_scan_inside(mode, make):
        stage.inner_run_refuses()

    if entry == "cli":
        result = _promptly(
            make, stage.env, lambda: _cli(stage, mode, "--config", str(stage.named))
        )
        code, output = result.exit_code, result.output
    else:
        code = _promptly(make, stage.env, lambda: _api(stage, mode, stage.named))
        output = _printed(capsys)

    if _left_to_the_scan_inside(mode, make):
        _assert_left_to_the_scan_inside(stage, code, output)
        return
    _assert_refused_on_the_host(stage, before, code, output)
    assert stage.env.name in " ".join(output.split()), output


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("make", DISCOVERED_REASONS)
def test_a_discovered_config(stage, mode, make):
    make(stage.discovered)
    before = stage.output_snapshot()

    result = _promptly(make, stage.discovered, lambda: _cli(stage, mode))

    _assert_refused_on_the_host(stage, before, result.exit_code, result.output)


@pytest.mark.parametrize("mode", MODES)
def test_a_discovered_link_to_nothing(stage, mode):
    stage.discovered.symlink_to(stage.root / "absent.yaml")
    before = stage.output_snapshot()

    result = _cli(stage, mode)

    _assert_refused_on_the_host(stage, before, result.exit_code, result.output)


BAD_OVERRIDES = [
    pytest.param("fail_on_findings=maybe", id="wrong-type"),
    pytest.param("global_settings=7", id="not-a-section"),
    pytest.param("no-equals-sign", id="unparsable"),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("override", BAD_OVERRIDES)
@pytest.mark.parametrize("with_config", [False, True], ids=["defaults", "config"])
def test_an_override_a_local_scan_refuses(stage, mode, override, with_config):
    """--config-overrides are applied on the host as a local scan applies them."""
    extra = ["--config-overrides", override]
    if with_config:
        stage.named.write_text("project_name: fine\n", encoding="utf-8")
        extra += ["--config", str(stage.named)]
    before = stage.output_snapshot()

    result = _cli(stage, mode, *extra)

    _assert_refused_on_the_host(stage, before, result.exit_code, result.output)


def _assert_started(stage: Stage, mode: str, output: str) -> None:
    calls = stage.runner_calls()
    if mode == "container":
        assert any(call.split()[1:2] == ["run"] for call in calls), (calls, output)
    else:
        assert any(call.startswith("nix ") for call in calls), (calls, output)
    assert "Invalid configuration" not in output


@pytest.mark.parametrize("mode", MODES)
def test_control_a_valid_named_config_starts(stage, mode):
    stage.named.write_text("project_name: fine\n", encoding="utf-8")

    result = _cli(stage, mode, "--config", str(stage.named))

    _assert_started(stage, mode, result.output)


@pytest.mark.parametrize("mode", MODES)
def test_control_a_valid_discovered_config_starts(stage, mode):
    stage.discovered.write_text("project_name: fine\n", encoding="utf-8")

    result = _cli(stage, mode)

    _assert_started(stage, mode, result.output)


@pytest.mark.parametrize("mode", MODES)
def test_control_no_config_file_starts(stage, mode):
    """No --config, no ASH_CONFIG and nothing at a discovered name: the defaults."""
    result = _cli(stage, mode)

    _assert_started(stage, mode, result.output)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "override",
    [
        pytest.param("fail_on_findings=false", id="core-field"),
        pytest.param("scanners.image-only-scanner.options.depth=3", id="plugin-option"),
    ],
)
def test_control_an_override_a_local_scan_accepts_starts(stage, mode, override):
    result = _cli(stage, mode, "--config-overrides", override)

    _assert_started(stage, mode, result.output)


@pytest.mark.parametrize("mode", MODES)
def test_control_options_of_a_plugin_only_the_image_holds_start(stage, mode):
    """Plugin options are checked by the scan inside, which can load the plugin."""
    stage.discovered.write_text(
        "project_name: fine\n"
        "ash_plugin_modules:\n"
        "  - image_only_plugins\n"
        "scanners:\n"
        "  image-only-scanner:\n"
        "    enabled: true\n"
        "    options:\n"
        "      depth: 3\n",
        encoding="utf-8",
    )

    result = _cli(stage, mode)

    _assert_started(stage, mode, result.output)


def test_control_container_no_run_builds_without_judging_the_config(stage):
    """``--no-run`` builds an image and scans nothing, so the config is not judged."""
    _make_unparsable(stage.named)

    from automated_security_helper.cli.main import app

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-progress",
            "--no-run",
            "--source-dir",
            str(stage.source),
            "--output-dir",
            str(stage.output),
            "--config",
            str(stage.named),
        ],
    )

    assert "Invalid configuration" not in result.output
    assert any(call.split()[1:2] == ["build"] for call in stage.runner_calls()), (
        stage.runner_calls(),
        result.output,
    )
