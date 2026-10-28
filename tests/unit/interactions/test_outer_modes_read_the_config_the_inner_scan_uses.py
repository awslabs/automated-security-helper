# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The host reads fail_on_findings and fail_on_incomplete_scanners from the config the scan uses.

Container and nix mode read these two fields on the host: container mode forwards
them to the scan inside as command-line flags, which win over that scan's own
config, and nix mode decides the exit code from them. The host read took
``--config`` or the discovered file only, without ``--config-overrides``, while a
local scan resolves ``ASH_CONFIG``'s file when it finds none and applies the
overrides. So an ``ASH_CONFIG``-only config or an override that sets either field
was dropped: nix mode failed on findings the operator turned off, and container
mode handed the scan inside the file's value in place of the override.

The host now reads the config in a local scan's order (``--config``, the
discovered file, ``ASH_CONFIG``'s file) with the overrides applied, the same read
that refuses an unusable config before anything starts.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _resolve_config_fail_on_findings,
    _resolve_config_fail_on_incomplete_scanners,
)
from automated_security_helper.utils import subprocess_utils


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture
def source(tmp_path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    return source


def _opts(source: Path, mode: RunMode, overrides: List[str] | None = None):
    return ScanOptions(
        source_dir=source,
        output_dir=source.parent / "out",
        mode=mode,
        config_overrides=overrides or [],
    )


def _operator_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(f"project_name: operator\n{body}", encoding="utf-8")
    return path


@pytest.mark.parametrize("mode", [RunMode.nix, RunMode.container])
def test_ash_config_s_file_is_read_when_no_config_is_found(
    tmp_path, source, monkeypatch, mode
):
    env_config = _operator_config(
        tmp_path, "fail_on_findings: false\nfail_on_incomplete_scanners: false\n"
    )
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    opts = _opts(source, mode)

    assert _resolve_config_fail_on_findings(opts) is False
    assert _resolve_config_fail_on_incomplete_scanners(opts) is False


@pytest.mark.parametrize("mode", [RunMode.nix, RunMode.container])
def test_an_override_sets_the_fields_with_no_config_file(source, mode):
    opts = _opts(
        source,
        mode,
        ["fail_on_findings=false", "fail_on_incomplete_scanners=false"],
    )

    assert _resolve_config_fail_on_findings(opts) is False
    assert _resolve_config_fail_on_incomplete_scanners(opts) is False


@pytest.mark.parametrize("mode", [RunMode.nix, RunMode.container])
def test_an_override_wins_over_the_config_file(source, mode):
    (source / ".ash.yaml").write_text(
        "project_name: p\nfail_on_findings: true\nfail_on_incomplete_scanners: true\n",
        encoding="utf-8",
    )
    opts = _opts(
        source,
        mode,
        ["fail_on_findings=false", "fail_on_incomplete_scanners=false"],
    )

    assert _resolve_config_fail_on_findings(opts) is False
    assert _resolve_config_fail_on_incomplete_scanners(opts) is False


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param([], id="nothing"),
        pytest.param(["scanners.bandit.enabled=false"], id="an-unrelated-override"),
    ],
)
def test_control_with_no_config_file_nothing_is_read(source, overrides):
    """Unset, as before: the caller tells "not set" from a file that sets it."""
    opts = _opts(source, RunMode.nix, overrides)

    assert _resolve_config_fail_on_findings(opts) is None
    assert _resolve_config_fail_on_incomplete_scanners(opts) is None


def test_control_the_discovered_file_wins_over_ash_config(
    tmp_path, source, monkeypatch
):
    """As in a local scan: ASH_CONFIG is the fallback when the directory has none."""
    monkeypatch.setenv(
        "ASH_CONFIG", str(_operator_config(tmp_path, "fail_on_findings: false\n"))
    )
    (source / ".ash.yaml").write_text(
        "project_name: p\nfail_on_findings: true\n", encoding="utf-8"
    )

    assert _resolve_config_fail_on_findings(_opts(source, RunMode.nix)) is True


def test_container_mode_hands_the_scan_inside_the_overridden_value(
    tmp_path, source, monkeypatch
):
    """The flag container mode forwards wins inside, so it has to be the override's."""
    runner_log = tmp_path / "runner.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("docker", "podman", "finch", "nerdctl"):
        if sys.platform == "win32":
            # CreateProcess starts no shell script. ASH tries name.exe, name.bat and
            # name.cmd before the bare name, so the stub is a .cmd that runs a
            # Python script appending the same line.
            script = bin_dir / f"{name}_stub.py"
            script.write_text(
                "import sys\n"
                f"with open({str(runner_log)!r}, 'a', encoding='utf-8') as log:\n"
                f"    log.write({name!r} + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n"
                "sys.exit(97)\n",
                encoding="utf-8",
            )
            (bin_dir / f"{name}.cmd").write_text(
                f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8"
            )
            continue
        stub = bin_dir / name
        stub.write_text(
            f'#!/bin/sh\necho "{name} $*" >> "{runner_log}"\nexit 97\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    for name in ("ASH_IMAGE_NAME", "ASH_IN_CONTAINER", "CI", "OCI_RUNNER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.chdir(tmp_path)
    config = _operator_config(tmp_path, "fail_on_findings: true\n")

    from automated_security_helper.cli.main import app

    CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(config),
            "--config-overrides",
            "fail_on_findings=false",
        ],
    )

    runs = [
        line.split()
        for line in runner_log.read_text(encoding="utf-8").splitlines()
        if line.split()[1:2] == ["run"]
    ]
    assert len(runs) == 1, runs
    assert "--no-fail-on-findings" in runs[0], runs[0]
    assert "--fail-on-findings" not in runs[0], runs[0]
