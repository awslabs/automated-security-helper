# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The ashrc and [tool.ash] config sources, found the way the IDEs and the container
run a scan.

None of the three passes ``--config``, so each relies on discovery from the scan
root:

* The VS Code extension runs ``ashx scan --source-dir <folder>`` with NO working
  directory of its own (src/ash-cli.ts, CommandOptions), so the process cwd is
  wherever the extension host started. Discovery must use ``--source-dir`` and
  never the cwd, or a stray config in the host's cwd would govern the scan.
* The JetBrains plugin runs the same command with the working directory set to
  the project (AshScanRunner.kt), so cwd and source dir agree.
* Container mode bind-mounts the source directory at ``/src`` and runs
  ``ashx scan --source-dir /src`` inside it. The host also reads the discovered
  config itself, for the exit-code fields, before the container starts.
"""

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _resolve_config_fail_on_findings,
)

SOURCES = {
    "pyproject.toml": (
        '[project]\nname = "app"\n\n'
        '[tool.ash]\nproject_name = "from-source-dir"\nfail_on_findings = false\n'
    ),
    ".ashrc.yaml": "project_name: from-source-dir\nfail_on_findings: false\n",
    "ashrc.json": '{"project_name": "from-source-dir", "fail_on_findings": false}\n',
}


def _project(tmp_path: Path, name: str) -> Path:
    source = tmp_path / "workspace"
    source.mkdir()
    (source / name).write_text(SOURCES[name])
    return source


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_vscode_shape_finds_the_source_dir_config_not_the_cwd_one(
    tmp_path, monkeypatch, name
):
    source = _project(tmp_path, name)
    host_cwd = tmp_path / "extension-host-cwd"
    host_cwd.mkdir()
    # A config the scan must NOT pick up: it sits in the process cwd, which for
    # VS Code is unrelated to the folder being scanned.
    (host_cwd / ".ashrc.yaml").write_text("project_name: from-cwd\n")
    monkeypatch.chdir(host_cwd)

    config = resolve_config(source_dir=source)

    assert config.project_name == "from-source-dir"


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_jetbrains_shape_finds_the_config_with_cwd_at_the_project(
    tmp_path, monkeypatch, name
):
    source = _project(tmp_path, name)
    monkeypatch.chdir(source)

    config = resolve_config(source_dir=source)

    assert config.project_name == "from-source-dir"


def _container_command(source: Path) -> list[str]:
    return _assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name="automated-security-helper:local",
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        offline=False,
        debug=False,
        color=False,
        quiet=False,
        progress=False,
        verbose=False,
        simple=False,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=None,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=None,
        ctx=None,
    )


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_container_mounts_the_dir_holding_the_config_and_lets_discovery_run(
    tmp_path, name
):
    source = _project(tmp_path, name)

    cmd = _container_command(source)

    # The config is at the root of the one directory mounted at /src...
    mounts = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--mount"]
    source_mounts = [m for m in mounts if "destination=/src" in m]
    assert len(source_mounts) == 1
    assert f"source={source}," in source_mounts[0]
    assert (source / name).is_file()
    # ...the in-container scan is rooted there, and no --config overrides
    # discovery, so the in-container resolver sees exactly what the host's would.
    assert cmd[cmd.index("--source-dir") + 1] == "/src"
    assert "--config" not in cmd
    assert resolve_config(source_dir=source).project_name == "from-source-dir"


@pytest.mark.parametrize("name", sorted(SOURCES))
def test_container_host_reads_fail_on_findings_from_the_newer_sources(
    tmp_path, monkeypatch, name
):
    source = _project(tmp_path, name)
    monkeypatch.chdir(tmp_path)

    opts = ScanOptions(source_dir=source, output_dir=source / ".ash" / "ash_output")

    assert _resolve_config_fail_on_findings(opts) is False
