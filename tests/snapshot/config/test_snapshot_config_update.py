# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config update`: what it prints, and the file it leaves behind.

`update` prints the whole updated config rather than a diff, so the snapshot is the
printed config plus the file as written. The printed config includes every default,
which differs on Windows, so the success cases render once per host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.snapshot.support.cli import CONFIG_HOSTS, run_cli, simulated_host

STARTING_CONFIG = """\
# yaml-language-server: $schema=https://example.invalid/AshConfig.json
project_name: snapshot-demo
global_settings:
  severity_threshold: MEDIUM
scanners:
  bandit:
    enabled: true
"""

MODIFICATIONS = [
    "--set",
    "global_settings.severity_threshold=LOW",
    "--set",
    "scanners.bandit.enabled=false",
    "--set",
    'global_settings.ignore_paths+={"path": "dist/**", "reason": "build output"}',
]


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "demo-project"
    project.mkdir()
    (project / "ash.yaml").write_text(STARTING_CONFIG, encoding="utf-8")
    monkeypatch.chdir(project)
    return project


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_update_writes_file(host, project_dir, monkeypatch, text_snapshot):
    with simulated_host(monkeypatch, host):
        run = run_cli(["config", "update", "ash.yaml", *MODIFICATIONS])

    assert run.exit_code == 0, run.output
    assert text_snapshot("txt")(name="stdout") == run.document
    assert text_snapshot("yaml")(name="ash-yaml") == (
        project_dir / "ash.yaml"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_update_dry_run_leaves_file(
    host, project_dir, monkeypatch, text_snapshot
):
    with simulated_host(monkeypatch, host):
        run = run_cli(["config", "update", "ash.yaml", "--dry-run", *MODIFICATIONS])

    assert run.exit_code == 0, run.output
    assert (project_dir / "ash.yaml").read_text(encoding="utf-8") == STARTING_CONFIG
    assert text_snapshot("txt") == run.document


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_update_skips_malformed_modification(
    host, project_dir, monkeypatch, text_snapshot
):
    """A --set without '=' is reported and skipped; the rest still apply and save."""
    with simulated_host(monkeypatch, host):
        run = run_cli(
            [
                "config",
                "update",
                "ash.yaml",
                "--set",
                "fail_on_findings",
                "--set",
                "fail_on_findings=false",
            ]
        )

    assert run.exit_code == 0, run.output
    assert "Invalid modification format: fail_on_findings." in run.output
    assert text_snapshot("txt") == run.document


@pytest.mark.parametrize(
    "args, exit_code",
    [
        pytest.param(["config", "update", "ash.yaml"], 0, id="no-modifications"),
        pytest.param(
            ["config", "update", "missing.yaml", "--set", "a=b"], 1, id="missing-file"
        ),
        pytest.param(
            ["config", "update", "ash.yaml", "--set", "fail_on_findings=maybe"],
            1,
            id="invalid-value",
        ),
        # Not JSON, so the list parser splits on every comma.
        pytest.param(
            [
                "config",
                "update",
                "ash.yaml",
                "--set",
                "global_settings.ignore_paths+=[{path: 'dist/**', reason: 'x'}]",
            ],
            1,
            id="non-json-object-in-list",
        ),
    ],
)
def test_config_update_errors(args, exit_code, project_dir, text_snapshot):
    run = run_cli(args)

    assert run.exit_code == exit_code, run.output
    assert (project_dir / "ash.yaml").read_text(encoding="utf-8") == STARTING_CONFIG
    assert text_snapshot("txt") == run.document
