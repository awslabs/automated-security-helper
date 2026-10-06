# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ashx plugin list`: the scanner, converter and reporter tables.

The plugin set is the real built-in one. What is faked is the environment probe
behind ``--show-versions``: ``list_scanner_inventory`` instantiates every scanner and
asks whether its tool is installed and which version it is, which is a fact about
the machine running the test. It is replaced by a fixed inventory that covers each
Reachable label (Yes, No, Unknown) and a missing version.

The Enabled column shows the semgrep and opengrep defaults, which are off on
Windows, so each listing renders once per host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.snapshot.support.cli import CONFIG_HOSTS, run_cli, simulated_host

#: scanner name -> (detected version, dependencies_satisfied). Scanners not listed
#: report neither, which renders as "Unknown" / "Unknown".
FAKE_PROBES = {
    "bandit": ("1.8.6", True),
    "checkov": ("3.2.470", True),
    "grype": (None, False),
    "semgrep": ("1.139.0", None),
    "syft": ("1.33.0", False),
}


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "demo-project"
    project.mkdir()
    monkeypatch.chdir(project)
    return project


@pytest.fixture
def fake_inventory(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the version/reachability probe; returns the names it was asked about."""
    from automated_security_helper.core import scanner_inventory

    asked: list[str] = []

    def list_scanner_inventory(scanner_classes_provider=None):
        entries = []
        for cls in scanner_classes_provider():
            name = scanner_inventory._scanner_name_from_class(cls)
            asked.append(name)
            version, satisfied = FAKE_PROBES.get(name, (None, None))
            entries.append(
                {
                    "name": name,
                    "version": version,
                    "dependencies_satisfied": satisfied,
                    "offline_strategy": "unknown",
                    "enabled": True,
                }
            )
        return entries

    monkeypatch.setattr(
        scanner_inventory, "list_scanner_inventory", list_scanner_inventory
    )
    return asked


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_plugin_list(host, project_dir, monkeypatch, text_snapshot):
    with simulated_host(monkeypatch, host):
        run = run_cli(["plugin", "list"])

    assert run.exit_code == 0, run.output
    for title in ("ASH Scanners", "ASH Converters", "ASH Reporters"):
        assert title in run.output
    assert text_snapshot("txt") == run.document


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_plugin_list_show_versions(
    host, project_dir, monkeypatch, fake_inventory, text_snapshot
):
    with simulated_host(monkeypatch, host):
        run = run_cli(["plugin", "list", "--show-versions"])

    assert run.exit_code == 0, run.output
    assert set(FAKE_PROBES) <= set(fake_inventory), fake_inventory
    assert text_snapshot("txt") == run.document


def test_plugin_list_with_plugin_config(project_dir, monkeypatch, text_snapshot):
    (project_dir / "custom.yaml").write_text(
        "project_name: snapshot-demo\n"
        "scanners:\n"
        "  bandit:\n"
        "    enabled: false\n"
        "reporters:\n"
        "  markdown:\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    from tests.snapshot.support.cli import LINUX_AMD64

    with simulated_host(monkeypatch, LINUX_AMD64):
        run = run_cli(
            ["plugin", "list", "-c", "custom.yaml", "--include-plugin-config"]
        )

    assert run.exit_code == 0, run.output
    assert text_snapshot("txt") == run.document


def test_plugin_list_bad_config(project_dir, text_snapshot):
    (project_dir / "bad.yaml").write_text(
        "project_name: x\nfail_on_findings: maybe\n", encoding="utf-8"
    )

    run = run_cli(["plugin", "list", "-c", "bad.yaml"])

    assert run.exit_code == 1, run.output
    assert text_snapshot("txt") == run.document
