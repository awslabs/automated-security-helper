# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``resolve_config(untrusted_config=True)``: a caller-supplied config grants nothing.

A config file inside the scanned tree has its sandbox grants confined, because the
repository under scan wrote it. ``untrusted_config`` applies the same rule to a
selected config whose author is the caller rather than the operator -- an MCP
client's upload named as ``config_path`` -- wherever the file sits. Every config
here lives outside the scanned directory, so without the flag its grants would be
kept; the positive controls show that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

GRANTS_AND_OFF = (
    "project_name: uploaded\n"
    "sandbox:\n"
    "  mode: 'off'\n"
    "  network_scanners: [checkov]\n"
    "  extra_read_paths: ['/']\n"
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A scanned directory, and an upload area beside it (outside the tree)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    upload = tmp_path / "upload"
    upload.mkdir()
    return scanned, upload


def _network(sandbox, scanner: str, declared: bool, tmp: Path) -> bool:
    (tmp / "res").mkdir(exist_ok=True)
    return build_scanner_policy(
        scanner,
        SandboxRequirements(network=declared),
        argv0="/bin/true",
        source_dir=tmp,
        output_dir=tmp,
        results_dir=tmp / "res",
        scan_target=None,
        cwd=None,
        offline=False,
        network_scanners=sandbox.network_scanners,
        extra_read_paths=sandbox.extra_read_paths,
        network_limit=sandbox.network_limit,
    ).network


def test_uploaded_grants_are_dropped_and_the_server_mode_holds(
    layout, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned, upload = layout
    operator = _write(tmp_path / "operator" / "ash.yaml", "sandbox:\n  mode: bwrap\n")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    uploaded = _write(upload / "ash.yaml", GRANTS_AND_OFF)

    config = resolve_config(
        config_path=uploaded, source_dir=scanned, untrusted_config=True
    )

    assert config.project_name == "uploaded"
    assert config.sandbox.mode == "bwrap"
    assert config.sandbox.network_scanners is None
    assert config.sandbox.extra_read_paths == []
    # The uploaded list is kept as a limit, which can only take network away.
    assert config.sandbox.network_limit == ["checkov"]


def test_an_uploaded_empty_network_list_still_removes_network(
    layout, tmp_path: Path
) -> None:
    scanned, upload = layout
    uploaded = _write(upload / "ash.yaml", "sandbox:\n  network_scanners: []\n")

    config = resolve_config(
        config_path=uploaded, source_dir=scanned, untrusted_config=True
    )

    assert config.sandbox.network_limit == []
    # grype declares a network need; the uploaded empty list takes it away.
    assert _network(config.sandbox, "grype", True, tmp_path) is False


def test_the_trusted_base_supplies_the_grants_and_the_mode(
    layout, tmp_path: Path
) -> None:
    """The session's registered profile, passed as trusted_config_path."""
    scanned, upload = layout
    profile = _write(
        tmp_path / "session" / "config" / "ash.yaml",
        "sandbox:\n"
        "  mode: bwrap\n"
        "  network_scanners: [grype]\n"
        "  extra_read_paths: ['/opt/ca']\n",
    )
    uploaded = _write(upload / "ash.yaml", GRANTS_AND_OFF)

    config = resolve_config(
        config_path=uploaded,
        source_dir=scanned,
        untrusted_config=True,
        trusted_config_path=profile,
    )

    assert config.sandbox.mode == "bwrap"
    assert config.sandbox.network_scanners == ["grype"]
    assert config.sandbox.extra_read_paths == ["/opt/ca"]
    assert config.sandbox.network_limit == ["checkov"]
    # checkov is neither granted by the profile nor declared: no network. grype is
    # granted by the profile but not named by the uploaded limit: no network either.
    assert _network(config.sandbox, "checkov", False, tmp_path) is False
    assert _network(config.sandbox, "grype", True, tmp_path) is False


def test_an_uploaded_mode_may_turn_the_sandbox_on(layout) -> None:
    """A mode other than off takes access away, so it applies when nothing sets one."""
    scanned, upload = layout
    uploaded = _write(upload / "ash.yaml", "sandbox:\n  mode: bwrap\n")

    config = resolve_config(
        config_path=uploaded, source_dir=scanned, untrusted_config=True
    )

    assert config.sandbox.mode == "bwrap"


def test_every_file_of_the_uploaded_chain_is_untrusted(layout) -> None:
    scanned, upload = layout
    _write(
        upload / "base.yaml",
        "sandbox:\n  network_scanners: [checkov]\n  extra_read_paths: ['/']\n",
    )
    uploaded = _write(upload / "ash.yaml", "extends: base.yaml\nproject_name: x\n")

    config = resolve_config(
        config_path=uploaded, source_dir=scanned, untrusted_config=True
    )

    assert config.sandbox.network_scanners is None
    assert config.sandbox.extra_read_paths == []


def test_positive_control_a_trusted_config_outside_the_tree_still_grants(
    layout, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same file, not marked untrusted: an operator's config keeps its grants."""
    scanned, upload = layout
    operator = _write(tmp_path / "operator" / "ash.yaml", "sandbox:\n  mode: bwrap\n")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    config_file = _write(upload / "ash.yaml", GRANTS_AND_OFF)

    config = resolve_config(config_path=config_file, source_dir=scanned)

    assert config.sandbox.mode == "off"
    assert config.sandbox.network_scanners == ["checkov"]
    assert config.sandbox.extra_read_paths == ["/"]
    assert config.sandbox.network_limit is None
