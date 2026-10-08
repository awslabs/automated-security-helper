# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file inside the scanned tree cannot widen the scanner sandbox."""

from pathlib import Path

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.orchestrator import ASHScanOrchestrator

REPO_CONFIG = """project_name: scanned
sandbox:
  mode: bwrap
  network_scanners: [checkov]
  extra_read_paths: ["~"]
"""


def _orchestrator(source: Path, config_path=None, overrides=None):
    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=source / "out",
        config_path=config_path,
        config_overrides=overrides,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    orchestrator.config = resolve_config(
        config_path=config_path,
        source_dir=source,
        config_overrides=overrides or [],
    )
    orchestrator._ignore_repo_sandbox_grants()
    return orchestrator.config.sandbox


def test_grants_from_a_discovered_config_in_the_tree_are_ignored(tmp_path):
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(REPO_CONFIG)
    sandbox = _orchestrator(source)
    assert sandbox.mode == "bwrap"
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_grants_from_an_explicit_config_inside_the_tree_are_ignored(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    config = source / "ash.yaml"
    config.write_text(REPO_CONFIG)
    sandbox = _orchestrator(source, config_path=config)
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []


def test_grants_from_a_config_outside_the_tree_are_kept(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    config = tmp_path / "trusted.yaml"
    config.write_text(REPO_CONFIG)
    sandbox = _orchestrator(source, config_path=config)
    assert sandbox.network_scanners == ["checkov"]
    assert sandbox.extra_read_paths == ["~"]


def test_grants_from_command_line_overrides_are_kept(tmp_path):
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(REPO_CONFIG)
    sandbox = _orchestrator(
        source,
        overrides=["sandbox.network_scanners=[grype]"],
    )
    assert sandbox.network_scanners == ["grype"]
    assert sandbox.extra_read_paths == []
