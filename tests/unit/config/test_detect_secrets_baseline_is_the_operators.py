# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository's config does not choose a detect-secrets baseline outside the tree.

detect-secrets reads its baseline file in the ASH process, outside any sandbox,
and applies the baseline's ``plugins_used``, ``filters_used`` and results. So
``scanners.detect-secrets.options.baseline_file`` is a choice of the operator's
(``config/tool_config_trust.py``): from a config file inside the scanned tree it
gets the trusted value, even when the operator's own config grants the sandbox a
read path that holds the file. The scanner's by-name lookup of
``.secrets.baseline`` is not covered here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
)

#: A plugin name only the host baseline lists, so its presence proves a read.
MARKER = "HostBaselineMarkerDetector"


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    host = tmp_path / "host"
    host.mkdir()
    baseline = host / "shared.baseline"
    baseline.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": MARKER}],
                "filters_used": [],
                "results": {},
            }
        ),
        encoding="utf-8",
    )
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    # The operator grants the sandbox a read path that holds the baseline.
    operator.write_text(
        yaml.safe_dump({"sandbox": {"extra_read_paths": [str(host)]}}),
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "repo",
                "scanners": {
                    "detect-secrets": {"options": {"baseline_file": str(baseline)}}
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    # The scanner looks up .secrets.baseline by name in the working directory;
    # the repository has none.
    monkeypatch.chdir(repo)
    return {"repo": repo, "baseline": baseline, "host": host, "tmp": tmp_path}


def _scanner(config, layout) -> DetectSecretsScanner:
    context = PluginContext(
        source_dir=layout["repo"],
        output_dir=layout["tmp"] / "out",
        work_dir=layout["tmp"] / "work",
        config=config,
    )
    return DetectSecretsScanner(context=context, config=config.scanners.detect_secrets)


def _plugin_names(scanner: DetectSecretsScanner) -> list:
    return [p.name for p in scanner.config.options.scan_settings.plugins_used]


def test_a_repository_baseline_outside_the_tree_is_not_read(layout) -> None:
    config = resolve_config(source_dir=layout["repo"])

    assert config.sandbox.extra_read_paths == [str(layout["host"])]
    assert config.scanners.detect_secrets.options.baseline_file is None
    scanner = _scanner(config, layout)
    assert scanner.config.options.baseline_file is None
    assert MARKER not in _plugin_names(scanner)


def test_positive_control_the_operator_naming_it_is_read(layout) -> None:
    """The same file named by the operator is read, so the check above can fail."""
    config = resolve_config(
        source_dir=layout["repo"],
        config_overrides=[
            f"scanners.detect-secrets.options.baseline_file={layout['baseline']}"
        ],
    )

    scanner = _scanner(config, layout)
    assert Path(scanner.config.options.baseline_file) == layout["baseline"]
    assert MARKER in _plugin_names(scanner)
