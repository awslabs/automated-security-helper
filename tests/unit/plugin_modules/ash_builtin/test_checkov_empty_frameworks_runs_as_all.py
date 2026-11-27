# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An empty ``frameworks`` list runs checkov as ``all`` does.

checkov reads no ``--framework`` as all frameworks: its parser gives the option no
default (checkov 3.3.26 common/util/ext_argument_parser.py:248) and its
normalization sets ``['all']`` when none is given (main.py:248-250). ASH passed no
``--framework`` for ``frameworks: []``, and left the GitLab, GitHub and Bitbucket
configuration frameworks out only when the list named ``all``, so an empty list
ran all three. It is now passed as ``all`` is: the config file's frameworks take
its place, and the three are left out unless a list names them.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _VCS_CONFIGURATION_FRAMEWORKS,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

#: The words each offline warning of a VCS configuration framework that runs
#: starts with (CheckovScanner._warn_offline_vcs_frameworks).
_RUNS_OFFLINE = "framework runs in this offline scan"


def _scanner(tmp_path: Path, name: str, **opts) -> CheckovScanner:
    """A scanner with its own source and output directories below ``tmp_path``."""
    source = tmp_path / name / "src"
    source.mkdir(parents=True)
    output = tmp_path / name / "out"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _framework_flags(scanner: CheckovScanner, *, offline: bool = False) -> dict:
    """The ``--framework`` and ``--skip-framework`` values of the command line
    checkov is given, in order."""
    with patch.object(CheckovScanner, "_scanner_offline", return_value=offline):
        command, _, _ = scanner._execute_scan(scanner.context.source_dir, "source", [])
    tokens = list(command)
    return {
        flag: [tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token == flag]
        for flag in ("--framework", "--skip-framework")
    }


def _operator_config(tmp_path: Path, text: str) -> str:
    config_file = tmp_path / "operator" / ".checkov.yaml"
    config_file.parent.mkdir(exist_ok=True)
    config_file.write_text(text, encoding="utf-8")
    return str(config_file)


def test_an_empty_list_passes_what_all_passes(tmp_path):
    empty = _framework_flags(_scanner(tmp_path, "empty", frameworks=[]))
    default = _framework_flags(_scanner(tmp_path, "default"))

    assert empty == default
    assert empty["--framework"] == ["all"]
    assert sorted(empty["--skip-framework"]) == sorted(_VCS_CONFIGURATION_FRAMEWORKS)


@pytest.mark.parametrize("vcs_fw", _VCS_CONFIGURATION_FRAMEWORKS)
def test_an_empty_list_takes_the_config_files_frameworks_as_all_does(tmp_path, vcs_fw):
    config_file = _operator_config(tmp_path, f"framework:\n  - all\n  - {vcs_fw}\n")
    empty = _framework_flags(
        _scanner(tmp_path, "empty", frameworks=[], config_file=config_file)
    )
    default = _framework_flags(_scanner(tmp_path, "default", config_file=config_file))

    assert empty == default
    assert empty["--framework"] == ["all", vcs_fw]
    assert vcs_fw not in empty["--skip-framework"]
    for other in _VCS_CONFIGURATION_FRAMEWORKS:
        if other != vcs_fw:
            assert other in empty["--skip-framework"]


def test_an_empty_list_beside_skip_frameworks_skips_as_all_does(tmp_path):
    empty = _framework_flags(
        _scanner(tmp_path, "empty", frameworks=[], skip_frameworks=["secrets"])
    )
    default = _framework_flags(
        _scanner(tmp_path, "default", skip_frameworks=["secrets"])
    )

    assert empty == default
    assert "secrets" in empty["--skip-framework"]
    for vcs_fw in _VCS_CONFIGURATION_FRAMEWORKS:
        assert empty["--skip-framework"].count(vcs_fw) == 1


def test_an_offline_scan_with_an_empty_list_warns_of_no_vcs_framework(tmp_path, caplog):
    scanner = _scanner(tmp_path, "empty", frameworks=[], offline=True)

    with caplog.at_level(logging.WARNING, logger="ash"):
        _framework_flags(scanner, offline=True)

    said = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and _RUNS_OFFLINE in record.getMessage()
    ]
    assert said == []
