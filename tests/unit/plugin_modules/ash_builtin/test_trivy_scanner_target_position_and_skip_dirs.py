# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where the builtin trivy scanner puts its own flags, and which output directories
it can tell trivy to skip.

- The flags were inserted before the FIRST token equal to the target's spelling.
  ``_resolve_arguments`` places the target last, after the options, so a relative
  target spelled like an earlier value (``sarif``, the format) moved the insertion
  point into the options and split ``--format`` from its value.
- An output directory whose relative path holds a line break was passed as a
  ``--skip-dirs`` value, which trivy reads as one line of CSV and cuts at the
  break, skipping a different directory.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for name in ("TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG"):
        monkeypatch.delenv(name, raising=False)


def _scanner(source: Path, output: Path) -> TrivyScanner:
    source.mkdir(parents=True, exist_ok=True)
    (source / "requirements.txt").write_text("requests==2.19.0\n")
    output.mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return TrivyScanner(
        context=context,
        config=TrivyScannerConfig(options=TrivyScannerConfigOptions(offline=False)),
    )


def test_a_relative_target_spelled_like_the_format_value_keeps_the_options_whole(
    tmp_path, monkeypatch
):
    """A tree named ``sarif``, scanned by its relative name from its parent."""
    source = tmp_path / "sarif"
    scanner = _scanner(source, source / ".ash" / "ash_output")
    monkeypatch.chdir(tmp_path)

    final_args, _, _ = scanner._execute_scan(Path("sarif"), "source", [])

    assert final_args[final_args.index("--format") + 1] == "sarif"
    target_index = len(final_args) - 1 - final_args[::-1].index("sarif")
    option_indexes = [
        index for index, token in enumerate(final_args) if token.startswith("--config=")
    ]
    assert option_indexes and all(index < target_index for index in option_indexes)
    assert final_args[target_index + 1] == "--output"


@pytest.mark.skipif(os.name == "nt", reason="a file name cannot hold a line break")
def test_an_output_directory_whose_path_holds_a_line_break_is_not_passed_to_skip_dirs(
    tmp_path, caplog
):
    source = tmp_path / "src"
    scanner = _scanner(source, source / "out\nput")

    with caplog.at_level("WARNING"):
        final_args, _, _ = scanner._execute_scan(source, "source", [])

    assert not any(token.startswith("--skip-dirs") for token in final_args), final_args
    assert "line break" in caplog.text
    assert "out\nput" not in caplog.text


def test_control_an_output_directory_inside_the_target_is_skipped(tmp_path):
    source = tmp_path / "src"
    scanner = _scanner(source, source / ".ash" / "ash_output")

    final_args, _, _ = scanner._execute_scan(source, "source", [])

    assert "--skip-dirs=.ash/ash_output" in final_args
