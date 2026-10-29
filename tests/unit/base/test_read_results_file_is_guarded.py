# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_read_results_file`` reads the tool's results file under the fs_guard reader.

A plain ``open()`` followed a link left at the name (a process the sandboxed
scanner left running can replace the file with a link to any file on the
host), blocked ASH for good on a FIFO at the name, and read without bound.
The read now goes through ``fs_guard.read_bytes_at_most``: the link is
refused, a FIFO cannot block the open, and a file over the bound is refused
with its size. The FIFO case is not measured here: at the base it would hang
the run that measures the base.
"""

from __future__ import annotations

import os

import pytest

import automated_security_helper.base.scanner_plugin as scanner_plugin_module
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def test_a_link_at_the_results_name_is_refused(plugin_context, tmp_path):
    real = tmp_path / "elsewhere.json"
    real.write_text('{"runs": []}', encoding="utf-8")
    link = tmp_path / "results.json"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    scanner = _scanner(plugin_context)

    with pytest.raises(OSError):
        scanner._read_results_file(link)


def test_a_results_file_over_the_bound_is_refused_with_its_size(
    plugin_context, tmp_path, monkeypatch
):
    monkeypatch.setattr(scanner_plugin_module, "_RESULTS_FILE_READ_LIMIT", 8)
    results = tmp_path / "results.json"
    results.write_text('{"runs": [1, 2, 3, 4]}', encoding="utf-8")
    scanner = _scanner(plugin_context)

    with pytest.raises(ScannerError, match="larger than 8 bytes"):
        scanner._read_results_file(results)


def test_a_regular_results_file_is_still_read(plugin_context, tmp_path):
    results = tmp_path / "results.json"
    results.write_text('{"runs": []}', encoding="utf-8")
    scanner = _scanner(plugin_context)

    assert scanner._read_results_file(results) == {"runs": []}
    results.write_text("   ", encoding="utf-8")
    assert scanner._read_results_file(results) is None
