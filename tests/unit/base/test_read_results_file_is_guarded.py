# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_read_results_file`` reads the tool's results file under the fs_guard reader.

A plain ``open()`` followed a link left at the name (a process the sandboxed
scanner left running can replace the file with a link to any file on the
host), blocked ASH for good on a FIFO at the name, and read without bound.
The read now goes through ``fs_guard.read_bytes_at_most``: the link is
refused, a FIFO cannot block the open, and a file over the bound is refused
with its size. The FIFO case runs the read on a daemon thread with a join
timeout and releases the FIFO afterwards, so a regression to a blocking open
fails the test and cannot hang the run that measures it.
"""

from __future__ import annotations

import os
import threading

import pytest

import automated_security_helper.base.scanner_plugin as scanner_plugin_module
from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.scanner_support import build_scanner as _scanner

pytestmark = pytest.mark.unit


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


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_fifo_at_the_results_name_is_refused_without_blocking(
    plugin_context, tmp_path
):
    fifo = tmp_path / "results.json"
    os.mkfifo(fifo)
    scanner = _scanner(plugin_context)
    outcome: list[BaseException | None] = []

    def _read() -> None:
        try:
            scanner._read_results_file(fifo)
            outcome.append(None)
        except BaseException as error:  # noqa: BLE001
            outcome.append(error)

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        reader.join(timeout=10)
        finished = not reader.is_alive()
    finally:
        # Opening a FIFO read-write never blocks and releases a reader stuck in
        # its own open, so a hung reader does not outlive the test.
        os.close(os.open(fifo, os.O_RDWR))
        reader.join(timeout=10)

    assert finished, "the reader blocked on the FIFO"
    assert len(outcome) == 1 and isinstance(outcome[0], OSError), outcome


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
