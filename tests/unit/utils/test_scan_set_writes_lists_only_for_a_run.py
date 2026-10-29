# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan_set`` writes the scan-set pair only for a run, or when asked to.

The pair is ``ash-ignore-report.txt`` and ``ash-scan-set-files-list.txt``. Were a
call with no run ID to write them into the output directory, nothing would read
them back without one (``get_scan_set``): a scanner or converter run on its own,
and ``ash merge``'s suppression step, would replace the pair there on every call,
a pair the repository committed to its ``.ash/ash_output`` included.

So the pair is written for a call with a run ID, which also writes the record the
read-back checks, and for one that passes ``write_lists=True``, as the
``get_scan_set`` command line does, which writes no record. Any other call
leaves the output directory out of the walk, and writes nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.get_scan_set import main, scan_set
from automated_security_helper.utils.scan_output_dirs import scan_set_of

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
PluginContext.model_rebuild()

IGNORE_REPORT = "ash-ignore-report.txt"
SCAN_SET_LIST = "ash-scan-set-files-list.txt"
RUN_RECORD = "ash-scan-set-run.json"
LISTS = (IGNORE_REPORT, SCAN_SET_LIST, RUN_RECORD)


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "src"
    source.mkdir()
    for name in ("app.py", "other.py"):
        (source / name).write_text("x = 1\n", encoding="utf-8")
    return source, tmp_path / "out"


def _present(output: Path) -> list[str]:
    return [name for name in LISTS if (output / name).exists()]


def test_a_call_without_a_run_id_writes_nothing(tmp_path):
    source, output = _tree(tmp_path)

    found = scan_set(source=str(source), output=str(output))

    assert {Path(f).name for f in found} == {"app.py", "other.py"}
    assert _present(output) == []


def test_a_call_without_a_run_id_leaves_a_pair_in_the_output_dir_as_it_was(tmp_path):
    source, output = _tree(tmp_path)
    output.mkdir()
    pair = {
        IGNORE_REPORT: b"# the repository's own report\n",
        SCAN_SET_LIST: b"app.py\n",
    }
    for name, data in pair.items():
        (output / name).write_bytes(data)

    scan_set(source=str(source), output=str(output))

    assert {name: (output / name).read_bytes() for name in pair} == pair
    assert not (output / RUN_RECORD).exists()


def test_a_scanner_run_on_its_own_writes_nothing(tmp_path):
    """A context with no run ID, as a plugin built outside a scan has."""
    source, output = _tree(tmp_path)
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())

    found = scan_set_of(context)

    assert {Path(f).name for f in found} == {"app.py", "other.py"}
    assert _present(output) == []


def test_write_lists_writes_the_pair_and_no_record(tmp_path):
    source, output = _tree(tmp_path)

    found = scan_set(source=str(source), output=str(output), write_lists=True)

    assert (output / SCAN_SET_LIST).read_text(encoding="utf-8") == "\n".join(found)
    assert "ASH_INCLUSIONS" in (output / IGNORE_REPORT).read_text(encoding="utf-8")
    assert not (output / RUN_RECORD).exists()


def test_a_run_writes_the_pair_and_its_record(tmp_path):
    source, output = _tree(tmp_path)

    scan_set(source=str(source), output=str(output), run_id="a" * 32)

    assert _present(output) == list(LISTS)


def test_the_command_line_writes_the_pair_to_its_output(tmp_path, capsys):
    source, output = _tree(tmp_path)
    argv = ["get_scan_set", "--source", str(source), "--output", str(output)]

    with patch.object(sys, "argv", argv):
        assert main() == 0

    capsys.readouterr()
    assert _present(output) == [IGNORE_REPORT, SCAN_SET_LIST]


def test_a_run_id_that_is_not_a_string_is_no_run_id(tmp_path):
    """A context a test or another plugin builds may carry anything in run_id. Only
    a string is a run's ID: anything else walks, and writes neither the pair nor a
    record, which could not hold it."""
    from automated_security_helper.utils import get_scan_set as gss

    source, output = _tree(tmp_path)

    with patch.object(
        gss,
        "_collect_ignorefiles_and_all_files",
        wraps=gss._collect_ignorefiles_and_all_files,
    ) as walk:
        found = scan_set(source=str(source), output=str(output), run_id=MagicMock())

    assert walk.call_count == 1
    assert {Path(f).name for f in found} == {"app.py", "other.py"}
    assert _present(output) == []
