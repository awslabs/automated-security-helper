# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan failure message keeps the tail of a long stderr.

``_describe_scan_failure`` quotes the tool's stderr through ``head_and_tail``,
because a tool says why it failed in its LAST lines. Before that excerpt ran,
the text was cut to its first 2000 characters, so the tail the excerpt was
meant to keep was already gone, the excerpt's tail was the cut's own marker,
and its omitted count was wrong.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import _STDERR_EXCERPT_LIMIT
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


def test_the_tools_last_words_survive_a_long_stderr(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.exit_code = 2
    filler = [f"progress line {index} of the tool's chatter" for index in range(120)]
    scanner.errors = [*filler, "FATAL: the rules file could not be read LASTWORDS"]
    assert len("\n".join(scanner.errors)) > _STDERR_EXCERPT_LIMIT

    detail = scanner._describe_scan_failure(ScannerError("planted"), None)

    assert "LASTWORDS" in detail, detail[-300:]
    assert len(detail) < _STDERR_EXCERPT_LIMIT + 1000, len(detail)
    # The head is kept too, and the omitted figure is exactly the text that was
    # left out between the head and the tail.
    assert "progress line 0" in detail, detail[:400]
    full = "\n".join(scanner.errors)
    marker = re.search(r" \.\.\.\[(\d+) characters omitted\]\.\.\. ", detail)
    assert marker is not None, detail
    kept_head = detail[: marker.start()]
    kept_head = kept_head[kept_head.index("progress line 0") :]
    after = detail[marker.end() :]
    kept_tail = after[: after.index("LASTWORDS") + len("LASTWORDS")]
    assert int(marker.group(1)) == len(full) - len(kept_head) - len(kept_tail), (
        marker.group(1),
        len(full),
        len(kept_head),
        len(kept_tail),
    )
