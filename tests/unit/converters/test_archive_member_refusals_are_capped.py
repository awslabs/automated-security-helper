# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An archive's member refusals are listed one by one up to 20 per reason, then counted.

Every refused member used to get its own record and its own warning, so an archive
holding many nested archives or links produced as many records, warnings and SARIF
notifications as it had members. The first 20 refusals of each reason in an archive
are listed; the rest are one record that says how many more there were.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from automated_security_helper.utils.converter_refusals import converter_refusals
from tests.utils.archive_builders import zip_bytes

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)
LISTED = 20


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def convert(context, monkeypatch, nested: int):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    members = {"top.py": b"print(1)\n"}
    members.update({f"vendor/p{i:03d}.whl": b"x" for i in range(nested)})
    archive = tree / "outer.zip"
    archive.write_bytes(zip_bytes(members))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def test_the_first_refusals_are_listed_and_the_rest_counted(
    test_plugin_context, monkeypatch, ash_warnings
):
    converter, results = convert(test_plugin_context, monkeypatch, LISTED + 5)

    assert len(results) == 1
    listed = [r for r in converter.refused_inputs if r.member is not None]
    summaries = [r for r in converter.refused_inputs if r.member is None]
    assert [r.member for r in listed] == [f"vendor/p{i:03d}.whl" for i in range(LISTED)]
    assert [(s.path, s.unlisted_members, s.limit) for s in summaries] == [
        ("outer.zip", 5, None)
    ]
    assert summaries[0].reason == listed[0].reason
    naming = [w for w in ash_warnings if "'outer.zip'" in w.getMessage()]
    assert len(naming) == LISTED + 1, [w.getMessage() for w in naming]


def test_the_count_reaches_the_reports(test_plugin_context, monkeypatch):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
        FlatJSONReporter,
    )

    converter, _ = convert(test_plugin_context, monkeypatch, LISTED + 5)
    model = AshAggregatedResults(ash_config=get_default_config())
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[], refused_inputs=list(converter.refused_inputs)
    )

    summary = [r for r in converter_refusals(model) if r.member is None]
    assert [r.message().split(" was not scanned")[0] for r in summary] == [
        "archive: 5 more members of 'outer.zip'"
    ]
    context = PluginContext(
        source_dir=Path("."), output_dir=Path("."), config=get_default_config()
    )
    rows = json.loads(FlatJSONReporter(context=context).report(model))[
        "converter_refusals"
    ]
    assert len(rows) == LISTED + 1
    assert [row["unlisted_members"] for row in rows if row["member"] is None] == [5]


def test_an_archive_at_the_cap_lists_every_refusal(test_plugin_context, monkeypatch):
    converter, _ = convert(test_plugin_context, monkeypatch, LISTED)

    assert len(converter.refused_inputs) == LISTED
    assert all(r.member is not None for r in converter.refused_inputs)
