# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The compression-ratio limit applies only once an archive declares more than 512 KiB.

A small archive of repetitive text compresses far better than 100 to 1 and can
write no more than it declares, which max_total_bytes already bounds. Measured: a
2.3 KB fixtures.zip holding 313 KiB of indented JSON expands 139 times, and was
refused, failing the scan. Below the floor the ratio is not checked; above it, it
is, so an archive declaring 1 MiB of zeros is still refused.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
    ArchiveConverterConfigOptions,
)
from tests.utils.archive_builders import GENEROUS_LIMITS, zip_bytes

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

#: The documented floor, in bytes the archive's members declare added up.
FLOOR = 512 * 1024


@pytest.fixture
def tree(test_plugin_context) -> Path:
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


def converter_for(context, monkeypatch, archives: List[Path], limits=None):
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(p) for p in archives]
    )
    if limits is None:
        config = ArchiveConverterConfig()
    else:
        config = ArchiveConverterConfig(
            options=ArchiveConverterConfigOptions(**{**GENEROUS_LIMITS, **limits})
        )
    context.config.converters.archive = config
    return ArchiveConverter(context=context, config=config)


def fixture_json() -> bytes:
    """Indented JSON records, as a test fixture directory might hold: 313 KiB."""
    records = [
        {"id": i % 10, "name": "example", "enabled": True, "tags": ["a", "b"]}
        for i in range(3000)
    ]
    return json.dumps(records, indent=2).encode()


def test_a_fixture_archive_of_repetitive_json_is_extracted_with_the_defaults(
    tree, test_plugin_context, monkeypatch
):
    members: Dict[str, bytes] = {
        "fixtures/users.json": fixture_json(),
        "fixtures/loader.py": b"import json\nUSERS = json.load(open('users.json'))\n",
    }
    archive = tree / "fixtures.zip"
    archive.write_bytes(zip_bytes(members))
    declared = sum(len(data) for data in members.values())
    assert declared < FLOOR and declared / archive.stat().st_size > 100, (
        declared,
        archive.stat().st_size,
    )
    converter = converter_for(test_plugin_context, monkeypatch, [archive])

    (extracted,) = converter.convert()

    assert (extracted / "fixtures" / "users.json").read_bytes() == members[
        "fixtures/users.json"
    ]
    assert converter.refused_inputs == []


def test_an_archive_declaring_the_floor_is_not_held_to_the_ratio(
    tree, test_plugin_context, monkeypatch
):
    archive = tree / "zeros.zip"
    archive.write_bytes(zip_bytes({"zeros.py": bytes(FLOOR)}))
    converter = converter_for(
        test_plugin_context, monkeypatch, [archive], {"max_compression_ratio": 100}
    )

    (extracted,) = converter.convert()

    assert (extracted / "zeros.py").stat().st_size == FLOOR


def test_an_archive_declaring_more_than_the_floor_is_held_to_the_ratio(
    tree, test_plugin_context, monkeypatch
):
    archive = tree / "zeros.zip"
    archive.write_bytes(zip_bytes({"zeros.py": bytes(FLOOR + 1)}))
    converter = converter_for(
        test_plugin_context, monkeypatch, [archive], {"max_compression_ratio": 100}
    )

    assert converter.convert() == []
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("zeros.zip", "max_compression_ratio")
    ]
