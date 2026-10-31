# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""All the archives one conversion extracts share a budget, and no member is free.

The per-archive limits bounded one archive at a time, so a tree of many archives,
each just inside them, extracted without bound. The archives of one ``convert()``
run now share one budget: four times ``max_members`` members and four times
``max_total_bytes`` bytes. An archive that would take the run over it is refused,
naming the limit to raise, and does not use up the budget, so a later, smaller
archive that still fits is extracted.

Every member also counts as at least 512 bytes, a tar header, toward the byte
totals, so an archive of empty members is not free.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
    ArchiveConverterConfigOptions,
)
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
)
from tests.utils.archive_builders import GENEROUS_LIMITS, incompressible, zip_bytes

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)


@pytest.fixture
def tree(test_plugin_context) -> Path:
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


def converter_for(context, monkeypatch, archives: List[Path], limits: Dict[str, int]):
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(p) for p in archives]
    )
    config = ArchiveConverterConfig(
        options=ArchiveConverterConfigOptions(**{**GENEROUS_LIMITS, **limits})
    )
    context.config.converters.archive = config
    return ArchiveConverter(context=context, config=config)


def write(tree: Path, name: str, members: Dict[str, bytes]) -> Path:
    path = tree / name
    path.write_bytes(zip_bytes(members))
    return path


def test_the_archive_that_takes_the_scan_over_four_times_max_total_bytes_is_refused(
    tree, test_plugin_context, monkeypatch
):
    archives = [
        write(tree, f"a{i}.zip", {"m.py": incompressible(3600, seed=i)})
        for i in range(5)
    ]
    archives.append(write(tree, "small.zip", {"s.py": incompressible(1000, seed=9)}))
    converter = converter_for(
        test_plugin_context, monkeypatch, archives, {"max_total_bytes": 4000}
    )

    results = converter.convert()

    # 4 x 3600 = 14400 fits in 16000; the fifth would make 18000; 14400 + 1000 fits.
    assert len(results) == 5
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("a4.zip", "max_total_bytes")
    ]
    assert "together with the archives" in converter.refused_inputs[0].reason
    # The extraction directories, less the converter's own record of their
    # sources (converted-sources.json), which sits beside them.
    written = [
        p.name
        for p in Path(converter.results_dir).iterdir()
        if p.name != CONVERTED_SOURCES_FILE_NAME
    ]
    assert len(written) == 5, written
    assert not [name for name in written if name.endswith("a4__zip")], written


def test_the_archive_that_takes_the_scan_over_four_times_max_members_is_refused(
    tree, test_plugin_context, monkeypatch
):
    archives = [
        write(tree, f"a{i}.zip", {f"m{k}.py": f"k = {k}\n".encode() for k in range(3)})
        for i in range(5)
    ]
    converter = converter_for(
        test_plugin_context, monkeypatch, archives, {"max_members": 3}
    )

    results = converter.convert()

    assert len(results) == 4
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("a4.zip", "max_members")
    ]


@pytest.mark.parametrize("count, refused", [(9, False), (10, True)])
def test_each_member_counts_at_least_512_bytes(
    count, refused, tree, test_plugin_context, monkeypatch
):
    archive = write(tree, "empty.zip", {f"e{i}.py": b"" for i in range(count)})
    converter = converter_for(
        test_plugin_context, monkeypatch, [archive], {"max_total_bytes": 5000}
    )

    results = converter.convert()

    if refused:
        assert results == []
        assert [(r.path, r.limit) for r in converter.refused_inputs] == [
            ("empty.zip", "max_total_bytes")
        ]
    else:
        assert len(results) == 1
        assert converter.refused_inputs == []
