# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A PluginContext's scan id is drawn without ``uuid.uuid4``.

The snapshot tests pin ``uuid.uuid4`` to a counter, because report ids are built from
it. ``PluginContext.scan_id`` is not a report id: its only consumer is the
once-per-scan content database refresh (``utils/content_db_refresh.py``), which needs
a value that differs from one scan to the next and nothing more. Drawn from
``uuid.uuid4`` it takes a slot from that counter every time a context is built, so
each context moves the id of the report made after it, and the workspace snapshots
that hold that id fail. A scan id only has to be unique, so it comes from
:mod:`secrets`, which nothing pins, the way an atomic write's staging name does
(``utils/atomic_write.py``).

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import itertools
import re
import uuid
from pathlib import Path
from typing import Optional

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig


def _config() -> AshConfig:
    return AshConfig(project_name="plugin-context-scan-id-draw")


def _context(root: Path, config: Optional[AshConfig] = None) -> PluginContext:
    source = root / "src"
    source.mkdir(parents=True)
    output = root / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=_config() if config is None else config,
    )


def test_building_a_context_draws_no_uuid4(tmp_path, monkeypatch):
    config = _config()

    def _refuse():
        raise AssertionError("a PluginContext drew from uuid.uuid4")

    monkeypatch.setattr(uuid, "uuid4", _refuse)

    context = _context(tmp_path / "ctx", config)

    assert isinstance(context.scan_id, str) and context.scan_id


def test_building_contexts_leaves_a_pinned_uuid4_counter_where_it_was(
    tmp_path, monkeypatch
):
    """The counter the snapshot tests pin is the report ids' alone."""
    first_config = _config()
    second_config = _config()
    counter = itertools.count(1)

    def _pinned():
        return uuid.UUID(int=next(counter), version=4)

    monkeypatch.setattr(uuid, "uuid4", _pinned)

    first = _context(tmp_path / "first", first_config)
    second = _context(tmp_path / "second", second_config)
    ids = (first.scan_id, second.scan_id)

    assert len(ids) == 2
    assert next(counter) == 1


def test_scan_id_is_hex_of_the_same_shape_fixed_per_context_and_unique(tmp_path):
    first = _context(tmp_path / "first")
    second = _context(tmp_path / "second")

    assert re.fullmatch(r"[0-9a-f]{32}", first.scan_id), first.scan_id
    assert re.fullmatch(r"[0-9a-f]{32}", second.scan_id), second.scan_id
    assert first.scan_id == first.scan_id
    assert first.scan_id != second.scan_id
