# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the operator's ash-unconverted-input suppression waives the completeness
gate for an input a converter could not convert.

A suppression a delivered tree's own config or a workspace policy file supplied
is marked ``client_supplied`` by ASH when the file is read. Such an entry belongs
to the finding step, where it marks results suppressed and the results show what
the client's config hid; it never skips scanning (the ignore-path contract,
``ignore_paths_that_skip_scanning``) and, since this change, never waives scan
coverage either. Before it, ``accepting_unconverted_input`` read ``path``,
``rule_id`` and ``expiration`` only, so a tree could carry a suppression that
waived the gate for an archive or notebook the tree itself made unreadable, and
the archive converter's failures, recorded as input errors now, would have been
the first to consult it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import waives_gate
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.utils.suppression_matcher import (
    accepting_unconverted_input,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = archive_converter.__name__


def _suppression(client_supplied: bool) -> AshSuppression:
    return AshSuppression(
        rule_id="ash-unconverted-input",
        path="lib/b.tar",
        reason="a fixture that only looks like a tar",
        client_supplied=client_supplied,
    )


def test_an_operators_entry_accepts_the_input():
    entry = _suppression(client_supplied=False)

    assert accepting_unconverted_input("lib/b.tar", [entry]) is entry


def test_a_client_supplied_entry_accepts_nothing():
    assert accepting_unconverted_input("lib/b.tar", [_suppression(True)]) is None


def test_the_operators_entry_is_found_past_a_client_supplied_one():
    """The client's entry is skipped, not the whole list."""
    operators = _suppression(client_supplied=False)

    assert (
        accepting_unconverted_input("lib/b.tar", [_suppression(True), operators])
        is operators
    )


@pytest.mark.parametrize(
    ("client_supplied", "accepted"),
    [
        pytest.param(False, True, id="operator-supplied-waives"),
        pytest.param(True, False, id="tree-supplied-stays-incomplete"),
    ],
)
def test_an_unreadable_archives_failure_is_waived_only_by_the_operator(
    test_plugin_context, monkeypatch, client_supplied, accepted
):
    source = Path(test_plugin_context.source_dir)
    archive = source / "lib" / "b.tar"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"not a tar at all\n")
    test_plugin_context.config.global_settings.suppressions = [
        _suppression(client_supplied)
    ]
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.convert()

    (failed,) = converter.failed_inputs
    assert failed.kind == "input"
    assert failed.accepted is accepted
    assert waives_gate(failed) is accepted
