# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warning about a capped extraction limit names where the capped value came from.

A config file in the scanned tree replaces ``ASH_CONFIG`` like any selected config,
so a limit it leaves out takes the default, and the cap then applies to the
default. The warning said the value was ignored "from" the file in that case too,
naming a file that never set the option. It now says the value is the default when
the file left it out, and names the file only when the file set it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tree = tmp_path / "repo"
    (tree / ".ash").mkdir(parents=True)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "project_name: operator\nconverters:\n  archive:\n    options:\n"
        "      max_members: 2\n"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.chdir(tree)
    return tree


def limit_warnings(records) -> List[str]:
    return [
        r.getMessage()
        for r in records
        if "converters.archive.options.max_members" in r.getMessage()
    ]


def test_a_limit_the_file_leaves_out_is_named_as_the_default(layout, ash_warnings):
    (layout / ".ash" / ".ash.yaml").write_text("project_name: scanned\n")

    config = resolve_config(source_dir=layout)

    assert config.converters.archive.options.max_members == 2
    (message,) = limit_warnings(ash_warnings)
    assert "the default" in message, message
    assert "set by" not in message, message


def test_a_limit_the_file_sets_is_named_as_set_by_the_file(layout, ash_warnings):
    (layout / ".ash" / ".ash.yaml").write_text(
        "project_name: scanned\nconverters:\n  archive:\n    options:\n"
        "      max_members: 1000\n"
    )

    config = resolve_config(source_dir=layout)

    assert config.converters.archive.options.max_members == 2
    (message,) = limit_warnings(ash_warnings)
    assert "set by" in message and ".ash.yaml" in message, message
    assert "the default" not in message, message
