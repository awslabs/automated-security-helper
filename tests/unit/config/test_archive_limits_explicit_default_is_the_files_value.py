# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which source the archive limit warning names for a value equal to the default.

``confine_archive_limits`` caps an archive extraction limit a repository's config file
raises above the trusted base. The warning names where the capped value came from: the
file, when it set the option, or the default, when the file left the option out and
replaced ``ASH_CONFIG`` as any selected config file does. A file that writes the
default value itself set the option, so the warning says that and does not tell its
author the file left the option out.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

OPTION = "converters.archive.options.max_total_bytes"
DEFAULT = ArchiveConverterConfigOptions().max_total_bytes
LOWERED = DEFAULT // 2


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
    """A scanned tree whose operator lowered ``max_total_bytes`` in ``ASH_CONFIG``."""
    tree = tmp_path / "repo"
    (tree / ".ash").mkdir(parents=True)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    write_options(operator, max_total_bytes=LOWERED)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.chdir(tree)
    return tree


def write_options(path: Path, **options) -> None:
    lines = "".join(f"      {name}: {value}\n" for name, value in options.items())
    path.write_text(
        f"project_name: scanned\nconverters:\n  archive:\n    options:\n{lines}"
    )


def warnings_naming_the_option(records) -> List[str]:
    return [r.getMessage() for r in records if OPTION in r.getMessage()]


def test_a_file_that_writes_the_default_is_named_as_setting_it(layout, ash_warnings):
    write_options(layout / ".ash" / ".ash.yaml", max_total_bytes=DEFAULT)

    config = resolve_config(source_dir=layout)

    assert config.converters.archive.options.max_total_bytes == LOWERED
    (message,) = warnings_naming_the_option(ash_warnings)
    assert message.startswith("Ignoring"), message
    assert "leaves the option out" not in message, message


def test_positive_control_a_file_that_leaves_the_option_out_is_named_as_doing_so(
    layout, ash_warnings
):
    write_options(layout / ".ash" / ".ash.yaml", max_members=10)

    config = resolve_config(source_dir=layout)

    assert config.converters.archive.options.max_total_bytes == LOWERED
    (message,) = warnings_naming_the_option(ash_warnings)
    assert message.startswith("Capping"), message
    assert "leaves the option out" in message, message


def test_positive_control_a_file_that_raises_the_option_is_named_as_setting_it(
    layout, ash_warnings
):
    write_options(layout / ".ash" / ".ash.yaml", max_total_bytes=DEFAULT * 4)

    config = resolve_config(source_dir=layout)

    assert config.converters.archive.options.max_total_bytes == LOWERED
    (message,) = warnings_naming_the_option(ash_warnings)
    assert message.startswith("Ignoring"), message
