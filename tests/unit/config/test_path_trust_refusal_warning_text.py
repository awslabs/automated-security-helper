# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a path-refusal warning prints for the path it refused.

* ``_named`` shows a path as ``<value>`` when it is the value the environment gave:
  compared as normalized paths, whole components only, so the spelling a load
  anchors and normalizes still corresponds, and a value that is only a piece of a
  name does not hide the path.
* The warning has the environment values hidden before the control characters are
  escaped, since an escaped character no longer matches the value that held it.
* The derived-product warning escapes control characters too, so a newline in a
  path a repository wrote cannot start a line of its own in the log.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.config import path_trust
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.utils.display_text import escape_controls
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

KEY = "scanners.standin.options.config_file"


@pytest.fixture(autouse=True)
def _fresh_warnings():
    path_trust.reset_path_refusal_warnings()
    yield
    path_trust.reset_path_refusal_warnings()


@pytest.fixture
def warnings():
    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _reference(resolved: str) -> SimpleNamespace:
    """A reference the config read from the environment, resolved to *resolved*."""
    return SimpleNamespace(resolved=resolved, value=resolved)


def _config(*references: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(_environment_references=list(references))


@pytest.mark.parametrize("recorded", ["../ops/rules.yaml", "./a/../ops/rules.yaml"])
def test_an_anchored_and_normalized_environment_path_is_shown_as_shown(recorded):
    # The environment gave a relative spelling; loading anchored it under the
    # config's directory and applied the dots.
    written = "/srv/ops/rules.yaml"

    named = path_trust._named(written, Path(written), _config(_reference(recorded)))

    assert named == ENVIRONMENT_VALUE_SHOWN


@pytest.mark.parametrize("recorded", ["rules", "yaml", "srv", "s"])
def test_a_value_that_is_only_part_of_a_name_does_not_hide_the_path(recorded):
    written = "/srv/ops/rules.yaml"

    named = path_trust._named(written, Path(written), _config(_reference(recorded)))

    assert named == written


@pytest.mark.parametrize(
    "recorded, written",
    [
        ("/srv/ops/rules.yaml", "/srv/ops/rules.yaml"),
        ("ops/rules.yaml", "/srv/ops/rules.yaml"),
        ("/srv/ops/rules.yaml", "rules.yaml"),
        ("file:///srv/ops/rules.yaml", "/srv/ops/rules.yaml"),
    ],
)
def test_the_spellings_one_environment_path_takes_still_correspond(recorded, written):
    named = path_trust._named(written, Path(written), _config(_reference(recorded)))

    assert named == ENVIRONMENT_VALUE_SHOWN


def test_an_unrelated_environment_path_does_not_hide_the_path():
    written = "/srv/ops/rules.yaml"

    named = path_trust._named(
        written, Path(written), _config(_reference("/etc/other.yaml"))
    )

    assert named == written


def test_an_environment_value_with_a_wide_format_character_is_hidden_not_escaped(
    tmp_path, warnings
):
    # U+E0001 is a format character outside the Basic Multilingual Plane. The
    # escape is `\u` plus its five digits, a spelling the redaction does not
    # match, so escaping before redacting printed the value in that spelling.
    source = tmp_path / "repo"
    source.mkdir()
    value = (source / f"cfg{chr(0xE0001)}.yaml").as_posix()
    try:
        os.fsencode(value)
    except UnicodeEncodeError:
        pytest.skip("the file system encoding cannot hold the character")

    refused = path_trust.honored_path(
        value,
        source_dir=source,
        key=KEY,
        config=SimpleNamespace(_environment_values=[value]),
    )

    assert refused is None
    messages = [message for message in warnings if KEY in message]
    assert messages, warnings
    escaped = escape_controls(value)
    assert escaped != value
    for message in messages:
        assert value not in message
        assert escaped not in message
    assert any(ENVIRONMENT_VALUE_SHOWN in message for message in messages)


@pytest.mark.skipif(os.name == "nt", reason="a Windows file name cannot hold a newline")
def test_a_derived_product_warning_escapes_control_characters_in_the_path(
    tmp_path, warnings
):
    source = tmp_path / "repo"
    source.mkdir()
    work = tmp_path / "out" / "work"
    work.mkdir(parents=True)
    value = f"{work.as_posix()}/bad\nname.yaml"

    refused = path_trust.refused_derived_product(
        value,
        source_dir=source,
        key=KEY,
        derived_dirs=(work,),
        operator_written=False,
    )

    assert refused is True
    (message,) = [message for message in warnings if KEY in message]
    assert "\n" not in message
    assert "bad\\nname.yaml" in message
