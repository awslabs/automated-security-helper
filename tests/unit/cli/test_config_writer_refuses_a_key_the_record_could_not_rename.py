# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config writer refuses a key it could not write as the reference.

A file ASH writes so that a scan loads it again records each key its files read
from the environment as the reference they wrote. When the mapping already holds
an entry under that reference, the rename would overwrite the entry, so the
record keeps the key as the environment gave it. That key is the variable's
value written as text, and a reference with a number after it would load back as
another key, so the writer has to refuse it. It refused values left as text and
looked at no key, so the file was written with the key in clear.

The record is built in memory, with the rewrite that records the key.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.config.config_validator import (
    EnvironmentRewrite,
    record_of_config,
)
from automated_security_helper.config.config_writer import (
    _as_reference,
    _refuse_a_value_left_as_text,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def config() -> SimpleNamespace:
    """A configuration whose files read the key ``k`` of the mapping ``m`` from
    the environment as ``${K}``."""
    rewrite = EnvironmentRewrite("key", ("m",), "k", "${K}", "k", "${K}")
    return SimpleNamespace(_written_references=[rewrite])


def test_a_key_left_under_the_value_on_a_collision_is_refused(config):
    record = record_of_config(config, {"m": {"k": 1, "${K}": 2}}, mark=_as_reference)
    # The record is the one the writer would have written: the entry that
    # holds the value's text as its key is still there.
    assert "k" in record["m"], record

    with pytest.raises(RuntimeError, match="was not written"):
        _refuse_a_value_left_as_text(record, config)


def test_a_key_that_was_renamed_is_not_refused(config):
    record = record_of_config(config, {"m": {"k": 1, "o": 2}}, mark=_as_reference)
    assert "k" not in record["m"], record

    assert _refuse_a_value_left_as_text(record, config) is None


def test_a_record_that_is_no_file_to_load_again_is_not_refused(config):
    """Without ``mark`` the colliding entry moves to the reference with a number
    after it and the record holds no key the environment gave."""
    record = record_of_config(config, {"m": {"k": 1, "${K}": 2}})
    assert "k" not in record["m"], record

    assert _refuse_a_value_left_as_text(record, config) is None
