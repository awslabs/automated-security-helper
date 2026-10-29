# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""environment_record.referenced_name: the one parser of a written reference's
variable, matched the way the loader matches it.

resolve_env_references, and the YAML and TOML loaders before it, match a
reference from the text's first character, so a text with leading whitespace
is no reference: the loader leaves it as written. A parser that stripped the
text first would name a variable the loader never read.
"""

import pytest

from automated_security_helper.config.ash_config import resolve_env_references
from automated_security_helper.config.environment_record import (
    _written_key_reference,
    reads_as_reference,
    referenced_name,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("written", "name"),
    [
        pytest.param("${ASH_PROBE_NAME}", "ASH_PROBE_NAME", id="bare"),
        pytest.param("${ASH_PROBE_NAME:fallback}", "ASH_PROBE_NAME", id="default"),
        pytest.param("!ENV ${ASH_PROBE_NAME}", "ASH_PROBE_NAME", id="env-tag"),
        pytest.param("plain text", None, id="not-a-reference"),
    ],
)
def test_the_variable_a_reference_names(written, name):
    assert referenced_name(written) == name


def test_leading_whitespace_names_nothing_as_the_loader_reads_nothing(monkeypatch):
    monkeypatch.setenv("ASH_PROBE_NAME", "read")
    written = "  ${ASH_PROBE_NAME}"

    # The control: the loader leaves this text as written.
    assert resolve_env_references(written) == written
    assert referenced_name(written) is None


def test_a_key_is_judged_by_the_same_parser(monkeypatch):
    monkeypatch.setenv("ASH_PROBE_NAME", "read")

    assert _written_key_reference("${ASH_PROBE_NAME}") is True
    assert _written_key_reference("  ${ASH_PROBE_NAME}") is False


@pytest.mark.parametrize(
    ("text", "is_reference"),
    [
        pytest.param("${ASH_PROBE_NAME}", True, id="bare"),
        pytest.param("!ENV ${ASH_PROBE_NAME}", True, id="env-tag"),
        pytest.param("  ${ASH_PROBE_NAME}", False, id="leading-whitespace"),
        pytest.param("plain text", False, id="not-a-reference"),
    ],
)
def test_a_record_s_reference_is_read_as_the_loader_reads_one(text, is_reference):
    """A recorded configuration holds a reference as its file wrote it, and a
    text the loader read nothing for (leading whitespace) is none there
    either: one whitespace rule for every reader of a written reference."""
    assert reads_as_reference(text) is is_reference


def test_the_module_matches_a_written_reference_in_one_place():
    """Every reader of a written reference in environment_record goes through
    one match, so no reader can take a different whitespace rule."""
    import inspect

    from automated_security_helper.config import environment_record

    source = inspect.getsource(environment_record)
    assert source.count("ENV_REFERENCE_PATTERN.match(") == 1, source.count(
        "ENV_REFERENCE_PATTERN.match("
    )
