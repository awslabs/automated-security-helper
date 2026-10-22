# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file that did not load is described without repeating what it holds.

ash report, and the container and Nix modes after their inner scan, read
ash_aggregated_results.json, which holds finding data: snippets, paths, and keys
a scanner or a configuration chose. pydantic's text quotes the input
(input_value='...'), an error's location names every mapping key on its path,
and a validator can quote the value it refuses (ASH's own state the rule
instead, and a test model here quotes on purpose). Printed raw, a key holding ESC
sequences would reach the terminal and one holding a newline would start a line
with "::error", which GitHub Actions reads as a workflow command, so the
description shows neither.

ash merge describes an unreadable shard the same way (cli/merge.py), so the
cases here mirror tests/unit/cli/test_merge_shard_errors_hide_the_file.py.
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError, field_validator

from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.config.config_validator import describe_results_error
from automated_security_helper.models.asharp_model import AshAggregatedResults

SECRET = "wJalrXUtnFEMIK7MDENG"
HOSTILE = SECRET + "\x1b[31m\n::error title=merge::" + SECRET

SAMPLE = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "outputs"
    / "ash_aggregated_results.json"
)


def _assert_hidden(text: str) -> None:
    assert SECRET not in text, text
    assert "\x1b" not in text, repr(text)
    assert "\n" not in text, repr(text)


def _rejection(document) -> ValidationError:
    try:
        AshAggregatedResults.model_validate_json(json.dumps(document))
    except ValidationError as error:
        return error
    pytest.fail(f"accepted: {document!r}")


def _one_of_each(node):
    """The sample with every list cut to its first item: each shape once."""
    if isinstance(node, dict):
        return {key: _one_of_each(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_one_of_each(node[0])] if node else []
    return node


def _paths(node, path=()):
    yield path, node
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _paths(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _paths(value, path + (index,))


def _replaced(document, path, value):
    document = copy.deepcopy(document)
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return document


def _mutations():
    """Each place of a results document given HOSTILE as a value, a key or an item."""
    document = _one_of_each(json.loads(SAMPLE.read_text(encoding="utf-8")))
    for key in ("scanner_results", "converter_results"):
        document.setdefault(key, {})
    for path, node in _paths(document):
        if path:
            yield _replaced(document, path, HOSTILE)
            yield _replaced(document, path, {HOSTILE: 5})
            yield _replaced(document, path, [HOSTILE])
        if isinstance(node, dict):
            yield _replaced(document, path + (HOSTILE,), 5)


def test_no_change_to_a_results_file_puts_its_content_in_the_description():
    """No rejected document puts its content in what describe_validation_error
    returns."""
    logging.disable(logging.CRITICAL)
    try:
        described = 0
        for document in _mutations():
            try:
                AshAggregatedResults.model_validate_json(json.dumps(document))
            except ValidationError as error:
                _assert_hidden(describe_results_error(error))
                described += 1
    finally:
        logging.disable(logging.NOTSET)

    # Measured: 1578 of 2629 mutations are rejected. A floor, so a sample that
    # stopped producing errors cannot pass this by describing nothing.
    assert described > 1000, described


SUPPRESSION = {"rule_id": "R1", "path": "a.py", "reason": "because"}


class _QuotingResults(AshAggregatedResults):
    """Results whose ``name`` validator quotes the value it refuses, as a
    plugin's validator may."""

    @field_validator("name")
    @classmethod
    def _refuse(cls, value: str) -> str:
        raise ValueError(f"not a report name: {value}")


@pytest.mark.parametrize(
    "name",
    [HOSTILE, f"  {SECRET}  "],
    ids=["as-given", "stripped-before-quoting"],
)
def test_a_validator_that_quotes_the_value_it_refuses_is_redacted(name):
    with pytest.raises(ValidationError) as caught:
        _QuotingResults.model_validate_json(json.dumps({"name": name}))
    described = describe_results_error(caught.value)

    _assert_hidden(described)
    assert "<value>" in described, described


@pytest.mark.parametrize(
    "document, rule",
    [
        pytest.param(
            {"metadata": {"generated_at": HOSTILE}},
            "generated_at must be an ISO 8601 date and time",
            id="generated-at",
        ),
        pytest.param(
            {"metadata": {"generated_at": f"  {SECRET}  "}},
            "generated_at must be an ISO 8601 date and time",
            id="generated-at-stripped",
        ),
        # A stored suppression whose expiration is not a date is kept, with a
        # warning, rather than refused, so it has no case here.
        pytest.param(
            {
                "ash_config": {
                    "project_name": "p",
                    "global_settings": {
                        "suppressions": [{**SUPPRESSION, "symbol": HOSTILE}]
                    },
                }
            },
            "symbol must be a dotted qualified name such as 'MyClass.my_method'",
            id="suppression-symbol",
        ),
    ],
)
def test_ash_s_validators_state_the_rule_without_the_value(document, rule):
    """ASH's own validators name the rule, not the value they refuse."""
    described = describe_results_error(_rejection(document))

    _assert_hidden(described)
    assert rule in described, described


def test_a_key_from_the_file_is_not_printed():
    """A mapping key on the error's path is the file's data, not a field name."""
    described = describe_results_error(_rejection({"scanner_results": {SECRET: 5}}))

    assert described == (
        "Invalid value at 'scanner_results.<key>': Input should be an object"
    ), described


def test_field_names_and_positions_are_printed():
    described = describe_results_error(
        _rejection(
            {"ash_config": {"project_name": "p", "build": {"tool_install_scripts": 7}}}
        )
    )

    assert described.startswith(
        "Invalid value at 'ash_config.build.tool_install_scripts': "
    ), described


def test_invalid_json_keeps_its_line_and_column():
    with pytest.raises(ValidationError) as caught:
        AshAggregatedResults.model_validate_json('{ "a": 1, ' + SECRET)

    described = describe_results_error(caught.value)

    assert described.startswith("Invalid value at '(top level)': Invalid JSON: "), (
        described
    )
    assert "line 1 column" in described
    _assert_hidden(described)


def test_a_file_that_is_not_utf8_names_the_offset_not_the_byte():
    """UnicodeDecodeError's own text prints the byte ("can't decode byte 0xff")."""
    try:
        b"ok\xff".decode("utf-8")
    except UnicodeDecodeError as error:
        described = describe_results_error(error)

    assert described == "not UTF-8 at byte offset 2", described


def test_any_other_error_is_its_text_with_controls_shown():
    """C0, and DEL and C1 (a CSI written as one byte), are each shown as \\xNN."""
    described = describe_results_error(OSError(f"cannot read \x9b2K\x7f{HOSTILE}"))

    assert described.startswith(
        "cannot read \\x9b2K\\x7fwJalrXUtnFEMIK7MDENG\\x1b[31m\\x0a::"
    ), described
