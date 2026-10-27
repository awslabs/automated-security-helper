# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ash merge says why a shard's results file did not load without repeating it.

A shard results file holds finding data: snippets, paths, and keys a scanner or
a configuration chose. The refusal reaches the CI log, so it must not repeat
any of it. pydantic's text quotes the input (input_value='...'), an error's
location names every mapping key on its path, and a validator can quote the
value it refuses (ASH's own state the rule instead, and a test model here
quotes on purpose). The refusal shows a key's controls as escapes and breaks
its CI command forms, so no line on stdout starts a workflow command such as
"::error".
"""

from __future__ import annotations

import copy
import json
import logging
import traceback
from pathlib import Path

import pytest
from pydantic import ValidationError, field_validator
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.merge import (
    ShardCoverageError,
    _describe_unreadable_shard,
    load_shard_results,
)
from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
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


def test_no_change_to_a_results_file_puts_its_content_in_the_refusal():
    """A fuzz run over every rejected document; 136 of them are regression cases."""
    logging.disable(logging.CRITICAL)
    try:
        described = 0
        for document in _mutations():
            try:
                AshAggregatedResults.model_validate_json(json.dumps(document))
            except ValidationError as error:
                _assert_hidden(_describe_unreadable_shard(error))
                described += 1
    finally:
        logging.disable(logging.NOTSET)

    # Measured: 1578 of 2629 mutations are rejected. A floor, so a sample that
    # stopped producing errors cannot pass this by describing nothing.
    assert described > 1000, described


SUPPRESSION = {"rule_id": "R1", "path": "a.py", "reason": "because"}


def _staleness_override(expiration: str) -> dict:
    """A stored config whose content-database override has ``expiration``.

    That date is still refused in a results file, by the rule ("Invalid
    expiration date format. Use YYYY-MM-DD"); a suppression's or ignore path's
    malformed date is kept instead, with a warning that names its location.
    """
    return {
        "ash_config": {
            "project_name": "p",
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": expiration,
                    "reason": "r",
                }
            ],
        }
    }


class _QuotingResults(AshAggregatedResults):
    """Results whose ``name`` validator quotes the value it refuses, as a
    plugin's validator may."""

    @field_validator("name")
    @classmethod
    def _refuse(cls, value: str) -> str:
        raise ValueError(f"not a report name: {value}")


@pytest.mark.parametrize(
    "name",
    # The model strips whitespace with pydantic's own set, which lacks the
    # U+001C-001F separators str.strip() also removes, so the value the
    # validator quotes ("\x1f<secret>") matches neither the input nor its
    # str.strip() form.
    [HOSTILE, f"  {SECRET}  ", " \x1f" + SECRET],
    ids=["as-given", "stripped-before-quoting", "stripped-by-pydantic"],
)
def test_a_validator_that_quotes_the_value_it_refuses_is_redacted(name):
    with pytest.raises(ValidationError) as caught:
        _QuotingResults.model_validate_json(json.dumps({"name": name}))
    described = _describe_unreadable_shard(caught.value)

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
        pytest.param(
            _staleness_override(HOSTILE),
            "Invalid expiration date format. Use YYYY-MM-DD",
            id="staleness-expiration",
        ),
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
        pytest.param(
            {
                "ash_config": {
                    "project_name": "p",
                    "content_db_staleness_overrides": [
                        {
                            "database": " \x1f" + SECRET,
                            "policy": "warn",
                            "expiration": "2030-01-01",
                            "reason": "r",
                        }
                    ],
                }
            },
            "unknown content database; declared databases: ",
            id="staleness-database",
        ),
    ],
)
def test_ash_s_validators_state_the_rule_without_the_value(document, rule):
    """ASH's own validators name the rule, not the value they refuse."""
    described = _describe_unreadable_shard(_rejection(document))

    _assert_hidden(described)
    assert rule in described, described


def test_a_key_from_the_file_is_not_printed():
    """A mapping key on the error's path is the file's data, not a field name."""
    described = _describe_unreadable_shard(_rejection({"scanner_results": {SECRET: 5}}))

    assert described == (
        "Invalid value at 'scanner_results.<key>': Input should be an object"
    ), described


def test_field_names_and_positions_are_printed():
    described = _describe_unreadable_shard(
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

    described = _describe_unreadable_shard(caught.value)

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
        described = _describe_unreadable_shard(error)

    assert described == "not UTF-8 at byte offset 2", described


def test_the_refusal_does_not_carry_the_validation_error_with_it(tmp_path):
    """The refusal does not carry the ValidationError, so no traceback of it
    prints input_value."""
    shard = tmp_path / "shard0.json"
    shard.write_text(json.dumps({"metadata": SECRET}), encoding="utf-8")

    with pytest.raises(ShardCoverageError) as caught:
        load_shard_results([shard])

    assert caught.value.__cause__ is None
    printed = "".join(traceback.format_exception(caught.value))
    assert SECRET not in printed, printed


def test_a_shard_it_cannot_open_is_named_once(tmp_path, monkeypatch):
    """The refusal names the shard; an OSError's own text names it again,
    quoted, with a Windows path's backslashes doubled. Only the error's reason is
    shown."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "shard0.json").write_text("{}", encoding="utf-8")

    def denied(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied", r"C:\scan\shard0.json")

    monkeypatch.setattr(
        "automated_security_helper.cli.merge.open", denied, raising=False
    )
    result = CliRunner().invoke(
        app, ["merge", "--output-dir", "out", "--results", "shard0.json"]
    )

    printed = " ".join(result.output.split())
    assert result.exit_code == 1, result.output
    assert "Could not read shard results from shard0.json: Permission denied" in (
        printed
    ), printed
    assert printed.count("shard0.json") == 1, printed


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(json.dumps({"scanner_results": {HOSTILE: 5}}), id="key"),
        pytest.param(json.dumps(_staleness_override(HOSTILE)), id="validator"),
    ],
)
def test_ash_merge_prints_no_workflow_command(tmp_path, monkeypatch, content):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "shard0.json").write_text(content, encoding="utf-8")

    result = CliRunner().invoke(
        app, ["merge", "--output-dir", "out", "--results", "shard0.json"]
    )

    assert result.exit_code == 1, result.output
    assert "Could not read shard results from shard0.json" in result.output
    assert SECRET not in result.output, result.output
    assert "\x1b" not in result.output, repr(result.output)
    assert "\n::" not in result.output, repr(result.output)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("\x1b[J", id="esc"),
        pytest.param("\n::", id="newline-colons"),
    ],
)
def test_a_value_too_short_to_redact_is_shown_not_obeyed(value):
    """Under the 4-character floor nothing is replaced, so only the escaping is left.

    Every other case here is a key or a long value, which redaction catches first;
    for a short value, the control-character pass is what shows its controls as
    escapes. The output-format
    validator quotes the entry exactly as stored, leading newline included.
    """
    described = _describe_unreadable_shard(
        _rejection({"ash_config": {"project_name": "p", "output_formats": [value]}})
    )

    assert "\x1b" not in described, repr(described)
    assert "\n" not in described, repr(described)
    assert "Invalid value at 'ash_config.output_formats[0]'" in (described), described
