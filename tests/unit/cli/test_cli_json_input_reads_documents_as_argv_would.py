# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--cli-json-input`` reads every document shape a tool writes, and refuses as argv does.

A byte order mark on a file or on stdin is dropped; stdin is read as UTF-8 and
a read that fails is the usage refusal the file branch gives; a file:// URI is
decoded and a host in it refused; a document nested too deeply, an infinite
number for an integer, a number for a true/false parameter and a fraction for
an integer are refusals, not tracebacks or silent truncation; the skeleton
leaves a parameter with an environment variable null; --help and
--generate-cli-skeleton run before the document is read.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

RUN_ASH_SCAN = "automated_security_helper.cli.scan.run_ash_scan"


def _flat(output: str) -> str:
    return "".join(output.translate(str.maketrans("", "", "│╭╮╰╯─")).split())


def _scan(args, **kwargs):
    with patch(RUN_ASH_SCAN) as mock_run:
        result = CliRunner().invoke(app, ["scan", *args], **kwargs)
    return result, mock_run


def _document(tmp_path: Path, payload: dict, name: str = "params.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# --- how the document is read ---


def test_a_file_with_a_byte_order_mark_is_read(tmp_path):
    """A document a Windows editor or PowerShell 5 saved was refused as
    invalid JSON for the mark json.loads does not accept."""
    path = tmp_path / "params.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"offline": True}).encode("utf-8"))

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


def test_stdin_with_a_byte_order_mark_is_read():
    result, mock_run = _scan(
        ["--cli-json-input", "-"],
        input=b"\xef\xbb\xbf" + json.dumps({"offline": True}).encode("utf-8"),
    )

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


def test_stdin_that_is_not_utf_8_is_the_same_refusal_a_file_gets():
    """The stdin branch had no handler, so bytes that do not decode were a
    UnicodeDecodeError traceback, where a file gives 'cannot read'."""
    result, mock_run = _scan(
        ["--cli-json-input", "-"], input=b'{"offline": "\xff\xfe"}'
    )

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "cannotreadstdin" in _flat(result.output)


def test_a_file_uri_is_decoded_before_the_file_is_read(tmp_path):
    """The prefix alone was stripped, so a percent-escaped name was read as
    the literal escaped text and not found."""
    path = _document(tmp_path, {"offline": True}, name="par ams.json")

    result, mock_run = _scan(["--cli-json-input", "file://" + quote(str(path))])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


def test_a_file_uri_with_a_host_is_refused(tmp_path):
    result, mock_run = _scan(["--cli-json-input", "file://share.example/params.json"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "share.example" in _flat(result.output)


def test_a_document_nested_too_deeply_is_refused_not_a_traceback(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text('{"x": ' + "[" * 100000 + "]" * 100000 + "}", encoding="utf-8")

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "nestedtoodeeply" in _flat(result.output)


# --- values argv could never carry ---


def test_an_infinite_number_for_an_integer_is_refused(tmp_path):
    """1e400 parses as infinity; click's integer conversion raised
    OverflowError past its own check."""
    path = tmp_path / "params.json"
    path.write_text('{"shard_index": 1e400, "shard_count": 2}', encoding="utf-8")

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "'shard_index'" in _flat(result.output)
    assert "toolarge" in _flat(result.output)


def test_a_number_for_a_true_false_parameter_is_refused(tmp_path):
    """click reads 0 and 1 as the booleans; 2 reached its text conversion and
    raised AttributeError."""
    path = _document(tmp_path, {"offline": 2})

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "'offline'" in _flat(result.output)
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_a_fraction_for_an_integer_is_refused_not_truncated(tmp_path):
    """int(3.5) is 3, so the shard index silently moved."""
    path = _document(tmp_path, {"shard_index": 3.5, "shard_count": 4})

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "'shard_index'" in _flat(result.output)


def test_a_whole_number_for_an_integer_is_still_accepted(tmp_path):
    path = _document(tmp_path, {"shard_index": 1, "shard_count": 4})

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["shard_index"] == 1


# --- the skeleton and the eager options ---


def test_the_skeleton_leaves_a_parameter_with_an_environment_variable_null():
    """The skeleton wrote ASH_MODE's parameter as its default, and the document
    sits above the environment, so the unedited skeleton overrode ASH_MODE."""
    result = CliRunner().invoke(app, ["scan", "--generate-cli-skeleton"])

    assert result.exit_code == 0, result.output
    skeleton = json.loads(result.stdout)
    assert skeleton["mode"] is None
    assert skeleton["source_dir"] is None
    # A parameter without one keeps showing its default.
    assert skeleton["strategy"] == "parallel"


def test_help_is_shown_whatever_document_was_named(tmp_path):
    result, mock_run = _scan(
        ["--cli-json-input", str(tmp_path / "no-such.json"), "--help"]
    )

    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output
    assert not mock_run.called


def test_the_skeleton_is_printed_whatever_document_was_named(tmp_path):
    result, mock_run = _scan(
        ["--cli-json-input", str(tmp_path / "no-such.json"), "--generate-cli-skeleton"]
    )

    assert result.exit_code == 0, result.output
    assert "source_dir" in json.loads(result.stdout)
    assert not mock_run.called


def test_a_missing_document_is_still_refused_when_the_command_would_run(tmp_path):
    """The control: without an eager option the document is read first."""
    result, mock_run = _scan(["--cli-json-input", str(tmp_path / "no-such.json")])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
