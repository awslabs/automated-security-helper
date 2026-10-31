# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--cli-json-input`` reads every document shape a tool writes, and refuses as argv does.

A byte order mark on a file or on stdin is dropped; stdin is read as UTF-8 and
a read that fails is the usage refusal the file branch gives; a ``file:///`` or
``file://localhost/`` URI is percent-decoded as a URI is, and any other text after
file:// is a path exactly as written, as the AWS CLI reads it, never a host, a
query or a fragment; a name with a null byte is the cannot-read refusal; a
document nested too deeply, an infinite
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


def test_a_file_uri_with_a_host_names_a_relative_path(tmp_path, monkeypatch):
    """Nothing after ``file://`` is a host: as the AWS CLI reads the prefix, the
    text is a path, so ``share.example/params.json`` is looked for below the
    working directory and refused as a file that cannot be read, by that name."""
    monkeypatch.chdir(tmp_path)

    result, mock_run = _scan(["--cli-json-input", "file://share.example/params.json"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "cannotreadshare.example/params.json" in _flat(result.output)


@pytest.mark.parametrize("prefix", ["", "./"], ids=["bare", "dot-slash"])
def test_a_relative_path_after_the_file_prefix_names_the_file(
    tmp_path, monkeypatch, prefix
):
    """``file://params.json``, the relative form the AWS CLI documents, was parsed
    as a URI whose host is ``params.json`` and refused as a remote host."""
    _document(tmp_path, {"offline": True})
    monkeypatch.chdir(tmp_path)

    result, mock_run = _scan(["--cli-json-input", f"file://{prefix}params.json"])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


def test_a_file_uri_with_the_local_host_names_the_file(tmp_path):
    path = _document(tmp_path, {"offline": True})

    # `file://localhost/tmp/x` on POSIX, `file://localhost/C:/dir/x` on Windows.
    uri = "file://localhost/" + quote(path.as_posix().lstrip("/"))
    result, mock_run = _scan(["--cli-json-input", uri])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


@pytest.mark.parametrize("host", ["LOCALHOST", "LocalHost"])
def test_a_file_uri_host_is_compared_without_regard_to_case(tmp_path, host):
    """A host name is case-insensitive (RFC 8089), so ``file://LOCALHOST/...`` is
    the local-host URI; it was taken for a relative path ``LOCALHOST/...`` and
    refused as unreadable."""
    path = _document(tmp_path, {"offline": True})

    uri = f"file://{host}/" + quote(path.as_posix().lstrip("/"))
    result, mock_run = _scan(["--cli-json-input", uri])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


def test_a_hash_in_the_file_name_stays_in_it(tmp_path):
    """Parsed as a URI, the name was cut at the ``#`` (a fragment), so a file named
    ``a#1.json`` was looked for as ``a``."""
    path = _document(tmp_path, {"offline": True}, name="a#1.json")

    result, mock_run = _scan(["--cli-json-input", "file://" + str(path)])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


def test_a_null_byte_in_the_file_name_is_the_cannot_read_refusal():
    """``file://a%00b`` decodes to a name with a null byte, which the file system
    refuses with a ValueError; only OSError was caught, so the command ended in a
    traceback instead of naming the file it cannot read."""
    result, mock_run = _scan(["--cli-json-input", "file://a%00b"])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "cannotread" in _flat(result.output), result.output
    mock_run.assert_not_called()


@pytest.mark.parametrize(
    ("uri", "path"),
    [
        ("file://C:\\dir\\params.json", "C:\\dir\\params.json"),
        ("file://c:/dir/params.json", "c:/dir/params.json"),
        ("file://C:\\dir\\pa%20rams.json", "C:\\dir\\pa%20rams.json"),
    ],
    ids=["backslashes", "slashes", "percent-kept"],
)
def test_a_file_uri_with_a_drive_letter_names_the_drive_not_a_host(uri, path):
    """`file://C:\\dir\\params.json`, the two-slash spelling a Windows path is
    pasted into, puts the drive letter where a URI's host goes (with backslashes
    the whole path, since no "/" ends the authority); it was refused as a remote
    host, and every Windows caller of the file:// form was turned away. The
    drive letter starts the path, which is read as written: it is not a URI, so a
    ``%20`` in it stays a ``%20``, as the AWS CLI reads it."""
    from automated_security_helper.cli.json_input import _document_path

    assert _document_path(uri) == path


def test_a_percent_in_a_relative_name_stays_in_it(tmp_path, monkeypatch):
    """Only a URI (``file:///`` or ``file://localhost/``) is percent-decoded. The
    relative form is a path as written, so ``a%20b.json`` names the file with a
    ``%`` in its name; it was decoded to ``a b.json`` and not found."""
    _document(tmp_path, {"offline": True}, name="a%20b.json")
    monkeypatch.chdir(tmp_path)

    result, mock_run = _scan(["--cli-json-input", "file://a%20b.json"])

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["offline"] is True


@pytest.mark.parametrize("form", ["uri", "relative"])
def test_a_file_uri_with_a_null_byte_is_the_unreadable_refusal(
    tmp_path, monkeypatch, form
):
    """``%00`` in a URI decodes to a null byte, which ``read_text`` refuses with a
    ValueError the handler did not catch: a traceback and exit 1, where a file that
    cannot be read is the usage refusal. The relative form is not decoded, so it
    names a file that does not exist; it is refused the same way."""
    monkeypatch.chdir(tmp_path)
    source = (
        "file://localhost/" + quote(tmp_path.as_posix().lstrip("/")) + "/a%00b.json"
        if form == "uri"
        else "file://a%00b.json"
    )

    result, mock_run = _scan(["--cli-json-input", source])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "cannotread" in _flat(result.output)
    assert "Traceback" not in result.output


def test_a_document_nested_too_deeply_is_refused_not_a_traceback(tmp_path, monkeypatch):
    """A document the parser cannot follow is refused like one that does not
    parse. Whether a given depth raises RecursionError depends on the interpreter
    (3.14's decoder followed 100,000 levels and then refused the unknown key), so
    the parser's refusal is forced rather than provoked."""
    path = tmp_path / "deep.json"
    document = '{"source_dir": ' + "[" * 100000 + "]" * 100000 + "}"
    path.write_text(document, encoding="utf-8")
    real_loads = json.loads

    def loads(text, *args, **kwargs):
        if text == document:
            raise RecursionError("maximum recursion depth exceeded")
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", loads)

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "nestedtoodeeply" in _flat(result.output)


# --- values argv could never carry ---


def test_an_infinite_number_for_an_integer_is_refused(tmp_path):
    """1e400 parses as infinity; click's integer conversion raised
    OverflowError past its own check. The shape check reads it first: a number
    with an exponent is not a JSON integer, and that is the refusal shown."""
    path = tmp_path / "params.json"
    path.write_text('{"shard_index": 1e400, "shard_count": 2}', encoding="utf-8")

    result, mock_run = _scan(["--cli-json-input", str(path)])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    assert "'shard_index'" in _flat(result.output)
    assert "expectedaJSONinteger" in _flat(result.output)
    assert "Traceback" not in result.output


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
