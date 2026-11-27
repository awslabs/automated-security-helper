# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config prints no value the server's environment gave to an ignored option.

get_config shows the operator-only options a file in a git checkout sets
(aws-security-hub ``findings_scope`` and ``archive_resolved_findings``,
detect-secrets ``max_worker_output_mib``) as ``<operator only; ignored from this
file: VALUE>``, because a scan of that checkout ignores them. A value the file
read from the environment (``${VAR}``) belongs to the server, so VALUE is the
reference the file wrote (``<from ${VAR}>``) where one survives at that place,
and ``<from the environment>`` where the load dropped it, as it does for a file
in a checkout the session does not scan.

The marker used to be compared whole with each environment value and withdrawn
on a match. That caught a string and missed every other shape: a list entry, a
mapping value or key and a set member printed the value inside the marker. It
also hid from the client that the file set an option the scan ignores. The
decision now sits in ``mark_operator_only_options``, which walks the value the
file wrote.

The cells drive get_config through a file in another checkout, named from a
working directory elsewhere, once for each shape a read value can take. They
keep the controls that must not change (a literal, a reference that survives, an
option left unmarked), pin the refusal for a load that did not record exactly
one set of settings, and call ``mark_operator_only_options`` directly.

Two more pin what the marker is made of. A value the operator's own file read
from the environment is never replaced inside a marker written at the place its
reference sits, because the display walk runs on the dump before the markers go
in. And a default the loader supplied for an unset variable is the file's own
text, shown as written and not as the placeholder.
"""

import contextlib
import copy
import json
import logging
import textwrap
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config.environment_record import EnvironmentReference
from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    mark_operator_only_options,
)
from automated_security_helper.utils.redacted_model import env_resolved_scalar
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: The variable the cells read and the distinctive value it holds. The name
#: starts with ASH_TEST_, which the loader reads, and does not end in _KEY,
#: _TOKEN, _SECRET or _PASSWORD, which it refuses.
_VAR = "ASH_TEST_GETCFG_VALUE"
_VALUE = "getcfg-env-test-value-5c1e"
_REFERENCE = "${" + _VAR + "}"
_SECTION = "aws-security-hub"
_ABSENT = "<absent>"

_IGNORED = "<operator only; ignored from this file: "
_PLACEHOLDER = "<operator only; ignored from this file: <from the environment>>"
_FROM_THE_VARIABLE = "<from ${ASH_TEST_GETCFG_VALUE}>"
_BY_REFERENCE = _IGNORED + _FROM_THE_VARIABLE + ">"


def _section(options: str) -> str:
    """A config file whose aws-security-hub reporter has *options*, YAML lines."""
    head = "reporters:\n  aws-security-hub:\n    options:\n"
    return head + textwrap.indent(options, "      ")


def _named_from_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, value: str = _VALUE
) -> Dict[str, Any]:
    """get_config of ``checkout/.ash.yaml``, which holds *body*, named from a
    working directory elsewhere, with the variable set to *value*.

    The file is in a git checkout the session does not scan, so the load drops
    the references it read from the environment at the places it settles, and
    the marker has none to show. The directory is the operator's
    (ASH_MCP_ALLOWED_CONFIG_ROOTS): a client's file is refused instead of shown.
    """
    monkeypatch.setenv(_VAR, value)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash.yaml"
    named.write_text(body, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(named))


def _found_by_ash_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, value: str = _VALUE
) -> Dict[str, Any]:
    """get_config with no file named: ASH_CONFIG names ``configs/ash.yaml`` in
    the checkout the process sits in, which holds *body*.

    The checkout is the searched tree, and the references the file read are
    kept at their places, so the marker shows them."""
    monkeypatch.setenv(_VAR, value)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / "configs" / "ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(body, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    monkeypatch.chdir(checkout)
    return mcp_get_config(search_dir=str(checkout))


#: The variables of the cell that puts a marker where the operator's own
#: reference sits. The operator's holds "no", a value that also occurs inside
#: the marker's own words; the checkout's holds a distinctive value. Neither
#: name ends in _KEY, _TOKEN, _SECRET or _PASSWORD.
_OPERATOR_VAR = "ASH_TEST_ARCHIVE_RESOLVED"
_OPERATOR_REFERENCE = "<from ${ASH_TEST_ARCHIVE_RESOLVED}>"
_OTHER_VAR = "ASH_TEST_OTHER_ARCHIVE"
_OTHER_VALUE = "other-archive-value-9e4d"


def _named_beside_the_operators_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> Dict[str, Any]:
    """get_config of ``checkout/.ash.yaml``, which holds *body*, named from a
    working directory elsewhere, while ASH_CONFIG names the operator's own file.

    The operator's file is in a plain directory, outside every checkout, and
    reads archive_resolved_findings from a variable that holds "no". What the
    checkout's file writes for the flag is left out of the load, as a scan of
    that checkout leaves it out, so the flag takes the operator's value, and the
    load takes the operator's reference at the flag's place with it
    (``_take_confined_references``): the place a marker is written at holds a
    reference whose value is "no"."""
    monkeypatch.setenv(_OPERATOR_VAR, "no")
    operator = tmp_path / "operator"
    operator.mkdir()
    operators_file = operator / "ash.yaml"
    operators_file.write_text(
        _section("archive_resolved_findings: ${ASH_TEST_ARCHIVE_RESOLVED}\n"),
        encoding="utf-8",
    )
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash.yaml"
    named.write_text(body, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("ASH_CONFIG", str(operators_file))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(named))


def _options(result: Dict[str, Any]) -> Dict[str, Any]:
    return result["reporters"][_SECTION]["options"]


def _scope(result: Dict[str, Any]) -> Any:
    return _options(result).get("findings_scope", _ABSENT)


def _limit(result: Dict[str, Any]) -> Any:
    scanners = result["scanners"]
    [key] = [name for name in scanners if name in ("detect-secrets", "detect_secrets")]
    return scanners[key]["options"].get("max_worker_output_mib", _ABSENT)


def _wrong(result: Dict[str, Any], shown: Any, expected: str, value: str = _VALUE):
    """What the answer gets wrong, as a list: *value* anywhere in it, and the
    option's marker *shown* not being *expected*. Both are collected, so a
    failure says whether the value printed, the marker is wrong, or both."""
    wrong = []
    if value in json.dumps(result, default=str):
        wrong.append("the answer holds the environment's value")
    if shown != expected:
        wrong.append(f"the option is {shown!r}, not {expected!r}")
    return wrong


# A value the file read from the environment, in each shape it can take at
# findings_scope. The loader resolves a reference only at the start of a scalar
# (``acct-${VAR}`` is plain text, see the literal controls below), so the
# interpolated value puts its text after the reference.
_SHAPES = {
    "whole-value": "findings_scope: ${ASH_TEST_GETCFG_VALUE}\n",
    "interpolated-value": "findings_scope: ${ASH_TEST_GETCFG_VALUE}-acct\n",
    "list-entry": "findings_scope:\n  - literal-entry\n  - ${ASH_TEST_GETCFG_VALUE}\n",
    "mapping-value": "findings_scope:\n  scope: ${ASH_TEST_GETCFG_VALUE}\n",
    "mapping-key": "findings_scope:\n  ${ASH_TEST_GETCFG_VALUE}: literal-entry\n",
    # The loader accepts a ``!!set``: the YAML loader builds a Python set, and
    # its member resolves as any other scalar does. The configuration's record
    # of what it read walks mappings, lists and strings only, so a set member
    # is in no record of reads, and only the scalar's own mark says it was read.
    "set-member": "findings_scope: !!set\n  ? ${ASH_TEST_GETCFG_VALUE}\n",
}


@pytest.mark.parametrize("shape", list(_SHAPES))
def test_a_read_value_in_a_file_in_another_checkout_shows_as_the_placeholder(
    tmp_path, monkeypatch, shape
):
    """The load drops the reference at findings_scope for a file in a checkout
    the session does not scan, so there is none to show. The marker still says
    the file set an option the scan ignores, and shows no part of the value, in
    every shape the value can take."""
    body = _section(_SHAPES[shape])

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _PLACEHOLDER), result


def test_a_read_scanner_option_in_a_file_in_another_checkout_shows_as_the_placeholder(
    tmp_path, monkeypatch
):
    """detect-secrets' ``max_worker_output_mib`` is marked as the reporter
    options are. The value is a number nothing else in the answer holds, and
    the option is ignored, so the answer shows the placeholder where it showed
    the configuration's own 256."""
    body = (
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: ${ASH_TEST_GETCFG_VALUE}\n"
    )

    result = _named_from_elsewhere(tmp_path, monkeypatch, body, value="73191")

    assert not _wrong(result, _limit(result), _PLACEHOLDER, "73191"), result


def test_a_read_archive_flag_in_a_file_in_another_checkout_shows_as_the_placeholder(
    tmp_path, monkeypatch
):
    """The flag that archives findings the scan no longer reports is shown as
    ignored when the file reads it from the environment, whatever it read."""
    body = _section("archive_resolved_findings: ${ASH_TEST_GETCFG_VALUE}\n")

    result = _named_from_elsewhere(tmp_path, monkeypatch, body, value="true")

    flag = _options(result).get("archive_resolved_findings", _ABSENT)
    assert flag == _PLACEHOLDER, result


# What a file in another checkout writes with no read at all is shown as written.
_LITERALS = {
    "plain": (
        "findings_scope: a-literal-scope\narchive_resolved_findings: true\n",
        {
            "findings_scope": _IGNORED + '"a-literal-scope">',
            "archive_resolved_findings": _IGNORED + "true>",
        },
    ),
    # A reference has to open the scalar to be read: this text is the file's own.
    "reference-not-at-the-start": (
        "findings_scope: acct-${ASH_TEST_GETCFG_VALUE}\n",
        {"findings_scope": _IGNORED + '"acct-${ASH_TEST_GETCFG_VALUE}">'},
    ),
}


@pytest.mark.parametrize("literal", list(_LITERALS))
def test_a_literal_in_a_file_in_another_checkout_is_shown_as_written(
    tmp_path, monkeypatch, literal
):
    """The control for the cells above: a value the file wrote and did not read
    is the repository's own text, and the variable being set in the server's
    environment does not change how it is shown."""
    options, expected = _LITERALS[literal]

    result = _named_from_elsewhere(tmp_path, monkeypatch, _section(options))

    assert _VALUE not in json.dumps(result, default=str), result
    for option, marker in expected.items():
        assert _options(result)[option] == marker, result


def test_a_literal_beside_a_read_value_is_shown_as_written(tmp_path, monkeypatch):
    """The file reads project_name from the variable and writes a literal
    scope that is neither the value nor holds it: the literal is shown."""
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + _section(
        "findings_scope: a-literal-scope\n"
    )

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _IGNORED + '"a-literal-scope">'), result


@pytest.mark.parametrize(
    "scope",
    [_VALUE, f"prefix-{_VALUE}-suffix"],
    ids=["equal", "containing"],
)
def test_a_literal_that_is_or_contains_a_read_value_shows_the_placeholder(
    tmp_path, monkeypatch, scope
):
    """The file reads project_name from the variable and writes findings_scope
    as a literal that equals the value, or holds it. The marker cannot tell
    that literal from the read, so it shows less: the placeholder."""
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + _section(
        f"findings_scope: {scope}\n"
    )

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _PLACEHOLDER), result


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(_named_from_elsewhere, id="named-file"),
        pytest.param(_found_by_ash_config, id="ash-config-no-file-named"),
    ],
)
def test_a_default_the_loader_supplied_is_shown_as_written_not_as_the_placeholder(
    tmp_path, monkeypatch, answer
):
    """``${VAR:default}`` with VAR unset resolves to the default, which is the
    file's own text. The loader marks that scalar as not read from the
    environment (``EnvResolvedScalar.from_environment`` is False), and the
    record of what the chain read lists no value for it
    (``config_validator._interpolated_pairs`` pairs a reference only when its
    variable is set), so no reference and no environment value matches it.
    Nothing was read, so the marker shows the default as JSON, as it shows any
    literal, and not the placeholder."""
    monkeypatch.delenv("ASH_TEST_UNSET_SCOPE", raising=False)
    body = _section("findings_scope: ${ASH_TEST_UNSET_SCOPE:a-default-scope}\n")

    result = answer(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _IGNORED + '"a-default-scope">'), result


def test_aws_region_read_from_the_environment_is_left_out_and_not_marked(
    tmp_path, monkeypatch
):
    """aws_region is not an operator-only option, so it is never marked. The
    load confines the whole aws-security-hub section to the operator's
    configuration (``record_operator_reporters``; a scan reads it through
    ``reporter_section``), so what a repository's file wrote for aws_region is
    left out of the answer, and the record the marking reads
    (``RepositorySettings``) holds only the operator-only places. The answer
    holds the section without it, neither as applied nor as ignored, and no
    value."""
    body = _section(
        "findings_scope: a-literal-scope\naws_region: ${ASH_TEST_GETCFG_VALUE}\n"
    )

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert "aws_region" not in _options(result), result
    assert _scope(result) == _IGNORED + '"a-literal-scope">', result
    assert _VALUE not in json.dumps(result, default=str), result


# A marker is written at a place where the operator's own reference sits, and
# that reference's value occurs inside the marker's own words. The cell asserts
# the option's exact text: an edit of the marker around that value would fail
# it, and a check that the value appears nowhere in the answer would not.
_ARCHIVE_WRITES = {
    "literal": ("archive_resolved_findings: true\n", _IGNORED + "true>"),
    "read-from-the-environment": (
        "archive_resolved_findings: ${ASH_TEST_OTHER_ARCHIVE}\n",
        _PLACEHOLDER,
    ),
}


@pytest.mark.parametrize("write", list(_ARCHIVE_WRITES))
def test_a_marker_where_the_operators_reference_sits_is_shown_whole(
    tmp_path, monkeypatch, write
):
    """The operator's own file reads the archive flag from a variable that holds
    "no", and the named file in another checkout writes the flag too, which a scan
    of that checkout ignores, so the flag is shown as ignored. The flag is the
    operator's now, and the operator's reference sits at its place. The marker is
    still whole: the checkout's value as the file wrote it (a literal) or the
    placeholder (a read), with nothing of the operator's reference inside the
    words around it. The display walk runs before the markers are written, and
    a marker is built from the record, never from the dump."""
    checkout_writes, expected = _ARCHIVE_WRITES[write]
    monkeypatch.setenv(_OTHER_VAR, _OTHER_VALUE)

    result = _named_beside_the_operators_file(
        tmp_path, monkeypatch, _section(checkout_writes)
    )

    assert "reporters" in result, result
    flag = _options(result).get("archive_resolved_findings", _ABSENT)
    assert _OPERATOR_REFERENCE not in str(flag), result
    assert flag == expected, result
    assert _OTHER_VALUE not in json.dumps(result, default=str), result


# With no file named, ASH_CONFIG's file in the searched checkout keeps the
# reference at the place the file wrote it, and the marker shows it.
_BY_REFERENCE_SHAPES = {
    "whole-value": (_SHAPES["whole-value"], _BY_REFERENCE),
    "interpolated-value": (
        _SHAPES["interpolated-value"],
        _IGNORED + _FROM_THE_VARIABLE + "-acct>",
    ),
    "list-entry": (
        _SHAPES["list-entry"],
        _IGNORED + '["literal-entry", "' + _FROM_THE_VARIABLE + '"]>',
    ),
    "mapping-value": (
        _SHAPES["mapping-value"],
        _IGNORED + '{"scope": "' + _FROM_THE_VARIABLE + '"}>',
    ),
    "mapping-key": (
        _SHAPES["mapping-key"],
        _IGNORED + '{"' + _FROM_THE_VARIABLE + '": "literal-entry"}>',
    ),
}


@pytest.mark.parametrize("shape", list(_BY_REFERENCE_SHAPES))
def test_a_reference_that_survives_is_shown_in_the_markers_place(
    tmp_path, monkeypatch, shape
):
    """A reference at the place the file wrote the value is shown as it was
    written, ``<from ${VAR}>``, and never as the placeholder: the placeholder is
    for a read the load left no reference for."""
    options, expected = _BY_REFERENCE_SHAPES[shape]

    result = _found_by_ash_config(tmp_path, monkeypatch, _section(options))

    assert not _wrong(result, _scope(result), expected), result


def test_a_scanner_option_with_a_surviving_reference_shows_the_reference(
    tmp_path, monkeypatch
):
    """The control for the scanner option: with no file named, the reference
    survives at the place, and the marker shows it, not the placeholder."""
    body = (
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: ${ASH_TEST_GETCFG_VALUE}\n"
    )

    result = _found_by_ash_config(tmp_path, monkeypatch, body, value="73191")

    assert not _wrong(result, _limit(result), _BY_REFERENCE, "73191"), result


def test_a_set_member_read_from_the_environment_shows_the_placeholder_with_no_file(
    tmp_path, monkeypatch
):
    """No reference is recorded for a set member, so none survives even where
    the file's references are kept: the marker shows the placeholder, where it
    printed the set, value included."""
    body = _section(_SHAPES["set-member"])

    result = _found_by_ash_config(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _PLACEHOLDER), result


def test_the_answer_with_no_file_hides_a_value_only_the_first_read_recorded(
    tmp_path, monkeypatch
):
    """With no file named, the references the marking uses come from the first
    read of ASH_CONFIG's chain, and the answer's own configuration is the second,
    scan-confined read. The values read from the environment join the same way:
    the first read's with the answer's. The second read here records none, so
    only the first read's value can make the placeholder of the literal that
    holds it."""
    from automated_security_helper.config import resolve_config as resolve_module

    real_resolve = resolve_module.resolve_config

    def resolve_and_forget_the_reads(*args, **kwargs):
        config = real_resolve(*args, **kwargs)
        config._environment_values = []
        return config

    monkeypatch.setattr(resolve_module, "resolve_config", resolve_and_forget_the_reads)
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + _section(
        f"findings_scope: prefix-{_VALUE}-suffix\n"
    )

    result = _found_by_ash_config(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _PLACEHOLDER), result


@contextlib.contextmanager
def _warnings() -> Iterator[List[str]]:
    """ASH's warnings while the block runs, as their messages."""
    from automated_security_helper.utils.log import ASH_LOGGER

    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
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


def _add_a_second_record(records: List[RepositorySettings]) -> None:
    records.append(RepositorySettings(trees=[]))


@pytest.mark.parametrize(
    "change, recorded",
    [(_add_a_second_record, 2), (lambda records: records.clear(), 0)],
    ids=["a-second-record", "no-record"],
)
def test_a_load_that_records_other_than_one_set_of_settings_is_refused(
    tmp_path, monkeypatch, change: Callable[[List[RepositorySettings]], None], recorded
):
    """The marking reads the one record of what the chain's files wrote for the
    operator-only options. A load that left two, or none, cannot be marked, and
    an answer shown without that judgment would print the options as applied:
    get_config returns a refusal with the exit code every internal refusal of
    the tool has, names the count in the log, and holds neither a path nor a
    value in the answer."""
    from automated_security_helper.config import resolve_config as resolve_module

    real_resolve = resolve_module.resolve_config

    def resolve_then_change_the_record(*args, **kwargs):
        config = real_resolve(*args, **kwargs)
        change(kwargs["repository_out"])
        return config

    monkeypatch.setattr(
        resolve_module, "resolve_config", resolve_then_change_the_record
    )
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + _section(
        "findings_scope: ${ASH_TEST_GETCFG_VALUE}\n"
    )

    with _warnings() as messages:
        result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert result["success"] is False, result
    assert result["error_category"] == "unexpected_error", result
    assert result["error_type"] == "MCPResourceError", result
    assert result["exit_code"] == 1, result
    assert result["operation"] == "get_config", result
    assert "operator-only options" in result["error"], result
    text = json.dumps(result, default=str)
    assert _VALUE not in text, result
    assert str(tmp_path) not in text, result
    ours = [m for m in messages if "operator-only options" in m and "recorded" in m]
    assert len(ours) == 1, messages
    assert str(recorded) in ours[0], ours
    assert _VALUE not in ours[0] and str(tmp_path) not in ours[0], ours


# --- mark_operator_only_options, called directly ---------------------------

_FLAGGED = "flag-only-value-3d7a"


def _a_reference(
    *below: Any, resolved: str = _VALUE, key: bool = False
) -> EnvironmentReference:
    """A reference the chain recorded at findings_scope, or *below* it."""
    return EnvironmentReference(
        path=("reporters", _SECTION, "options", "findings_scope", *below),
        written=_REFERENCE,
        resolved=resolved,
        value=resolved,
        key=key,
    )


def _mark(scope: Any, references=(), **environment) -> Any:
    """The marker written for a findings_scope of *scope*. No record of what
    the files wrote is given, so every option the data holds is marked.
    *environment* is passed on as it is, so a call that gives no environment
    values is made as it was before the parameter existed."""
    data = {"reporters": {_SECTION: {"options": {"findings_scope": scope}}}}
    marked = mark_operator_only_options(data, None, references, **environment)
    return marked["reporters"][_SECTION]["options"]["findings_scope"]


@pytest.mark.parametrize(
    "environment_values",
    [False, True],
    ids=["references-only", "with-environment-values"],
)
def test_marking_changes_neither_its_input_nor_anything_nested_in_it(
    environment_values,
):
    """The marker is written into a copy: the caller's dict, and every dict and
    list inside it, keep what they held, and the leaf the loader marked as read
    is the same object."""
    read = env_resolved_scalar(_VALUE, _VAR)
    scope = ["literal-entry", read]
    data = {
        "reporters": {
            _SECTION: {
                "options": {
                    "findings_scope": scope,
                    "archive_resolved_findings": True,
                    "aws_region": "us-west-2",
                }
            }
        },
        "scanners": {"detect-secrets": {"options": {"max_worker_output_mib": 256}}},
    }
    before = copy.deepcopy(data)
    environment = {"environment_values": [_VALUE]} if environment_values else {}

    marked = mark_operator_only_options(data, None, [_a_reference(1)], **environment)

    assert data == before
    assert scope == ["literal-entry", read] and scope[1] is read
    assert type(scope[1]) is type(read)
    assert marked is not data
    assert marked["reporters"] is not data["reporters"]
    options = marked["reporters"][_SECTION]["options"]
    assert options is not data["reporters"][_SECTION]["options"]
    assert options["findings_scope"] == (
        _IGNORED + '["literal-entry", "' + _FROM_THE_VARIABLE + '"]>'
    )
    assert options["archive_resolved_findings"] == _IGNORED + "true>"
    assert options["aws_region"] == "us-west-2"
    limit = marked["scanners"]["detect-secrets"]["options"]["max_worker_output_mib"]
    assert limit == _IGNORED + "256>"


@pytest.mark.parametrize(
    "scope, environment_values",
    [
        pytest.param(_VALUE, [_VALUE], id="equal-string"),
        pytest.param(f"prefix-{_VALUE}-suffix", [_VALUE], id="string-containing-it"),
        pytest.param(["literal-entry", _VALUE], [_VALUE], id="list-entry"),
        pytest.param(("literal-entry", _VALUE), [_VALUE], id="tuple-entry"),
        pytest.param({"scope": _VALUE}, [_VALUE], id="mapping-value"),
        pytest.param({_VALUE: "literal-entry"}, [_VALUE], id="mapping-key"),
        pytest.param({"literal-member", _VALUE}, [_VALUE], id="set-member"),
        pytest.param(frozenset({"literal-member", _VALUE}), [_VALUE], id="frozenset"),
        pytest.param({"scopes": [{"deep": _VALUE}]}, [_VALUE], id="nested"),
        pytest.param(73191, ["73191"], id="number"),
    ],
)
def test_a_value_that_is_or_contains_an_environment_value_shows_the_placeholder(
    scope, environment_values
):
    """No part of the value is shown: the whole marker value is the placeholder,
    the literal entries beside a read one included. A literal that equals or
    contains a value the configuration read cannot be told from the read, so it
    gets the placeholder too, which shows less rather than more."""
    assert _mark(scope, environment_values=environment_values) == _PLACEHOLDER


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param(env_resolved_scalar(_FLAGGED, _VAR), id="whole-value"),
        pytest.param(
            ["literal-entry", env_resolved_scalar(_FLAGGED, _VAR)], id="list-entry"
        ),
        pytest.param(
            {"scope": env_resolved_scalar(_FLAGGED, _VAR)}, id="mapping-value"
        ),
        pytest.param(
            {env_resolved_scalar(_FLAGGED, _VAR): "literal-entry"}, id="mapping-key"
        ),
        pytest.param(
            {"literal-member", env_resolved_scalar(_FLAGGED, _VAR)}, id="set-member"
        ),
    ],
)
def test_a_leaf_the_loader_marked_as_read_shows_the_placeholder_alone(scope):
    """The loader marks each scalar it read from the environment
    (``EnvResolvedScalar.from_environment``). That mark is enough: no
    environment values are given here, as for a read the configuration's record
    of values does not hold (a set member)."""
    assert _mark(scope) == _PLACEHOLDER


def test_a_default_that_supplied_a_value_is_shown_as_written():
    """A ``${VAR:default}`` whose variable is unset resolves to the file's own
    text, which the loader marks as not read from the environment."""
    default = env_resolved_scalar("a-default-scope", _VAR, from_environment=False)

    assert _mark(default) == _IGNORED + '"a-default-scope">'


@pytest.mark.parametrize(
    "scope, reference, expected",
    [
        pytest.param(_VALUE, _a_reference(), _BY_REFERENCE, id="whole-value"),
        pytest.param(
            ["literal-entry", _VALUE],
            _a_reference(1),
            _IGNORED + '["literal-entry", "' + _FROM_THE_VARIABLE + '"]>',
            id="list-entry",
        ),
        pytest.param(
            {_VALUE: "literal-entry"},
            _a_reference(key=True),
            _IGNORED + '{"' + _FROM_THE_VARIABLE + '": "literal-entry"}>',
            id="mapping-key",
        ),
    ],
)
def test_a_leaf_a_reference_shows_keeps_the_reference_beside_environment_values(
    scope, reference, expected
):
    """The reference is tried first: a value the surviving references show
    entirely is shown as them, and the environment values, which hold it, add
    nothing."""
    assert _mark(scope, [reference], environment_values=[_VALUE]) == expected


def test_one_read_leaf_with_no_reference_turns_the_whole_value_into_the_placeholder():
    """Two entries are read, and a reference survives for the first only: the
    second shows nothing of itself, so the marker shows nothing of either."""
    first = env_resolved_scalar(_VALUE, _VAR)
    second = env_resolved_scalar(_FLAGGED, _VAR)

    assert _mark([first, second], [_a_reference(0)]) == _PLACEHOLDER


@pytest.mark.parametrize("kind", [set, frozenset])
def test_a_set_is_shown_as_a_json_list_in_sorted_order(kind):
    """A set has no order, and its repr is Python's: it is shown as a JSON list,
    in the order of the shown members, the same text whatever the order the
    members were added in."""
    shown = _mark(kind(["c-member", "a-member", "b-member"]))

    assert shown == _IGNORED + '["a-member", "b-member", "c-member"]>'


def test_environment_values_given_as_one_string_are_one_value():
    """A lone string is the one value, never the list of its characters: read
    as characters, every literal holding an "a" would be the placeholder."""
    assert _mark("a-literal-scope", environment_values=_VALUE) == (
        _IGNORED + '"a-literal-scope">'
    )
    assert _mark(_VALUE, environment_values=_VALUE) == _PLACEHOLDER


def test_an_empty_environment_value_marks_nothing():
    """The empty string is in every text: it is no value read from the
    environment, and no literal becomes the placeholder because of it."""
    assert _mark("a-literal-scope", environment_values=[""]) == (
        _IGNORED + '"a-literal-scope">'
    )
