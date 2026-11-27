# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config prints no value the server's environment gave to an ignored option.

get_config shows the operator-only options a file in a git checkout sets
(aws-security-hub ``findings_scope`` and ``archive_resolved_findings``,
detect-secrets ``max_worker_output_mib``) as ``<operator only; ignored from this
file: VALUE>``, because a scan of that checkout ignores them. A value the file
read from the environment (``${VAR}``) belongs to the server, so VALUE is the
reference the file wrote (``<from ${VAR}>``), on both routes: from the
reference the load kept at that place, or else, where the load dropped it (as
it does for a file in a checkout the session does not scan), from the loader's
own mark on the value, which carries the reference. Only a literal that equals
or contains a value the configuration read elsewhere is withheld, with a
placeholder that says nothing of where the value came from; for a number or a
boolean only an equal text counts.

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
#: What a literal that only equals or contains a value the configuration read
#: is shown as: no word of where the value came from, and none of the value.
_WITHHELD = (
    "<operator only; ignored from this file: "
    "<withheld: may hold a value read from the environment>>"
)
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


def _named_extending_a_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, value: str = _VALUE
) -> Dict[str, Any]:
    """get_config of ``checkout/.ash.yaml``, which only extends
    ``configs/ash.yaml``, the chain file that holds *body*, named from a working
    directory elsewhere, with the variable set to *value*.

    Both files are in a checkout the session does not scan, so the confined
    read drops the references the base wrote at the places it settles, as
    ``_named_from_elsewhere`` does for a file that holds the body itself."""
    monkeypatch.setenv(_VAR, value)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    base = checkout / "configs" / "ash.yaml"
    base.parent.mkdir(parents=True)
    base.write_text(body, encoding="utf-8")
    named = checkout / ".ash.yaml"
    named.write_text("extends: configs/ash.yaml\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(named))


#: The variables of the cell that puts a marker where the operator's own
#: reference sits. The operator's holds "no", a value that also occurs inside
#: the marker's own words; the checkout's holds a distinctive value. Neither
#: name ends in _KEY, _TOKEN, _SECRET or _PASSWORD.
_OPERATOR_VAR = "ASH_TEST_ARCHIVE_RESOLVED"
_OPERATOR_REFERENCE = "<from ${ASH_TEST_ARCHIVE_RESOLVED}>"
_OTHER_VAR = "ASH_TEST_OTHER_ARCHIVE"
_OTHER_VALUE = "other-archive-value-9e4d"
_OTHER_REFERENCE = "<from ${ASH_TEST_OTHER_ARCHIVE}>"


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


# What the answer shows for findings_scope in each of those shapes: the
# reference the file wrote, at the place the value sits. A set shows as a JSON
# list in the order of its shown members.
_SHAPE_MARKERS = {
    "whole-value": _BY_REFERENCE,
    "interpolated-value": _IGNORED + _FROM_THE_VARIABLE + "-acct>",
    "list-entry": _IGNORED + '["literal-entry", "' + _FROM_THE_VARIABLE + '"]>',
    "mapping-value": _IGNORED + '{"scope": "' + _FROM_THE_VARIABLE + '"}>',
    "mapping-key": _IGNORED + '{"' + _FROM_THE_VARIABLE + '": "literal-entry"}>',
    "set-member": _IGNORED + '["' + _FROM_THE_VARIABLE + '"]>',
}


@pytest.mark.parametrize("shape", list(_SHAPES))
def test_a_read_value_in_a_file_in_another_checkout_shows_the_reference_it_was_read_by(
    tmp_path, monkeypatch, shape
):
    """The load drops the reference at findings_scope for a file in a checkout
    the session does not scan, so none of the load's survives there. The
    loader's own mark on the value the file read still carries the text the file
    wrote, so the marker shows ``<from ${VAR}>`` at the place, in every shape the
    value can take, and shows no part of the value."""
    body = _section(_SHAPES[shape])

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _SHAPE_MARKERS[shape]), result


def test_a_read_scanner_option_in_a_file_in_another_checkout_shows_the_reference(
    tmp_path, monkeypatch
):
    """detect-secrets' ``max_worker_output_mib`` is marked as the reporter
    options are. The value is a number nothing else in the answer holds, and
    the option is ignored. The file wrote a reference, so the record's value
    carries the loader's mark and the answer shows the reference where it
    showed the configuration's own 256."""
    body = (
        "scanners:\n  detect-secrets:\n    options:\n"
        "      max_worker_output_mib: ${ASH_TEST_GETCFG_VALUE}\n"
    )

    result = _named_from_elsewhere(tmp_path, monkeypatch, body, value="73191")

    assert not _wrong(result, _limit(result), _BY_REFERENCE, "73191"), result


def test_a_read_archive_flag_in_a_file_in_another_checkout_shows_the_reference(
    tmp_path, monkeypatch
):
    """The flag that archives findings the scan no longer reports is shown as
    ignored when the file reads it from the environment: by the reference the
    file wrote, whatever it read."""
    body = _section("archive_resolved_findings: ${ASH_TEST_GETCFG_VALUE}\n")

    result = _named_from_elsewhere(tmp_path, monkeypatch, body, value="true")

    flag = _options(result).get("archive_resolved_findings", _ABSENT)
    assert flag == _BY_REFERENCE, result


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
    as a literal that equals the value, or holds it. Nothing at findings_scope
    says it was read: no reference of the load sits there and the loader put no
    mark on it, so the marker cannot tell the literal from the read and shows
    less: the placeholder, which names no source."""
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + _section(
        f"findings_scope: {scope}\n"
    )

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _WITHHELD), result


def test_the_same_reference_is_shown_alike_with_no_file_and_as_a_named_files_base(
    tmp_path, monkeypatch
):
    """One chain file in another checkout writes ``findings_scope`` as a
    reference. With no file named, the first read's references reach the
    marking and the file's own reference matches. As the base a named file's
    chain extends, the confined read has dropped those references, and only the
    loader's mark on the value names the reference. Both answers show the same
    text, the reference the file wrote, and the value is in neither."""
    body = _section("findings_scope: ${ASH_TEST_GETCFG_VALUE}\n")
    for name in ("no-file", "named"):
        (tmp_path / name).mkdir()

    by_ash_config = _found_by_ash_config(tmp_path / "no-file", monkeypatch, body)
    as_a_base = _named_extending_a_base(tmp_path / "named", monkeypatch, body)

    assert _scope(by_ash_config) == _BY_REFERENCE, by_ash_config
    assert _scope(as_a_base) == _scope(by_ash_config), as_a_base
    for result in (by_ash_config, as_a_base):
        assert _VALUE not in json.dumps(result, default=str), result


def _flag(result: Dict[str, Any]) -> Any:
    return _options(result).get("archive_resolved_findings", _ABSENT)


@pytest.mark.parametrize(
    "literal, read_text, option, shown",
    [
        pytest.param(
            "scanners:\n  detect-secrets:\n    options:\n"
            "      max_worker_output_mib: 256\n",
            "25",
            _limit,
            _IGNORED + "256>",
            id="number-holding-the-read-text",
        ),
        pytest.param(
            _section("archive_resolved_findings: false\n"),
            "als",
            _flag,
            _IGNORED + "false>",
            id="boolean-holding-the-read-text",
        ),
    ],
)
def test_a_number_or_boolean_literal_is_withheld_only_by_an_equal_text(
    tmp_path, monkeypatch, literal, read_text, option, shown
):
    """The file writes a literal number or boolean at an ignored option and
    reads project_name from the variable. The read text ("25", "als") sits
    inside the literal's text ("256", "false") but is not equal to it. A value
    interpolated from the environment is a string and carries the loader's mark,
    so a number or a boolean can only be a read when its text equals one: each
    literal is shown as its JSON inside the marker, not withheld."""
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + literal

    result = _named_from_elsewhere(tmp_path, monkeypatch, body, value=read_text)

    assert option(result) == shown, result


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
    load gives it the operator's value (``confine_reporter_destinations``
    replaces or fills each destination option from the operator's
    configuration), so what a repository's file wrote for aws_region is left
    out of the answer, and the record the marking reads
    (``RepositorySettings``) holds only the operator-only places. With
    ASH_CONFIG unset the operator's configuration is the defaults, which set no
    aws_region, so the option is absent: neither applied nor ignored, and no
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
        _IGNORED + _OTHER_REFERENCE + ">",
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
    checkout's own reference (a read, shown by the loader's mark on the value
    since the load kept none at the place), with nothing of the operator's
    reference inside the words around it. The display walk runs before the markers are written, and
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
    name: (_SHAPES[name], _SHAPE_MARKERS[name])
    for name in _SHAPES
    if name != "set-member"
}


@pytest.mark.parametrize("shape", list(_BY_REFERENCE_SHAPES))
def test_a_reference_that_survives_is_shown_in_the_markers_place(
    tmp_path, monkeypatch, shape
):
    """A reference at the place the file wrote the value is shown as it was
    written, ``<from ${VAR}>``, and never as the placeholder: the placeholder is
    for a leaf that only matches a read value, and a read the file wrote as a
    reference is shown as that reference on this route as on the named one."""
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


def test_a_set_member_read_from_the_environment_shows_its_reference_with_no_file(
    tmp_path, monkeypatch
):
    """No reference is recorded for a set member, so none survives even where
    the file's references are kept. The loader's mark on the member names the
    reference the file wrote, so the marker shows it in a JSON list, where it
    printed the set, value included."""
    body = _section(_SHAPES["set-member"])

    result = _found_by_ash_config(tmp_path, monkeypatch, body)

    assert not _wrong(result, _scope(result), _SHAPE_MARKERS["set-member"]), result


def test_the_answer_with_no_file_hides_a_value_only_the_first_read_recorded(
    tmp_path, monkeypatch
):
    """With no file named, the references the marking uses come from the first
    read of ASH_CONFIG's chain, and the answer's own configuration is the second,
    scan-confined read. The values read from the environment join the same way:
    the first read's with the answer's. The second read here records none, so
    only the first read's value can withhold the literal that holds it. The
    cell also pins that the wrapper ran and that the config it returned reports
    no values, so the withheld text cannot come from the answer's own read."""
    from automated_security_helper.config import resolve_config as resolve_module
    from automated_security_helper.utils.error_text import config_environment_values

    real_resolve = resolve_module.resolve_config
    returned = []

    def resolve_and_forget_the_reads(*args, **kwargs):
        config = real_resolve(*args, **kwargs)
        config._environment_values = []
        returned.append(config)
        return config

    monkeypatch.setattr(resolve_module, "resolve_config", resolve_and_forget_the_reads)
    body = "project_name: ${ASH_TEST_GETCFG_VALUE}\n" + _section(
        f"findings_scope: prefix-{_VALUE}-suffix\n"
    )

    result = _found_by_ash_config(tmp_path, monkeypatch, body)

    assert len(returned) >= 1, "resolve_config was never called through the wrapper"
    assert all(not config_environment_values(config) for config in returned)
    assert not _wrong(result, _scope(result), _WITHHELD), result


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
    assert f"recorded {recorded} sets" in ours[0], ours
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
    assert _mark(scope, environment_values=environment_values) == _WITHHELD


@pytest.mark.parametrize(
    "scope, expected",
    [
        pytest.param(
            env_resolved_scalar(_FLAGGED, _VAR), _BY_REFERENCE, id="whole-value"
        ),
        pytest.param(
            ["literal-entry", env_resolved_scalar(_FLAGGED, _VAR)],
            _IGNORED + '["literal-entry", "' + _FROM_THE_VARIABLE + '"]>',
            id="list-entry",
        ),
        pytest.param(
            {"scope": env_resolved_scalar(_FLAGGED, _VAR)},
            _IGNORED + '{"scope": "' + _FROM_THE_VARIABLE + '"}>',
            id="mapping-value",
        ),
        pytest.param(
            {env_resolved_scalar(_FLAGGED, _VAR): "literal-entry"},
            _IGNORED + '{"' + _FROM_THE_VARIABLE + '": "literal-entry"}>',
            id="mapping-key",
        ),
        pytest.param(
            {"literal-member", env_resolved_scalar(_FLAGGED, _VAR)},
            _IGNORED + '["' + _FROM_THE_VARIABLE + '", "literal-member"]>',
            id="set-member",
        ),
    ],
)
def test_a_leaf_the_loader_marked_as_read_shows_the_reference_its_mark_carries(
    scope, expected
):
    """The loader marks each scalar it read from the environment
    (``EnvResolvedScalar.from_environment``) and the mark carries the text the
    file wrote (``shown``). That is enough to show the reference: no references
    and no environment values are given here, as for a read the load kept no
    reference for and the configuration's record of values does not hold (a set
    member). The value is in none of the texts."""
    assert _mark(scope) == expected
    assert _FLAGGED not in _mark(scope)


def test_a_leaf_the_loader_marked_as_read_with_no_shown_text_is_withheld():
    """A mark that carries no text of what the file wrote cannot be shown as a
    reference. It is still a read, so the marker withholds the whole value, with
    a placeholder that names no source."""
    read = env_resolved_scalar(_FLAGGED, _VAR)
    read.shown = ""

    assert _mark(["literal-entry", read]) == _WITHHELD


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


def test_one_leaf_only_matching_a_read_turns_the_whole_value_into_the_placeholder():
    """Two entries: the first is read and a reference shows it. The second is a
    literal that only equals a value the configuration read, and nothing shows
    it, so the marker shows nothing of itself, and nothing of the first either."""
    first = env_resolved_scalar(_VALUE, _VAR)

    assert (
        _mark([first, _FLAGGED], [_a_reference(0)], environment_values=[_FLAGGED])
        == _WITHHELD
    )


def test_two_read_leaves_are_each_shown_by_the_reference_they_carry():
    """Both entries are read. A reference of the load shows the first, and the
    loader's mark shows the second, so neither is withheld."""
    first = env_resolved_scalar(_VALUE, _VAR)
    second = env_resolved_scalar(_FLAGGED, _VAR)

    assert _mark([first, second], [_a_reference(0)]) == (
        _IGNORED + '["' + _FROM_THE_VARIABLE + '", "' + _FROM_THE_VARIABLE + '"]>'
    )


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
    assert _mark(_VALUE, environment_values=_VALUE) == _WITHHELD


def test_an_empty_environment_value_marks_nothing():
    """The empty string is in every text: it is no value read from the
    environment, and no literal becomes the placeholder because of it."""
    assert _mark("a-literal-scope", environment_values=[""]) == (
        _IGNORED + '"a-literal-scope">'
    )


# The operator's own file sets a destination option of the off-host reporter
# (findings_scope, aws_region) by reference, and the named file in another
# checkout writes none of it, or a value of its own. The load gives the option
# the operator's value (confine_reporter_destinations), so the answer must show
# the operator's reference there, never the server's value, and never the
# position of a value the checkout's own reference read.
#
# What each cell reads on the tip's bytes, without the fix to
# _take_confined_references (the load carries no reference for a destination
# value it copied in):
#   1. findings_scope prints the operator's variable value in clear.
#   2. aws_region prints the operator's variable value in clear. (aws_region is
#      a plain optional string whose blank is unset: no shape check at load, so
#      "xx-test-9" loads.)
#   3. the same as 1, through the fill branch (the checkout's file has no
#      aws-security-hub section, so the confinement creates one holding the
#      operator's options); the cell is written for what the fix does on that
#      route, and the fill branch is not confirmed by a run here.
#   4. aws_region reads "eu-<from ${ASH_TEST_REPO_REGION}>-7": the checkout's
#      reference, still displayed at the place, replaces its value ("test")
#      inside the operator's literal "eu-test-7".
#   5. passes on both: a literal is shown as written either way.
_OPERATOR_SCOPE_VAR = "ASH_TEST_OPERATOR_SCOPE"
_OPERATOR_SCOPE_VALUE = "operator-scope-env-3b7d"
_OPERATOR_SCOPE_REFERENCE = "<from ${ASH_TEST_OPERATOR_SCOPE}>"
_OPERATOR_REGION_VAR = "ASH_TEST_OPERATOR_REGION"
_OPERATOR_REGION_VALUE = "xx-test-9"
_OPERATOR_REGION_REFERENCE = "<from ${ASH_TEST_OPERATOR_REGION}>"
_REPO_REGION_VAR = "ASH_TEST_REPO_REGION"
_REPO_REGION_REFERENCE = "<from ${ASH_TEST_REPO_REGION}>"


def _named_beside_an_operators_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operators_body: str,
    body: str,
) -> Dict[str, Any]:
    """get_config of ``checkout/.ash.yaml``, which holds *body*, named from a
    working directory elsewhere, while ASH_CONFIG names the operator's own file,
    which holds *operators_body*, in a plain directory outside every checkout.

    The same route as ``_named_beside_the_operators_file``, with the operator's
    file given by the caller instead of its archive flag. The caller sets the
    variables the files read."""
    operator = tmp_path / "operator"
    operator.mkdir()
    operators_file = operator / "ash.yaml"
    operators_file.write_text(operators_body, encoding="utf-8")
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


def test_a_destination_the_operator_reads_from_the_environment_is_shown_by_reference(
    tmp_path, monkeypatch
):
    """The operator's file reads findings_scope from a variable; the file in
    another checkout writes only the archive flag. The load gives the section
    the operator's findings_scope, and the answer shows the operator's reference
    there, not the server's value. The flag the checkout wrote is the ignored
    option it always was."""
    monkeypatch.setenv(_OPERATOR_SCOPE_VAR, _OPERATOR_SCOPE_VALUE)

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("findings_scope: ${ASH_TEST_OPERATOR_SCOPE}\n"),
        _section("archive_resolved_findings: true\n"),
    )

    assert _OPERATOR_SCOPE_VALUE not in json.dumps(result, default=str), result
    assert _options(result).get("findings_scope", _ABSENT) == (
        _OPERATOR_SCOPE_REFERENCE
    ), result
    assert _options(result).get("archive_resolved_findings", _ABSENT) == (
        _IGNORED + "true>"
    ), result


def test_an_aws_region_the_operator_reads_from_the_environment_is_shown_by_reference(
    tmp_path, monkeypatch
):
    """The operator's file reads aws_region from a variable; the file in another
    checkout writes a literal aws_region of its own and nothing operator-only.
    The load replaces the checkout's region with the operator's, and the answer
    shows the operator's reference, not the server's value."""
    monkeypatch.setenv(_OPERATOR_REGION_VAR, _OPERATOR_REGION_VALUE)

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("aws_region: ${ASH_TEST_OPERATOR_REGION}\n"),
        _section("aws_region: checkout-region-1\n"),
    )

    assert _OPERATOR_REGION_VALUE not in json.dumps(result, default=str), result
    assert "checkout-region-1" not in json.dumps(result, default=str), result
    assert _options(result).get("aws_region", _ABSENT) == (
        _OPERATOR_REGION_REFERENCE
    ), result


def test_a_destination_filled_into_a_file_with_no_reporter_section_is_shown_by_reference(
    tmp_path, monkeypatch
):
    """The file in another checkout has no aws-security-hub section at all. The
    load creates the section holding the operator's options (the fill branch of
    ``confine_reporter_destinations``), and the answer shows the operator's
    findings_scope as the reference the operator's file wrote, not the server's
    value."""
    monkeypatch.setenv(_OPERATOR_SCOPE_VAR, _OPERATOR_SCOPE_VALUE)

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("findings_scope: ${ASH_TEST_OPERATOR_SCOPE}\n"),
        "project_name: harmless-checkout-name\n",
    )

    assert _OPERATOR_SCOPE_VALUE not in json.dumps(result, default=str), result
    assert _options(result).get("findings_scope", _ABSENT) == (
        _OPERATOR_SCOPE_REFERENCE
    ), result


def test_the_checkouts_reference_at_a_replaced_destination_is_not_shown(
    tmp_path, monkeypatch
):
    """The operator's file holds a literal aws_region, and the file in another
    checkout reads its own from a variable whose value ("test") is inside the
    operator's text. The load replaces the checkout's region with the operator's
    literal, so the checkout's reference describes a value the configuration no
    longer holds: the answer reads the operator's literal whole, with nothing of
    the checkout's variable inside it."""
    monkeypatch.setenv(_REPO_REGION_VAR, "test")

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("aws_region: eu-test-7\n"),
        _section("aws_region: ${ASH_TEST_REPO_REGION}\n"),
    )

    assert _options(result).get("aws_region", _ABSENT) == "eu-test-7", result
    assert _REPO_REGION_REFERENCE not in json.dumps(result, default=str), result


def test_a_literal_destination_the_operator_wrote_is_shown_as_written(
    tmp_path, monkeypatch
):
    """The control: the operator's file holds a literal findings_scope and the
    file in another checkout writes only the archive flag. The operator's
    literal is shown as written."""
    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("findings_scope: operator-literal-scope\n"),
        _section("archive_resolved_findings: true\n"),
    )

    assert _options(result).get("findings_scope", _ABSENT) == (
        "operator-literal-scope"
    ), result


# A destination value is shown by the reference its own mark carries, wherever
# the load put it:
#   1. AWS_Region: the confinement matches an option name with its case kept,
#      so the load leaves this spelling as the checkout wrote it, and the
#      reference the checkout's file wrote there still describes it.
#   2. the settle writes the operator's value under the checkout's spelling of
#      the section, while the operator's reference names the operator's own
#      spelling: the copy is shown by the reference its value carries.
#   3. a set member has no position for a reference to name: it is shown by
#      the reference its value carries.
_AWS_REGION_CASE_VARIANT = "AWS_Region: ${ASH_TEST_GETCFG_VALUE}\n"


def test_a_case_variant_of_a_destination_name_keeps_its_reference(
    tmp_path, monkeypatch
):
    """A file in another checkout writes ``AWS_Region``, which is no spelling of
    the ``aws_region`` option the confinement replaces, so the load keeps the
    value where it was read. The reference the file wrote there still describes
    it: the answer shows the reference, and the value is nowhere."""
    body = _section(_AWS_REGION_CASE_VARIANT)

    result = _named_from_elsewhere(tmp_path, monkeypatch, body)

    assert _VALUE not in json.dumps(result, default=str), result
    assert _options(result)["AWS_Region"] == _FROM_THE_VARIABLE, result


def test_a_settled_option_is_shown_by_the_operators_reference_under_the_checkouts_spelling(
    tmp_path, monkeypatch
):
    """The operator's file (ASH_CONFIG, outside every checkout) reads
    findings_scope from a variable. The checkout's file spells the section
    ``AwsSecurityHub`` and writes its own findings_scope, which the load leaves
    out. The file is inside the searched tree, so the answer is not marked, and
    the operator's value sits under the checkout's spelling: it is shown by the
    operator's reference there."""
    monkeypatch.setenv(_OPERATOR_SCOPE_VAR, _OPERATOR_SCOPE_VALUE)
    operator = tmp_path / "operator"
    operator.mkdir()
    operators_file = operator / "ash.yaml"
    operators_file.write_text(
        _section("findings_scope: ${ASH_TEST_OPERATOR_SCOPE}\n"), encoding="utf-8"
    )
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash.yaml"
    named.write_text(
        "reporters:\n  AwsSecurityHub:\n    options:\n"
        "      findings_scope: repo-scope\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("ASH_CONFIG", str(operators_file))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))

    result = mcp_get_config(config_path=str(named), search_dir=str(checkout))

    assert _OPERATOR_SCOPE_VALUE not in json.dumps(result, default=str), result
    shown = result["reporters"]["AwsSecurityHub"]["options"]["findings_scope"]
    assert shown == _OPERATOR_SCOPE_REFERENCE, result


def test_a_set_member_the_operator_read_from_the_environment_is_shown_by_reference(
    tmp_path, monkeypatch
):
    """The operator's file writes findings_scope as a ``!!set`` whose one member
    is a reference. The load gives the section that set, and the answer shows the
    member as the reference: the value is nowhere."""
    monkeypatch.setenv(_OPERATOR_SCOPE_VAR, _OPERATOR_SCOPE_VALUE)

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("findings_scope: !!set\n  ? ${ASH_TEST_OPERATOR_SCOPE}\n"),
        _section("archive_resolved_findings: true\n"),
    )

    assert _OPERATOR_SCOPE_VALUE not in json.dumps(result, default=str), result
    assert _options(result)["findings_scope"] == {_OPERATOR_SCOPE_REFERENCE}, result


# Whether a checkout's literal equals the server's value is never visible in an
# answer, and a name that differs from an option's only in case is its own key:
#   1. an equal literal and a different one: the operator's reference is shown
#      at the destination option whichever literal the checkout wrote, so the
#      answer to a guess is the same as the answer to a miss.
#   2. a checkout's reference at ``AWS_Region``: it describes that key alone and
#      is never read into the operator's ``aws_region`` beside it.
@pytest.mark.parametrize(
    "written",
    ["xx-test-9", "checkout-region-1"],
    ids=["a-literal-equal-to-the-value", "a-different-literal"],
)
def test_a_literal_in_another_checkout_does_not_tell_whether_it_equals_the_value(
    tmp_path, monkeypatch, written
):
    """The operator's file reads aws_region from a variable, and the file in
    another checkout writes a literal aws_region: the value itself, or another
    text. The load replaces the checkout's literal with the operator's value
    either way, and the answer shows the operator's reference there, with the
    value nowhere."""
    monkeypatch.setenv(_OPERATOR_REGION_VAR, _OPERATOR_REGION_VALUE)

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("aws_region: ${ASH_TEST_OPERATOR_REGION}\n"),
        _section(f"aws_region: {written}\n"),
    )

    assert _OPERATOR_REGION_VALUE not in json.dumps(result, default=str), result
    assert written not in json.dumps(result, default=str), result
    assert _options(result).get("aws_region", _ABSENT) == (
        _OPERATOR_REGION_REFERENCE
    ), result


def test_a_reference_at_a_case_variant_of_a_destination_is_not_read_into_the_option(
    tmp_path, monkeypatch
):
    """The operator's file holds a literal aws_region ("eu-test-7"), and the file
    in another checkout writes ``AWS_Region`` as a reference to a variable whose
    value ("test") is inside that text. The two names are two keys: the
    reference describes ``AWS_Region`` alone, so ``aws_region`` reads the
    operator's literal whole and ``AWS_Region`` shows the reference."""
    monkeypatch.setenv(_REPO_REGION_VAR, "test")

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("aws_region: eu-test-7\n"),
        _section("AWS_Region: ${ASH_TEST_REPO_REGION}\n"),
    )

    options = _options(result)
    assert options.get("aws_region", _ABSENT) == "eu-test-7", result
    assert options.get("AWS_Region", _ABSENT) == _REPO_REGION_REFERENCE, result
    assert "test" not in options["AWS_Region"], result


# The checkout's reference at a destination option is dropped whatever it
# resolved to, so the answer never tells whether the variable the checkout named
# holds the operator's value. The twin of the literal cell above, for a file that
# reads its own variable.
@pytest.mark.parametrize(
    "repository_region",
    [_OPERATOR_REGION_VALUE, "checkout-region-1"],
    ids=["a-variable-equal-to-the-operators-value", "a-different-value"],
)
def test_a_reference_in_another_checkout_does_not_tell_whether_its_variable_equals_the_value(
    tmp_path, monkeypatch, repository_region
):
    """The operator's file reads aws_region from one variable, and the file in
    another checkout reads its own from another, which holds the operator's value
    or a different text. The load gives the option the operator's value either
    way, and the answer shows the operator's reference there, never the
    checkout's, and neither value."""
    monkeypatch.setenv(_OPERATOR_REGION_VAR, _OPERATOR_REGION_VALUE)
    monkeypatch.setenv(_REPO_REGION_VAR, repository_region)

    result = _named_beside_an_operators_file(
        tmp_path,
        monkeypatch,
        _section("aws_region: ${ASH_TEST_OPERATOR_REGION}\n"),
        _section("aws_region: ${ASH_TEST_REPO_REGION}\n"),
    )

    dumped = json.dumps(result, default=str)
    assert _OPERATOR_REGION_VALUE not in dumped, result
    assert repository_region not in dumped, result
    assert _REPO_REGION_REFERENCE not in dumped, result
    assert _options(result).get("aws_region", _ABSENT) == (
        _OPERATOR_REGION_REFERENCE
    ), result
