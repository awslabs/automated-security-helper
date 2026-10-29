# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config reads the file it checked, not one swapped in after.

Why this exists
---------------
``get_config`` checks a config name against the session's grant
(``sandbox.validate_config_input``) and then reads it. Both reads bind their
open to the check with the file's (device, inode)
(``config_sources.file_identity`` / ``read_config_bytes(expect=...)``): the raw
read, and the resolved read, which hands the identity to ``resolve_config``. The
raw read once did too, and lost the binding when it became a read "as written":
the as-written reader opened the name a second time, by name, so a file moved
into place after the grant check was read although it was never checked, and a
parse error then quoted a line of it. The identity taken before the check was
left behind as an unused local, which a cleanup pass deleted. The resolved read
never had it for the root file: ``resolve_config_document`` took its own
identity when it opened the file, after the check and several steps past it.

The identity is the one the check reports for the file it approved
(``validate_config_input(identity_out=)``), not one taken before the check, which
a name that led to one file, then another during the check, then the first again
would satisfy. A file where the check approved none is not read.

Each cell checks one file, swaps another into the same name from inside the
check, and expects the swap to be refused with none of the swapped file's text
in the answer. The control cell does not swap and expects the document as
written, so a read that fails for another reason cannot pass the swap cell. The
named and the discovered path each take the identity themselves, so each is a
cell.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config import config_sources, resolve_config

pytestmark = pytest.mark.unit

CANARY = "swapped-in-canary-5d1f"

#: Per suffix: the checked file's text, the document it reads as, and the text of
#: the file swapped in. The swapped text parses, so only the identity compare can
#: refuse it.
FORMATS: Dict[str, Any] = {
    "yaml": ("x: 1\n", {"x": 1}, f"x: {CANARY}\n"),
    "json": ('{"x": 1}', {"x": 1}, f'{{"x": "{CANARY}"}}'),
    "toml": ("x = 1\n", {"x": 1}, f'x = "{CANARY}"\n'),
}

#: The same for the resolved read, which validates the document: the checked
#: file's text, the project name it resolves to, and the swapped file's text.
RESOLVED_FORMATS: Dict[str, Any] = {
    "yaml": ("project_name: checked\n", "checked", f"project_name: {CANARY}\n"),
    "json": (
        '{"project_name": "checked"}',
        "checked",
        f'{{"project_name": "{CANARY}"}}',
    ),
    "toml": (
        'project_name = "checked"\n',
        "checked",
        f'project_name = "{CANARY}"\n',
    ),
}


@pytest.fixture(autouse=True)
def _local_caller(monkeypatch) -> None:
    """A local caller: the search directory is not itself checked first."""
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _arrange(
    tmp_path: Path,
    monkeypatch,
    fmt: str,
    discovered: bool,
    swap: bool,
    raw: bool = True,
) -> Dict[str, Any]:
    """Call get_config on a file whose check swaps another file in."""
    checked_text, _document, swapped_text = (FORMATS if raw else RESOLVED_FORMATS)[fmt]
    config = tmp_path / f"ash-config.{fmt}"
    config.write_text(checked_text, encoding="utf-8")
    # Written while the checked file exists, so the two never share an inode.
    other = tmp_path / f"other.{fmt}"
    other.write_text(swapped_text, encoding="utf-8")
    swapped: List[bool] = []

    def check_then_swap(target: Any, *_args: Any, **_kwargs: Any) -> None:
        # The check a grant makes; the swap lands right after it, once, and only
        # for the config file (a check of the search directory leaves it alone).
        if swap and not swapped and Path(target) == config:
            os.replace(other, config)
            swapped.append(True)
        return None

    monkeypatch.setattr(sandbox, "validate_config_input", check_then_swap)
    if discovered:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sandbox, "validate_discovered_config", lambda *a, **k: None)
        monkeypatch.setattr(resolve_config, "find_config_file", lambda *a, **k: config)
        response = mcp_get_config(raw=raw)
    else:
        response = mcp_get_config(config_path=str(config), raw=raw)
    assert bool(swapped) is swap, "the swap did not happen where the cell expects it"
    return response


@pytest.mark.parametrize("fmt", sorted(FORMATS))
@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_the_file_that_was_checked_is_read_as_written(
    fmt, discovered, tmp_path, monkeypatch
) -> None:
    response = _arrange(tmp_path, monkeypatch, fmt, discovered, swap=False)

    assert response == FORMATS[fmt][1], response


@pytest.mark.parametrize("fmt", sorted(FORMATS))
@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_file_swapped_in_after_the_check_is_refused_unread(
    fmt, discovered, tmp_path, monkeypatch
) -> None:
    response = _arrange(tmp_path, monkeypatch, fmt, discovered, swap=True)

    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response


@pytest.mark.parametrize("fmt", sorted(RESOLVED_FORMATS))
@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_the_file_that_was_checked_is_the_one_the_resolved_read_shows(
    fmt, discovered, tmp_path, monkeypatch
) -> None:
    response = _arrange(tmp_path, monkeypatch, fmt, discovered, swap=False, raw=False)

    assert response.get("success") is not False, response
    assert response.get("project_name") == RESOLVED_FORMATS[fmt][1], response


@pytest.mark.parametrize("fmt", sorted(RESOLVED_FORMATS))
@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_file_swapped_in_after_the_check_is_not_shown_by_the_resolved_read(
    fmt, discovered, tmp_path, monkeypatch
) -> None:
    response = _arrange(tmp_path, monkeypatch, fmt, discovered, swap=True, raw=False)

    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response


def test_the_grant_check_reports_the_identity_of_the_file_it_approved(tmp_path) -> None:
    config = tmp_path / "ash-config.yaml"
    config.write_text("x: 1\n", encoding="utf-8")
    approved: List[Any] = []

    refusal = sandbox.validate_config_input(str(config), identity_out=approved)

    assert refusal is None
    assert approved == [config_sources.file_identity(config)]


def test_a_path_that_leads_nowhere_is_approved_with_no_identity(tmp_path) -> None:
    approved: List[Any] = []

    refusal = sandbox.validate_config_input(
        str(tmp_path / "absent.yaml"), identity_out=approved
    )

    assert refusal is None
    assert approved == [None]


def test_a_refused_path_reports_no_identity(tmp_path, monkeypatch) -> None:
    config = tmp_path / "ash-config.yaml"
    config.write_text("x: 1\n", encoding="utf-8")
    monkeypatch.setattr(sandbox, "_config_input_refusal", lambda *a, **k: "refused")
    approved: List[Any] = []

    refusal = sandbox.validate_config_input(str(config), identity_out=approved)

    assert refusal == "refused"
    assert approved == []


def _arrange_swap_and_back(
    tmp_path: Path, monkeypatch, discovered: bool
) -> Dict[str, Any]:
    """Call raw get_config on a name that leads to the file X, then to the file Y
    while the grant check resolves it, then to X again.

    X holds the canary and Y is what the check sees. An identity taken before the
    check is X's, and X is what the read then opens, so only the identity the
    check reports (Y's) refuses it. X is a hard link, so the name leads to the
    very same inode both times.
    """
    config = tmp_path / "ash-config.yaml"
    x_file = tmp_path / "x-file.yaml"
    x_file.write_text(f"x: {CANARY}\n", encoding="utf-8")
    y_file = tmp_path / "y-file.yaml"
    y_file.write_text("x: 1\n", encoding="utf-8")
    try:
        os.link(x_file, config)
    except OSError as error:
        pytest.skip(f"cannot make a hard link here: {error}")
    real_check = sandbox.validate_config_input
    swapped: List[bool] = []

    def check_between_the_swaps(target: Any, *args: Any, **kwargs: Any) -> Any:
        if Path(target) != config:
            return real_check(target, *args, **kwargs)
        config.unlink()
        os.link(y_file, config)
        try:
            return real_check(target, *args, **kwargs)
        finally:
            config.unlink()
            os.link(x_file, config)
            swapped.append(True)

    monkeypatch.setattr(sandbox, "validate_config_input", check_between_the_swaps)
    if discovered:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sandbox, "validate_discovered_config", lambda *a, **k: None)
        monkeypatch.setattr(resolve_config, "find_config_file", lambda *a, **k: config)
        response = mcp_get_config(raw=True)
    else:
        response = mcp_get_config(config_path=str(config), raw=True)
    assert swapped == [True], "the name did not lead to Y during the check"
    assert os.stat(config).st_ino == os.stat(x_file).st_ino, "the name is X again"
    return response


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_file_swapped_in_during_the_check_and_out_again_is_refused(
    discovered, tmp_path, monkeypatch
) -> None:
    response = _arrange_swap_and_back(tmp_path, monkeypatch, discovered)

    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_link_swapped_in_after_the_name_was_resolved_is_refused(
    discovered, tmp_path, monkeypatch
) -> None:
    """One swap, inside the check: the check resolves the name while it is a
    regular file, a link to a file outside is put there, and the identity the
    check reports (a stat that follows the link) is the outside file's. An
    identity taken only from the check would then match what the read opens;
    the identity of the name before the check is the file that was there."""
    config = tmp_path / "ash-config.yaml"
    config.write_text("x: 1\n", encoding="utf-8")
    outside = tmp_path / "outside.yaml"
    outside.write_text(f"x: {CANARY}\n", encoding="utf-8")
    real_refusal = sandbox._config_input_refusal
    swapped: List[bool] = []

    def swap_then_judge(config_path: Any, resolved: Any, session_id: Any) -> Any:
        if Path(config_path) == config and not swapped:
            config.unlink()
            try:
                config.symlink_to(outside)
            except (OSError, NotImplementedError) as error:
                pytest.skip(f"cannot make a symbolic link here: {error}")
            swapped.append(True)
        return real_refusal(config_path, resolved, session_id)

    monkeypatch.setattr(sandbox, "_config_input_refusal", swap_then_judge)
    if discovered:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sandbox, "validate_discovered_config", lambda *a, **k: None)
        monkeypatch.setattr(resolve_config, "find_config_file", lambda *a, **k: config)
        response = mcp_get_config(raw=True)
    else:
        response = mcp_get_config(config_path=str(config), raw=True)

    assert swapped == [True], "the link was not put where the cell expects it"
    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response


def _arrange_appears(tmp_path: Path, monkeypatch, discovered: bool) -> Dict[str, Any]:
    """Call raw get_config on a name that leads nowhere when the grant check
    approves it, and that a file appears at right after.

    An identity of None, for a path that led nowhere, once held the read to
    nothing: the file made after the check was read, unjudged.
    """
    config = tmp_path / "ash-config.yaml"
    real_check = sandbox.validate_config_input
    appeared: List[bool] = []

    def check_then_create(target: Any, *args: Any, **kwargs: Any) -> Any:
        refusal = real_check(target, *args, **kwargs)
        if Path(target) == config and not appeared:
            config.write_text(f"x: {CANARY}\n", encoding="utf-8")
            appeared.append(True)
        return refusal

    monkeypatch.setattr(sandbox, "validate_config_input", check_then_create)
    if discovered:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sandbox, "validate_discovered_config", lambda *a, **k: None)
        monkeypatch.setattr(resolve_config, "find_config_file", lambda *a, **k: config)
        response = mcp_get_config(raw=True)
    else:
        response = mcp_get_config(config_path=str(config), raw=True)
    assert appeared == [True], "the file did not appear where the cell expects it"
    return response


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_file_that_appears_after_an_absent_name_was_approved_is_refused_unread(
    discovered, tmp_path, monkeypatch
) -> None:
    response = _arrange_appears(tmp_path, monkeypatch, discovered)

    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response


def test_control_a_name_that_stays_absent_is_not_reported_as_changed(
    tmp_path,
) -> None:
    response = mcp_get_config(config_path=str(tmp_path / "ash-config.yaml"), raw=True)

    assert response.get("success") is False, response
    assert "changed after it was checked" not in json.dumps(response, default=str)


def test_a_json_config_with_a_byte_order_mark_reads_raw(tmp_path) -> None:
    """The loader reads JSON as utf-8-sig, for the mark Windows PowerShell 5
    writes (config_sources.read_config_file), and YAML and TOML drop it; the raw
    read decoded utf-8 and refused such a file ("Unexpected UTF-8 BOM")."""
    config = tmp_path / "ash-config.json"
    config.write_bytes(b'\xef\xbb\xbf{"project_name": "bom"}')

    raw = mcp_get_config(config_path=str(config), raw=True)

    assert raw == {"project_name": "bom"}, raw


def test_a_yaml_error_of_the_raw_read_names_the_file_and_quotes_no_line(
    tmp_path,
) -> None:
    """A parser given a bare string marks its errors "<unicode string>" and
    carries a copy of the offending line; given a stream named for the file, as
    every other parse of read text is, it names the file and the position."""
    config = tmp_path / "ash-config.yaml"
    config.write_text("x: [1, 2\ny: line-the-error-would-quote\n", encoding="utf-8")

    with pytest.raises(yaml.YAMLError) as raised:
        mcp_tools._config_as_written(config)

    text = str(raised.value)
    assert "<unicode string>" not in text, text
    # The stream is named as the platform spells the path (os.fspath), which is
    # not the POSIX form on Windows.
    assert os.fspath(config) in text, text


def test_a_raw_read_is_bounded_like_the_resolved_read(tmp_path, monkeypatch) -> None:
    """The as-written reader once opened the name itself, with no size bound."""
    monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 16)
    config = tmp_path / "ash-config.yaml"
    config.write_text("x: " + "a" * 64 + "\n", encoding="utf-8")
    monkeypatch.setattr(sandbox, "validate_config_input", lambda *a, **k: None)

    response = mcp_get_config(config_path=str(config), raw=True)

    assert response.get("success") is False, response
    assert "larger than 16 bytes" in json.dumps(response, default=str), response
