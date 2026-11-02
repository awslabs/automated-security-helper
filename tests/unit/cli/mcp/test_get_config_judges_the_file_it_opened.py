# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config judges the file it opened, and reads that file.

The session's grant is a decision about a path. The file a read then opens must
be the file the decision was made about, so the check opens the file first,
judges the path the descriptor leads to, and holds the read to that descriptor's
(device, inode). Each cell here changes what a name leads to while the check
runs, and expects a refusal with nothing of the outside file in the answer. The
control cells leave the name alone and expect the ordinary answers, so a refusal
for another reason cannot pass a changing-name cell.

The grant is a stand-in policy in these cells (``_config_input_refusal``): a path
under ``outside/`` is refused and any other is permitted, so the cells do not
depend on the environment's roots.

Windows cannot make the changes a cell makes from inside the check while the
server holds the file. The call keeps the descriptor it opened to judge the file
until it has answered (``config_sources.open_config_for_judgment``), and a file
opened without ``FILE_SHARE_DELETE`` cannot be replaced on Windows while it is
open. A replacement made from inside the call gets a ``PermissionError`` there,
from the server's own handle, and its cell skips: the change it pins is one the
operating system does not allow on that platform. Anywhere else the same error is
the cell's to see.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config import resolve_config

pytestmark = pytest.mark.unit

CANARY = "outside-file-canary-7c41"


@pytest.fixture(autouse=True)
def _local_caller(monkeypatch) -> None:
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


class _Layout:
    """A granted directory with a file, an ungranted directory with another, and
    the name ``granted/ash-config.yaml`` that can lead to either."""

    def __init__(self, tmp_path: Path) -> None:
        tmp_path = tmp_path.resolve()
        self.granted = tmp_path / "granted"
        self.granted.mkdir()
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        self.far = self.outside / "far.yaml"
        self.far.write_text(f"project_name: {CANARY}\n", encoding="utf-8")
        self.name = self.granted / "ash-config.yaml"

    def _put_at_the_name(
        self, source: Path, refused: Optional[List[BaseException]]
    ) -> None:
        """``os.replace(source, self.name)``.

        A change made from inside the call under test passes `refused`: on Windows
        the server's own open handle on the name can refuse it with a
        ``PermissionError`` (see the module doc), and that is recorded there for
        ``_skip_where_the_server_holds_the_file``, not raised, because it would be
        raised inside the server's call, which could turn it into an answer.
        Anywhere else the error is a real one and is raised, as it is for a change
        made without `refused`.
        """
        try:
            os.replace(source, self.name)
        except PermissionError as error:
            if refused is None or sys.platform != "win32":
                raise
            refused.append(error)

    def lead_to_the_outside_file(
        self, refused: Optional[List[BaseException]] = None
    ) -> None:
        link = self.granted / ".link-to-far"
        if os.path.lexists(link):
            link.unlink()
        try:
            link.symlink_to(self.far)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"cannot make a symbolic link here: {error}")
        self._put_at_the_name(link, refused)

    def be_a_granted_file(self, refused: Optional[List[BaseException]] = None) -> None:
        replacement = self.granted / ".granted-file"
        replacement.write_text("project_name: granted\n", encoding="utf-8")
        self._put_at_the_name(replacement, refused)


def _skip_where_the_server_holds_the_file(refused: List[BaseException]) -> None:
    """Skip the cell when the operating system refused a change (the module doc)."""
    if refused:
        pytest.skip(
            "Windows does not let a file the server holds open be replaced, so "
            f"the change this cell pins cannot be made ({refused[0]})"
        )


def _grant_everything_but_the_outside(monkeypatch, layout: _Layout, after=None) -> None:
    """Judge a path as the stand-in policy does; run ``after`` once the verdict
    on the config name is made and before it is returned."""

    def judge(config_path: Any, resolved: Any, session_id: Any) -> Any:
        if Path(resolved).is_relative_to(layout.outside):
            return sandbox._refusal(
                "Config input", config_path, Path(resolved), "outside the grant"
            )
        if after is not None and Path(config_path) == layout.name:
            after()
        return None

    monkeypatch.setattr(sandbox, "_config_input_refusal", judge)


def _get_config(monkeypatch, layout: _Layout, discovered: bool, **kwargs: Any) -> Any:
    if discovered:
        monkeypatch.chdir(layout.granted)
        monkeypatch.setattr(sandbox, "validate_discovered_config", lambda *a, **k: None)
        monkeypatch.setattr(
            resolve_config, "find_config_file", lambda *a, **k: layout.name
        )
        return mcp_get_config(raw=True, **kwargs)
    return mcp_get_config(config_path=str(layout.name), raw=True, **kwargs)


def _refused_with_nothing_from_the_outside_file(response: Dict[str, Any]) -> None:
    assert response.get("success") is False, response
    assert CANARY not in json.dumps(response, default=str), response


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_name_that_leads_to_the_ungranted_file_is_refused(
    discovered, tmp_path, monkeypatch
) -> None:
    layout = _Layout(tmp_path)
    layout.lead_to_the_outside_file()
    _grant_everything_but_the_outside(monkeypatch, layout)

    response = _get_config(monkeypatch, layout, discovered)

    _refused_with_nothing_from_the_outside_file(response)


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_granted_file_is_read_as_written(discovered, tmp_path, monkeypatch) -> None:
    layout = _Layout(tmp_path)
    layout.be_a_granted_file()
    _grant_everything_but_the_outside(monkeypatch, layout)

    response = _get_config(monkeypatch, layout, discovered)

    assert response == {"project_name": "granted"}, response


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_a_name_that_led_elsewhere_while_the_check_resolved_it_is_refused(
    discovered, tmp_path, monkeypatch
) -> None:
    """The name leads to the ungranted file, to a granted file while the check
    resolves it, and to the ungranted file again once the verdict is made. The
    verdict is about the granted file, and the read would open the other one.

    The steps are driven from the two places the check passes through: the
    resolution of the name (``os.path.realpath``) and the verdict.
    """
    layout = _Layout(tmp_path)
    layout.lead_to_the_outside_file()
    state: List[str] = []
    refused: List[BaseException] = []
    real_realpath = os.path.realpath

    def realpath_that_sees_a_granted_file(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == str(layout.name) and not state:
            state.append("granted")
            layout.be_a_granted_file(refused)
        return real_realpath(path, *args, **kwargs)

    def lead_back_to_the_outside_file() -> None:
        if state == ["granted"]:
            state.append("outside")
            layout.lead_to_the_outside_file(refused)

    monkeypatch.setattr(os.path, "realpath", realpath_that_sees_a_granted_file)
    _grant_everything_but_the_outside(
        monkeypatch, layout, after=lead_back_to_the_outside_file
    )

    response = _get_config(monkeypatch, layout, discovered)

    _skip_where_the_server_holds_the_file(refused)
    _refused_with_nothing_from_the_outside_file(response)


@pytest.mark.parametrize("discovered", [False, True], ids=["named", "discovered"])
def test_the_resolved_read_shows_nothing_of_a_name_that_led_elsewhere_either(
    discovered, tmp_path, monkeypatch
) -> None:
    layout = _Layout(tmp_path)
    layout.lead_to_the_outside_file()
    state: List[str] = []
    refused: List[BaseException] = []
    real_realpath = os.path.realpath

    def realpath_that_sees_a_granted_file(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == str(layout.name) and not state:
            state.append("granted")
            layout.be_a_granted_file(refused)
        return real_realpath(path, *args, **kwargs)

    def lead_back_to_the_outside_file() -> None:
        if state == ["granted"]:
            state.append("outside")
            layout.lead_to_the_outside_file(refused)

    monkeypatch.setattr(os.path, "realpath", realpath_that_sees_a_granted_file)
    _grant_everything_but_the_outside(
        monkeypatch, layout, after=lead_back_to_the_outside_file
    )
    if discovered:
        monkeypatch.chdir(layout.granted)
        monkeypatch.setattr(sandbox, "validate_discovered_config", lambda *a, **k: None)
        monkeypatch.setattr(
            resolve_config, "find_config_file", lambda *a, **k: layout.name
        )
        response = mcp_get_config()
    else:
        response = mcp_get_config(config_path=str(layout.name))

    _skip_where_the_server_holds_the_file(refused)
    _refused_with_nothing_from_the_outside_file(response)


def _arrange_asked_with_an_environment_config(
    tmp_path: Path, monkeypatch, swap: bool
) -> Dict[str, Any]:
    """Call get_config on the file ASH_CONFIG names, with the file changed (a new
    inode, other text) after the grant check returned and before the load."""
    config = tmp_path / "ash-config.yaml"
    config.write_text("project_name: checked\n", encoding="utf-8")
    other = tmp_path / "other.yaml"
    other.write_text(f"project_name: {CANARY}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    changed: List[bool] = []
    refused: List[BaseException] = []

    def untrusted_after_the_file_changed(*_args: Any, **_kwargs: Any) -> bool:
        # Called once the check has returned and before the file is loaded.
        if swap and not changed and not refused:
            try:
                os.replace(other, config)
            except PermissionError as error:
                # The server holds the file it checked (see the module doc).
                if sys.platform != "win32":
                    raise
                refused.append(error)
            else:
                changed.append(True)
        return False

    monkeypatch.setattr(
        sandbox, "client_named_config_is_untrusted", untrusted_after_the_file_changed
    )
    response = mcp_get_config(config_path=str(config))
    _skip_where_the_server_holds_the_file(refused)
    assert bool(changed) is swap, "the file did not change where the cell expects it"
    return response


def test_a_file_the_environment_config_also_names_is_held_to_the_checked_file(
    tmp_path, monkeypatch
) -> None:
    """The file ASH_CONFIG names is read first and kept; the named file is then
    asked for from that read. A file that changed in between is not shown."""
    response = _arrange_asked_with_an_environment_config(tmp_path, monkeypatch, True)

    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response


def test_control_the_environment_config_unchanged_is_shown(
    tmp_path, monkeypatch
) -> None:
    response = _arrange_asked_with_an_environment_config(tmp_path, monkeypatch, False)

    assert response.get("success") is not False, response
    assert response.get("project_name") == "checked", response
