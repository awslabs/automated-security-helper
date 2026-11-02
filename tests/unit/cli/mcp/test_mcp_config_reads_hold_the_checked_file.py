# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file the MCP tools check is the file they read.

``get_config`` and ``validate_config`` check a named path, then read it. The
identity ``file_identity`` gave the file at the check is handed to the read
(``read_config_bytes(..., expect=...)``), so a file swapped in between is
refused with ESTALE and not read. Each cell swaps the file after the identity is
taken, with a same-file control where nothing is swapped.

Windows cannot make the swap while ``get_config`` holds the file. The call keeps
the descriptor it opened to judge the file until it has answered
(``config_sources.open_config_for_judgment``), and a file opened without
``FILE_SHARE_DELETE`` cannot be replaced on Windows while it is open. A swap made
from inside such a call gets a ``PermissionError`` there, from the server's own
handle, and its cell skips: the replacement it pins is one the operating system
does not allow on that platform. Anywhere else the same error is the cell's to
see.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp_tools import (
    mcp_get_config,
    mcp_validate_config,
)
from automated_security_helper.config import config_sources, operator_only_options
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.config_validator import ConfigValidator
from tests.utils.held_file_swaps import skip_if_refused, swap_or_record

pytestmark = pytest.mark.unit

CHECKED = "project_name: checked\n"
# The replacement's content. Every cell asserts it is nowhere in the answer, so it
# is a word no test name or temporary directory holds: the answers quote the
# config's path, and pytest names that directory after the test ("swapped" is in
# many of these names).
SWAP_MARKER = "swap-content-7731"
SWAPPED = f"project_name: {SWAP_MARKER}\n"


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


class _Calls(list):
    """What a swap hook has seen, and the swaps the operating system refused."""

    def __init__(self) -> None:
        super().__init__()
        self.refused: List[BaseException] = []


def _swap_in_a_new_file(
    path: Path, text: str, refused: List[BaseException] | None = None
) -> bool:
    """Replace `path` by a different file (a new inode), as a racing writer would.

    True when it was replaced. A swap made from inside the call under test passes
    `refused`: on Windows the server's own open handle on `path` refuses it (see
    the module doc), and ``swap_or_record`` records that there for
    ``skip_if_refused`` instead of raising it, because it would be raised inside
    the server's call, which could turn it into an answer. Any other error is a
    real one and is raised, as every error is for a swap made without `refused`.
    """
    replacement = path.with_name(path.name + ".new")
    replacement.write_text(text, encoding="utf-8")
    if refused is None:
        os.replace(replacement, path)
        return True
    return swap_or_record(lambda: os.replace(replacement, path), refused)


def _swap_after_the_check(monkeypatch, path: Path, swap: bool) -> _Calls:
    """Make the first ``file_identity`` call of the tool swap `path` after it.

    The tool takes the identity at its check; a swap right after is the race
    the identity is there to refuse. Returns the paths the identity was taken
    for, so a cell can show the check ran; its ``refused`` lists a swap the
    operating system refused.
    """
    real = config_sources.file_identity
    taken = _Calls()

    def identity_then_swap(candidate):
        identity = real(candidate)
        taken.append(Path(candidate))
        if swap and len(taken) == 1:
            _swap_in_a_new_file(path, SWAPPED, taken.refused)
        return identity

    monkeypatch.setattr(config_sources, "file_identity", identity_then_swap)
    return taken


def _swap_when_the_read_starts(monkeypatch, path: Path) -> _Calls:
    """Swap `path` the moment get_config calls ``resolve_config`` for it.

    That call is the read. Everything the tool checks, the grant check and the
    identity it holds the read to included, comes before it, so the swap lands
    after the check whatever number of identities the tool and the checks it runs
    took on the way (a discovered file is checked by discovery before the tool
    checks it). Returns the files swapped, so a cell can show the swap happened;
    its ``refused`` lists a swap the operating system refused.
    """
    real = resolve_config_module.resolve_config
    swapped = _Calls()

    def swap_then_resolve(*args, **kwargs):
        named = kwargs.get("config_path", args[0] if args else None)
        if (
            not swapped
            and not swapped.refused
            and named is not None
            and Path(named) == path
        ):
            if _swap_in_a_new_file(path, SWAPPED, swapped.refused):
                swapped.append(Path(named))
        return real(*args, **kwargs)

    monkeypatch.setattr(resolve_config_module, "resolve_config", swap_then_resolve)
    return swapped


def _appear_after_the_identity(monkeypatch, path: Path, text: str) -> list:
    """Make `path` appear right after the tool takes its identity for it.

    The path leads nowhere when the tool judges it, so ``file_identity`` gives
    None; a file (or a link, in a client's hands) is then made at the name before
    the tool opens it. Returns what ``file_identity`` gave, so a cell can show the
    premise: the identity was None.
    """
    real = config_sources.file_identity
    given: list = []

    def identity_then_appear(candidate):
        identity = real(candidate)
        given.append(identity)
        if len(given) == 1:
            path.write_text(text, encoding="utf-8")
        return identity

    monkeypatch.setattr(config_sources, "file_identity", identity_then_appear)
    return given


class TestAPathThatLedNowhereAtTheCheckIsNotReadAsAFile:
    """No identity must not switch the guard off.

    ``file_identity`` of a path that leads nowhere is None, and a None handed to
    the read as ``expect`` held it to nothing: a client that made a link at the
    name between the name judgment and the open had the file read unchecked.
    """

    def test_get_config_refuses_a_file_that_appeared(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        given = _appear_after_the_identity(monkeypatch, config, SWAPPED)

        result = mcp_get_config(config_path=str(config))

        assert given and given[0] is None, "premise: the path led nowhere at the check"
        assert result.get("success") is False, result
        assert SWAP_MARKER not in str(result), result

    def test_get_config_raw_refuses_a_file_that_appeared(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        given = _appear_after_the_identity(monkeypatch, config, SWAPPED)

        result = mcp_get_config(config_path=str(config), raw=True)

        assert given and given[0] is None, "premise: the path led nowhere at the check"
        assert result.get("success") is False, result
        assert SWAP_MARKER not in str(result), result

    def test_validate_config_does_not_validate_a_file_that_appeared(
        self, tmp_path, monkeypatch
    ):
        config = tmp_path / ".ash.yaml"
        given = _appear_after_the_identity(monkeypatch, config, SWAPPED)

        result = mcp_validate_config(config_path=str(config))

        assert given and given[0] is None, "premise: the path led nowhere at the check"
        assert result["valid"] is False, result
        assert SWAP_MARKER not in str(result), result

    def test_control_a_path_that_stays_absent_is_still_not_found(self, tmp_path):
        config = tmp_path / ".ash.yaml"

        result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False, result
        assert [e["type"] for e in result["errors"]] == ["file_not_found"], result


class TestGetConfigReadsTheFileItChecked:
    def test_a_file_swapped_in_after_the_check_is_refused(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=True)

        result = mcp_get_config(config_path=str(config))

        skip_if_refused(taken.refused)
        assert taken, "premise: the tool took an identity at its check"
        assert result.get("success") is False, result
        assert SWAP_MARKER not in str(result), result

    def test_control_the_same_file_is_read(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=False)

        result = mcp_get_config(config_path=str(config))

        assert taken, "premise: the tool took an identity at its check"
        assert result.get("success") is not False, result
        assert result["project_name"] == "checked", result

    def test_a_discovered_file_swapped_in_after_the_check_is_refused(
        self, tmp_path, monkeypatch
    ):
        """Swapped when the tool's read starts, which is after everything it
        checks. Discovery runs its own check of the file it finds, which reads it
        and takes an identity of it before the tool takes the one it holds its read
        to, so a swap on the first identity taken anywhere lands before the tool's
        check and is the file the tool then checks and reads."""
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        swapped = _swap_when_the_read_starts(monkeypatch, config)

        result = mcp_get_config(search_dir=str(tmp_path))

        skip_if_refused(swapped.refused)
        assert swapped, "premise: the file was swapped between the check and the read"
        assert result.get("success") is False, result
        assert SWAP_MARKER not in str(result), result

    def test_control_the_same_discovered_file_is_read(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=False)

        result = mcp_get_config(search_dir=str(tmp_path))

        assert taken, "premise: the tool took an identity at its check"
        assert result.get("success") is not False, result
        assert result["project_name"] == "checked", result

    def test_the_raw_read_of_a_file_swapped_in_after_the_check_is_refused(
        self, tmp_path, monkeypatch
    ):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=True)

        result = mcp_get_config(config_path=str(config), raw=True)

        skip_if_refused(taken.refused)
        assert taken, "premise: the tool took an identity at its check"
        assert result.get("success") is False, result
        assert SWAP_MARKER not in str(result), result

    def test_control_the_same_file_is_read_raw(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=False)

        result = mcp_get_config(config_path=str(config), raw=True)

        assert taken, "premise: the tool took an identity at its check"
        assert result.get("success") is not False, result
        assert result["project_name"] == "checked", result


class TestValidateConfigChecksTheFileItChecked:
    def test_a_file_swapped_in_after_the_check_is_not_validated(
        self, tmp_path, monkeypatch
    ):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=True)

        result = mcp_validate_config(config_path=str(config))

        skip_if_refused(taken.refused)
        assert taken, "premise: the tool took an identity at its check"
        assert result["valid"] is False, result
        assert SWAP_MARKER not in str(result), result

    def test_control_the_same_file_is_validated(self, tmp_path, monkeypatch):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        taken = _swap_after_the_check(monkeypatch, config, swap=False)

        result = mcp_validate_config(config_path=str(config))

        assert taken, "premise: the tool took an identity at its check"
        assert result["valid"] is True, result


class TestCheckConfigFileReadsTheFileItIsHanded:
    def test_a_file_swapped_in_after_its_identity_was_taken_is_not_read(self, tmp_path):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        identity = config_sources.file_identity(config)
        _swap_in_a_new_file(config, SWAPPED)

        check = ConfigValidator.check_config_file(config, expect=identity)

        assert check.could_not_read is True, check.errors
        assert not check.scan_accepts
        assert SWAP_MARKER not in str(check.errors), check.errors

    def test_control_the_same_file_is_read(self, tmp_path):
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")

        check = ConfigValidator.check_config_file(
            config, expect=config_sources.file_identity(config)
        )

        assert check.could_not_read is False, check.errors
        assert check.scan_accepts, check.errors

    def test_a_file_swapped_in_after_the_check_is_not_read_with_its_text_handed_in(
        self, tmp_path
    ):
        """The caller read the data but not the text (the linter's shape): the
        text is read here, and held to the identity too."""
        config = tmp_path / ".ash.yaml"
        config.write_text(CHECKED, encoding="utf-8")
        identity = config_sources.file_identity(config)
        data = config_sources.read_config_file(config)
        _swap_in_a_new_file(config, SWAPPED)

        check = ConfigValidator.check_config_file(
            config, config_data=data, expect=identity
        )

        assert check.could_not_read is True, check.errors
        assert SWAP_MARKER not in str(check.errors), check.errors

    def test_an_extends_base_swapped_in_after_its_check_is_not_read(
        self, tmp_path, monkeypatch
    ):
        base = tmp_path / "base.yaml"
        base.write_text(CHECKED, encoding="utf-8")
        child = tmp_path / ".ash.yaml"
        child.write_text("extends: base.yaml\n", encoding="utf-8")
        real_resolve_base_path = config_sources._resolve_base_path

        def resolve_then_swap(*args, **kwargs):
            result = real_resolve_base_path(*args, **kwargs)
            _swap_in_a_new_file(base, SWAPPED)
            return result

        monkeypatch.setattr(config_sources, "_resolve_base_path", resolve_then_swap)

        check = ConfigValidator.check_config_file(child, source_dir=tmp_path)

        assert not check.scan_accepts
        assert SWAP_MARKER not in str(check.errors), check.errors

    def test_control_an_extends_base_that_is_not_swapped_is_read(self, tmp_path):
        base = tmp_path / "base.yaml"
        base.write_text(CHECKED, encoding="utf-8")
        child = tmp_path / ".ash.yaml"
        child.write_text("extends: base.yaml\n", encoding="utf-8")

        check = ConfigValidator.check_config_file(child, source_dir=tmp_path)

        assert check.scan_accepts, check.errors


FIRST = "project_name: first-file\n"
SECOND = "project_name: second-file\n"


def _link_to(link: Path, target: str) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"cannot create a symlink here: {error}")


def _repoint(link: Path, target: str) -> None:
    """Make the symbolic link `link` lead to `target`, as a racing writer would."""
    link.unlink()
    link.symlink_to(target)


def _repoint_once_after(monkeypatch, owner, name: str, link: Path, target: str):
    """Make `owner.name` repoint `link` to `target` the first time it returns.

    A rename over the file (``_swap_in_a_new_file``) changes the inode but keeps
    the resolved path, which the check's caches are keyed by, so a cell that
    only swaps that way never leaves the cache. A link repointed to another file
    changes the resolved path: the cache misses, and the next read is of the
    other file. Returns the calls made, so a cell can show the hook ran.
    """
    real = getattr(owner, name)
    calls: list = []

    def call_then_repoint(*args, **kwargs):
        result = real(*args, **kwargs)
        calls.append(name)
        if len(calls) == 1:
            _repoint(link, target)
        return result

    monkeypatch.setattr(owner, name, call_then_repoint)
    return calls


class TestCheckConfigFileHoldsEveryReadToTheFileItRead:
    """The reads after the first are of the file the first read opened.

    The check reads the named file, then loads it again through the loader and,
    for ``ash_plugin_modules``, resolves it a second time. The caches those reads
    share are keyed by the resolved path taken at the first read. A symbolic link
    repointed since reaches another path, so the cache misses and the later read
    opens the other file: the structural warnings describe the first file and
    the load, or the module check, the second. Each read is held to the identity
    the first read was.
    """

    def test_a_link_repointed_after_the_first_read_is_not_loaded_in_its_place(
        self, tmp_path, monkeypatch
    ):
        first = tmp_path / "first.yaml"
        first.write_text(FIRST, encoding="utf-8")
        (tmp_path / "second.yaml").write_text(SECOND, encoding="utf-8")
        link = tmp_path / ".ash.yaml"
        _link_to(link, first.name)
        identity = config_sources.file_identity(link)
        calls = _repoint_once_after(
            monkeypatch,
            operator_only_options,
            "repository_settings_for_root",
            link,
            "second.yaml",
        )

        check = ConfigValidator.check_config_file(
            link, source_dir=tmp_path, expect=identity
        )

        assert calls, "premise: the link was repointed after the first read"
        assert check.could_not_read is True, check.errors
        assert not check.scan_accepts
        assert "second-file" not in str(check.errors), check.errors
        assert any("changed after it was checked" in e for e in check.errors), (
            check.errors
        )

    def test_a_caller_that_handed_no_identity_is_held_to_the_first_read_too(
        self, tmp_path, monkeypatch
    ):
        first = tmp_path / "first.yaml"
        first.write_text(FIRST, encoding="utf-8")
        (tmp_path / "second.yaml").write_text(SECOND, encoding="utf-8")
        link = tmp_path / ".ash.yaml"
        _link_to(link, first.name)
        calls = _repoint_once_after(
            monkeypatch,
            operator_only_options,
            "repository_settings_for_root",
            link,
            "second.yaml",
        )

        check = ConfigValidator.check_config_file(link, source_dir=tmp_path)

        assert calls, "premise: the link was repointed after the first read"
        assert check.could_not_read is True, check.errors
        assert not check.scan_accepts
        assert "second-file" not in str(check.errors), check.errors

    def test_control_a_link_that_is_not_repointed_is_loaded(self, tmp_path):
        first = tmp_path / "first.yaml"
        first.write_text(FIRST, encoding="utf-8")
        link = tmp_path / ".ash.yaml"
        _link_to(link, first.name)

        check = ConfigValidator.check_config_file(
            link, source_dir=tmp_path, expect=config_sources.file_identity(link)
        )

        assert check.could_not_read is False, check.errors
        assert check.scan_accepts, check.errors
        assert check.resolved_data.get("project_name") == "first-file", (
            check.resolved_data
        )

    def test_a_link_repointed_before_the_module_check_is_not_judged_in_its_place(
        self, tmp_path, monkeypatch
    ):
        """The module check resolves the file once more, with the caches the check
        filled; the other file is read when the link no longer leads to the first."""
        first = tmp_path / "first.yaml"
        first.write_text(FIRST, encoding="utf-8")
        (tmp_path / "second.yaml").write_text(SECOND, encoding="utf-8")
        link = tmp_path / ".ash.yaml"
        _link_to(link, first.name)
        identity = config_sources.file_identity(link)
        real = ConfigValidator._ash_config_check
        calls: list = []

        def check_then_repoint(*args, **kwargs):
            result = real(*args, **kwargs)
            calls.append(True)
            _repoint(link, "second.yaml")
            return result

        monkeypatch.setattr(
            ConfigValidator, "_ash_config_check", staticmethod(check_then_repoint)
        )

        check = ConfigValidator.check_config_file(
            link,
            source_dir=tmp_path,
            expect=identity,
            additional_plugin_modules=("automated_security_helper.plugin_modules",),
        )

        assert calls, "premise: the link was repointed before the module check"
        assert "second-file" not in str(check.errors), check.errors
        assert any("changed after it was checked" in e for e in check.errors), (
            check.errors
        )
