# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config(raw=True) returns the file that was checked, bounded, and only if regular.

Why this file exists
--------------------
``get_config`` checks a config path against the session's grant
(``validate_config_input``) and, for ``raw``, reads it afterwards. The read has to
be of the file the check saw: ``identity_to_hold`` is taken before the check and
passed to the read as ``expect``, so a file that replaced the name in between is
refused (``read_config_bytes``) instead of returned. A path that led nowhere at
that moment is held to the identity no file has, so a file that has come to be
there is refused the same way, and a path that still leads nowhere is not found
(``file_not_found``), not refused as changed. The same read bounds the file at
``ASH_CONFIG_MAX_FILE_BYTES`` and opens without blocking.

The check-then-read order is the one ``test_config_file_reads.py`` pins for a
named YAML file. Here every format the raw read parses (YAML, JSON, TOML) and the
file discovery selects are covered. The size bound is pinned for YAML and JSON,
which a plain ``open()`` read whole; the TOML read already went through
``read_config_bytes`` and is held by a control that passes on the base.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config import config_sources, resolve_config

#: (file name, text when checked, text of the file that replaces it).
FORMATS = {
    "yaml": ("config.yaml", "project_name: checked\n", "project_name: swapped\n"),
    "json": (
        "config.json",
        '{"project_name": "checked"}\n',
        '{"project_name": "swapped"}\n',
    ),
    "toml": (
        "config.toml",
        'project_name = "checked"\n',
        'project_name = "swapped"\n',
    ),
}


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _swap_in_a_new_file(path: Path, text: str) -> None:
    """Replace ``path`` by a different file (a new inode)."""
    replacement = path.with_name(path.name + ".new")
    replacement.write_text(text, encoding="utf-8")
    os.replace(replacement, path)


def _swap_after_the_check(
    monkeypatch: pytest.MonkeyPatch, target: Path, text: str
) -> None:
    """Make the session's check of ``target`` the last thing before it is replaced."""
    real = sandbox.validate_config_input

    def validate_then_swap(candidate: Any, *args: Any, **kwargs: Any) -> Any:
        refusal = real(candidate, *args, **kwargs)
        if Path(candidate).resolve() == target.resolve():
            _swap_in_a_new_file(target, text)
        return refusal

    monkeypatch.setattr(sandbox, "validate_config_input", validate_then_swap)


def _refused_as_changed(result: Dict[str, Any]) -> None:
    shown = json.dumps(result, default=str)
    assert result.get("success") is False, result
    assert "swapped" not in shown, result
    assert "changed after it was checked" in shown, result


@pytest.mark.parametrize("fmt", FORMATS.values(), ids=FORMATS)
def test_a_named_file_replaced_after_the_check_is_refused(tmp_path, monkeypatch, fmt):
    name, checked, swapped = fmt
    target = tmp_path / name
    target.write_text(checked, encoding="utf-8")
    _swap_after_the_check(monkeypatch, target, swapped)

    result = mcp_get_config(config_path=str(target), raw=True)

    _refused_as_changed(result)


@pytest.mark.parametrize("fmt", FORMATS.values(), ids=FORMATS)
def test_control_the_checked_file_is_returned(tmp_path, fmt):
    name, checked, _swapped = fmt
    target = tmp_path / name
    target.write_text(checked, encoding="utf-8")

    result = mcp_get_config(config_path=str(target), raw=True)

    assert result == {"project_name": "checked"}, result


def test_a_discovered_file_replaced_after_the_check_is_refused(tmp_path, monkeypatch):
    target = tmp_path / ".ash.yaml"
    target.write_text("project_name: checked\n", encoding="utf-8")
    _swap_after_the_check(monkeypatch, target, "project_name: swapped\n")

    result = mcp_get_config(search_dir=str(tmp_path), raw=True)

    _refused_as_changed(result)


def test_control_a_discovered_file_is_returned(tmp_path):
    (tmp_path / ".ash.yaml").write_text("project_name: checked\n", encoding="utf-8")

    result = mcp_get_config(search_dir=str(tmp_path), raw=True)

    assert result == {"project_name": "checked"}, result


def _identity_missing_at_the_check(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    *,
    remove: bool = False,
    recreate: str | None = None,
    after_discovery: bool = False,
) -> None:
    """Make the first ``file_identity`` of ``target`` find nothing there.

    This is the state a file is in when the caller takes its identity before the
    file exists (it is created afterwards) or after it has gone (it is removed
    once discovery selected it). With ``remove`` the stand-in also deletes the
    file, so the identity read after it is the real one of a path that leads
    nowhere. With ``recreate`` it then writes a new file at the name, so the
    read finds something where the identity found nothing. Later calls, and any
    other path, are the real ``file_identity``.

    With ``after_discovery`` the stand-in is armed once discovery has returned
    the file. A search of a directory checks what it would discover before it
    discovers (``validate_discovered_config`` reads the chain of the file it
    finds), and that read takes a ``file_identity`` of the file too. Armed from
    the start, the stand-in would be spent there, and the file would go while
    discovery was still looking: the answer would be the default configuration,
    or the recreated file read as any file. Armed after discovery, the first
    identity it meets is the one the caller takes when it checks the file.
    """
    real = config_sources.file_identity
    seen = []
    armed = [not after_discovery]

    def identity(candidate: Path) -> Any:
        if armed[0] and Path(candidate).resolve() == target.resolve() and not seen:
            seen.append(candidate)
            if remove:
                target.unlink()
                found = real(candidate)
                if recreate is not None:
                    target.write_text(recreate, encoding="utf-8")
                return found
            return None
        return real(candidate)

    monkeypatch.setattr(config_sources, "file_identity", identity)

    if after_discovery:
        discover = resolve_config.find_config_file

        def discover_then_arm(*args: Any, **kwargs: Any) -> Any:
            found = discover(*args, **kwargs)
            armed[0] = True
            return found

        monkeypatch.setattr(resolve_config, "find_config_file", discover_then_arm)


@pytest.mark.parametrize("fmt", FORMATS.values(), ids=FORMATS)
def test_a_named_file_that_appears_after_its_identity_check_is_refused(
    tmp_path, monkeypatch, fmt
):
    name, checked, _swapped = fmt
    target = tmp_path / name
    target.write_text(checked.replace("checked", "appeared"), encoding="utf-8")
    _identity_missing_at_the_check(monkeypatch, target)

    result = mcp_get_config(config_path=str(target), raw=True)

    shown = json.dumps(result, default=str)
    assert result.get("success") is False, result
    assert "appeared" not in shown, result
    assert "changed after it was checked" in shown, result


def test_a_discovered_file_that_is_gone_after_discovery_is_not_found(
    tmp_path, monkeypatch
):
    """Nothing at the path when the read opens it: the file does not exist, and
    that is what the answer says (``file_not_found``), not that it changed."""
    target = tmp_path / ".ash.yaml"
    target.write_text("project_name: discovered\n", encoding="utf-8")
    _identity_missing_at_the_check(
        monkeypatch, target, remove=True, after_discovery=True
    )

    result = mcp_get_config(search_dir=str(tmp_path), raw=True)

    shown = json.dumps(result, default=str)
    assert result.get("success") is False, result
    assert result.get("error_category") == "file_not_found", result
    assert "changed after it was checked" not in shown, result


def test_a_discovered_file_that_is_gone_after_discovery_and_back_is_refused(
    tmp_path, monkeypatch
):
    """Something at the path where the identity found nothing: a different file
    from the one discovery selected, so the read is refused, not made."""
    target = tmp_path / ".ash.yaml"
    target.write_text("project_name: discovered\n", encoding="utf-8")
    _identity_missing_at_the_check(
        monkeypatch,
        target,
        remove=True,
        recreate="project_name: appeared\n",
        after_discovery=True,
    )

    result = mcp_get_config(search_dir=str(tmp_path), raw=True)

    shown = json.dumps(result, default=str)
    assert result.get("success") is False, result
    assert "appeared" not in shown, result
    assert "changed after it was checked" in shown, result


PADDING = "x" * 200

#: (file name, text longer than the bound set below). YAML and JSON were read
#: whole by a plain open() before the raw read went through read_config_bytes.
OVERSIZED = {
    "yaml": ("config.yaml", f"project_name: {PADDING}\n"),
    "json": ("config.json", f'{{"project_name": "{PADDING}"}}\n'),
}


@pytest.mark.parametrize("oversized", OVERSIZED.values(), ids=OVERSIZED)
def test_a_file_over_the_size_bound_is_refused_not_read(
    tmp_path, monkeypatch, oversized
):
    name, text = oversized
    monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 64)
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")

    result = mcp_get_config(config_path=str(target), raw=True)

    assert result.get("success") is False, result
    assert PADDING not in json.dumps(result, default=str), result


def test_control_a_toml_file_over_the_size_bound_was_refused_already(
    tmp_path, monkeypatch
):
    """TOML is bounded on the base too: the raw read took its text through
    ``_read_toml_text``, which reads with ``read_config_bytes``. What the TOML read
    lacked was the identity, which the swap cases above pin. This case holds the
    contract the other formats now share and passes before and after."""
    monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 64)
    target = tmp_path / "config.toml"
    target.write_text(f'project_name = "{PADDING}"\n', encoding="utf-8")

    result = mcp_get_config(config_path=str(target), raw=True)

    assert result.get("success") is False, result
    assert PADDING not in json.dumps(result, default=str), result
