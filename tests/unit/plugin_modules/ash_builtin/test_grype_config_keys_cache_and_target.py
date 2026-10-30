# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How the grype scanner reads the operator's config and names its target.

- grype reads its config through viper, which lowercases keys, so ``Only-Fixed:
  true`` filters as ``only-fixed`` does; the restricting-keys and ``db`` reads
  compare lowercased keys. ``vex-documents`` is a filter too: with a document
  loaded, matches it marks ``not_affected`` or ``fixed`` leave the report.
- A config file that is not UTF-8 raised ``UnicodeDecodeError`` (a
  ``ValueError``) out of the scanner's construction; it reads as unreadable.
- The ``db.cache-dir`` warning spelled the config path unredacted.
- A blank ``config_file`` was joined to the source directory, which exists, and
  grype was handed the directory as its config.
- A configured path under a directory this process cannot search raised
  ``PermissionError`` out of ``Path.exists`` (Python 3.10-3.13) at construction.
- Offline, the cache check judged only ``GRYPE_DB_CACHE_DIR`` and warned about
  every offline scan whose default cache held a database.
- A relative target was passed as ``dir:<relative>``, which grype read from its
  working directory, the scanned source.
- A raise between the ``extra_args`` swap and its restore left this target's
  ``--exclude`` values for the next target.
- ``_name_grype_garbled`` split on ``/`` alone, so on Windows a garbled component
  behind a backslash was never matched.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    grype_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
    _name_grype_garbled,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _offline_and_fresh(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def root(tmp_path) -> Path:
    return Path(os.path.realpath(tmp_path))


def _context(root: Path) -> PluginContext:
    ctx = PluginContext(
        source_dir=root / "repo",
        output_dir=root / "out",
        work_dir=root / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (ctx.source_dir, ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (ctx.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    return ctx


def _grype(ctx, **options) -> GrypeScanner:
    return GrypeScanner(
        context=ctx,
        config=GrypeScannerConfig(options=GrypeScannerConfigOptions(**options)),
    )


# --- the config keys ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("Only-Fixed: true\n", ["only-fixed"]),
        ("IGNORE:\n  - vulnerability: CVE-2000-0001\n", ["ignore"]),
        ("vex-documents:\n  - ./vex.json\n", ["vex-documents"]),
        (
            "VEX-Documents: [./vex.json]\nonly-fixed: true\n",
            ["only-fixed", "vex-documents"],
        ),
    ],
)
def test_restricting_keys_are_read_as_viper_reads_them(tmp_path, body, expected):
    config = tmp_path / ".grype.yaml"
    config.write_text(body, encoding="utf-8")

    assert GrypeScanner._output_restricting_keys(config) == expected


def test_a_config_that_is_not_utf8_reports_nothing_and_raises_nothing(tmp_path):
    config = tmp_path / ".grype.yaml"
    config.write_bytes(b"\xff\xfeonly-fixed: true\n")

    assert GrypeScanner._output_restricting_keys(config) == []
    assert GrypeScanner._read_config(config) is None


def test_the_cache_dir_warning_is_redacted_and_reads_the_key_case_insensitively(
    root,
):
    ctx = _context(root)
    scanner = _grype(ctx)
    config = root / "operator" / "zz-grype-config.yaml"
    config.parent.mkdir()
    config.write_text("DB:\n  Cache-Dir: /elsewhere/db\n", encoding="utf-8")
    messages: list[str] = []

    with patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: messages.append(str(m))
    ):
        scanner._warn_if_config_moves_the_database(config, values=(str(config),))

    (warning,) = messages
    assert "db.cache-dir" in warning
    assert "zz-grype-config" not in warning


# --- the configured path ------------------------------------------------------------


def test_a_blank_config_file_names_no_file(root, caplog):
    ctx = _context(root)

    with caplog.at_level(logging.WARNING):
        scanner = _grype(ctx, config_file="  ")

    configured = [a.value for a in scanner.args.extra_args if a.key == "--config"]
    assert Path(ctx.source_dir).as_posix() not in configured
    assert "does not exist" not in caplog.text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
def test_a_config_under_an_unsearchable_directory_is_judged_missing_not_raised(
    root, caplog
):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root searches every directory")
    ctx = _context(root)
    locked = root / "locked"
    locked.mkdir()
    (locked / "grype.yaml").write_text("only-fixed: true\n", encoding="utf-8")
    locked.chmod(0)
    try:
        with caplog.at_level(logging.WARNING):
            scanner = _grype(ctx, config_file=str(locked / "grype.yaml"))
    finally:
        locked.chmod(0o755)

    configured = [a.value for a in scanner.args.extra_args if a.key == "--config"]
    assert (locked / "grype.yaml").as_posix() not in configured
    assert "does not exist" in caplog.text


# --- the offline cache check --------------------------------------------------------


def test_offline_without_grype_db_cache_dir_the_default_cache_is_judged_by_name(
    root, monkeypatch, caplog
):
    absent = root / "cache" / "absent"
    monkeypatch.setattr(grype_scanner, "default_cache_dir", lambda *a, **k: absent)

    with caplog.at_level(logging.WARNING):
        _grype(_context(root))

    assert absent.as_posix() in caplog.text
    assert "environment variable not set" not in caplog.text


def test_control_offline_with_a_default_cache_present_nothing_is_said(
    root, monkeypatch, caplog
):
    present = root / "cache" / "grype"
    present.mkdir(parents=True)
    monkeypatch.setattr(grype_scanner, "default_cache_dir", lambda *a, **k: present)

    with caplog.at_level(logging.WARNING):
        _grype(_context(root))

    assert present.as_posix() not in caplog.text
    assert "environment variable not set" not in caplog.text


# --- the target ---------------------------------------------------------------------


def test_a_relative_target_is_named_to_grype_by_its_absolute_path(root, monkeypatch):
    """grype runs with the scanned source as its working directory, where a
    relative ``dir:`` would name something else."""
    ctx = _context(root)
    monkeypatch.chdir(root)
    scanner = _grype(ctx)

    final_args, _, _ = scanner._execute_scan(Path("repo"), "source", [])

    assert f"dir:{(root / 'repo').as_posix()}" in final_args
    assert "dir:repo" not in final_args


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_a_raise_while_resolving_leaves_the_next_target_no_exclude_values(
    root, monkeypatch
):
    ctx = _context(root)
    outside = root / "outside.txt"
    outside.write_text("x\n", encoding="utf-8")
    (ctx.source_dir / "leaving.txt").symlink_to(outside)
    scanner = _grype(ctx)
    before = list(scanner.args.extra_args)

    def refuse(*args, **kwargs):
        raise RuntimeError("the empty config could not be written")

    monkeypatch.setattr(grype_scanner, "empty_tool_config", refuse)
    with pytest.raises(RuntimeError):
        scanner._execute_scan(Path(ctx.source_dir), "source", [])

    assert scanner.args.extra_args == before
    assert not any(arg.key == "--exclude" for arg in scanner.args.extra_args)


# --- garbled names ------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
def test_a_backslash_is_a_name_character_where_the_separator_is_a_slash(root):
    garbled = os.fsdecode(b"a\\b\xff")
    (root / garbled).write_text("x\n", encoding="utf-8")

    assert _name_grype_garbled(root, "a\\b�") == garbled


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
def test_a_backslash_separator_is_kept_in_place_when_asked_for(root):
    garbled = os.fsdecode(b"b\xff")
    (root / "a").mkdir()
    (root / "a" / garbled).write_text("x\n", encoding="utf-8")

    assert _name_grype_garbled(root, "a\\b�", separators="/\\") == f"a\\{garbled}"
    assert _name_grype_garbled(root, "a/b�", separators="/\\") == f"a/{garbled}"
