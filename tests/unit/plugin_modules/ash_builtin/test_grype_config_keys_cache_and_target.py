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
- ``validate_plugin_dependencies`` probed PATH itself instead of chaining to the
  base check, so a recorded ``dependency_unavailable_reason`` was ignored and a
  refused in-tree copy read as "not installed".

The blank-config test reads the argv grype gets, the swap-window test records
where its raise landed, and the garbled-name tests write their names through
``tests.utils.undecodable_names.make_tree``, which skips where the filesystem
cannot hold them.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base import scanner_plugin
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
from tests.utils.undecodable_names import make_tree

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


@pytest.mark.parametrize("form", ["tilde", "symlink"])
def test_the_config_warnings_name_the_config_as_configured_not_as_resolved(
    root, monkeypatch, form
):
    """Redaction finds the spelling the operator configured, so a warning that
    named the resolved path (``~`` expanded, a link followed) printed it whole. The
    value is passed to the scanner as the environment's, as ``config_file:
    ${GRYPE_CFG}`` does."""
    if form == "symlink" and sys.platform == "win32":
        pytest.skip("symlinks")
    body = "only-fixed: true\ndb:\n  cache-dir: /elsewhere/db\n"
    if form == "tilde":
        home = root / "zz-home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        real = home / "zz-grype-config.yaml"
        configured = "~/zz-grype-config.yaml"
    else:
        folder = root / "zz-elsewhere"
        folder.mkdir()
        real = folder / "zz-grype-real.yaml"
        link = folder / "zz-grype-link.yaml"
        configured = str(link)
    real.write_text(body, encoding="utf-8")
    if form == "symlink":
        link.symlink_to(real)
    messages: list[str] = []

    with (
        patch.object(GrypeScanner, "_environment_values", return_value=[configured]),
        patch.object(
            GrypeScanner,
            "_plugin_log",
            autospec=True,
            side_effect=lambda self, message, **kwargs: messages.append(str(message)),
        ),
    ):
        _grype(_context(root), config_file=configured)

    restricting = [m for m in messages if "restricts which matches" in m]
    moving = [m for m in messages if "db.cache-dir" in m]
    assert len(restricting) == 1 and len(moving) == 1, messages
    for message in (*restricting, *moving):
        assert str(real) not in message, message
        assert "zz-grype" not in message, message
        assert "zz-home" not in message and "zz-elsewhere" not in message, message


def _symlinked_source_context(root: Path) -> tuple[PluginContext, Path]:
    """A context whose source directory is a link to the real repository, as a
    macOS ``/var`` temporary directory or a symlinked CI workspace is."""
    real = root / "zz-real-repo"
    real.mkdir()
    link = root / "repo-link"
    link.symlink_to(real, target_is_directory=True)
    ctx = PluginContext(
        source_dir=link,
        output_dir=root / "out",
        work_dir=root / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (real / "requirements.txt").write_text("requests==2.19.0\n")
    return ctx, real


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_an_in_tree_config_is_not_handed_to_the_refresh_when_the_source_is_a_link(
    root,
):
    """The config is resolved before it is judged, and the source directory is
    named by a link. Compared as spelled, the in-tree file read as outside the
    tree and went to the database refresh, which runs outside the sandbox."""
    ctx, real = _symlinked_source_context(root)
    config = real / "grype.yaml"
    config.write_text("only-fixed: true\n", encoding="utf-8")

    scanner = _grype(ctx, config_file=str(config))

    assert scanner._content_db_operator_config is None


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_control_a_config_outside_a_linked_source_is_handed_to_the_refresh(root):
    ctx, _ = _symlinked_source_context(root)
    config = root / "zz-operator" / "grype.yaml"
    config.parent.mkdir()
    config.write_text("only-fixed: true\n", encoding="utf-8")

    scanner = _grype(ctx, config_file=str(config))

    assert scanner._content_db_operator_config == config


# --- the configured path ------------------------------------------------------------


def _values(command: list[str], flag: str) -> list[str]:
    found = []
    for index, arg in enumerate(command):
        if arg.startswith(f"{flag}="):
            found.append(arg.split("=", 1)[1])
        elif arg == flag and index + 1 < len(command):
            found.append(command[index + 1])
    return found


def _scan_command(scanner) -> list[str]:
    """The argv of one source scan, with the tool replaced by a double that writes
    no results file; what the scan makes of the missing file is not read here.

    A raise before the tool was reached is not that: with no command recorded the
    error is re-raised, so a scan that never got as far as the tool fails the
    test with its own error and not with a failed unpacking of an empty list."""
    commands: list[list[str]] = []

    def run(command, *args, **kwargs):
        commands.append([str(part) for part in command])
        return {"returncode": 0}

    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        try:
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")
        except Exception:
            if not commands:
                raise
            # otherwise the double wrote no results file
    (command,) = commands
    return command


def test_a_blank_config_file_names_no_file(root, caplog):
    """Read from the argv grype gets, not the arguments at construction: a fix
    that dropped ``--config`` altogether would pass a check of what is absent, and
    grype would then load a .grype.yaml from the scanned source, where it runs."""
    ctx = _context(root)

    with caplog.at_level(logging.WARNING):
        scanner = _grype(ctx, config_file="  ")

    (named,) = _values(_scan_command(scanner), "--config")
    assert not Path(named).resolve().is_relative_to(Path(ctx.source_dir).resolve())
    # The config-file message, named in full: this module runs offline (the
    # autouse fixture), and in a HOME without a grype database the offline cache
    # check warns that the database directory "does not exist", which is not
    # about the config file.
    assert "Configured grype config file does not exist" not in caplog.text


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
    # The config-file message in full, as the blank-config test names it: this
    # module runs offline, and the offline cache check also says a database
    # directory "does not exist", so the short phrase alone is met without the
    # config file having been judged missing.
    assert "Configured grype config file does not exist" in caplog.text


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
    (present / "6").mkdir(parents=True)
    (present / "6" / "vulnerability.db").write_bytes(b"db")
    monkeypatch.setattr(grype_scanner, "default_cache_dir", lambda *a, **k: present)

    with caplog.at_level(logging.WARNING):
        _grype(_context(root))

    assert present.as_posix() not in caplog.text
    assert "environment variable not set" not in caplog.text


def test_offline_with_an_empty_default_cache_the_missing_database_is_said(
    root, monkeypatch, caplog
):
    """A directory that exists is not a database: a fresh cache directory, or one
    another tool made, holds nothing grype can read. trivy's twin check looks for
    the database file for the same reason. The schema version is not named: grype
    keeps a directory per version."""
    empty = root / "cache" / "grype"
    empty.mkdir(parents=True)
    (empty / "6").mkdir()
    monkeypatch.setattr(grype_scanner, "default_cache_dir", lambda *a, **k: empty)

    with caplog.at_level(logging.WARNING):
        _grype(_context(root))

    (line,) = [
        r.getMessage() for r in caplog.records if empty.as_posix() in r.getMessage()
    ]
    assert "holds no vulnerability database" in line, line


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
def test_offline_a_cache_under_an_unsearchable_directory_is_judged_missing_not_raised(
    root, monkeypatch, caplog
):
    """``Path.is_dir`` raises ``PermissionError`` on Python 3.10-3.13 under a
    directory this process cannot search, out of the scanner's construction."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root searches every directory")
    locked = root / "locked"
    locked.mkdir()
    cache = locked / "grype"
    cache.mkdir()
    monkeypatch.setattr(grype_scanner, "default_cache_dir", lambda *a, **k: cache)
    locked.chmod(0)
    try:
        with caplog.at_level(logging.WARNING):
            _grype(_context(root))
    finally:
        locked.chmod(0o755)

    assert cache.as_posix() in caplog.text


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
    keys_at_the_raise: list[str] = []

    def refuse(*args, **kwargs):
        # Inside the swap window: the --exclude values are in place when the
        # empty config is written, so the raise lands where the restore matters.
        keys_at_the_raise.extend(arg.key for arg in scanner.args.extra_args)
        raise RuntimeError("the empty config could not be written")

    monkeypatch.setattr(grype_scanner, "empty_tool_config", refuse)
    with pytest.raises(RuntimeError):
        scanner._execute_scan(Path(ctx.source_dir), "source", [])

    assert "--exclude" in keys_at_the_raise, keys_at_the_raise
    assert scanner.args.extra_args == before
    assert not any(arg.key == "--exclude" for arg in scanner.args.extra_args)


# --- garbled names ------------------------------------------------------------------


def test_a_backslash_is_a_name_character_where_the_separator_is_a_slash(root):
    """The name is written through ``make_tree``, which skips where the filesystem
    cannot hold it (Windows cannot decode it; APFS refuses it with EILSEQ), rather
    than on the platform's name alone."""
    make_tree(root, {b"a\\b\xff": b"x\n"})
    garbled = os.fsdecode(b"a\\b\xff")

    assert _name_grype_garbled(root, "a\\b�") == garbled


def test_a_backslash_separator_is_kept_in_place_when_asked_for(root):
    make_tree(root, {b"a/b\xff": b"x\n"})
    garbled = os.fsdecode(b"b\xff")

    assert _name_grype_garbled(root, "a\\b�", separators="/\\") == f"a\\{garbled}"
    assert _name_grype_garbled(root, "a/b�", separators="/\\") == f"a/{garbled}"


def test_a_uri_that_begins_with_the_scan_root_is_walked_from_what_follows_it(root):
    """grype's Windows spelling is the scan root, then the relative path with
    backslashes (``D:/a/r/r/\\deploy\\...``). Walked from the root again, the root's
    own components named a directory that does not exist, so nothing matched and
    the garbled name was left as it was. The shape is written here with the
    separators the Windows host passes, so a POSIX host runs it too."""
    make_tree(root, {b"deploy/b\xff": b"x\n"})
    garbled = os.fsdecode(b"b\xff")
    uri = f"{root.as_posix()}/\\deploy\\b�"

    assert _name_grype_garbled(root, uri, separators="/\\") == (
        f"{root.as_posix()}/\\deploy\\{garbled}"
    )


def test_control_a_uri_that_merely_looks_like_the_root_is_walked_whole(root):
    """Only a URI that begins with the root's whole last component is cut there:
    ``<root>-other`` is another directory's name."""
    other = Path(f"{root.as_posix()}-other")
    uri = f"{other.as_posix()}/\\deploy\\b�"

    assert _name_grype_garbled(root, uri, separators="/\\") == uri


# --- the dependency check -----------------------------------------------------------


def _probe_answers(monkeypatch, found):
    """Make every PATH probe the check can reach answer ``found``: the base
    module's, and the scanner module's own import (gone once the override chains,
    kept so the test runs against the pre-fix shape too)."""
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda command: found)
    monkeypatch.setattr(
        grype_scanner, "find_executable", lambda command: found, raising=False
    )


def test_a_recorded_reason_makes_the_check_answer_false_without_a_path_probe(
    root, monkeypatch
):
    """A construction-time reason is not outvoted by the binary being on PATH, and
    the check does not look for the binary at all: the probes are recorded."""
    scanner = _grype(_context(root))
    scanner.dependency_unavailable_reason = "grype is in offline mode with no database"
    probed: list[str] = []

    def probe(command):
        probed.append(command)
        return "/usr/bin/grype"

    monkeypatch.setattr(scanner_plugin, "find_executable", probe)
    monkeypatch.setattr(grype_scanner, "find_executable", probe, raising=False)

    assert scanner.validate_plugin_dependencies() is False
    assert probed == []
    assert (
        scanner.dependency_unavailable_reason
        == "grype is in offline mode with no database"
    )


def test_a_refused_in_tree_copy_is_recorded_as_the_reason(root, monkeypatch, caplog):
    """No binary on PATH and a refused copy inside the tree: the refusal is the
    MISSING row's reason, and the "not installed" warning is not given."""
    scanner = _grype(_context(root))
    _probe_answers(monkeypatch, None)
    monkeypatch.setattr(
        scanner_plugin,
        "in_tree_refusal",
        lambda command: f"{command} inside the scanned tree was refused",
    )

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependency_unavailable_reason == (
        "grype inside the scanned tree was refused"
    )
    assert "not found in PATH" not in caplog.text


def test_control_a_binary_on_path_and_no_reason_passes_the_check(root, monkeypatch):
    scanner = _grype(_context(root))
    _probe_answers(monkeypatch, "/usr/bin/grype")

    assert scanner.validate_plugin_dependencies() is True
    assert not scanner.dependency_unavailable_reason


def test_control_no_binary_and_no_refusal_still_warns(root, monkeypatch, caplog):
    scanner = _grype(_context(root))
    _probe_answers(monkeypatch, None)
    monkeypatch.setattr(scanner_plugin, "in_tree_refusal", lambda command: None)

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    assert "Grype executable not found in PATH" in caplog.text
    assert not scanner.dependency_unavailable_reason
