# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ``.semgrepignore`` files the unhonored-file note names, and when it is made.

``_note_unhonored_semgrepignore`` names every ``.semgrepignore`` either tool would
have read and did not, because ASH runs both with ``--x-ignore-semgrepignore-files``.

- The walk goes from the source directory up to the repository root, the first
  directory holding ``.git``. Outside a repository there is no root, and the tools
  read the file in the scanned directory alone; the walk used to continue to the
  filesystem root and name a ``.semgrepignore`` in the home directory, say, as one
  "in the scanned tree" that was not honored.
- The note is logged whether or not the context's config keeps a list of
  resolution warnings; it used to be neither recorded nor logged without one.
- A disabled scanner runs neither tool, so it records no note; it used to, because
  the arguments are built at construction for every registered scanner.

Building the scanners probes uv and opengrep; the tool guard answers the probes as
a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    _semgrepignore_files,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    from tests.utils.tool_guard import stub_tool_probes

    stub_tool_probes(monkeypatch)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)


def _planted(*paths: Path):
    """A presence test over a planted set of paths, so the walk's answer does not
    depend on what sits above the test's temporary directory."""
    planted = {Path(path) for path in paths}
    return lambda path: Path(path) in planted


def test_outside_a_repository_only_the_scanned_directorys_file_is_named():
    """No ``.git`` anywhere above: the file in the scanned directory is named and
    the one in its parent is not.

    Fails at the base: the walk went to the filesystem root and named both.
    """
    source = Path("/srv/checkouts/app")
    files = _semgrepignore_files(
        source,
        exists=_planted(source / ".semgrepignore", source.parent / ".semgrepignore"),
    )

    assert files == [source / ".semgrepignore"]


def test_inside_a_repository_every_file_up_to_its_root_is_named():
    """The control: with ``.git`` two levels up, the files in the scanned directory,
    its parent and the root are named, and nothing above the root."""
    root = Path("/srv/checkouts/repo")
    source = root / "services" / "api"
    files = _semgrepignore_files(
        source,
        exists=_planted(
            root / ".git",
            source / ".semgrepignore",
            source.parent / ".semgrepignore",
            root / ".semgrepignore",
            root.parent / ".semgrepignore",
        ),
    )

    assert files == [
        source / ".semgrepignore",
        source.parent / ".semgrepignore",
        root / ".semgrepignore",
    ]


def test_a_file_above_a_scanned_directory_outside_any_repository_is_not_noted(
    tmp_path, monkeypatch
):
    """Driven through the scanner: a ``.semgrepignore`` in the parent of a scanned
    directory that no repository holds is not noted as unhonored, while the one in
    the scanned directory itself is, which proves the note is live in this setup.

    Fails at the base: the parent's file was noted.
    """
    if any((parent / ".git").exists() for parent in (tmp_path, *tmp_path.parents)):
        pytest.skip("a repository holds the temporary directory; the walk stops there")
    source = tmp_path / "outer" / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".semgrepignore").write_text("docs/\n", encoding="utf-8")
    (tmp_path / "outer" / ".semgrepignore").write_text("tests/\n", encoding="utf-8")
    config = get_default_config()
    context = PluginContext(
        source_dir=source, output_dir=tmp_path / "out", config=config
    )

    SemgrepScanner(
        context=context,
        # Enabled on every platform: the default turns semgrep off on Windows, and a
        # disabled scanner writes no note.
        config=SemgrepScannerConfig(
            enabled=True, options=SemgrepScannerConfigOptions(offline=False)
        ),
    )

    noted = [w for w in config._resolution_warnings if ".semgrepignore" in w]
    assert len(noted) == 1, config._resolution_warnings
    assert (source / ".semgrepignore").as_posix() in noted[0], noted
    assert (tmp_path / "outer" / ".semgrepignore").as_posix() not in noted[0], noted


def test_the_note_is_logged_when_the_config_keeps_no_warnings_list(
    test_plugin_context, monkeypatch
):
    """With no ``_resolution_warnings`` list on the config the note is still logged
    at WARNING, so it reaches ash.log and the console.

    Fails at the base: the log call sat inside the branch that appends to the
    list, so without one nothing was said.
    """
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    (source / ".semgrepignore").write_text("tests/\n", encoding="utf-8")
    test_plugin_context.config._resolution_warnings = None
    logged: list[tuple[int, str]] = []
    original = SemgrepScanner._plugin_log

    def recording_log(self, message, *args, **kwargs):
        logged.append((kwargs.get("level", logging.INFO), str(message)))
        return original(self, message, *args, **kwargs)

    monkeypatch.setattr(SemgrepScanner, "_plugin_log", recording_log)

    SemgrepScanner(
        context=test_plugin_context,
        # Enabled on every platform: the default turns semgrep off on Windows, and a
        # disabled scanner writes no note.
        config=SemgrepScannerConfig(
            enabled=True, options=SemgrepScannerConfigOptions(offline=False)
        ),
    )

    assert any(
        level == logging.WARNING and ".semgrepignore" in message
        for level, message in logged
    ), logged


def test_a_disabled_scanner_records_no_note(test_plugin_context):
    """``enabled: false`` builds the arguments as every registered scanner does,
    but runs no tool, so no ``.semgrepignore`` goes unhonored by it.

    Fails at the base: the note was recorded for the disabled scanner too.
    """
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    (source / ".semgrepignore").write_text("tests/\n", encoding="utf-8")
    warnings = test_plugin_context.config._resolution_warnings

    SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            enabled=False, options=SemgrepScannerConfigOptions(offline=False)
        ),
    )

    assert not [w for w in warnings if ".semgrepignore" in w], warnings


def test_an_enabled_scanner_records_the_note(test_plugin_context):
    """The control: enabled, the file in the scanned directory is noted."""
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    (source / ".semgrepignore").write_text("tests/\n", encoding="utf-8")
    warnings = test_plugin_context.config._resolution_warnings

    SemgrepScanner(
        context=test_plugin_context,
        # Enabled on every platform: the default turns semgrep off on Windows, and a
        # disabled scanner writes no note.
        config=SemgrepScannerConfig(
            enabled=True, options=SemgrepScannerConfigOptions(offline=False)
        ),
    )

    assert [w for w in warnings if (source / ".semgrepignore").as_posix() in w], (
        warnings
    )
