# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.semgrepignore`` that cannot be resolved does not stop the scanner from building.

``_note_unhonored_semgrepignore`` runs while the scanner is built and asks
``config_is_client_supplied`` about each ``.semgrepignore`` it finds. That judgment
resolves the path; a link loop at the name raises RuntimeError on Python 3.10 to 3.12
("Symlink loop from ...") and OSError (ELOOP) on 3.13. Either used to escape the
constructor, so semgrep and opengrep failed to construct for a tree holding such a
link. The file is named as the repository's instead.

The judgment is stood in for here: the real one resolves only under an MCP shared
workspace root, and the exception shape is Python's, not this repository's.
"""

from __future__ import annotations

import errno

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


SCANNERS = [
    pytest.param(
        SemgrepScanner,
        SemgrepScannerConfig,
        SemgrepScannerConfigOptions,
        "SEMGREP_RULES_CACHE_DIR",
        id="semgrep",
    ),
    pytest.param(
        OpengrepScanner,
        OpengrepScannerConfig,
        OpengrepScannerConfigOptions,
        "OPENGREP_RULES_CACHE_DIR",
        id="opengrep",
    ),
]

LOOP_ERRORS = [
    pytest.param(
        RuntimeError("Symlink loop from '/repo/.semgrepignore'"), id="py310-312"
    ),
    pytest.param(
        OSError(
            errno.ELOOP, "Too many levels of symbolic links", "/repo/.semgrepignore"
        ),
        id="py313",
    ),
]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
@pytest.mark.parametrize("error", LOOP_ERRORS)
def test_an_unresolvable_semgrepignore_leaves_the_scanner_constructed(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    error,
    test_plugin_context,
    monkeypatch,
):
    """Fails at the base: the exception left ``config_is_client_supplied`` and the
    constructor with it."""
    from automated_security_helper.cli.mcp import sandbox

    source = test_plugin_context.source_dir
    source.mkdir(parents=True, exist_ok=True)
    (source / ".semgrepignore").write_text("tests/\n", encoding="utf-8")
    monkeypatch.delenv(cache_env, raising=False)
    monkeypatch.setattr(scanner_cls, "_scanner_offline", lambda self: False)

    asked = []

    def refuse_to_resolve(config_path):
        asked.append(config_path)
        raise error

    monkeypatch.setattr(sandbox, "config_is_client_supplied", refuse_to_resolve)

    # Enabled on every platform: the default turns semgrep off on Windows, and a
    # disabled scanner never asks about the file, so the stub would never run.
    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(enabled=True, options=options_cls(offline=False)),
    )

    assert asked, "the stub was never reached, so nothing here measures the fix"
    assert scanner.command in ("semgrep", "opengrep")
    assert any(
        arg.key == "--x-ignore-semgrepignore-files" for arg in scanner.args.extra_args
    )


@pytest.mark.parametrize("error", LOOP_ERRORS)
def test_the_unresolvable_file_is_named_as_the_repositorys(
    test_plugin_context, monkeypatch, error
):
    """The warning still names the file, as one the repository holds, whichever
    exception the resolution raised."""
    from automated_security_helper.cli.mcp import sandbox

    source = test_plugin_context.source_dir
    source.mkdir(parents=True, exist_ok=True)
    ignore_file = source / ".semgrepignore"
    ignore_file.write_text("tests/\n", encoding="utf-8")
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    asked = []

    def refuse_to_resolve(config_path):
        asked.append(config_path)
        raise error

    monkeypatch.setattr(sandbox, "config_is_client_supplied", refuse_to_resolve)
    # The config's own list of resolution warnings, which the note is appended to.
    warnings = test_plugin_context.config._resolution_warnings

    # Enabled on every platform: the default turns semgrep off on Windows, and a
    # disabled scanner writes no note.
    SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            enabled=True, options=SemgrepScannerConfigOptions(offline=False)
        ),
    )

    assert asked, "the stub was never reached, so nothing here measures the fix"
    named = [message for message in warnings if ignore_file.as_posix() in message]
    assert len(named) == 1, warnings
    assert "client-supplied" not in named[0], named
    assert "in the scanned tree" in named[0], named
