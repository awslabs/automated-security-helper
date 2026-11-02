# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""semgrep and opengrep scan the converted target, and read git-ignored files when asked.

Both scanners' ``exclude`` option defaults to ``*-converted.py``, the name the jupyter
converter gives every notebook it converts. The converted target holds nothing else,
so the pattern excluded every file there: the tools found files and skipped them all
as ``cli_exclude_flags_match``, and the scanned-nothing refusal turned a repository of
notebooks into a scanner error. The converted target's command now carries no such
exclude; the source target's keeps it, and an operator's own patterns stay as written.

The converted target also lives under ASH's output directory, whose ``.gitignore``
ignores everything in it, so inside a git work tree both tools skipped it whole (graded
SKIPPED). Its command carries ``--no-git-ignore``, as does the source target's when
the operator set ``honor_ignore_files: false``, which asks for the files the
repository's ignore files match to be scanned too.

Building the scanners probes uv and opengrep; the unit conftest's tool guard answers
the probes as a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    CONVERTED_FILE_EXCLUDE,
    NO_GIT_IGNORE_FLAG,
)
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


def _context(tmp_path: Path) -> PluginContext:
    """A source tree with ASH's output directory inside it, as the default layout
    has, and a converted target holding one converted notebook."""
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    work = output / "converted"
    (work / "jupyter").mkdir(parents=True)
    (work / "jupyter" / "notebook-converted.py").write_text(
        "import os\n", encoding="utf-8"
    )
    (output / ".gitignore").write_text("*\n", encoding="utf-8")
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work,
        config=get_default_config(),
    )


def _online_scanner(scanner_cls, config_cls, options, context, cache_env, monkeypatch):
    """The scanner built online, whatever ASH's own offline mode is here: offline
    without a rule cache it declines before it builds a command."""
    monkeypatch.delenv(cache_env, raising=False)
    monkeypatch.setattr(scanner_cls, "_scanner_offline", lambda self: False)
    return scanner_cls(context=context, config=config_cls(options=options))


def _command(scanner, target: Path, target_type: str) -> list[str]:
    final_args, _results_file, _env = scanner._execute_scan(
        target=target, target_type=target_type, global_ignore_paths=[]
    )
    return final_args


def _exclude_values(command: list[str]) -> list[str]:
    """Every ``--exclude`` value in the command: the split form ASH's own constants
    take, and the joined form (``--exclude=<pattern>``) the operator's patterns
    take."""
    values = [
        command[index + 1]
        for index, word in enumerate(command[:-1])
        if word == "--exclude"
    ]
    prefix = "--exclude="
    values.extend(word[len(prefix) :] for word in command if word.startswith(prefix))
    return values


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_default_exclude_names_the_converted_files(
    scanner_cls, config_cls, options_cls, cache_env
):
    """The premise: the pattern the converted target drops is the one both
    scanners exclude by default. A default that stops naming the converted files
    has to change the constant with it."""
    assert CONVERTED_FILE_EXCLUDE in options_cls().exclude


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_converted_target_command_has_no_converted_file_exclude(
    scanner_cls, config_cls, options_cls, cache_env, tmp_path, monkeypatch
):
    """The converted target's command does not exclude the files it exists for.

    Fails at the base: the default ``--exclude *-converted.py`` reached every
    target's command, the converted one included.
    """
    context = _context(tmp_path)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False),
        context,
        cache_env,
        monkeypatch,
    )

    converted = _command(scanner, context.work_dir, "converted")
    source = _command(scanner, context.source_dir, "source")

    assert CONVERTED_FILE_EXCLUDE not in _exclude_values(converted), converted
    # The source target keeps the configured default.
    assert CONVERTED_FILE_EXCLUDE in _exclude_values(source), source


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_converted_target_command_reads_git_ignored_files(
    scanner_cls, config_cls, options_cls, cache_env, tmp_path, monkeypatch
):
    """The converted target's command carries ``--no-git-ignore``; the source
    target's does not while the repository's ignore files are honored.

    Fails at the base: no command carried the flag, so a converted target under
    ASH's ignored output directory was skipped whole inside a git work tree.
    """
    context = _context(tmp_path)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False),
        context,
        cache_env,
        monkeypatch,
    )

    assert NO_GIT_IGNORE_FLAG in _command(scanner, context.work_dir, "converted")
    assert NO_GIT_IGNORE_FLAG not in _command(scanner, context.source_dir, "source")


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_source_target_reads_git_ignored_files_when_ignore_files_are_not_honored(
    scanner_cls, config_cls, options_cls, cache_env, tmp_path, monkeypatch
):
    """``honor_ignore_files: false`` reaches the tool as ``--no-git-ignore``.

    Fails at the base: the setting decided ASH's own scan set and nothing else,
    so the tools' git-ignore reading still left those files out.
    """
    context = _context(tmp_path)
    monkeypatch.setattr(context.config, "honor_ignore_files", False)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False),
        context,
        cache_env,
        monkeypatch,
    )

    assert NO_GIT_IGNORE_FLAG in _command(scanner, context.source_dir, "source")


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_operator_exclude_patterns_stay_on_the_converted_target(
    scanner_cls, config_cls, options_cls, cache_env, tmp_path, monkeypatch
):
    """Only ASH's own converted-file pattern is dropped; the operator's stay."""
    context = _context(tmp_path)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False, exclude=[CONVERTED_FILE_EXCLUDE, "*.txt", "docs/"]),
        context,
        cache_env,
        monkeypatch,
    )

    excludes = _exclude_values(_command(scanner, context.work_dir, "converted"))
    assert "*.txt" in excludes
    assert "docs/" in excludes
    assert CONVERTED_FILE_EXCLUDE not in excludes


def _context_with_output_under_a_default_ignore(tmp_path: Path) -> PluginContext:
    """A git work tree whose ASH output directory sits under ``build`` (the
    ``--output-dir build/ash`` layout): the tools anchor ``build/`` at the
    repository root, so the re-passed default covers the converted target whole."""
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / "build" / "ash"
    work = output / "converted"
    (work / "jupyter").mkdir(parents=True)
    (work / "jupyter" / "notebook-converted.py").write_text(
        "import os\n", encoding="utf-8"
    )
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work,
        config=get_default_config(),
    )


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_converted_target_under_a_default_ignore_drops_that_default(
    scanner_cls, config_cls, options_cls, cache_env, tmp_path, monkeypatch
):
    """The converted target's command leaves out the re-passed default that names
    one of its own directories below the repository root, and keeps the rest; the
    source target's command keeps every default.

    Fails at the base: ``--exclude build/`` reached the converted command, the tools
    excluded every converted file, and the target graded SKIPPED with no notebook
    scanned.
    """
    context = _context_with_output_under_a_default_ignore(tmp_path)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False),
        context,
        cache_env,
        monkeypatch,
    )

    converted = _exclude_values(_command(scanner, context.work_dir, "converted"))
    source = _exclude_values(_command(scanner, context.source_dir, "source"))

    assert "build/" not in converted, converted
    assert "tests/" in converted, converted
    assert "build/" in source, source


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_configured_arguments_are_left_as_they_were(
    scanner_cls, config_cls, options_cls, cache_env, tmp_path, monkeypatch
):
    """The per-target changes live in the resolved command only: ``extra_args``
    persists across scan() calls, and the next target starts from the configured
    list."""
    context = _context(tmp_path)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False),
        context,
        cache_env,
        monkeypatch,
    )

    _command(scanner, context.work_dir, "converted")

    pairs = [(arg.key, arg.value) for arg in scanner.args.extra_args]
    assert (f"--exclude={CONVERTED_FILE_EXCLUDE}", None) in pairs, pairs
    assert NO_GIT_IGNORE_FLAG not in [key for key, _ in pairs], pairs
    # And the source target, resolved after, is a source command.
    source = _command(scanner, context.source_dir, "source")
    assert CONVERTED_FILE_EXCLUDE in _exclude_values(source)
    assert NO_GIT_IGNORE_FLAG not in source
