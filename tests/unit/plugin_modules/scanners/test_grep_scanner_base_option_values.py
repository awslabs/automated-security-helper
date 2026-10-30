# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How the operator's ``exclude`` and ``exclude_rule`` values reach semgrep and opengrep.

Both values used to travel as separate argv tokens (``--exclude`` then the pattern),
which has two holes the class already closed for its own ignore names by writing
them joined (``--exclude=<name>``, ``_execute_scan``):

- a value starting with ``-`` is read by the tools as an option, not as the value;
- a blank value is dropped by ``ScannerPluginBase._resolve_arguments`` after its
  flag was appended, so the flag takes the next argument of the command as its
  value, and a separate token that starts with ``--json-output=`` is read by
  ``_read_paths_output`` as the file the scanned-path counts come from.

The operator's values now travel joined, and a blank entry is left out with a
warning naming the option. The tools' own default ignore list and the output
directory excludes keep the split form (their values are ASH's constants).

Building the scanners probes uv and opengrep; the tool guard answers the probes as
a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    _PATHS_OUTPUT_FLAG,
    SEMGREP_DEFAULT_IGNORES,
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


@pytest.fixture(autouse=True)
def _no_tool_probe(monkeypatch):
    from tests.utils.tool_guard import stub_tool_probes

    stub_tool_probes(monkeypatch)


def _online_scanner(scanner_cls, config_cls, options, context, cache_env, monkeypatch):
    monkeypatch.delenv(cache_env, raising=False)
    monkeypatch.setattr(scanner_cls, "_scanner_offline", lambda self: False)
    return scanner_cls(context=context, config=config_cls(options=options))


def _keys(scanner) -> list[str]:
    return [arg.key for arg in scanner.args.extra_args]


def _command(scanner, target: Path) -> list[str]:
    final_args, _results_file, _env = scanner._execute_scan(
        target=target, target_type="source", global_ignore_paths=[]
    )
    return [str(word) for word in final_args]


def _values_after(argv: list[str], flag: str) -> list[str]:
    return [argv[index + 1] for index, word in enumerate(argv[:-1]) if word == flag]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_operator_values_travel_in_the_joined_form(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """``--exclude=<pattern>`` and ``--exclude-rule=<id>``, so a value starting with
    ``-`` is the value and not an option the tool reads.

    Fails at the base: the values were separate tokens, so ``-weird.py`` stood on
    its own in the command after ``--exclude``.
    """
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False, exclude=["-weird.py", "docs/"], exclude_rule=["-r"]),
        test_plugin_context,
        cache_env,
        monkeypatch,
    )

    keys = _keys(scanner)
    assert "--exclude=-weird.py" in keys, keys
    assert "--exclude=docs/" in keys, keys
    assert "--exclude-rule=-r" in keys, keys
    assert "-weird.py" not in [arg.value for arg in scanner.args.extra_args]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_blank_value_is_left_out_and_named(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """A blank ``exclude`` or ``exclude_rule`` entry adds no flag, and a warning
    names the option it was found in.

    Fails at the base: ``--exclude`` was appended with the blank value, which
    ``_resolve_arguments`` then dropped, so the bare flag took the next argument.
    """
    logged: list[tuple[int, str]] = []
    original = scanner_cls._plugin_log

    def recording_log(self, message, *args, **kwargs):
        logged.append((kwargs.get("level", logging.INFO), str(message)))
        return original(self, message, *args, **kwargs)

    monkeypatch.setattr(scanner_cls, "_plugin_log", recording_log)
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False, exclude=["", "   ", "foo.py"], exclude_rule=[""]),
        test_plugin_context,
        cache_env,
        monkeypatch,
    )

    keys = _keys(scanner)
    assert "--exclude=foo.py" in keys, keys
    assert "--exclude=" not in keys and "--exclude=   " not in keys, keys
    assert "--exclude-rule=" not in keys, keys
    assert not any(
        arg.key in ("--exclude", "--exclude-rule") and not str(arg.value or "").strip()
        for arg in scanner.args.extra_args
    ), keys
    name = scanner.config.name
    warnings = [message for level, message in logged if level == logging.WARNING]
    assert any(f"scanners.{name}.options.exclude" in message for message in warnings), (
        warnings
    )
    assert any(
        f"scanners.{name}.options.exclude_rule" in message for message in warnings
    ), warnings


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_no_bare_exclude_flag_takes_another_argument(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """In the resolved command every split ``--exclude`` is followed by one of ASH's
    own values (the tools' default ignore list, or an anchored output-directory
    pattern), never by another flag or by the target.

    Fails at the base: the blank operator entry left a bare ``--exclude`` whose next
    token was the following flag.
    """
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False, exclude=["", "*.txt"]),
        test_plugin_context,
        cache_env,
        monkeypatch,
    )
    target = tmp_path / "src"
    target.mkdir()

    argv = _command(scanner, target)

    for value in _values_after(argv, "--exclude"):
        assert value in SEMGREP_DEFAULT_IGNORES or value.startswith("/"), argv
    assert "--exclude=*.txt" in argv, argv
    assert target.as_posix() in argv, argv
    assert argv[argv.index(target.as_posix()) - 1] != "--exclude", argv


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_an_operator_value_cannot_name_the_scanned_paths_file(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """Only the ``--json-output=`` token ASH inserts is in the command, so
    ``_read_paths_output`` reads the counts from ASH's own file.

    Fails at the base: the operator's value was a separate token starting with
    the same prefix, and the last such token won.
    """
    elsewhere = (tmp_path / "elsewhere.json").as_posix()
    scanner = _online_scanner(
        scanner_cls,
        config_cls,
        options_cls(offline=False, exclude=[f"{_PATHS_OUTPUT_FLAG}={elsewhere}"]),
        test_plugin_context,
        cache_env,
        monkeypatch,
    )
    target = tmp_path / "src"
    target.mkdir()

    argv = _command(scanner, target)

    named = [word for word in argv if word.startswith(f"{_PATHS_OUTPUT_FLAG}=")]
    assert len(named) == 1, argv
    assert elsewhere not in named[0], argv
    assert f"--exclude={_PATHS_OUTPUT_FLAG}={elsewhere}" in argv, argv
