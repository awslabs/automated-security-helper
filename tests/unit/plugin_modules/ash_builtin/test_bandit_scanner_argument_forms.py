# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What bandit's argv can carry, and what the operator is told when it cannot.

Each test here pins one way an exclusion or an option was lost without a word,
or carried a value the command line cannot hold:

* A NUL in an ``excluded_paths`` or ignore path entry reached argv, and exec
  refuses a command line holding one, so the scan failed instead of excluding
  one path. Such an entry now gets no bandit form, with a warning.
* The ``--exclude`` bound was Linux's per-argument limit on every platform;
  Windows bounds the whole command line at 32,767 characters, so many entries
  made bandit fail to start there instead of dropping the best-effort globs.
* A comma in the scanned target's own path made every anchored entry vanish
  with no warning, and bandit ran with an empty ``--exclude``.
* A literal made only of ``/!^-]`` was passed as itself, a plain substring of
  any path that continues it, so bandit skipped files the entry did not name.
* An absolute ``excluded_paths`` entry was read relative to the target and
  excluded nothing, silently.
* An entry a walked path holds as text was left out with a VERBOSE line only,
  though an ``excluded_paths`` entry left out is applied nowhere after the scan.
* ``tool_version: null`` removed the version constraint entirely; semgrep's
  null falls back to its default range.
* A verified bandit on PATH ran while the reports named the version uv's
  environment probe had read, not the copy that ran.
* ``configure()`` swapped the configuration and left the old option arguments
  in argv, so a new ``confidence_level`` was never applied.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import bandit_scanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    _EXCLUDE_ARGUMENT_LIMIT,
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
    _exclude_fits,
    _not_a_plain_substring,
    _spelled_absolute,
    bandit_exclude_globs,
    bandit_excluded_path_globs,
)
from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.pre_installed_tool import PreInstalledToolVerdict

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.usefixtures("no_tool_probes"),
    pytest.mark.skipif(
        sys.platform == "win32", reason="bandit exclude entries are POSIX paths here"
    ),
]


def _ignore(*paths: str) -> list[IgnorePathWithReason]:
    return [IgnorePathWithReason(path=path, reason="ignored") for path in paths]


def _tree(base: Path, files: list[str], name: str = "source") -> Path:
    source = base / name
    for rel in files:
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text("x = 1\n", encoding="utf-8")
    source.mkdir(exist_ok=True)
    return source


def _scanner(source: Path, base: Path, options=None) -> BanditScanner:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return BanditScanner(
        context=context,
        config=BanditScannerConfig(options=options or BanditScannerConfigOptions()),
    )


def _entries(argv: list[str]) -> list[str]:
    tokens = [arg for arg in argv if arg.startswith("--exclude=")]
    assert len(tokens) == 1, argv
    return tokens[0][len("--exclude=") :].split(",")


def _warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]


# ---------------------------------------------------------------------------
# A NUL never reaches the --exclude argument
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ["ven\0dor", "a\0", "src/\0.py"])
def test_an_excluded_paths_entry_with_a_nul_has_no_bandit_form(entry):
    """At the base the entry's globs carried the NUL into the argument, and exec
    refuses a command line that holds one."""
    assert bandit_excluded_path_globs("/scan", entry) == []


@pytest.mark.parametrize("pattern", ["ven\0dor/**", "src/*.p\0y", "app\0.py"])
def test_a_global_ignore_path_with_a_nul_is_not_passed(pattern):
    assert bandit_exclude_globs("/scan", pattern) == []


def test_a_nul_entry_leaves_the_other_exclusions_in_place(tmp_path, caplog):
    """The excluded_paths entry's own warning: no ignore path is passed, so the
    ignore-path NUL warning (the next test's) cannot stand in for it."""
    source = _tree(tmp_path, ["app.py"])
    with caplog.at_level(logging.WARNING):
        scanner = _scanner(
            source,
            tmp_path,
            BanditScannerConfigOptions(excluded_paths=_ignore("ven\0dor", "vendor")),
        )
        argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    assert not any("\0" in entry for entry in entries), entries
    # The other entry's globs are all there; a builder that returned none for
    # it would have made the loop below check nothing.
    expected = bandit_excluded_path_globs(source.as_posix(), "vendor")
    assert expected
    assert set(expected) <= set(entries), (expected, entries)
    nul_lines = [
        message
        for message in _warnings(caplog)
        if "NUL" in message and "excluded_paths" in message
    ]
    assert nul_lines, _warnings(caplog)
    # No warning carries the entry's NUL raw; the entry is written as its repr.
    assert not any("\0" in message for message in _warnings(caplog)), _warnings(caplog)
    assert any("\\x00" in message for message in nul_lines), nul_lines


def test_a_global_ignore_path_with_a_nul_is_warned_about(tmp_path, caplog):
    """The entry was dropped silently by the builder; the scan now says so, and
    the other ignore paths still reach bandit."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(
            source, "source", _ignore("gen\0erated/**", "vendor/**")
        )

    entries = _entries(argv)
    assert not any("\0" in entry for entry in entries), entries
    assert f"{source.as_posix()}/vendor/*" in entries
    nul_lines = [
        message
        for message in _warnings(caplog)
        if "ignore path" in message and "NUL" in message
    ]
    assert nul_lines, _warnings(caplog)
    # The entry is written as its repr: the NUL is visible as an escape and
    # a line break in an entry cannot start a log line of its own.
    assert all("\0" not in message and "\\x00" in message for message in nul_lines), (
        nul_lines
    )


def test_an_ini_exclude_entry_with_a_nul_is_dropped_and_counted(tmp_path, caplog):
    """The operator's .bandit exclude entries are split on commas and anchored
    below the scanned target; one holding a NUL is left out, counted in the
    warning, and the entry beside it stays."""
    source = _tree(tmp_path, ["app.py"])
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = ven\0dor,vendor\n", encoding="utf-8")
    scanner = _scanner(source, tmp_path)
    scanner._ini_file = ini

    with caplog.at_level(logging.WARNING):
        entries = scanner._ini_excludes(source)

    assert not any("\0" in entry for entry in entries), entries
    assert entries == bandit_excluded_path_globs(source.as_posix(), "vendor")
    assert any(
        "1 exclude entries" in message and "NUL" in message
        for message in _warnings(caplog)
    ), _warnings(caplog)


# ---------------------------------------------------------------------------
# The --exclude bound follows the platform's command-line limit
# ---------------------------------------------------------------------------


def test_the_windows_bound_is_the_whole_command_line():
    """Windows limits the WHOLE command line to 32,767 characters, so the budget
    for --exclude is what the other arguments leave: a fixed 24 KiB bound
    refused required entries of 24 to 31 KiB that fit the real line."""
    rest = ["bandit", "--recursive", "--format", "sarif", "C:/src"]
    assert _exclude_fits("--exclude=" + "x" * 30000, rest, "nt")
    assert not _exclude_fits("--exclude=" + "x" * 32760, rest, "nt")
    long_rest = ["x" * 2000]
    assert not _exclude_fits("--exclude=" + "x" * 30000, long_rest, "nt")
    # The 32,767 of CreateProcess counts the terminating NUL, so under the
    # margin a line of 32,766 characters less the margin is the longest that
    # fits and one character more is not.
    assert _exclude_fits("x" * (32766 - 2048), [], "nt")
    assert not _exclude_fits("x" * (32767 - 2048), [], "nt")


def test_the_windows_bound_keeps_a_margin_for_the_uv_wrapper():
    """The measured command starts with bare ``bandit``; the scan runs it through
    ``uv tool run --from ...``, a prefix of a hundred characters or more that the
    measured line does not hold. A line filled to within a few characters of
    32,767 went over it in CreateProcess once the prefix was added, so the
    bound keeps a margin: a token that fits the bare limit does not fit."""
    rest = ["bandit", "--recursive", "--format", "sarif", "C:/src"]
    bare_limit_fits = "--exclude=" + "x" * 30700
    assert len(subprocess.list2cmdline([*rest, bare_limit_fits])) < 32767
    assert not _exclude_fits(bare_limit_fits, rest, "nt")
    assert _exclude_fits("--exclude=" + "x" * (30700 - 2048), rest, "nt")


def test_the_windows_bound_counts_utf16_units():
    """Windows counts the command line in UTF-16 units; a character outside the
    Basic Multilingual Plane is two of them and one code point, so a line
    measured by ``len`` passed the bound and still exceeded it."""
    rest = ["bandit", "C:/src"]
    plane_two = "\U0001f600"
    token = "--exclude=" + plane_two * 15340
    line = subprocess.list2cmdline([*rest, token])
    assert len(line) < 32767 - 2048
    assert len(line.encode("utf-16-le")) // 2 > 32767 - 2048
    assert not _exclude_fits(token, rest, "nt")
    assert _exclude_fits("--exclude=" + "x" * 15340, rest, "nt")


def test_elsewhere_one_argument_is_bounded_on_its_own():
    """Linux refuses one argument of 128 KiB or more (MAX_ARG_STRLEN counts the
    terminating NUL), so the 120 KiB limit sits well under it and a token of
    exactly the limit still fits; the length is in UTF-8 bytes, as exec passes
    an argument, so a two-byte character counts twice."""
    long_rest = ["x" * 200_000]
    assert _EXCLUDE_ARGUMENT_LIMIT < 128 * 1024 - 1
    assert _exclude_fits(
        "--exclude=" + "x" * (_EXCLUDE_ARGUMENT_LIMIT - 10), long_rest, "posix"
    )
    assert not _exclude_fits(
        "--exclude=" + "x" * _EXCLUDE_ARGUMENT_LIMIT, long_rest, "posix"
    )
    two_bytes_each = "--exclude=" + "\u00e9" * (_EXCLUDE_ARGUMENT_LIMIT // 2)
    assert len(two_bytes_each) < _EXCLUDE_ARGUMENT_LIMIT
    assert not _exclude_fits(two_bytes_each, long_rest, "posix")
    assert _exclude_fits("--exclude=vendor", [], os.name)


def test_the_required_entries_are_judged_on_the_resolved_command(tmp_path, monkeypatch):
    """The bound is measured beside the other arguments of the resolved
    command, and the token the scan passes is the one that was judged: the
    bound is recorded as the scan consults it, since any small argv would
    satisfy a second measurement taken afterwards."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    judged: list[tuple[str, list[str]]] = []
    real = bandit_scanner._exclude_fits

    def recorder(token, rest, platform=os.name):
        judged.append((token, [str(argument) for argument in rest]))
        return real(token, rest, platform)

    monkeypatch.setattr(bandit_scanner, "_exclude_fits", recorder)

    argv, _, _ = scanner._execute_scan(source, "source", _ignore("vendor/**"))

    tokens = [arg for arg in argv if arg.startswith("--exclude=")]
    assert len(tokens) == 1
    rest = [arg for arg in argv if not arg.startswith("--exclude=")]
    assert judged, "the bound was never consulted"
    # The last candidate judged is the token the scan passes, beside the
    # resolved command's other arguments.
    assert judged[-1] == (tokens[0], rest)
    assert f"{source.as_posix()}/vendor/*" in _entries(argv)


# ---------------------------------------------------------------------------
# A comma in the target's own path is said, not swallowed
# ---------------------------------------------------------------------------


def test_a_comma_in_the_targets_path_is_warned_about(tmp_path, caplog):
    """Every entry is anchored at the target and bandit splits --exclude on
    commas, so nothing anchored at such a target can be passed; at the base
    the scan ran with an empty --exclude and said nothing."""
    source = _tree(tmp_path, ["app.py"], name="a,b")
    scanner = _scanner(source, tmp_path)
    with caplog.at_level(logging.WARNING):
        scanner._execute_scan(source, "source", _ignore("vendor/**"))

    assert any("comma" in message for message in _warnings(caplog)), _warnings(caplog)


# ---------------------------------------------------------------------------
# A literal of only "/!^-]" has no safe glob form
# ---------------------------------------------------------------------------


def test_a_literal_of_only_special_characters_has_no_form():
    assert _not_a_plain_substring("app.py") == "app.p[y]"
    assert _not_a_plain_substring("-") is None
    assert _not_a_plain_substring("]]") is None


def test_such_a_literal_is_not_passed_as_a_plain_substring():
    """``/scan/-`` is a plain substring of ``/scan/-x.py``; at the base it was
    passed as written and bandit skipped that file too."""
    assert bandit_exclude_globs("/scan", "-") == []
    entries = bandit_excluded_path_globs("/scan", "-")
    assert "/scan/-" not in entries
    assert "/scan/*/-" in entries
    assert "/scan/-/*" in entries

    def skipped(path: str) -> bool:
        """bandit 1.9.4's rule: an fnmatch glob, or a plain substring."""
        return any(fnmatch.fnmatch(path, e) or e in path for e in entries)

    # Applied as bandit applies them: the neighbor file stays, a nested "-" and
    # the files under a top-level "-" directory are skipped, and a top-level
    # FILE named "-" is left to bandit, since the only entry that would name it
    # is the plain substring that also took the neighbor.
    assert not skipped("/scan/-x.py")
    assert skipped("/scan/d/-")
    assert skipped("/scan/-/a.py")
    assert not skipped("/scan/-")


def test_a_link_named_only_with_special_characters_still_gets_an_entry(tmp_path):
    """A link's entry is ``<root>/<name>``, and the root always holds a
    bracketable character, so the glob form brackets one of the root's: the
    link is left out alone and the scan runs."""
    source = _tree(tmp_path, ["app.py"])
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    (source / "-").symlink_to(outside)
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", [])

    link = f"{source.as_posix()}/-"
    matching = [entry for entry in _entries(argv) if fnmatch.fnmatch(link, entry)]
    assert matching, _entries(argv)
    assert all("[" in entry for entry in matching), matching


# ---------------------------------------------------------------------------
# An absolute excluded_paths entry is said to name nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "absolute"),
    [
        ("/home/me/project/vendor", True),
        ("\\\\server\\share", True),
        ("C:\\project\\vendor", True),
        ("c:/project", True),
        ("vendor", False),
        ("./vendor", False),
        ("src/vendor", False),
    ],
)
def test_an_absolute_spelling_is_recognized(path, absolute):
    assert _spelled_absolute(path) is absolute


def test_an_absolute_excluded_paths_entry_is_warned_about(tmp_path, caplog):
    """The leading "/" was dropped and the rest read below the target, so the
    entry excluded nothing and the operator was told nothing."""
    source = _tree(tmp_path, ["app.py"])
    with caplog.at_level(logging.WARNING):
        _scanner(
            source,
            tmp_path,
            BanditScannerConfigOptions(excluded_paths=_ignore("/home/me/vendor")),
        )

    assert any("absolute path" in message for message in _warnings(caplog)), _warnings(
        caplog
    )


def test_a_relative_excluded_paths_entry_draws_no_such_warning(tmp_path, caplog):
    source = _tree(tmp_path, ["app.py"])
    with caplog.at_level(logging.WARNING):
        _scanner(
            source,
            tmp_path,
            BanditScannerConfigOptions(excluded_paths=_ignore("vendor")),
        )

    assert not any("absolute path" in message for message in _warnings(caplog))


# ---------------------------------------------------------------------------
# An entry left out because a path holds it as text is a warning
# ---------------------------------------------------------------------------


def test_a_best_effort_glob_a_path_holds_as_text_is_left_out_quietly(tmp_path, caplog):
    """A global ignore path's glob left out is covered by the SARIF step, so
    its drop is a VERBOSE line, not a warning; the whole-run promotion warned
    here too, with text that spoke of excluded_paths."""
    source = _tree(tmp_path, ["app.py", "docs/*.md/evil.py"])
    scanner = _scanner(source, tmp_path)
    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", _ignore("docs/*.md"))

    assert f"{source.as_posix()}/docs/*.md" not in _entries(argv)
    assert not any("Not passing" in message for message in _warnings(caplog)), (
        _warnings(caplog)
    )


def test_a_required_entry_a_path_holds_as_text_is_left_out_with_a_warning(
    tmp_path, caplog
):
    """An excluded_paths entry left out is applied by nothing after the scan,
    so its drop is a WARNING that says the findings are reported."""
    source = _tree(tmp_path, ["app.py", "docs/*.md/evil.py"])
    scanner = _scanner(
        source,
        tmp_path,
        BanditScannerConfigOptions(excluded_paths=_ignore("docs/*.md")),
    )
    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    assert f"{source.as_posix()}/docs/*.md" not in _entries(argv)
    dropped = [message for message in _warnings(caplog) if "Not passing" in message]
    assert len(dropped) == 1, _warnings(caplog)
    assert "findings are reported" in dropped[0]


def test_a_dropped_entry_from_an_environment_value_is_redacted(
    tmp_path, monkeypatch, caplog
):
    """The drop warning names the globs built from configured excluded_paths,
    which can be read from the environment; it is redacted like the scanner's
    other lines, including the bracketed top-level form of the value."""
    source = _tree(tmp_path, ["app.py", "secretvendor/*.md/evil.py"])
    monkeypatch.setattr(
        BanditScanner, "_environment_values", lambda self: ("secretvendor",)
    )
    scanner = _scanner(
        source,
        tmp_path,
        BanditScannerConfigOptions(excluded_paths=_ignore("secretvendor/*.md")),
    )
    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    assert f"{source.as_posix()}/secretvendor/*.md" not in _entries(argv)
    dropped = [message for message in _warnings(caplog) if "Not passing" in message]
    assert dropped, _warnings(caplog)
    # The bracketed top-level form puts "[" and "]" around one character of
    # the value (secretvendo[r]), so the plain text is checked with any
    # single-character bracket removed as well.
    unbracketed = [re.sub(r"\[(.)\]", r"\1", message) for message in dropped]
    assert not any("secretvendor" in message for message in dropped), dropped
    assert not any("secretvendor" in message for message in unbracketed), unbracketed


# ---------------------------------------------------------------------------
# tool_version: null keeps the default constraint
# ---------------------------------------------------------------------------


def test_a_null_tool_version_uses_the_default_constraint(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path, BanditScannerConfigOptions(tool_version=None))

    default = BanditScannerConfigOptions.model_fields["tool_version"].default
    assert default is not None
    assert scanner._get_tool_version_constraint() == default


def test_a_configured_tool_version_is_used_as_written(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(tool_version=">=1.7.8,<1.8.0")
    )

    assert scanner._get_tool_version_constraint() == ">=1.7.8,<1.8.0"


# ---------------------------------------------------------------------------
# The copy that runs is the version the reports name
# ---------------------------------------------------------------------------


def _verifier(status: str, executable: str, detail: str, version: str | None):
    """A stand-in for ``verify_pre_installed_tool`` that records each call and
    answers the real verdict type, so a test proves the scanner asked it."""
    calls: list[tuple[tuple, dict]] = []

    def verify(*args, **kwargs):
        calls.append((args, kwargs))
        return PreInstalledToolVerdict(
            status=status,
            executable=executable,
            requirement="bandit[sarif,toml]",
            detail=detail,
            version=version,
        )

    verify.calls = calls
    return verify


def test_a_verified_path_binary_reports_its_own_version(tmp_path, monkeypatch):
    """The deferred probe read the version of uv's environment; the binary on
    PATH that runs instead has its own, which is what the SARIF names."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    binary = str(tmp_path / "bandit")
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: [binary]
    )
    verify = _verifier("satisfied", binary, "1.8.0 with the extras", "1.8.0")
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)

    assert scanner.validate_plugin_dependencies() is True
    assert [call[0][0] for call in verify.calls] == [binary]
    assert scanner.use_uv_tool is False
    assert scanner.tool_version == "1.8.0"


def test_a_path_binary_with_no_version_answer_keeps_the_probes(tmp_path, monkeypatch):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    binary = str(tmp_path / "bandit")
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: [binary]
    )
    verify = _verifier("unverifiable", binary, "no probe", None)
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)
    scanner.resolve_deferred_tool_version()
    before = scanner.tool_version
    assert before is not None

    assert scanner.validate_plugin_dependencies() is True
    assert [call[0][0] for call in verify.calls] == [binary]
    assert scanner.tool_version == before


# ---------------------------------------------------------------------------
# configure() applies the new options, once
# ---------------------------------------------------------------------------


def _option_values(argv: list[str], key: str) -> list[str]:
    return [argv[index + 1] for index, token in enumerate(argv) if token == key]


def test_configure_applies_the_new_options_once(tmp_path):
    """At the base configure() swapped self.config and left the argv built at
    construction, so the first confidence level stayed."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    argv, _, _ = scanner._execute_scan(source, "source", [])
    assert _option_values(argv, "--confidence-level") == ["all"]

    scanner.configure(
        BanditScannerConfig(options=BanditScannerConfigOptions(confidence_level="high"))
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert _option_values(argv, "--confidence-level") == ["high"]
    assert argv.count("--recursive") == 1
    assert len([arg for arg in argv if arg.startswith("--exclude=")]) == 1


def test_configure_with_ignore_nosec_adds_the_flag_once(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    argv, _, _ = scanner._execute_scan(source, "source", [])
    assert "--ignore-nosec" not in argv

    scanner.configure(
        BanditScannerConfig(options=BanditScannerConfigOptions(ignore_nosec=True))
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert argv.count("--ignore-nosec") == 1


# ---------------------------------------------------------------------------
# A configuration handed to scan() is applied before the scan, once
# ---------------------------------------------------------------------------


def test_a_config_handed_to_the_scan_is_applied_before_it(tmp_path, monkeypatch):
    """The executor passes each target's configuration to scan(); the base
    pre-scan swapped self.config without rebuilding argv, so the construction
    confidence level stayed and --ignore-nosec never appeared."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    monkeypatch.setattr(
        BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    handed = BanditScannerConfig(
        options=BanditScannerConfigOptions(confidence_level="high", ignore_nosec=True)
    )

    assert scanner._pre_scan(source, "source", config=handed) is True
    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert _option_values(argv, "--confidence-level") == ["high"]
    assert argv.count("--ignore-nosec") == 1
    assert argv.count("--recursive") == 1
    assert len([arg for arg in argv if arg.startswith("--exclude=")]) == 1


def test_the_same_config_handed_again_changes_nothing(tmp_path, monkeypatch):
    """The executor hands the same configuration on every target; an equal one
    re-reads no option (no second config_file warning, no second probe)."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    monkeypatch.setattr(
        BanditScanner, "validate_plugin_dependencies", lambda self: True
    )
    applied: list[int] = []
    monkeypatch.setattr(BanditScanner, "_apply_config", lambda self: applied.append(1))

    same = BanditScannerConfig(options=BanditScannerConfigOptions())
    assert scanner._pre_scan(source, "source", config=same) is True
    assert scanner._pre_scan(source, "source", config=same.model_dump()) is True

    assert applied == []


def test_a_new_tool_version_rebuilds_the_install_command_and_probe(
    tmp_path, monkeypatch
):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    setups: list[int] = []
    monkeypatch.setattr(
        BanditScanner, "_setup_uv_tool_install_commands", lambda self: setups.append(1)
    )

    scanner.configure(
        BanditScannerConfig(options=BanditScannerConfigOptions(confidence_level="low"))
    )
    assert setups == [], "the same tool_version builds no new install command"

    scanner.configure(
        BanditScannerConfig(
            options=BanditScannerConfigOptions(tool_version=">=1.7.8,<1.8.0")
        )
    )

    assert setups == [1]
    assert scanner._deferred_tool_version_probe == ("bandit", scanner._uv_from_spec())
    assert ">=1.7.8,<1.8.0" in (scanner._uv_from_spec() or "")
