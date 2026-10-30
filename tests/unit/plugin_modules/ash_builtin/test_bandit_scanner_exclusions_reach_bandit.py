# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""bandit's ``--exclude`` reaches bandit whole, and only what it names is skipped.

Each test here pins one way the exclusions, or the scan, used to fail:

* A line break in one ``excluded_paths`` entry, one global ignore path or the
  target's own path made the base class drop the WHOLE ``--exclude`` argument
  (its flag-key check refuses a key holding one, with a warning), so bandit ran
  with no exclusion at all, the links that leave the tree included. Such an entry
  now excludes nothing, with a warning, and such a target refuses the scan.
* A link leaving the tree was passed as its literal path, which bandit also reads
  as a plain substring: ``.venv/bin/python`` is a substring of
  ``.venv/bin/python3``, so every tree with a symlinked virtualenv was refused.
  The entry is now a glob that matches that one path (``pytho[n]``).
* ``additional_formats`` appended a second ``--format``; bandit's is
  single-valued, so it wrote that format into bandit.sarif and the scan failed.
* ASH's explicit ``--exclude`` replaced bandit's own default excludes (``.tox``,
  ``.eggs``, ``*.egg`` and the rest), which were then scanned.
* The ``--exclude`` length was measured with a strict ``str.encode``, which raised
  on a path holding a byte that is not UTF-8.
* The operator's ``.bandit`` ``exclude`` was ignored, because bandit reads it only
  while ``--exclude`` is still its default and ASH always passes one. Its entries
  are anchored at the target like ``excluded_paths`` entries: passed raw, bandit
  also read them as substrings of the directories above the scanned tree.
* A file bandit skipped (a syntax error) kept its metrics entry and was counted
  as scanned, so a target whose every file failed to parse passed with nothing.
* A bandit found on PATH with no uv was run with no check of its extras or
  version, and after a failed uv install a binary on PATH never ran at all.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import bandit_scanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BANDIT_DEFAULT_EXCLUDES,
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
    _spelled_path,
    bandit_exclude_globs,
    bandit_excluded_path_globs,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
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


# ---------------------------------------------------------------------------
# A line break never reaches the --exclude argument
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ["vendor\nx", "a\n"])
def test_an_excluded_paths_entry_with_a_line_break_has_no_bandit_form(entry):
    """At the base the entry's globs carried the line break into the argument."""
    assert bandit_excluded_path_globs("/scan", entry) == []


@pytest.mark.parametrize("pattern", ["vendor\n/**", "src/*.p\ny"])
def test_a_global_ignore_path_with_a_line_break_is_not_passed(pattern):
    assert bandit_exclude_globs("/scan", pattern) == []


def test_a_carriage_return_is_passed_as_written():
    """Only a line feed fails the base class's flag-key check (its ``.`` matches
    every other character), so an entry holding a carriage return reaches exec
    and bandit as written; refusing it said bandit "would run with no exclusion
    at all", which was not so."""
    entries = bandit_excluded_path_globs("/scan", "ven\rdor")
    assert entries, "a carriage return is not a line feed"
    assert all("\r" in entry and "\n" not in entry for entry in entries), entries
    assert bandit_exclude_globs("/scan", "app\r.py") != []


def test_an_anchor_with_a_line_break_gets_no_entries():
    assert bandit_excluded_path_globs("/sc\nan", "vendor") == []
    assert bandit_exclude_globs("/sc\nan", "vendor/**") == []


def test_a_line_break_entry_leaves_the_other_exclusions_in_place(tmp_path, caplog):
    """The argument keeps every other entry; the base class never sees a key it
    would drop, and the operator is told, once per input, that the entry
    excludes nothing: the excluded_paths entry is reported when the scanner is
    built, the global ignore path when the scan's arguments are assembled."""
    source = _tree(tmp_path, ["app.py"])
    with caplog.at_level(logging.WARNING):
        scanner = _scanner(
            source,
            tmp_path,
            BanditScannerConfigOptions(excluded_paths=_ignore("ven\ndor")),
        )
        argv, _, _ = scanner._execute_scan(source, "source", _ignore("gen\nerated/**"))

    entries = _entries(argv)
    assert entries, argv
    assert not any("\n" in entry or "\r" in entry for entry in entries), entries
    for entry in bandit_excluded_path_globs(source.as_posix(), ".venv/"):
        assert entry in entries
    told = [
        record.message for record in caplog.records if "line break" in record.message
    ]
    # Once per input: a warning repeated on every reprocess or scan would
    # still satisfy an any().
    assert sum(repr("ven\ndor") in message for message in told) == 1, told
    assert sum(repr("gen\nerated/**") in message for message in told) == 1, told


def test_a_target_whose_path_holds_a_line_break_refuses_the_scan(tmp_path):
    """Every entry is anchored at the target, so each would carry its line break
    and the base class would drop the whole argument: bandit is not run."""
    source = _tree(tmp_path, ["app.py"], name="sou\nrce")
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError, match="line break"):
        scanner._execute_scan(source, "source", [])


# ---------------------------------------------------------------------------
# Links leaving the tree: one entry, one file
# ---------------------------------------------------------------------------


def test_a_symlinked_virtualenv_does_not_refuse_the_scan(tmp_path):
    """``.venv/bin/python`` and ``.venv/bin/python3`` both leave the tree; the
    first's path is a substring of the second's, which refused the whole scan."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "python3.12").write_text("", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    bin_dir = source / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    os.symlink(outside / "python3.12", bin_dir / "python")
    os.symlink(outside / "python3.12", bin_dir / "python3")
    scanner = _scanner(source, tmp_path)

    entries = scanner._link_excludes(source)

    root = source.as_posix()
    python = f"{root}/.venv/bin/python"
    python3 = f"{root}/.venv/bin/python3"
    assert len(entries) == 2, entries
    for path in (python, python3):
        own = [entry for entry in entries if fnmatch.fnmatchcase(path, entry)]
        assert len(own) == 1, (path, entries)
        other = python3 if path == python else python
        assert not fnmatch.fnmatchcase(other, own[0]), (own[0], other)
        # bandit also reads an entry as a plain substring of a walked path.
        assert own[0] not in other
        assert own[0] not in python
        assert own[0] not in python3

    # The whole scan is assembled too: a check later in it (the argument bound,
    # the flag-key check, the text check over every entry) could still refuse
    # this tree, and the two link globs have to reach the argument.
    argv, _, _ = scanner._execute_scan(source, "source", [])
    passed = _entries(argv)
    for entry in entries:
        assert entry in passed, (entry, passed)


def test_a_link_entry_with_glob_characters_is_escaped(tmp_path):
    """A link named with ``*`` used to be refused outright; its entry is now the
    escaped glob, which bandit matches as the literal name."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.py").write_text("x = 1\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    os.symlink(outside / "target.py", source / "li*nk.py")
    scanner = _scanner(source, tmp_path)

    entries = scanner._link_excludes(source)

    link = f"{source.as_posix()}/li*nk.py"
    assert len(entries) == 1
    assert fnmatch.fnmatchcase(link, entries[0])
    assert not fnmatch.fnmatchcase(f"{source.as_posix()}/lixnk.py", entries[0])


def test_a_directory_named_like_a_links_entry_refuses_the_scan(tmp_path):
    """bandit rewrites an ``--exclude`` entry that names an existing directory to
    ``<entry>/*``. The link ``link.py`` gets the entry ``link.p[y]``; an empty
    directory literally named ``link.p[y]`` beside it made bandit cover that
    directory instead of the link, and read the file the link points at."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.py").write_text("x = 1\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    os.symlink(outside / "target.py", source / "link.py")
    (source / "link.p[y]").mkdir()
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError, match="named like its --exclude entry"):
        scanner._link_excludes(source)


def test_a_link_whose_path_holds_a_comma_is_still_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.py").write_text("x = 1\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    os.symlink(outside / "target.py", source / "a,b.py")
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError, match="cannot leave out that file alone"):
        scanner._link_excludes(source)


def test_a_link_name_with_a_non_utf8_byte_does_not_fail_the_scan(tmp_path):
    """The argument's length is measured as exec passes the bytes; a strict
    encode raised UnicodeEncodeError on the surrogate such a name decodes to."""
    name = os.fsdecode(b"li\xffnk.py")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.py").write_text("x = 1\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    # The codec round-trips any byte under surrogateescape, so only the file
    # system can say whether it keeps such a name: APFS refuses it (EILSEQ).
    try:
        os.symlink(outside / "target.py", source / name)
    except OSError:
        pytest.skip("the file system refuses a name that is not valid UTF-8")
    if b"li\xffnk.py" not in os.listdir(os.fsencode(source)):
        pytest.skip("the file system did not keep the non-UTF-8 name as written")
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", [])

    link = f"{source.as_posix()}/{name}"
    assert any(fnmatch.fnmatchcase(link, entry) for entry in _entries(argv)), argv


# ---------------------------------------------------------------------------
# What else the argument carries
# ---------------------------------------------------------------------------


def test_bandits_own_default_excludes_are_passed(tmp_path):
    """bandit replaces its defaults with any --exclude it is given. Checked as
    bandit applies the entries (an fnmatch glob or a plain substring) against
    files under the defaults' names, not against the builder's own output,
    which a builder returning nothing for ``*.egg`` would have satisfied."""
    source = _tree(tmp_path, ["app.py", ".tox/x.py", "pkg.egg"])
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    assert ".tox" in BANDIT_DEFAULT_EXCLUDES and "*.egg" in BANDIT_DEFAULT_EXCLUDES

    def skipped(relative: str) -> bool:
        path = f"{source.as_posix()}/{relative}"
        return any(fnmatch.fnmatchcase(path, e) or e in path for e in entries)

    for item in BANDIT_DEFAULT_EXCLUDES:
        globs = bandit_excluded_path_globs(source.as_posix(), item)
        assert globs, item
        for entry in globs:
            assert entry in entries, (item, entry)
    assert skipped(".tox/x.py")
    assert skipped("pkg.egg")
    assert not skipped("app.py")


def test_the_operators_bandit_ini_exclude_reaches_bandit(tmp_path):
    """bandit reads the ini's ``exclude`` only while ``--exclude`` is its default,
    and ASH always passes one, so the setting was silently ignored."""
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = tests,legacy/\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )
    assert any(arg.key == "--ini" for arg in scanner.args.extra_args), (
        "the configured .bandit must be passed with --ini for this test to mean "
        "anything"
    )

    argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    # Anchored at the target as an excluded_paths entry is: never the raw text,
    # which bandit would also read as a substring of the directories ABOVE the
    # target (a scan under /home/ci/tests-lab would have skipped every file).
    assert "tests" not in entries and "legacy/" not in entries, entries
    for item in ("tests", "legacy/"):
        for entry in bandit_excluded_path_globs(source.as_posix(), item):
            assert entry in entries, (item, entry)
    assert all(entry.startswith(source.as_posix()) for entry in entries), entries


def test_an_ini_entry_naming_the_targets_own_path_skips_only_below_it(tmp_path, caplog):
    """``exclude = tests`` with the tree itself under a directory named ``tests``:
    bandit alone would skip every file; anchored, the entry skips a ``tests``
    directory below the target, and the operator is told."""
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = tests\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py", "tests/test_app.py"], name="tests")
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )

    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    app = f"{source.as_posix()}/app.py"
    below = f"{source.as_posix()}/tests/test_app.py"
    assert not any(fnmatch.fnmatchcase(app, e) or e in app for e in entries), entries
    assert any(fnmatch.fnmatchcase(below, e) or e in below for e in entries), entries
    assert any(
        "scanned target's own path" in record.getMessage() for record in caplog.records
    )


def test_an_ini_entry_holding_a_line_break_is_left_out_with_a_warning(tmp_path, caplog):
    """A multi-line ini value keeps its line break inside the second entry
    (bandit splits on commas only); such an entry has no --exclude form."""
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = tests,\n  legacy\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py", "legacy/old.py"])
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )

    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    old = f"{source.as_posix()}/legacy/old.py"
    assert not any(fnmatch.fnmatchcase(old, e) or e in old for e in entries), entries
    assert not any("\n" in e for e in entries)
    assert any(
        "has no --exclude form" in record.getMessage() for record in caplog.records
    )


def _covers(entries: list[str], path: str) -> bool:
    """Whether bandit would skip ``path`` for ``entries``: an fnmatch glob or a
    plain substring, its two readings of an --exclude entry."""
    return any(fnmatch.fnmatchcase(path, e) or e in path for e in entries)


def test_a_plain_name_ini_entry_is_the_exact_name_with_a_warning(tmp_path, caplog):
    """``exclude = test``: bandit alone read it as a substring of every walked
    path, so ``tests/`` and ``test_x.py`` were skipped too. Anchored, it names
    the ``test`` directory or file at any depth and nothing that merely
    contains the word, and the operator is told what the entry no longer
    covers, with the console markup off."""
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = test\n", encoding="utf-8")
    source = _tree(
        tmp_path, ["app.py", "test/old.py", "tests/test_app.py", "test_x.py"]
    )
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )

    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    root = source.as_posix()
    for entry in bandit_excluded_path_globs(root, "test"):
        assert entry in entries, (entry, entries)
    assert _covers(entries, f"{root}/test/old.py"), entries
    assert not _covers(entries, f"{root}/tests/test_app.py"), entries
    assert not _covers(entries, f"{root}/test_x.py"), entries
    told = [r for r in caplog.records if "is a plain name" in r.getMessage()]
    assert len(told) == 1, [r.getMessage() for r in caplog.records]
    assert repr("test") in told[0].getMessage()
    assert "test_x.py" in told[0].getMessage()
    assert told[0].markup is False


def test_an_absolute_ini_entry_is_read_below_the_target_with_a_warning(
    tmp_path, caplog
):
    """``exclude = /legacy`` is read as ``legacy`` below the target, as an
    ``excluded_paths`` entry spelled that way is, and the operator is told."""
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = /legacy\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py", "legacy/old.py"])
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )

    with caplog.at_level(logging.WARNING):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    root = source.as_posix()
    assert _covers(entries, f"{root}/legacy/old.py"), entries
    assert not _covers(entries, f"{root}/app.py"), entries
    assert not any(e.startswith("/legacy") for e in entries), entries
    told = [
        r for r in caplog.records if "written as an absolute path" in r.getMessage()
    ]
    assert len(told) == 1, [r.getMessage() for r in caplog.records]
    assert repr("/legacy") in told[0].getMessage()
    assert repr("legacy") in told[0].getMessage()
    assert told[0].markup is False


def test_an_ini_warning_is_given_once_per_build_not_once_per_target(tmp_path, caplog):
    """``_ini_excludes`` runs for every scanned target (the source and the
    converted one); its warnings describe the operator's file, so a second
    target repeats none of them."""
    ini = tmp_path / ".bandit"
    # Three entries, three warnings: a plain name, an absolute path and one with
    # surrounding whitespace (a glob, so it is not also a plain name).
    ini.write_text("[bandit]\nexclude = test,/legacy, vend*r\n", encoding="utf-8")
    source = _tree(tmp_path, ["app.py"])
    converted = _tree(tmp_path, ["gen.py"], name="converted")
    scanner = _scanner(
        source, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )

    with caplog.at_level(logging.WARNING):
        scanner._execute_scan(source, "source", [])
        scanner._execute_scan(converted, "converted", [])

    messages = [r.getMessage() for r in caplog.records]
    assert sum("is a plain name" in m for m in messages) == 1, messages
    assert sum("written as an absolute path" in m for m in messages) == 1, messages
    assert sum("surrounding whitespace" in m for m in messages) == 1, messages
    assert all(
        r.markup is False
        for r in caplog.records
        if ".bandit exclude entry" in r.getMessage()
    )


def test_a_target_whose_path_holds_a_comma_gets_no_ini_entries(tmp_path, caplog):
    """No entry anchored at such a target can be passed (bandit splits the
    argument on commas), which the scan says once for the target; the entries
    are not blamed one by one."""
    ini = tmp_path / ".bandit"
    ini.write_text("[bandit]\nexclude = tests,legacy/\n", encoding="utf-8")
    plain = _tree(tmp_path, ["app.py"])
    comma = _tree(tmp_path, ["app.py"], name="src,lab")
    scanner = _scanner(
        plain, tmp_path, BanditScannerConfigOptions(config_file=str(ini))
    )

    with caplog.at_level(logging.WARNING):
        assert scanner._ini_excludes(comma) == []
    assert not caplog.records, [r.getMessage() for r in caplog.records]
    # The same file does yield entries under a target it can anchor at.
    assert scanner._ini_excludes(plain), "the control target must get entries"


def test_no_ini_adds_no_raw_entries(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert all(entry.startswith(source.as_posix()) for entry in _entries(argv))


def test_additional_formats_leave_one_sarif_format_in_argv(tmp_path, caplog):
    """bandit's --format is single-valued (argparse store): a second one after
    the base class's ``--format sarif`` won, bandit wrote that format into
    bandit.sarif, and the SARIF read failed the scan. The option is logged as
    not produced and adds nothing to argv."""
    source = _tree(tmp_path, ["app.py"])
    with caplog.at_level(logging.WARNING):
        scanner = _scanner(
            source,
            tmp_path,
            BanditScannerConfigOptions(additional_formats=["json", "html"]),
        )

    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert argv.count("--format") == 1
    assert argv[argv.index("--format") + 1] == "sarif"
    assert "html" not in argv
    assert "json" not in argv
    assert any(
        "additional_formats" in record.message and "not produced" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]


# ---------------------------------------------------------------------------
# Files bandit skipped are not scanned files
# ---------------------------------------------------------------------------


def _report(root: Path, scanned: list[str], skipped: list[str]) -> SarifReport:
    metrics = {"_totals": {"loc": 0}}
    for rel in scanned + skipped:
        metrics[f"{root.as_posix()}/{rel}"] = {"loc": 0}
    notifications = [
        {
            "message": {"text": "syntax error while parsing AST from file"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": (root / rel).as_uri()}
                    }
                }
            ],
        }
        for rel in skipped
    ]
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Bandit"}},
                    "results": [],
                    "properties": {"metrics": metrics},
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolConfigurationNotifications": notifications,
                        }
                    ],
                }
            ],
        }
    )


def test_a_file_bandit_could_not_parse_is_not_counted_as_scanned(tmp_path):
    source = _tree(tmp_path, ["a.py", "b.py"])
    scanner = _scanner(source, tmp_path)

    scanner._record_scanned_files(_report(source, ["b.py"], ["a.py"]), [], source)

    assert scanner.targets_attempted == 1


def test_a_target_whose_every_file_failed_to_parse_is_not_passed(tmp_path):
    """The error names the cause: the files bandit could not parse, with an
    example. It said only that they were "not excluded", which sent the
    operator looking for an exclusion problem."""
    source = _tree(tmp_path, ["a.py"])
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError, match="scanned no file") as raised:
        scanner._record_scanned_files(_report(source, [], ["a.py"]), [], source)

    assert "could not parse 1 of them" in str(raised.value)
    assert f"{source.as_posix()}/a.py" in str(raised.value)


def test_the_skipped_files_are_still_read_after_the_invocation_record(tmp_path):
    """The scan records ASH's own invocation before the skipped-file count runs,
    and that record replaced bandit's invocations, which is where bandit names
    the files it could not parse. Read in the scan's own order, every skipped
    file counted as scanned and an all-syntax-error target graded PASSED."""
    source = _tree(tmp_path, ["a.py"])
    scanner = _scanner(source, tmp_path)
    report = _report(source, [], ["a.py"])

    scanner._inject_invocation(report, ["bandit"], source)
    with pytest.raises(ScannerError, match="scanned no file"):
        scanner._post_process_sarif(report, ["bandit"], source)

    [invocation] = report.runs[0].invocations
    [note] = invocation.toolConfigurationNotifications
    # ``PhysicalLocation`` is a root model over its two shapes; the record is
    # under ``root``, as ``_skipped_file_paths`` reads it.
    uri = note.locations[0].physicalLocation.root.artifactLocation.uri
    assert uri.endswith("/a.py")


def test_a_parsed_file_is_still_counted_after_the_invocation_record(tmp_path):
    source = _tree(tmp_path, ["a.py", "b.py"])
    scanner = _scanner(source, tmp_path)
    report = _report(source, ["b.py"], ["a.py"])

    scanner._inject_invocation(report, ["bandit"], source)
    scanner._post_process_sarif(report, ["bandit"], source)

    assert scanner.targets_attempted == 1


@pytest.mark.parametrize(
    ("uri", "key", "windows"),
    [
        ("file:///C:/proj/x.py", "C:\\proj\\x.py", True),
        ("file://server/share/proj/x.py", "\\\\server\\share\\proj\\x.py", True),
        ("file:///home/u/proj/x.py", "/home/u/proj/x.py", False),
        ("file:///a:/proj/x.py", "/a:/proj/x.py", False),
        # ``to_uri`` percent-encodes the ``%`` of a file named ``x%41.py``.
        ("proj/x%2541.py", "proj/x%41.py", False),
    ],
    ids=["drive", "unc", "posix", "posix-colon-dir", "relative-encoded"],
)
def test_a_skipped_files_uri_spells_the_same_path_as_its_metrics_key(uri, key, windows):
    """bandit spells a skipped file as ``to_uri(fname)`` and its metrics key as
    ``fname`` walked; on Windows the URI of an absolute path starts
    ``file:///C:/`` and a UNC path's ``file://server/``, which dropping the
    prefix alone left as ``/C:/...`` and ``server/...`` against keys spelled
    ``C:/...`` and ``//server/...``. On POSIX a root directory named ``a:``
    is spelled ``file:///a:/``, and reading it as a drive dropped the slash
    the key keeps."""
    assert _spelled_path(uri, uri=True, windows=windows) == _spelled_path(
        key, uri=False, windows=windows
    )


@pytest.mark.parametrize(
    "platform, expected",
    [("nt", "C:/x.py"), ("posix", "/C:/x.py")],
    ids=["windows", "posix"],
)
def test_the_platform_reading_of_a_skipped_files_uri_defaults_to_the_host(
    monkeypatch, platform, expected
):
    """Without ``windows`` the spelling reads the running platform, so the
    scanner's own calls need no argument: the drive reading on Windows, the
    POSIX one elsewhere. Both platforms are read here, on any host, so the
    default is pinned to the platform and not to whichever host runs the test."""
    monkeypatch.setattr(os, "name", platform)
    assert _spelled_path("file:///C:/x.py", uri=True) == expected


def test_a_skipped_file_with_a_percent_in_its_name_is_told_from_its_decoded_twin(
    tmp_path,
):
    """Only the notification URI is percent-encoded. Decoding the metrics key
    too read ``x%41.py`` as ``xA.py``: the skipped file was counted as scanned
    and collided with a real ``xA.py``."""
    source = _tree(tmp_path, ["xA.py", "x%41.py"])
    scanner = _scanner(source, tmp_path)

    scanner._record_scanned_files(_report(source, ["xA.py"], ["x%41.py"]), [], source)

    assert scanner.targets_attempted == 1


def test_a_parsed_file_is_still_counted(tmp_path):
    source = _tree(tmp_path, ["a.py"])
    scanner = _scanner(source, tmp_path)

    scanner._record_scanned_files(_report(source, ["a.py"], []), [], source)

    assert scanner.targets_attempted == 1


def test_an_operator_config_whose_exclude_dirs_cover_the_tree_is_skipped(tmp_path):
    """bandit applies the config file's exclude_dirs like --exclude entries, so a
    tree it legitimately leaves out is SKIPPED (0 scanned), not an error."""
    source = _tree(tmp_path, ["legacy/a.py"])
    config = tmp_path / "bandit.yaml"
    config.write_text("exclude_dirs:\n  - legacy\n", encoding="utf-8")
    scanner = _scanner(source, tmp_path)

    scanner._record_scanned_files(
        _report(source, [], []), ["bandit", "--configfile", str(config)], source
    )

    assert scanner.targets_attempted == 0


def test_an_exclude_dirs_entry_inside_the_targets_own_path_keeps_the_error(
    tmp_path, caplog
):
    """bandit reads a config file's exclude_dirs entry as a substring of every
    walked path, so ``tests`` under a target at ``.../tests-infra`` skipped the
    whole tree. Read as an exclusion of the files, that graded the target
    SKIPPED with no word; the entry is named and the grade stays an error."""
    source = _tree(tmp_path, ["a.py"], name="tests-infra")
    config = tmp_path / "bandit.yaml"
    config.write_text("exclude_dirs:\n  - tests\n", encoding="utf-8")
    scanner = _scanner(source, tmp_path)

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ScannerError, match="scanned no file"):
            scanner._record_scanned_files(
                _report(source, [], []), ["bandit", "--configfile", str(config)], source
            )

    assert any(
        "exclude_dirs entry 'tests'" in record.message
        and "scanned target's own path" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]


def test_an_operator_config_whose_include_names_no_file_is_skipped(tmp_path):
    source = _tree(tmp_path, ["a.py"])
    config = tmp_path / "bandit.toml"
    config.write_text('[tool.bandit]\ninclude = ["*.pyx"]\n', encoding="utf-8")
    scanner = _scanner(source, tmp_path)

    scanner._record_scanned_files(
        _report(source, [], []), ["bandit", f"--configfile={config}"], source
    )

    assert scanner.targets_attempted == 0


@pytest.mark.parametrize(
    "body", ["include: []\n", "skips: []\n"], ids=["empty-include", "no-include"]
)
def test_a_config_file_without_an_include_list_means_py_only(tmp_path, body):
    """bandit reads ``get_option("include") or ["*.py"]`` once a config file is
    given, so under such a config a ``.pyw``-only tree is scanned by no file
    and is SKIPPED, not "scanned no file"; the ``*.pyw`` default holds only
    with no config file at all."""
    source = _tree(tmp_path, ["script.pyw"])
    config = tmp_path / "bandit.yaml"
    config.write_text(body, encoding="utf-8")
    scanner = _scanner(source, tmp_path)

    scanner._record_scanned_files(
        _report(source, [], []), ["bandit", "--configfile", str(config)], source
    )

    assert scanner.targets_attempted == 0


def test_without_a_config_file_pyw_files_are_still_expected(tmp_path):
    """The control: with no --configfile, bandit's defaults include ``*.pyw``,
    so a ``.pyw``-only tree bandit reported nothing for is still an error."""
    source = _tree(tmp_path, ["script.pyw"])
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError, match="scanned no file"):
        scanner._record_scanned_files(_report(source, [], []), ["bandit"], source)


def test_an_operator_config_that_leaves_python_files_in_still_errors(tmp_path):
    source = _tree(tmp_path, ["a.py", "legacy/b.py"])
    config = tmp_path / "bandit.yaml"
    config.write_text("exclude_dirs:\n  - legacy\n", encoding="utf-8")
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError, match="scanned no file"):
        scanner._record_scanned_files(
            _report(source, [], []), ["bandit", "--configfile", str(config)], source
        )


# ---------------------------------------------------------------------------
# A bandit on PATH is verified before it runs, and then it does run
# ---------------------------------------------------------------------------


def _verifier(status: str, executable: str, detail: str):
    """A stand-in for ``verify_pre_installed_tool`` that records each call and
    answers the real verdict type. The scanner imports the verifier at call
    time, so patching it on its module is live; the recorded calls are what
    proves a test exercised the verified route rather than passing on the real
    verifier's grade of a file that does not exist."""
    calls: list[tuple[tuple, dict]] = []

    def verify(*args, **kwargs):
        calls.append((args, kwargs))
        # The requirement names the package the call asked about, as the real
        # verifier builds it, so a message built from the answer names the
        # right package too.
        package = args[1] if len(args) > 1 else kwargs.get("package", "bandit")
        return PreInstalledToolVerdict(
            status=status,
            executable=executable,
            requirement=f"{package}[sarif,toml]>=1.7.8,<2.0.0",
            detail=detail,
        )

    verify.calls = calls
    return verify


def test_a_path_binary_that_falls_short_is_refused_when_uv_is_absent(
    tmp_path, monkeypatch
):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    binary = str(tmp_path / "bandit")
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: [binary]
    )
    verify = _verifier("unsatisfied", binary, "the sarif extra is not installed")
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)

    assert scanner.validate_plugin_dependencies() is False
    assert [call[0][0] for call in verify.calls] == [binary]
    assert scanner.dependencies_satisfied is False
    assert scanner.dependency_unavailable_reason is not None
    assert "cannot be used" in scanner.dependency_unavailable_reason


def test_the_refusal_names_the_package_that_provides_the_command(tmp_path, monkeypatch):
    """The requirement a copy is held to is built from the package that provides
    the command when one is named apart from it, as the mixin's own check
    builds it; built from the command's name it named a package the scan does
    not run under."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    scanner.uv_tool_package_name = "bandit-provider"
    binary = str(tmp_path / "bandit")
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: [binary]
    )
    verify = _verifier("unsatisfied", binary, "the sarif extra is not installed")
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)

    assert scanner.validate_plugin_dependencies() is False
    # The verifier is asked about the resolved binary and the providing package.
    assert [call[0][:2] for call in verify.calls] == [(binary, "bandit-provider")]
    assert "bandit-provider[" in scanner.dependency_unavailable_reason


def test_a_verified_path_binary_runs_directly_when_uv_is_absent(tmp_path, monkeypatch):
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    binary = str(tmp_path / "bandit")
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: [binary]
    )
    verify = _verifier("satisfied", binary, "1.9.4 with the extras")
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)

    assert scanner.validate_plugin_dependencies() is True
    assert [call[0][0] for call in verify.calls] == [binary]
    assert scanner.use_uv_tool is False
    assert scanner.dependencies_satisfied is True


def test_after_a_failed_install_a_path_binary_runs_directly(tmp_path, monkeypatch):
    """The final fallback marked the dependency satisfied and left the uv route
    on, so the scan went back through the install that had just failed."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    binary = str(tmp_path / "bandit")
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        BanditScanner, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(
        BanditScanner, "_install_uv_tool", lambda self, timeout, retry_config: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: [binary]
    )
    verify = _verifier("satisfied", binary, "1.9.4 with the extras")
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verify)

    assert scanner.validate_plugin_dependencies() is True
    assert [call[0][0] for call in verify.calls] == [binary]
    assert scanner.use_uv_tool is False, "the binary on PATH is what runs now"
    assert scanner.dependencies_satisfied is True


@pytest.mark.parametrize(
    "answer",
    ["uv", "tools/uv", "tools/uv.exe", "tools/UV.EXE"],
    ids=["bare", "path", "exe", "upper-exe"],
)
def test_a_uv_answer_by_path_keeps_the_uv_route(tmp_path, monkeypatch, answer):
    """The resolver may name uv as the bare word or by its path, on Windows as
    ``uv.exe``; compared as the bare word, or by name without the suffix in
    mind, a path answer was taken for a bandit binary, verified as one, and run
    directly. Every shape runs with the verifier set to fail the test, so a uv
    answer wrongly verified as bandit cannot pass unnoticed."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    uv = answer if answer == "uv" else str(tmp_path / answer)
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        BanditScanner, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(
        BanditScanner, "_install_uv_tool", lambda self, timeout, retry_config: False
    )
    monkeypatch.setattr(
        bandit_scanner,
        "get_uv_tool_command",
        lambda command, **kwargs: [uv, "tool", "run", "bandit"],
    )
    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda *args, **kwargs: pytest.fail("a uv answer is not verified as bandit"),
    )

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is True
    assert scanner.dependencies_satisfied is True
