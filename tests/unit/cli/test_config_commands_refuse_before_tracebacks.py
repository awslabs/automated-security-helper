# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The `ash config` commands refuse, on one line, where they crashed or misled.

init --force overwrites the file ASH reads beside an ignored source; a file at
`.ash` or a dangling `.ash/.gitignore` link does not abort init; a deleted working
directory, a deeply nested document, an oversized integer literal, a file swapped
mid-command, an unwritable target and an unexpected validation error are each a
refusal, not a traceback; a plugin module a scan refuses is not written; the schema
line of a file starting with a byte order mark is kept; the printed config is wrapped,
not cut; update and the wizard find the config where a scan would; and lint's exit
codes, hints and "Remaining after the fixes" follow its documented contract.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli
from automated_security_helper.cli.config import _refused_file_label, config_app
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintIssue,
    LintResult,
    LintSeverity,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

INVALID_CONFIG_EXIT = 3
USAGE_ERROR_EXIT = 5

VALID_CONFIG = "project_name: demo\nfail_on_findings: true\n"


@pytest.fixture(autouse=True)
def _no_ambient_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)


def _invoke(args, **kwargs):
    return CliRunner().invoke(config_app, args, **kwargs)


def _no_traceback(result) -> bool:
    """Whether the command ended by its own exit, not by an escaped exception."""
    return result.exception is None or isinstance(result.exception, SystemExit)


# --- init ---


def test_init_force_overwrites_the_file_ash_reads_beside_an_ignored_source(
    tmp_path, monkeypatch
):
    """With .ashrc.yaml (selected) and pyproject.toml's [tool.ash] (ignored) both
    present, `init --force` was refused as "ASH already reads its configuration
    from pyproject.toml", which was false, and --force never reached the file."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ashrc.yaml").write_text("project_name: old\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ash]\nproject_name = "ignored"\n', encoding="utf-8"
    )

    result = _invoke(["init", "--force"])

    assert result.exit_code == 0, result.output
    assert "ASH already reads its configuration from" not in result.output
    data = yaml.safe_load((tmp_path / ".ashrc.yaml").read_text(encoding="utf-8"))
    assert data["project_name"] == tmp_path.name


def test_init_without_force_names_the_existing_file_not_an_ignored_source(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ashrc.yaml").write_text("project_name: old\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ash]\nproject_name = "ignored"\n', encoding="utf-8"
    )

    result = _invoke(["init"])

    assert result.exit_code == 1, result.output
    assert "Include --force to overwrite" in result.output, result.output
    assert "pyproject.toml" not in result.output, result.output


def test_init_still_refuses_a_new_file_beside_the_one_ash_reads(tmp_path, monkeypatch):
    """The refusal still names the selected source when the target is another name."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ash").mkdir()
    (tmp_path / ".ash" / ".ash.yaml").write_text(
        "project_name: old\n", encoding="utf-8"
    )

    result = _invoke(["init"])

    assert result.exit_code == 1, result.output
    assert "ASH already reads its configuration from" in result.output, result.output


def test_init_writes_the_config_when_dot_ash_is_a_regular_file(tmp_path):
    """mkdir on a regular file at .ash raised FileExistsError out of init."""
    (tmp_path / ".ash").write_text("not a directory\n", encoding="utf-8")
    target = tmp_path / ".ashrc.yaml"

    result = _invoke(["init", "--config", str(target)])

    assert result.exit_code == 0, result.output
    assert target.is_file()
    assert "is not a directory" in result.output, result.output


def test_init_does_not_write_the_gitignore_through_a_dangling_link(tmp_path):
    """exists() is False for a dangling link, so the write went through it."""
    ash_dir = tmp_path / ".ash"
    ash_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (ash_dir / ".gitignore").symlink_to(elsewhere / "written-through-the-link")

    result = _invoke(["init", "--config", str(tmp_path / ".ashrc.yaml")])

    assert result.exit_code == 0, result.output
    assert not (elsewhere / "written-through-the-link").exists()


def test_init_reports_an_unwritable_target_on_one_line(tmp_path):
    """A parent that is a regular file made mkdir raise NotADirectoryError as a
    traceback; update reports the same failure on one line and exits 1."""
    (tmp_path / "parent").write_text("a file\n", encoding="utf-8")

    result = _invoke(["init", "--config", str(tmp_path / "parent" / "x.yaml")])

    assert result.exit_code == 1, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "Error writing config file" in result.output, result.output


# --- a deleted working directory ---


def test_get_refuses_a_deleted_working_directory_with_the_usage_exit(tmp_path):
    """Path.cwd() raised FileNotFoundError before the source-directory refusal."""
    gone = tmp_path / "gone"
    gone.mkdir()
    before = os.getcwd()
    os.chdir(gone)
    try:
        gone.rmdir()
        result = _invoke(["get"])
    finally:
        os.chdir(before)

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "deleted" in result.output, result.output


def _invoke_in_a_deleted_directory(tmp_path, args):
    gone = tmp_path / "gone"
    gone.mkdir()
    before = os.getcwd()
    os.chdir(gone)
    try:
        gone.rmdir()
        return _invoke(args)
    finally:
        os.chdir(before)


def test_the_wizard_refuses_a_deleted_working_directory_before_any_prompt(
    tmp_path, monkeypatch
):
    """Red at the base: without --source-dir the wizard searched "." and asked
    every question, then failed in the write's os.getcwd with "Error writing
    config file". No prompt is answered here, so a prompt would raise."""
    _scripted_wizard(monkeypatch, [])

    result = _invoke_in_a_deleted_directory(tmp_path, ["wizard"])

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "deleted" in result.output, result.output


def test_init_with_a_relative_config_refuses_a_deleted_working_directory(tmp_path):
    """Red at the base: `init --config rel.yaml` resolved the path with
    config_path.absolute() outside any try, a FileNotFoundError traceback."""
    result = _invoke_in_a_deleted_directory(tmp_path, ["init", "--config", "rel.yaml"])

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "deleted" in result.output, result.output


# --- labels and refusals ---


def test_refused_file_label_survives_an_ash_config_symlink_loop(tmp_path, monkeypatch):
    """named.resolve() raised RuntimeError (Python 3.10 to 3.12) inside the label
    of a refusal, so the refusal became a traceback."""
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    monkeypatch.setenv("ASH_CONFIG", str(loop))
    error = ASHConfigValidationError("refused")
    error.ash_config_file = loop

    label = _refused_file_label("Config file 'other'", tmp_path / "other.yaml", error)

    assert label.startswith("The file ASH_CONFIG names"), label


def test_the_ash_config_refusal_is_shown_when_the_named_file_has_errors_too(
    tmp_path, monkeypatch
):
    """With both files invalid, get printed only the named file's errors and the
    ASH_CONFIG file's refusal, the one that stopped the load, never appeared."""
    base = tmp_path / "base.yaml"
    base.write_text("fail_on_findings: maybe\n", encoding="utf-8")
    named = tmp_path / "named.yaml"
    named.write_text(
        "global_settings:\n  severity_threshold: NOT_A_LEVEL\n", encoding="utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(base))

    result = _invoke(["get", "--config", str(named), "--source-dir", str(tmp_path)])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "ASH_CONFIG names" in result.output, result.output


def test_the_named_file_is_checked_when_ash_config_names_the_same_file(
    tmp_path, monkeypatch
):
    """The per-field check of the named file was skipped for every ASH_CONFIG
    refusal, including the common case where ASH_CONFIG names the very file
    --config names, which left only the refusal's one line. The field is named
    in the output here."""
    named = tmp_path / "named.yaml"
    named.write_text(
        "global_settings:\n  severity_threshold: NOT_A_LEVEL\n", encoding="utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))

    result = _invoke(["get", "--config", str(named), "--source-dir", str(tmp_path)])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "severity_threshold" in result.output, result.output


def test_a_refusal_only_from_ash_plugin_modules_does_not_blame_the_file(
    tmp_path, monkeypatch
):
    config = tmp_path / ".ashrc.yaml"
    config.write_text(VALID_CONFIG, encoding="utf-8")
    monkeypatch.setenv("ASH_PLUGIN_MODULES", "no_such_plugin_module_zz")

    result = _invoke(
        [
            "validate-plugin-dependencies",
            "--config",
            str(config),
            "--source-dir",
            str(tmp_path),
        ]
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "ASH_PLUGIN_MODULES" in result.output, result.output
    assert f"Invalid configuration in {config}" not in result.output, result.output
    assert f"Config file '{config.as_posix()}' is not valid" not in result.output


# --- update ---


@pytest.fixture
def config_file(tmp_path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / ".ashrc.yaml"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    return path


def test_update_refuses_a_deeply_nested_document_instead_of_crashing(config_file):
    """The parser's RecursionError escaped update as a traceback where every
    other reader refuses the file with exit 3."""
    nested = "[" * 3000 + "]" * 3000
    config_file.write_text(f"project_name: demo\nfail_on_findings: {nested}\n")

    result = _invoke(["update", str(config_file), "--set", "project_name=x"])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)


def test_update_refuses_an_oversized_integer_literal_in_a_list(config_file):
    """int() of a literal over the interpreter's digit limit inside a JSON list
    raised ValueError out of the reference-shape pre-check."""
    digits = "1" * 4400

    result = _invoke(
        [
            "update",
            str(config_file),
            "--set",
            f"global_settings.severity_threshold=[{digits}]",
        ]
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)


def test_update_leaves_a_key_with_surrounding_whitespace_to_the_apply(config_file):
    """The pre-check compared the first segment as typed, so ' scanners' was
    reported as not a top-level key while listing scanners as one."""
    result = _invoke(
        ["update", str(config_file), "--set", " scanners.bandit.enabled=false"]
    )

    assert "is not a top-level configuration key" not in result.output, result.output
    # The apply strips each key segment, so the padded key reaches the field: a
    # pre-check that merely stayed silent while the apply dropped the key would
    # report "updated" and change nothing.
    assert result.exit_code == 0, result.output
    data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert data["scanners"]["bandit"]["enabled"] is False


def test_update_reports_a_text_it_cannot_parse_for_keep_from(config_file, monkeypatch):
    """The parse for keep_from was bare: a file made unparseable after the load
    crashed update with a traceback. It is parsed from the compared bytes now,
    and a parse failure is still reported on one line."""

    def unparseable(*_args, **_kwargs):
        raise yaml.YAMLError("the text went bad")

    monkeypatch.setattr(config_cli, "parse_config_text", unparseable)

    result = _invoke(["update", str(config_file), "--set", "project_name=x"])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "went bad" in result.output, result.output


def test_update_renders_keep_from_from_the_bytes_it_compared(config_file, monkeypatch):
    """Red at the base: keep_from came from a further open of the file, after
    the bytes comparison, so a file swapped in that window fed the rewrite. With
    no such open, a reader that fails on every open is never reached and the
    update goes through on the compared bytes."""

    def gone(*_args, **_kwargs):
        raise OSError("the file went away")

    monkeypatch.setattr(config_cli, "read_config_file", gone)

    result = _invoke(["update", str(config_file), "--set", "project_name=x"])

    assert result.exit_code == 0, result.output
    data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert data["project_name"] == "x"
    assert data["fail_on_findings"] is True


def test_update_does_not_replace_a_file_the_user_may_not_write(config_file):
    """Red at the base: the staged write renamed over a read-only file, because a
    rename asks the directory, not the file. The write is made in place for such
    a file, so the file's own refusal is the outcome, as it was before staging."""
    if getattr(os, "geteuid", lambda: 1)() == 0:
        pytest.skip("root may write a read-only file")
    config_file.chmod(0o444)
    try:
        result = _invoke(["update", str(config_file), "--set", "project_name=x"])

        assert result.exit_code == 1, result.output
        assert _no_traceback(result), repr(result.exception)
        assert "Error writing config file" in result.output, result.output
        assert config_file.read_text(encoding="utf-8") == VALID_CONFIG
        assert stat.S_IMODE(config_file.stat().st_mode) == 0o444
    finally:
        config_file.chmod(0o644)


def test_update_refuses_a_file_that_changed_while_it_read_it(config_file, monkeypatch):
    """The refusal checks and the load each opened the file; a file swapped between
    them was rewritten from a text the checks never saw."""
    real = config_cli.read_config_bytes
    calls = {"n": 0}

    def changing(path, *args, **kwargs):
        calls["n"] += 1
        data = real(path, *args, **kwargs)
        return data + b"# changed\n" if calls["n"] >= 3 else data

    monkeypatch.setattr(config_cli, "read_config_bytes", changing)

    result = _invoke(["update", str(config_file), "--set", "project_name=x"])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "changed while" in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == VALID_CONFIG


def test_update_keeps_the_schema_line_of_a_file_with_a_byte_order_mark(config_file):
    """The first line was decoded as utf-8, so the mark made it read as not a
    comment and the default schema line replaced the file's own."""
    schema_line = "# yaml-language-server: $schema=https://example.invalid/custom.json"
    config_file.write_bytes(
        b"\xef\xbb\xbf" + f"{schema_line}\n{VALID_CONFIG}".encode("utf-8")
    )

    result = _invoke(["update", str(config_file), "--set", "project_name=new"])

    assert result.exit_code == 0, result.output
    first_line = config_file.read_text(encoding="utf-8-sig").splitlines()[0]
    assert "custom.json" in first_line, first_line


def test_update_does_not_write_a_plugin_module_a_scan_refuses(config_file):
    """update wrote the entry and exited 0; get, validate and
    validate-plugin-dependencies then refused the file with exit 3."""
    result = _invoke(
        [
            "update",
            str(config_file),
            "--set",
            "ash_plugin_modules=[no_such_plugin_module_zz]",
        ]
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "Not updating" in result.output, result.output
    assert config_file.read_text(encoding="utf-8") == VALID_CONFIG


def test_update_finds_the_config_where_ash_source_dir_points(tmp_path, monkeypatch):
    """update discovered in the working directory alone, so it edited a different
    file than get, validate and lint show and a scan reads."""
    elsewhere = tmp_path / "project"
    elsewhere.mkdir()
    config = elsewhere / ".ashrc.yaml"
    config.write_text(VALID_CONFIG, encoding="utf-8")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("ASH_SOURCE_DIR", str(elsewhere))

    result = _invoke(["update", "--set", "project_name=moved"])

    assert result.exit_code == 0, result.output
    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert data["project_name"] == "moved"


# --- get ---


def test_get_wraps_a_long_line_instead_of_cutting_it(config_file):
    """Syntax cropped every line longer than the console to its width."""
    token = "x" * 120
    config_file.write_text(f'project_name: "{token}"\n', encoding="utf-8")

    result = _invoke(["get", str(config_file)], env={"COLUMNS": "40"})

    assert result.exit_code == 0, result.output
    assert token in "".join(result.output.split()), result.output


# --- validate ---


def test_validate_shows_an_unexpected_errors_text(config_file, monkeypatch):
    """The catch-all printed the exception's text raw."""
    from automated_security_helper.config.config_validator import ConfigValidator

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom\x1b[2Jafter")

    monkeypatch.setattr(ConfigValidator, "check_config_file", boom)

    result = _invoke(["validate", "--config", str(config_file)])

    assert result.exit_code == 1, result.output
    assert "Error validating config" in result.output, result.output
    assert "\x1b" not in result.output, repr(result.output)


# --- lint ---


def test_lint_fix_passes_a_toml_file_with_nothing_to_fix(tmp_path):
    """`lint --fix` exited 1 for every TOML config, a clean one included, so the
    documented pre-commit invocation always failed for such repositories."""
    config = tmp_path / ".ashrc.toml"
    config.write_text('project_name = "t"\n', encoding="utf-8")

    result = _invoke(["lint", "--config", str(config), "--fix", "-y"])

    assert result.exit_code == 0, result.output


ENV_FILE_WITH_A_FIX = (
    "project_name: ${PROJ}\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: a.py\n"
    "      line_start: 3\n"
    "      reason: r\n"
)


def test_lint_does_not_advise_fix_for_a_file_fix_refuses(tmp_path):
    """The hint said "Run with --fix" for a file --fix then refused. The linter
    now clears the fixable mark on every issue the fixer would refuse the file
    for (ConfigLinter._clear_fixable_a_fixer_refuses), so the issue is reported
    as a plain warning and no fix is advised either way."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(ENV_FILE_WITH_A_FIX, encoding="utf-8")

    result = _invoke(["lint", "--config", str(config)], env={"PROJ": "demo"})

    assert "missing 'line_end'" in result.output, result.output
    assert "Run with --fix" not in result.output, result.output
    assert "[auto-fixable]" not in result.output, result.output


def test_a_refused_fix_does_not_hide_the_scans_refusal(tmp_path):
    """lint --fix on a file that reads the environment exited 1 even when a scan
    refuses the file, skipping the documented exit 3."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(
        ENV_FILE_WITH_A_FIX + "fail_on_findings: maybe\n", encoding="utf-8"
    )

    result = _invoke(
        ["lint", "--config", str(config), "--fix", "-y"], env={"PROJ": "demo"}
    )

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output


def _issue(severity, category, message, **kwargs) -> LintIssue:
    return LintIssue(severity=severity, category=category, message=message, **kwargs)


def test_a_declined_fix_prints_no_remaining_issues(tmp_path, monkeypatch):
    """With the prompt declined nothing was written, yet "Remaining after the
    fixes" listed fewer issues, because the re-lint does not look for unused
    suppressions."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(VALID_CONFIG, encoding="utf-8")
    fixable = _issue(
        LintSeverity.WARNING,
        LintCategory.INTERNAL_FIELD,
        "internal field",
        fixable=True,
        fix_description="drop it",
    )
    unused = _issue(LintSeverity.WARNING, LintCategory.SUPPRESSION_UNUSED, "unused")
    results = iter(
        [
            LintResult(issues=[fixable, unused], config_path=config),
            LintResult(issues=[fixable], config_path=config),
        ]
    )
    monkeypatch.setattr(ConfigLinter, "lint", staticmethod(lambda **_: next(results)))

    result = _invoke(["lint", "--config", str(config), "--fix"], input="n\n")

    assert result.exit_code == 0, result.output
    assert "Remaining after the fixes" not in result.output, result.output


def test_an_error_a_scan_accepts_exits_0_as_the_docstring_says(tmp_path, monkeypatch):
    """An ERROR-severity issue a scan accepts exited 1, against lint's documented
    exit codes, and 0 for the same file when a --fix prompt was declined."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(VALID_CONFIG, encoding="utf-8")
    error = _issue(LintSeverity.ERROR, LintCategory.UNKNOWN_FIELD, "accepted error")
    monkeypatch.setattr(
        ConfigLinter,
        "lint",
        staticmethod(lambda **_: LintResult(issues=[error], config_path=config)),
    )

    result = _invoke(["lint", "--config", str(config)])

    assert result.exit_code == 0, result.output


def _fresh_report(path: Path):
    return (path, datetime.now(), 0)


def test_fix_unused_is_not_run_on_a_file_that_does_not_parse(tmp_path, monkeypatch):
    """--fix-unused called the fixer on a config lint had just reported as
    unparseable, and the fixer's own load raised."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text("a: [\n", encoding="utf-8")
    monkeypatch.setattr(
        ConfigLinter,
        "get_unused_report_age",
        staticmethod(lambda *_a, **_k: _fresh_report(tmp_path / "report.json")),
    )

    def fixer(*_args, **_kwargs):
        raise ValueError("the fixer loaded an unparseable file")

    monkeypatch.setattr(ConfigLinter, "fix_unused_suppressions", staticmethod(fixer))

    result = _invoke(["lint", "--config", str(config), "--fix-unused", "-y"])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)


def test_fix_unused_writes_the_text_computed_after_the_prompt(tmp_path, monkeypatch):
    """The new text was computed before the confirmation prompt and written after
    it, over any edit made while the prompt waited."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(VALID_CONFIG, encoding="utf-8")
    monkeypatch.setattr(
        ConfigLinter,
        "get_unused_report_age",
        staticmethod(lambda *_a, **_k: _fresh_report(tmp_path / "report.json")),
    )
    unused = _issue(LintSeverity.WARNING, LintCategory.SUPPRESSION_UNUSED, "unused")
    texts = iter(["project_name: first\n", "project_name: second\n"])
    calls = {"n": 0}

    def fixer(*_args, **_kwargs):
        calls["n"] += 1
        return next(texts), [unused], None

    monkeypatch.setattr(ConfigLinter, "fix_unused_suppressions", staticmethod(fixer))

    result = _invoke(["lint", "--config", str(config), "--fix-unused"], input="y\n")

    assert result.exit_code == 0, result.output
    assert calls["n"] == 2, calls
    assert config.read_text(encoding="utf-8") == "project_name: second\n"


def test_lint_fix_reports_a_write_failure_on_one_line(tmp_path, monkeypatch):
    """An OSError from writing the fixed file escaped as a traceback."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(ENV_FILE_WITH_A_FIX.replace("${PROJ}", "demo"), encoding="utf-8")

    def refuse_write(*_args, **_kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(config_cli, "_write_config_text", refuse_write)

    result = _invoke(["lint", "--config", str(config), "--fix", "-y"])

    assert result.exit_code == 1, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "Error writing config file" in result.output, result.output


# --- wizard ---


def _scripted_wizard(monkeypatch, answers):
    """Answer the wizard's prompts: project name, then module names, blank to end;
    every yes/no question is answered no; the toggle tables are skipped."""
    replies = iter(answers)
    monkeypatch.setattr(config_cli, "prompt", lambda *_a, **_k: next(replies))
    monkeypatch.setattr(config_cli, "confirm", lambda *_a, **_k: False)
    monkeypatch.setattr(config_cli, "_prompt_toggle_items", lambda *_a, **_k: {})


def test_the_wizard_does_not_write_a_plugin_module_a_scan_refuses(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    _scripted_wizard(monkeypatch, ["demo", "no_such_plugin_module_zz", ""])
    target = tmp_path / "new.yaml"

    result = _invoke(["wizard", "--config", str(target)])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "Not writing" in result.output, result.output
    assert not target.exists()


def test_the_wizard_refuses_an_environment_module_before_the_first_prompt(
    tmp_path, monkeypatch
):
    """Red at the base: with ASH_PLUGIN_MODULES naming a module a scan refuses,
    the wizard asked every question and then refused to write, throwing the
    answers away. No prompt is answered here, so a prompt would raise."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASH_PLUGIN_MODULES", "no_such_plugin_module_zz")
    _scripted_wizard(monkeypatch, [])
    target = tmp_path / "new.yaml"

    result = _invoke(["wizard", "--config", str(target)])

    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "ASH_PLUGIN_MODULES" in result.output, result.output
    assert not target.exists()


def test_the_wizard_reports_an_unwritable_target_on_one_line(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _scripted_wizard(monkeypatch, ["demo", ""])
    (tmp_path / "parent").write_text("a file\n", encoding="utf-8")

    result = _invoke(["wizard", "--config", str(tmp_path / "parent" / "x.yaml")])

    assert result.exit_code == 1, result.output
    assert _no_traceback(result), repr(result.exception)
    assert "Error writing config file" in result.output, result.output


def test_the_wizard_finds_the_config_where_ash_source_dir_points(tmp_path, monkeypatch):
    elsewhere = tmp_path / "project"
    elsewhere.mkdir()
    config = elsewhere / ".ashrc.yaml"
    config.write_text(VALID_CONFIG, encoding="utf-8")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("ASH_SOURCE_DIR", str(elsewhere))
    _scripted_wizard(monkeypatch, ["moved", ""])

    result = _invoke(["wizard"])

    assert result.exit_code == 0, result.output
    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert data["project_name"] == "moved"
    assert not (cwd / ".ashrc.yaml").exists()
