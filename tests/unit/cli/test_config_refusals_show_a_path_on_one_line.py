# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config refusal that names a path is one line, whatever the path holds.

A path is the caller's text. With a newline in it printed as given, ``ash config
get``'s "Config file not found" and "Invalid configuration in <path>:" and ``ash
report``'s "Invalid configuration: ..." would put the rest of the path at the
start of a line of its own, a line of the path's choosing. Each is shown on one
line, the newline written as ``\\x0a``.

So are the other lines that name the config's path: the refusal of a path that
is not a regular file (``get``, ``validate``, ``lint``,
``validate-plugin-dependencies``), the "Validating/Linting configuration file:"
header, ``validate-plugin-dependencies``' "Config file '<path>' is not valid.",
the log line naming the file ASH_CONFIG names, and ``ash report``'s warning for
a ``--config`` that does not exist. So are ``ash scan``'s refusal of a config
file that does not exist, named by ``--config`` or by ASH_CONFIG, and of an
ASH_CONFIG file that does not parse, refused in the shared formatter's one
line ("<path> could not be parsed (...)"). The load never falls back to the
defaults for a file that does not parse or does not exist: it refuses, exit 3,
and the file is replaced by the defaults only when there is no config file at
all.

So are a scan's and a workspace scan's refusals of an unexpected error, whose
text can name a path (an OSError names its files as given), and of a scanner
selection, which names the scanners as the caller typed them.
"""

from __future__ import annotations

import os
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="Windows file names hold no newline"
    ),
]

#: A value the model refuses, so the refusal names the file.
REFUSED = "project_name: t\nfail_on_findings: maybe\n"


def _assert_one_line(output: str, tail: str) -> None:
    """No line of *output* starts with *tail*, the part after the newline, and
    the newline is shown once, as ``\\x0a``: not shown again as ``\\\\x0a``."""
    starts = [line for line in output.splitlines() if line.startswith(tail)]
    assert starts == [], f"the path's rest began a line of its own:\n{output}"
    assert "\\x0a" + tail in output, output
    assert "\\\\x0a" not in output, f"the path's newline was shown twice:\n{output}"


def test_get_names_a_missing_path_on_one_line(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "a\nmissing.yaml"

    result = CliRunner().invoke(app, ["config", "get", "--config", str(missing)])

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "missing.yaml")


@pytest.mark.parametrize("named", ["--config", "ASH_CONFIG"])
def test_get_names_a_refused_path_on_one_line(tmp_path, monkeypatch, named):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    refused = tmp_path / "a\nrefused.yaml"
    refused.write_text(REFUSED, encoding="utf-8")
    args = ["config", "get"]
    if named == "--config":
        args += ["--config", str(refused)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(refused))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "refused.yaml")


@pytest.mark.parametrize("named", ["--config", "ASH_CONFIG"])
def test_report_names_a_refused_path_on_one_line(tmp_path, monkeypatch, named):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    refused = tmp_path / "a\nrefused.yaml"
    refused.write_text(REFUSED, encoding="utf-8")
    args = ["report"]
    if named == "--config":
        args += ["--config", str(refused)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(refused))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "refused.yaml")


@pytest.fixture
def _wide(monkeypatch):
    # A console this wide wraps none of these lines, so a line that starts with
    # the path's rest started there because of the newline.
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.mark.parametrize(
    "command,named",
    [
        ("get", "--config"),
        ("get", "ASH_CONFIG"),
        ("validate", "--config"),
        ("validate", "ASH_CONFIG"),
        ("lint", "--config"),
        ("lint", "ASH_CONFIG"),
        ("validate-plugin-dependencies", "--config"),
    ],
)
def test_a_path_that_is_not_a_file_is_named_on_one_line(
    tmp_path, monkeypatch, _wide, command, named
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / "a\ndirectory.yaml"
    directory.mkdir()
    args = ["config", command]
    if named == "--config":
        args += ["--config", str(directory)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(directory))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "directory.yaml")


@pytest.mark.parametrize(
    "content", ["project_name: t\n", REFUSED], ids=["valid", "refused"]
)
@pytest.mark.parametrize("command", ["validate", "lint"])
def test_the_check_s_header_names_the_file_on_one_line(
    tmp_path, monkeypatch, _wide, command, content
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nchecked.yaml"
    config.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(app, ["config", command, "--config", str(config)])

    assert result.exit_code == (3 if content == REFUSED else 0), result.output
    _assert_one_line(result.output, "checked.yaml")


@pytest.mark.parametrize(
    "name,flag", [("a\nrefused.toml", "--fix"), ("a\nrefused.json", "--fix-unused")]
)
def test_lint_s_rewrite_refusals_name_the_file_on_one_line(
    tmp_path, monkeypatch, _wide, name, flag
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / name
    config.write_text(
        '{"project_name": "t"}\n' if name.endswith(".json") else 'project_name = "t"\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app, ["config", "lint", "--config", str(config), flag, "-y"]
    )

    assert result.exit_code == 1, result.output
    _assert_one_line(result.output, name.split("\n")[1])


def test_validate_plugin_dependencies_names_an_invalid_file_on_one_line(
    tmp_path, monkeypatch, _wide
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\ninvalid.yaml"
    config.write_text(REFUSED, encoding="utf-8")

    result = CliRunner().invoke(
        app, ["config", "validate-plugin-dependencies", "--config", str(config)]
    )

    assert result.exit_code == 3, result.output
    assert "is not valid." in result.output, result.output
    _assert_one_line(result.output, "invalid.yaml")


#: Text that is not YAML. The refusal says where the parser stopped and names
#: the file once (unparsed_config_reason).
UNPARSED = "project_name: [unclosed\n"


@pytest.mark.parametrize(
    "args,named",
    [
        (["config", "validate-plugin-dependencies"], "--config"),
        (["config", "validate-plugin-dependencies"], "ASH_CONFIG"),
        (["config", "get"], "--config"),
        (["config", "get"], "ASH_CONFIG"),
        (["config", "validate"], "--config"),
        (["config", "validate"], "ASH_CONFIG"),
        (["config", "lint"], "--config"),
        (["config", "lint"], "ASH_CONFIG"),
        (["report"], "--config"),
    ],
)
def test_a_parse_refusal_names_the_file_on_one_line(
    tmp_path, monkeypatch, _wide, args, named
):
    """The parse refusal names the file on one line, whatever its name holds."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nunparsed.yaml"
    config.write_text(UNPARSED, encoding="utf-8")
    if named == "--config":
        args = [*args, "--config", str(config)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(config))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "unparsed.yaml")
    # The control: the parse refusal is printed, saying where the parser
    # stopped (unparsed_config_reason), so the line checked above is it.
    assert (
        "could not be parsed "
        "(ParserError at line 2, column 1; started at line 1, column 15)"
    ) in result.output, result.output


@pytest.fixture
def _logged():
    """Every message ASH's logger logs during the test. A filter on the logger,
    not a handler: the command's get_logger replaces the logger's handlers. The
    console wraps a log line and indents what follows, so the record is read,
    not the output."""
    from automated_security_helper.utils.log import ASH_LOGGER

    messages: list = []

    def keep(record) -> bool:
        messages.append(record.getMessage())
        return True

    ASH_LOGGER.addFilter(keep)
    yield messages
    ASH_LOGGER.removeFilter(keep)


def _assert_logged_on_one_line(messages: list, start: str, tail: str) -> None:
    logged = [m for m in messages if m.startswith(start)]
    assert logged, messages
    for message in logged:
        assert "\n" not in message, f"the path's rest began a line: {message!r}"
        assert "\\x0a" + tail in message, message


def test_the_log_line_names_the_ash_config_file_on_one_line(
    tmp_path, monkeypatch, _wide, _logged
):
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nnamed.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    result = CliRunner().invoke(app, ["config", "get"])

    assert result.exit_code == 0, result.output
    _assert_logged_on_one_line(
        _logged, "Using ASH config path found in ASH_CONFIG", "named.yaml"
    )


def test_the_workspace_refusal_with_the_parser_s_message_keeps_its_lines(capsys):
    """_fail_workspace_config keeps a parser message's own lines when the
    refusal names its file, as the scan's refusal does: the shared rule,
    parser_text.refusal_own_lines. The CLI reaches this branch only for a
    config the plan's resolution refuses as unparsable; today it defers that
    parse to the projects, so the branch is exercised here directly."""
    import typer

    from automated_security_helper.cli.scan import _fail_workspace_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from pathlib import Path as _Path

    refused = ASHConfigValidationError(
        'it does not parse: while parsing a flow sequence\n  in "a\ntail.yaml",'
        " line 1, column 15\nexpected ',' or ']'"
    )
    refused.parser_message = True
    refused.ash_config_file = _Path("a\ntail.yaml")

    with pytest.raises(typer.Exit):
        _fail_workspace_config(refused)

    output = capsys.readouterr().err
    _assert_one_line(output, "tail.yaml")
    # The control: the parser's own lines are kept.
    assert len(output.splitlines()) >= 3, output


def test_the_dry_run_workspace_refusal_hides_carried_values(capsys):
    """The real run prints a WorkspaceDefinitionError through error_text,
    which redacts the values the prewarm carried on it
    (carry_environment_values); the dry run's arm printed str(exc), so a
    value a plugin-load failure carried reached the dry run's output raw."""
    import typer

    from automated_security_helper.cli.scan import _fail_workspace_definition
    from automated_security_helper.core.exceptions import WorkspaceDefinitionError
    from automated_security_helper.utils.error_text import (
        carry_environment_values,
        error_text,
    )

    value = "ENVCANARYDRYRUNWSD"
    refused = WorkspaceDefinitionError(
        f"a plugin module read {value} from the environment"
    )
    carry_environment_values(refused, [value])
    # The control: the real run's text function hides the value.
    assert value not in error_text(refused)

    with pytest.raises(typer.Exit):
        _fail_workspace_definition(refused)

    output = capsys.readouterr().err
    assert "a plugin module read" in output, output
    assert value not in output, output


def test_the_dry_run_config_refusal_hides_carried_values(capsys):
    """The same for the ASHConfigValidationError arm: the real run's refusal
    text is error_text's (_config_refusal_text), which redacts carried
    values; the dry run's arm fed str(exc) to its line split."""
    import typer

    from automated_security_helper.cli.scan import _fail_workspace_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils.error_text import (
        carry_environment_values,
        error_text,
    )

    value = "ENVCANARYDRYRUNCFG"
    refused = ASHConfigValidationError(f"the prewarm refused a module naming {value}")
    carry_environment_values(refused, [value])
    assert value not in error_text(refused)

    with pytest.raises(typer.Exit):
        _fail_workspace_config(refused)

    output = capsys.readouterr().err
    assert "the prewarm refused a module naming" in output, output
    assert value not in output, output


def test_the_workspace_refusal_without_the_file_s_name_is_one_line(capsys):
    """_fail_workspace_config, like the scan's refusal below: a parser-message
    refusal that carries no file name is one line."""
    import typer

    from automated_security_helper.cli.scan import _fail_workspace_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    refused = ASHConfigValidationError(
        'it does not parse: while parsing a flow sequence\n  in "a\ntail.yaml",'
        " line 1, column 15"
    )
    refused.parser_message = True
    assert refused.ash_config_file is None

    with pytest.raises(typer.Exit):
        _fail_workspace_config(refused)

    output = capsys.readouterr().err
    _assert_one_line(output, "tail.yaml")


def test_the_scan_s_refusal_without_the_file_s_name_is_one_line(capsys):
    """A parser-message refusal that does not carry the file's name is shown as
    one line: without the name, the printer cannot tell the name's newlines from
    the parser's, and splitting at every newline would start a line of the
    name's choosing."""
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions.run_ash_scan import (
        ScanRefusedExit,
        _printed_config_refusal,
    )

    refused = ASHConfigValidationError(
        'it does not parse: while parsing a flow sequence\n  in "a\ntail.yaml",'
        " line 1, column 15"
    )
    refused.parser_message = True
    assert refused.ash_config_file is None

    with pytest.raises(ScanRefusedExit):
        _printed_config_refusal(3, refused)

    output = capsys.readouterr().out
    _assert_one_line(output, "tail.yaml")


def test_report_names_a_missing_config_on_one_line(tmp_path, monkeypatch, _wide):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "a\nmissing.yaml"

    result = CliRunner().invoke(app, ["report", "--config", str(missing)])

    assert result.exit_code == 3, result.output
    assert "Configuration file not found" in result.output, result.output
    _assert_one_line(result.output, "missing.yaml")


def _scan_args(tmp_path) -> list:
    source = tmp_path / "src"
    source.mkdir()
    return [
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(tmp_path / "out"),
        "--no-progress",
    ]


@pytest.mark.parametrize("named", ["--config", "ASH_CONFIG"])
def test_a_scan_given_its_dirs_names_a_missing_config_on_one_line(
    tmp_path, monkeypatch, _wide, _no_scan, named
):
    """The scan given explicit source and output dirs: the refusal of a missing
    config stays one line with the rest of the arguments parsed. The bare
    invocation's cell below pins the printed words per source. Both cells read
    the same refusal line through the same handler, so no change fails only
    this cell; it documents that the explicit-dirs invocation reaches the same
    handler, and _no_scan keeps a regression from scanning the test's
    directory."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "a\nmissing.yaml"
    args = _scan_args(tmp_path)
    if named == "--config":
        args += ["--config", str(missing)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(missing))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "missing.yaml")


def test_a_workspace_scan_names_a_refused_config_on_one_line(
    tmp_path, monkeypatch, _wide
):
    """In a workspace scan --config is the config of a project that has none;
    the plan's refusal of one the model refuses names it on one line too."""
    import json

    from automated_security_helper.models.workspace import WorkspaceExitCode

    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "api").mkdir()
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    refused = tmp_path / "a\nrefused.yaml"
    refused.write_text(REFUSED, encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["scan", "--workspace", str(workspace), "--config", str(refused), "--dry-run"],
    )

    assert result.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG, result.output
    _assert_one_line(result.output, "refused.yaml")


def test_a_workspace_root_config_that_does_not_parse_is_refused_on_one_line(
    tmp_path, monkeypatch, _wide
):
    """The workspace root's own config is read before the plan is shown, so
    --dry-run refuses a root config the run refuses. That refusal quotes the
    config's path, the caller's text, so it is shown on one line, the path's
    newline written ``\\x0a``."""
    import json

    from automated_security_helper.models.workspace import WorkspaceExitCode

    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "a\nroot"
    (root / "api").mkdir(parents=True)
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    (root / ".ash").mkdir()
    (root / ".ash" / ".ash.yaml").write_text(UNPARSED, encoding="utf-8")

    result = CliRunner().invoke(
        app, ["scan", "--workspace", str(workspace), "--dry-run"]
    )

    assert result.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG, result.output
    assert "could not be parsed (" in result.output, result.output
    _assert_one_line(result.output, "root/.ash/.ash.yaml")


def test_scan_names_an_ash_config_that_does_not_parse_on_one_line(
    tmp_path, monkeypatch, _wide
):
    """The scan's refusal of an ASH_CONFIG that does not parse is the shared
    formatter's one line, type and place, with nothing the parser said
    (config_sources.unparsed_config_reason)."""
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nunparsed.yaml"
    config.write_text(UNPARSED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    result = CliRunner().invoke(app, _scan_args(tmp_path))

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "unparsed.yaml")
    # The control: the refusal is the formatter's, so the line checked above
    # is the one that names the file.
    assert "could not be parsed (" in result.output, result.output


def test_the_load_s_refusal_of_a_missing_config_is_shown_on_one_line(
    tmp_path, monkeypatch, capsys
):
    """resolve_config refuses a config path that does not exist, even when its
    caller allows the defaults as a fallback, and the scan's printer shows that
    refusal on one line. The exception holds the path as the caller wrote it;
    the printer (run_ash_scan._printed_config_refusal) writes the path's newline
    as ``\\x0a``."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFileNotFoundError
    from automated_security_helper.interactions.run_ash_scan import (
        ScanRefusedExit,
        _printed_config_refusal,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    missing = tmp_path / "a\nmissing.yaml"

    with pytest.raises(ASHConfigFileNotFoundError) as refused:
        resolve_config(
            config_path=missing, source_dir=tmp_path, fallback_to_default=True
        )

    text = str(refused.value)
    assert text.startswith("Configuration file not found: "), text
    assert missing.as_posix() in text, text

    with pytest.raises(ScanRefusedExit):
        _printed_config_refusal(3, refused.value)

    output = capsys.readouterr().out
    assert "Configuration file not found: " in output, output
    _assert_one_line(output, "missing.yaml")


def _unreadable(path) -> None:
    path.write_text("project_name: t\n", encoding="utf-8")
    path.chmod(0)
    if os.access(path, os.R_OK):
        pytest.skip("this user reads a file with no permissions (root)")


def _assert_no_record_splits(messages: list, tail: str) -> None:
    """No logged message holds a raw newline before *tail*. Read from the
    records, not the console lines: the log console folds a long message at
    its own width, and a fold just before *tail* lands the tail at a line
    start with no defect, so a console read is flaky in the folded case."""
    split = [m for m in messages if "\n" + tail in m]
    assert split == [], f"the path's rest began a line of its own: {split!r}"


def test_the_load_s_debug_record_names_the_config_on_one_line(
    tmp_path, monkeypatch, _logged, caplog
):
    """resolve_config's debug record naming the file it loads keeps the path
    whole, as its warning for a missing file does: a newline in the path is a
    line of the path's choosing in any sink that keeps records verbatim."""
    import logging

    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "a\nnamed.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")
    with caplog.at_level(logging.DEBUG, logger="ash"):
        resolve_config(config_path=config, source_dir=tmp_path)

    loading = [m for m in _logged if m.startswith("Loading configuration from")]
    assert loading, _logged
    for message in loading:
        assert "\n" not in message, repr(message)
        assert "\\x0a" + "named.yaml" in message, message


@pytest.mark.parametrize("named", ["--config", "ASH_CONFIG"])
def test_report_refuses_a_config_it_cannot_read_on_one_line(
    tmp_path, monkeypatch, _wide, named
):
    """``ash report`` with a config it may not read refuses it as a config,
    exit 3, in the words the scan uses, and not as an unexpected error with
    exit 1: the file was meant to configure the reports, and rendering without
    it is not what the operator asked for."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nunreadable.yaml"
    _unreadable(config)
    args = ["report"]
    if named == "--config":
        args += ["--config", str(config)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(config))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    assert "could not" in result.output and "read" in result.output, result.output
    _assert_one_line(result.output, "unreadable.yaml")


def test_scan_refuses_an_ash_config_it_cannot_read_on_one_line(
    tmp_path, monkeypatch, _wide, _logged
):
    """An ASH_CONFIG file the scan cannot read is a config the run cannot use:
    exit 3, the refusal naming the file on one line, as for one that does not
    parse."""
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nunreadable.yaml"
    _unreadable(config)
    monkeypatch.setenv("ASH_CONFIG", str(config))

    result = CliRunner().invoke(app, _scan_args(tmp_path))

    assert result.exit_code == 3, result.output
    # The words the scan refuses a --config file it cannot read in.
    assert "could not read" in result.output, result.output
    _assert_one_line(result.output, "unreadable.yaml")
    _assert_no_record_splits(_logged, "unreadable.yaml")


def test_a_workspace_dry_run_refuses_an_ash_config_it_cannot_read_on_one_line(
    tmp_path, monkeypatch, _wide, _logged
):
    """The workspace plan reads ASH_CONFIG as the run does, and refuses one it
    cannot read the same way: exit 3, on one line."""
    import json

    from automated_security_helper.models.workspace import WorkspaceExitCode

    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "api").mkdir()
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    config = tmp_path / "a\nunreadable.yaml"
    _unreadable(config)
    monkeypatch.setenv("ASH_CONFIG", str(config))

    result = CliRunner().invoke(
        app, ["scan", "--workspace", str(workspace), "--dry-run"]
    )

    assert result.exit_code == WorkspaceExitCode.INVALID_PROJECT_CONFIG, result.output
    assert "could not be read" in result.output, result.output
    _assert_one_line(result.output, "unreadable.yaml")
    _assert_no_record_splits(_logged, "unreadable.yaml")


def _named_refusal_that_is_not_a_parser_s(message: str):
    """A refusal that names its file and is not a parser's message: one the
    model refuses, say, whose description can span lines."""
    from pathlib import Path as _Path

    from automated_security_helper.core.exceptions import ASHConfigValidationError

    refused = ASHConfigValidationError(message)
    refused.ash_config_file = _Path("a\nnamed.yaml")
    assert refused.parser_message is False
    return refused


def test_a_named_refusal_that_is_not_a_parser_s_is_one_line():
    """Only a parser's message keeps its lines: one that names its file and is
    not a parser's is one line, a newline outside the name included."""
    from automated_security_helper.utils.parser_text import refusal_own_lines

    refused = _named_refusal_that_is_not_a_parser_s("x\ny")

    assert refusal_own_lines(refused, "x\ny") == ["x\ny"]


def test_the_scan_shows_a_named_refusal_that_is_not_a_parser_s_on_one_line(capsys):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanRefusedExit,
        _printed_config_refusal,
    )

    refused = _named_refusal_that_is_not_a_parser_s(
        "Configuration validation failed for 'a\nnamed.yaml': first\nsecond"
    )

    with pytest.raises(ScanRefusedExit):
        _printed_config_refusal(3, refused)

    output = capsys.readouterr().out
    assert len(output.splitlines()) == 1, output
    _assert_one_line(output, "named.yaml")


def test_the_workspace_shows_a_named_refusal_that_is_not_a_parser_s_on_one_line(
    capsys,
):
    import typer

    from automated_security_helper.cli.scan import _fail_workspace_config

    refused = _named_refusal_that_is_not_a_parser_s(
        "Configuration validation failed for 'a\nnamed.yaml': first\nsecond"
    )

    with pytest.raises(typer.Exit):
        _fail_workspace_config(refused)

    output = capsys.readouterr().err
    assert len(output.splitlines()) == 1, output
    _assert_one_line(output, "named.yaml")


@pytest.fixture
def _no_scan(monkeypatch):
    """A scan that gets past its config refusal fails here, before any scanner
    starts, rather than scanning the test's directory."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def _refuse(*args, **kwargs):
        raise AssertionError("the scan started; its config refusal did not fire")

    monkeypatch.setattr(ASHScanOrchestrator, "create", _refuse)


@pytest.mark.parametrize(
    "named,printed",
    [
        ("--config", "Configuration file not found"),
        ("ASH_CONFIG", "ASH_CONFIG names"),
    ],
)
def test_scan_names_a_missing_config_on_one_line(
    tmp_path, monkeypatch, _wide, _no_scan, named, printed
):
    """The scan's "ERROR (3) Invalid configuration:" line: one line, however the
    missing path was given."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "a\nmissing.yaml"
    args = ["scan"]
    if named == "--config":
        args += ["--config", str(missing)]
    else:
        monkeypatch.setenv("ASH_CONFIG", str(missing))

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    assert printed in result.output, result.output
    _assert_one_line(result.output, "missing.yaml")


def test_plugin_list_names_the_config_it_was_given_on_one_line(
    tmp_path, monkeypatch, _wide, _logged
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nnamed.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(config)])

    assert result.exit_code == 0, result.output
    _assert_logged_on_one_line(_logged, "Using config file specified at:", "named.yaml")


def test_plugin_list_names_the_config_it_found_on_one_line(
    tmp_path, monkeypatch, _wide, _logged
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "a\nproject"
    (project / ".ash").mkdir(parents=True)
    (project / ".ash" / ".ash.yaml").write_text("project_name: t\n", encoding="utf-8")
    monkeypatch.chdir(project)

    result = CliRunner().invoke(app, ["plugin", "list"])

    assert result.exit_code == 0, result.output
    _assert_logged_on_one_line(_logged, "Using config file found at:", "project")


@pytest.mark.parametrize("given", ["--config", "found"])
def test_plugin_list_refuses_a_config_that_does_not_parse_on_one_line(
    tmp_path, monkeypatch, _wide, given
):
    """plugin list's exit-3 refusal, not only its log lines, names the file on
    one line, whether the file was given or found."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    if given == "--config":
        monkeypatch.chdir(tmp_path)
        config = tmp_path / "a\nunparsed.yaml"
        config.write_text(UNPARSED, encoding="utf-8")
        args, tail = ["plugin", "list", "--config", str(config)], "unparsed.yaml"
    else:
        project = tmp_path / "a\nproject"
        (project / ".ash").mkdir(parents=True)
        (project / ".ash" / ".ash.yaml").write_text(UNPARSED, encoding="utf-8")
        monkeypatch.chdir(project)
        args, tail = ["plugin", "list"], "project"

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3, result.output
    # The control: the refusal is printed, so the line checked is it.
    assert "could not be parsed" in result.output, result.output
    _assert_one_line(result.output, tail)


def test_the_scan_names_the_config_it_loads_on_one_line(
    tmp_path, monkeypatch, _wide, _logged
):
    """The scan's "Using ASH configuration from" line, for a --config file that
    loads. The run stops at the orchestrator's first call after the line, so
    no scanner starts."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def stop(*args, **kwargs):
        raise AssertionError("stopped after the configuration line")

    monkeypatch.setattr(ASHScanOrchestrator, "add_metadata", stop)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "a\nnamed.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")

    CliRunner().invoke(app, [*_scan_args(tmp_path), "--config", str(config)])

    _assert_logged_on_one_line(_logged, "Using ASH configuration from", "named.yaml")


def test_the_committed_output_refusal_names_the_output_dir_on_one_line(
    tmp_path, monkeypatch, _wide, capsys
):
    """The refusal of committed files in the output directory names that
    directory, whose path is the caller's text: one line."""
    from types import SimpleNamespace

    from automated_security_helper.interactions import run_ash_scan as module

    output = tmp_path / "a\nout"
    monkeypatch.setattr(
        module, "_committed_entries_this_run_writes", lambda opts: [output / "ash.log"]
    )

    with pytest.raises(module.ScanRefusedExit):
        module._refuse_committed_output(SimpleNamespace(output_dir=output))

    printed = capsys.readouterr().out
    # The control: the refusal is printed, so the line checked is it.
    assert "committed to git" in printed, printed
    _assert_one_line(printed, "out")


def test_the_sandbox_refusal_names_the_output_dir_on_one_line(
    tmp_path, monkeypatch, _wide, capsys
):
    """The sandbox's refusal of an output directory reached through a symlink
    names that directory: one line. A config that does not resolve counts as
    the sandbox on, as the check does."""
    from types import SimpleNamespace

    from automated_security_helper.config import resolve_config as resolving
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan as module

    def unresolved(**kwargs):
        raise ValueError("no config here")

    monkeypatch.setattr(resolving, "resolve_config", unresolved)
    (tmp_path / "real").mkdir()
    link = tmp_path / "a\nout"
    link.symlink_to(tmp_path / "real")
    opts = SimpleNamespace(
        mode=RunMode.local,
        source_dir=tmp_path,
        output_dir=link,
        config=str(tmp_path / "none.yaml"),
        config_overrides=[],
        config_base_gate=None,
        # A ScanOptions field the check reads (a workspace run's output tree is
        # checked with the rest); a local scan has none.
        workspace_plan=None,
    )

    with pytest.raises(module.ScanRefusedExit):
        module._refuse_symlinked_output_dir(opts)

    printed = capsys.readouterr().out
    assert "is a symlink" in printed, printed
    _assert_one_line(printed, "out")


def _missing_file(tmp_path) -> FileNotFoundError:
    """An error whose text names a path the caller chose: an OSError names its
    files as given."""
    return FileNotFoundError(
        2, "No such file or directory", str(tmp_path / "a\nmissing.json")
    )


def test_the_scan_s_unexpected_error_names_a_path_on_one_line(
    tmp_path, monkeypatch, _wide
):
    """The scan's "Exiting due to exception during ASH scan" refusal quotes the
    error's text, which can name a path: one line."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def missing(*args, **kwargs):
        raise _missing_file(tmp_path)

    monkeypatch.setattr(ASHScanOrchestrator, "add_metadata", missing)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, _scan_args(tmp_path))

    assert result.exit_code == 1, result.output
    # The control: the refusal is printed, so the line checked is it.
    assert "Exiting due to exception during ASH scan" in result.output, result.output
    _assert_one_line(result.output, "missing.json")


def test_the_scan_s_scanner_selection_refusal_is_one_line(tmp_path, monkeypatch, _wide):
    """A refused --scanners names the names as the caller typed them: one line.
    The run stops at the orchestrator's first call after the selection is
    checked, so no scanner starts if it is not refused."""
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def stop(*args, **kwargs):
        raise AssertionError("the scanner selection was not refused")

    monkeypatch.setattr(ASHScanOrchestrator, "add_metadata", stop)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        app, [*_scan_args(tmp_path), "--scanners", "no\nsuch-scanner"]
    )

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "None of the requested scanners exist" in result.output, result.output
    _assert_one_line(result.output, "such-scanner")


@pytest.mark.parametrize(
    "refused,printed,tail",
    [
        pytest.param(
            "unexpected-error",
            "Exiting due to exception during ASH workspace scan",
            "missing.json",
            id="unexpected-error",
        ),
        pytest.param(
            "scanner-selection",
            "None of the requested scanners exist",
            "such-scanner",
            id="scanner-selection",
        ),
    ],
)
def test_the_workspace_s_refusal_of_a_run_error_is_one_line(
    tmp_path, monkeypatch, _wide, capsys, refused, printed, tail
):
    """The workspace scan's refusals of an unexpected error and of a scanner
    selection quote text the caller chose: one line each."""
    from types import SimpleNamespace

    from automated_security_helper.core.scanner_selection import (
        refuse_selection_matching_no_scanner,
    )
    from automated_security_helper.interactions import run_ash_scan as module
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.workspace import execution

    def run(plan, settings):
        if refused == "unexpected-error":
            raise _missing_file(tmp_path)
        refuse_selection_matching_no_scanner(["no\nsuch-scanner"], ["bandit"])
        raise AssertionError("the scanner selection was not refused")

    monkeypatch.setattr(module, "build_project_scan_settings", lambda opts: None)
    monkeypatch.setattr(execution, "execute_workspace", run)

    with pytest.raises(module.ScanRefusedExit):
        module._run_workspace_mode(
            SimpleNamespace(workspace_plan=object(), offline=False), ASH_LOGGER
        )

    output = capsys.readouterr().out
    # The control: the refusal is printed, so the line checked is it.
    assert printed in output, output
    _assert_one_line(output, tail)
