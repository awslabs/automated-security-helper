# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the CLI prints with typer.echo and secho is shown, not obeyed.

typer.echo writes its text as given, so through a bare call a workspace file name,
a project folder or a configuration path quoted in a refusal would reach a
terminal or a CI log with its controls (an OSC 52 clipboard write, a C1 CSI) and
its CI command forms (a newline then "::add-mask::", "##vso[" anywhere). The
console sinks write such text with its controls as escapes and its command
forms broken; a bare typer.echo writes it as given. So every typer.echo and
secho in the package goes through utils/console.py's echo and secho, which
pass the text through terminal_text's shown_not_obeyed, and echo_raw is kept
for machine output (a JSON skeleton a script parses). typer.echo does not
wrap, so the text rule is enough here.

typer.prompt and typer.confirm write their question through the same echo, and
the wizard's questions quote the file it edits: a plugin module's name, and the
project name as the first prompt's default. They go through utils/console.py's
prompt and confirm, which show the question and the default the same way.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.unit.walked_package import package_sources

pytestmark = pytest.mark.unit

runner = CliRunner()

#: A raw control a terminal acts on (tab and newline lay text out and are kept),
#: the bidirectional and format controls built with chr() so this file holds none.
_BIDI = "".join(chr(c) for c in (0x061C, 0x200E, 0x200F))
_BIDI += f"{chr(0x202A)}-{chr(0x202E)}{chr(0x2066)}-{chr(0x2069)}"
_RAW = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")
#: A line a CI runner reads as a command.
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

HOSTILE_NAME = (
    "p\x1b]52;c;ZXZpbA==\x07\n::add-mask::hidden ##vso[task.setvariable variable=x]y"
)
AZURE_FOLDER = "app ##vso[task.complete result=Succeeded]x"

posix_names = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names cannot hold control characters"
)


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def no_scan(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
        raising=True,
    )
    return calls


def _assert_shown(text: str) -> None:
    assert not _RAW.search(text), repr(text)
    assert not _COMMAND_LINE.search(text), _COMMAND_LINE.search(text)


def _workspace(root: Path, folders, name="dev.code-workspace") -> Path:
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


@posix_names
def test_two_workspace_candidates_are_named_shown_not_obeyed(
    tmp_path, no_scan, monkeypatch
):
    (tmp_path / "api").mkdir()
    _workspace(tmp_path, ["api"], name="alpha.code-workspace")
    _workspace(tmp_path, ["api"], name=f"{HOSTILE_NAME}.code-workspace")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["scan", "--workspace", "auto"])

    assert result.exit_code == 4, result.output
    assert "alpha.code-workspace" in result.output, result.output
    assert "add-mask" in result.output, result.output
    _assert_shown(result.output)
    assert not no_scan


@pytest.mark.parametrize(
    "folder",
    [
        pytest.param(AZURE_FOLDER, id="azure-command"),
        pytest.param(
            "app\n::add-mask::hidden",
            id="newline-command",
            marks=posix_names,
        ),
    ],
)
def test_a_dry_run_plan_shows_the_folders_it_quotes(
    tmp_path, no_scan, monkeypatch, folder
):
    (tmp_path / folder).mkdir()
    _workspace(tmp_path, [folder])
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["scan", "--workspace", "auto", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "Succeeded" in result.output or "add-mask" in result.output, result.output
    _assert_shown(result.output)
    assert not no_scan


def test_a_refused_policy_pattern_is_shown_on_one_line(tmp_path, no_scan, monkeypatch):
    """A workspace policy pattern is quoted twice in its refusal, and the refusal
    is one line: a newline in the pattern is written \\x0a each time, so the
    pattern cannot start a line of its own, "::error::" or any other."""
    (tmp_path / "api").mkdir()
    workspace = _workspace(tmp_path, ["api"])
    (tmp_path / "ash-workspace.yaml").write_text(
        'workspace:\n  suppressions:\n    - path: "api/./x\\n::error::X"\n'
        "      rule_id: R1\n      reason: r\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["scan", "--workspace", str(workspace), "--dry-run"])

    assert result.exit_code == 4, result.output
    assert result.output.endswith("\n"), repr(result.output)
    assert result.output.count("\n") == 1, repr(result.output)
    assert result.output.count("\\x0a") == 2, repr(result.output)
    # Shown once: a second showing writes the backslash again, "\\\\x0a", which
    # the count above also matches.
    assert "\\\\x0a" not in result.output, repr(result.output)
    _assert_shown(result.output)
    assert not no_scan


@posix_names
def test_a_listed_refusal_keeps_each_project_inside_its_item(
    tmp_path, no_scan, monkeypatch
):
    """A refusal that lists problems keeps ASH's layout, a headline and one line per
    item, while the project name in an item is shown on that line: a newline in it
    is written \\x0a, so "\\n  - forged" cannot add an item of its own."""
    workspace = _workspace(tmp_path, ["api\n  - forged"])
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["scan", "--workspace", str(workspace), "--dry-run"])

    assert result.exit_code == 4, result.output
    lines = result.output.splitlines()
    assert len(lines) == 2, repr(result.output)
    assert lines[0].endswith("to skip them instead:"), repr(result.output)
    assert lines[1].startswith("  - 'api\\x0a  - forged' does not exist"), lines[1]
    _assert_shown(result.output)
    assert not no_scan


@pytest.mark.parametrize("command", ["validate", "get"])
def test_ash_config_shows_what_it_quotes(tmp_path, monkeypatch, command):
    """An extends path is read from the config file, which the repository holds."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cfg.yaml").write_text(
        'project_name: x\nextends: "nope\\e]52;c;ZXZpbA==\\a\\x9b2K\\n'
        '::add-mask::hidden ##vso[task.complete]x.yaml"\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["config", command, "--config", "cfg.yaml"])

    assert result.exit_code == 3, result.output
    assert "add-mask" in result.output, result.output
    _assert_shown(result.output)


def test_ash_plugin_list_shows_the_configuration_error_it_quotes(tmp_path, monkeypatch):
    """`ash plugin list -c` refuses a config it cannot load, and the error quotes
    the file's extends path, which the repository chose."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cfg.yaml").write_text(
        'project_name: x\nextends: "nope\\e]52;c;ZXZpbA==\\a\\x9b2K\\n'
        '::add-mask::hidden ##vso[task.complete]x.yaml"\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["plugin", "list", "-c", "cfg.yaml"])

    assert result.exit_code == 3, result.output
    assert "Invalid configuration" in result.output, result.output
    assert "add-mask" in result.output, result.output
    _assert_shown(result.output)


#: Enter, for every question the wizard asks: each keeps its default.
_KEEP_EVERY_DEFAULT = "\n" * 300


def _wizard(config_file: Path):
    return runner.invoke(
        app,
        ["config", "wizard", "--config", str(config_file)],
        input=_KEEP_EVERY_DEFAULT,
    )


@posix_names
def test_the_wizards_questions_show_what_they_quote(tmp_path, monkeypatch):
    """typer.prompt and typer.confirm write their text, and a prompt its default,
    through click's echo as given. The wizard asks about the configuration it
    edits: the project name is the first prompt's default, and each plugin module
    is named in a question of its own."""
    monkeypatch.chdir(tmp_path)
    config_file = tmp_path / ".ashrc.yaml"
    # No backslash in the names: the rule doubles one that comes before a shown
    # control, which the last assertion would read as a second escape.
    config_file.write_text(
        'project_name: "p\\e]8;;https://example.invalid\\a \\x9b2K'
        '\\n::error title=x::pwned"\n'
        "ash_plugin_modules:\n"
        '  - "mod\\e]52;c;ZXZpbA==\\a\\n::add-mask::hidden ##vso[task.complete]x"\n',
        encoding="utf-8",
    )

    result = _wizard(config_file)

    assert result.exit_code == 0, result.output
    assert "Keep module 'mod" in result.output, result.output
    assert "Project name [p" in result.output, result.output
    _assert_shown(result.output)
    assert "\\x1b]52;c;ZXZpbA==\\x07" in result.output, result.output
    assert "\\x1b]8;;https://example.invalid" in result.output, result.output
    # Each control shown once: the list of modules is not shown again.
    assert "\\\\x" not in result.output, result.output


@pytest.mark.parametrize(
    "module",
    [
        pytest.param("legacy[/bold]", id="closing-tag"),
        pytest.param("[bold]legacy[/bold]", id="tags"),
    ],
)
def test_the_wizard_lists_the_configured_modules_as_written(
    tmp_path, monkeypatch, module
):
    """The list of modules is printed by rich, which read the names as markup."""
    monkeypatch.chdir(tmp_path)
    config_file = tmp_path / ".ashrc.yaml"
    config_file.write_text(
        f"project_name: x\nash_plugin_modules:\n  - '{module}'\n", encoding="utf-8"
    )

    result = _wizard(config_file)

    assert result.exit_code == 0, result.output
    assert f"Currently configured: ['{module}']" in result.output, result.output


@posix_names
def test_the_wizard_names_its_config_file_as_written(tmp_path, monkeypatch):
    """The panels that name the file read it as markup: here a closing tag."""
    monkeypatch.setenv("COLUMNS", "1000")
    folder = tmp_path / "proj[" / "bold]"
    folder.mkdir(parents=True)
    config_file = folder / ".ashrc.yaml"
    config_file.write_text("project_name: x\n", encoding="utf-8")
    monkeypatch.chdir(folder)

    result = _wizard(config_file)

    assert result.exit_code == 0, result.output
    assert "proj[/bold]/.ashrc.yaml" in result.output, result.output


def test_echo_and_secho_show_the_text_and_echo_raw_keeps_it(capsys):
    from automated_security_helper.utils.console import echo, echo_raw, secho

    echo(HOSTILE_NAME)
    secho(HOSTILE_NAME, fg="red", err=True)
    out, err = capsys.readouterr()
    _assert_shown(out)
    _assert_shown(err)
    assert "\\x1b]52;c;ZXZpbA==\\x07" in out, out

    echo_raw('{"a": "##[error]x"}')
    assert capsys.readouterr().out == '{"a": "##[error]x"}\n'


PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"


def _package_sources(package: Path = PACKAGE) -> list[Path]:
    # Refused unless every part of the package is in the walk (walked_package).
    return package_sources(package)


#: typer.echo is click's echo, which typer vendors as typer._click.utils.echo, so
#: a module anywhere under either package can hand one out.
_ECHO_PACKAGES = {"typer", "click"}
#: Each writes its text as given: a prompt and a confirmation write their question
#: through echo, and the pager writes its pages to the terminal.
_ECHO_NAMES = {"echo", "secho", "prompt", "confirm", "echo_via_pager"}


def _echo_offenders(tree: ast.AST, relative: str) -> list[str]:
    """Every way *tree* reaches typer's or click's echo, secho, prompt, confirm or
    echo_via_pager.

    Import aliases are followed: ``import typer as t``, ``import click.utils as u``
    and ``from typer import _click`` bind a name that is checked where it is used,
    and ``getattr`` with a constant name counts as the attribute.
    """
    modules: dict[str, str] = {}  # bound name -> typer or click module it stands for
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _ECHO_PACKAGES and alias.asname:
                    modules[alias.asname] = alias.name
                elif root in _ECHO_PACKAGES:  # "import click.utils" binds "click"
                    modules[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            if node.module.split(".")[0] in _ECHO_PACKAGES:
                for alias in node.names:
                    if alias.name not in _ECHO_NAMES and alias.name != "*":
                        bound = alias.asname or alias.name
                        modules[bound] = f"{node.module}.{alias.name}"

    def resolve(node: ast.AST) -> str | None:
        """The dotted typer or click name an expression stands for, if it is one."""
        if isinstance(node, ast.Name):
            return modules.get(node.id)
        if isinstance(node, ast.Attribute):
            base = resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    offenders = []
    for node in ast.walk(tree):
        where = f"{relative}:{getattr(node, 'lineno', 0)}"
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            if node.module.split(".")[0] in _ECHO_PACKAGES:
                offenders.extend(
                    f"{where} from {node.module} import {alias.name}"
                    for alias in node.names
                    if alias.name in _ECHO_NAMES or alias.name == "*"
                )
        elif isinstance(node, ast.Attribute) and node.attr in _ECHO_NAMES:
            base = resolve(node.value)
            if base:
                offenders.append(f"{where} {base}.{node.attr}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _ECHO_NAMES
        ):
            base = resolve(node.args[0])
            if base:
                offenders.append(f"{where} getattr({base}, {node.args[1].value!r})")
    return offenders


def test_nothing_else_calls_typer_or_click_echo():
    """A direct typer.echo, secho, prompt or confirm, or click's, or click's
    echo_via_pager, writes past the text rule."""
    found = []
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative == "utils/console.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        found.extend(_echo_offenders(tree, relative))

    assert found == [], found


@pytest.mark.parametrize(
    "source, line",
    [
        pytest.param("import typer\ntyper.echo('x')\n", 2, id="typer-echo"),
        pytest.param("from typer import secho\n", 1, id="from-typer"),
        pytest.param("import click\nclick.secho('x')\n", 2, id="click-secho"),
        pytest.param("import typer as t\nt.echo('x')\n", 2, id="typer-alias-echo"),
        pytest.param("import typer as t\nt.secho('x')\n", 2, id="typer-alias-secho"),
        pytest.param("import click\nclick.utils.echo('x')\n", 2, id="click-utils"),
        pytest.param("from click.termui import secho\n", 1, id="from-click-termui"),
        pytest.param("from typer._click import echo\n", 1, id="from-typer-click"),
        pytest.param(
            "from typer._click.utils import echo as e\n", 1, id="from-typer-click-utils"
        ),
        pytest.param(
            "from typer import _click\n\n_click.utils.echo('x')\n",
            3,
            id="typer-click-module",
        ),
        pytest.param(
            "import click.utils as u\nu.echo('x')\n", 2, id="click-utils-alias"
        ),
        pytest.param(
            "import typer as t\ngetattr(t, 'echo')('x')\n", 2, id="getattr-echo"
        ),
        pytest.param("import typer\ntyper.confirm('x')\n", 2, id="typer-confirm"),
        pytest.param("from click import prompt\n", 1, id="from-click-prompt"),
        pytest.param(
            "import click\nclick.echo_via_pager('x')\n", 2, id="click-echo-via-pager"
        ),
    ],
)
def test_the_echo_guard_finds_each_way_to_typer_or_click_echo(source, line):
    offenders = _echo_offenders(ast.parse(source), "fixture.py")

    assert any(o.startswith(f"fixture.py:{line} ") for o in offenders), offenders


def test_the_echo_guard_refuses_a_tree_with_nothing_to_check(tmp_path):
    """Moved or pointed elsewhere, the guard would pass having read no module."""
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(AssertionError):
        _package_sources(tmp_path)
