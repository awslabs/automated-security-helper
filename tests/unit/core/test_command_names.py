"""The commands a hint or a message prints come from one registry below the CLI.

``core/command_names.py`` names each ``ash`` command that a hint outside the CLI
prints, so a hint never names a command the CLI does not register, and a
rename is one edit. It lists only commands the CLI registers; the walk below
fails for any other. The loader, the models and lint read it, and it imports
nothing from the CLI, which imports them.

Every printed command is built by its ``render_command``, which quotes each
argument, so a name a repository chose (a file name with ``;`` or ``|`` in it)
cannot become shell text when the command is pasted. No string literal in the
package spells a listed name outside the registry.
"""

import ast
import shlex
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import click
import pytest
import typer.main
import yaml

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.core import command_names

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

SENTINEL = "ash-registry-sentinel lint"


def _is_a_command(path: str) -> bool:
    program, *words = path.split()
    if program != "ash" or not words:
        return False
    command: Any = typer.main.get_command(ash_app)
    context = click.Context(command, info_name=program)
    for word in words:
        if not isinstance(command, click.Group):
            return False
        sub = command.get_command(context, word)
        if sub is None:
            return False
        context = click.Context(sub, parent=context, info_name=word)
        command = sub
    return True


@pytest.mark.parametrize("name", command_names.REGISTERED)
def test_every_listed_name_is_a_command_the_cli_registers(name: str) -> None:
    assert _is_a_command(name), name


def test_the_walk_refuses_a_command_the_cli_does_not_register() -> None:
    """The control: the walk can fail."""
    assert not _is_a_command("ash config no-such-command")
    assert not _is_a_command("ash")


def test_every_listed_name_is_in_the_list_the_walk_reads() -> None:
    listed = {
        value
        for name, value in vars(command_names).items()
        if name.isupper() and isinstance(value, str)
    }

    assert listed == set(command_names.REGISTERED)


def test_the_registry_imports_nothing_from_the_cli() -> None:
    source = Path(command_names.__file__).read_text(encoding="utf-8")

    assert "automated_security_helper.cli" not in source
    assert "typer" not in source
    assert "click" not in source


def test_a_refusals_lint_hint_takes_its_command_from_the_registry(
    monkeypatch, tmp_path: Path
) -> None:
    from automated_security_helper.config.resolve_config import lint_hint

    monkeypatch.setattr(command_names, "CONFIG_LINT", SENTINEL)

    assert SENTINEL in lint_hint(tmp_path / ".ash.yaml")


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ((), "ash config lint"),
        (("--fix",), "ash config lint --fix"),
        (
            ("--config", "a;curl x|sh;.yaml"),
            "ash config lint --config 'a;curl x|sh;.yaml'",
        ),
        (
            ("--config", "dir with space/.ash.yaml"),
            "ash config lint --config 'dir with space/.ash.yaml'",
        ),
        (("--config", "it's.yaml"), "ash config lint --config 'it'\"'\"'s.yaml'"),
    ],
    ids=["bare", "flag", "metacharacters", "space", "quote"],
)
def test_a_command_quotes_each_argument(
    arguments: Tuple[str, ...], expected: str
) -> None:
    rendered = command_names.render_command(command_names.CONFIG_LINT, *arguments)

    assert rendered == expected


def test_a_placeholder_is_printed_as_itself() -> None:
    """A part that stands for a value the message names elsewhere is not a value."""
    rendered = command_names.render_command(
        command_names.CONFIG_LINT,
        "--config",
        command_names.Placeholder("the file named above"),
    )

    assert rendered == "ash config lint --config <the file named above>"


@pytest.mark.parametrize(
    "path", ["cfg/.ash.yaml", "C:/repo/.ash.yaml", "a_b-c.d/e:f", "-odd-.yaml"]
)
def test_quoting_leaves_a_path_lint_hint_prints_as_it_is(path: str) -> None:
    """Why lint_hint's bytes do not change: every path it prints is one that
    shlex leaves bare."""
    from automated_security_helper.config.resolve_config import pasteable_path

    assert pasteable_path(path)
    assert shlex.quote(path) == path


def test_lint_hint_builds_its_command_with_render_command(
    monkeypatch, tmp_path: Path
) -> None:
    from automated_security_helper.config.resolve_config import lint_hint

    calls: List[Tuple[str, Tuple[Any, ...]]] = []

    def spy(name: str, *arguments: Any) -> str:
        calls.append((name, arguments))
        return "SPY-COMMAND"

    monkeypatch.setattr(command_names, "render_command", spy)

    assert lint_hint(tmp_path / ".ash.yaml") == "Run: SPY-COMMAND"
    assert [name for name, _ in calls] == [command_names.CONFIG_LINT]


def test_lint_hint_never_prints_a_file_name_that_holds_shell_metacharacters(
    tmp_path: Path,
) -> None:
    """The guard: no one quoting is safe in every shell, so such a name is
    pointed at, never printed."""
    from automated_security_helper.config.resolve_config import lint_hint

    hint = lint_hint(tmp_path / "a;curl x|sh;.yaml")

    assert "curl" not in hint
    assert "<the file named above>" in hint


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_lints_old_spelling_message_takes_its_command_from_the_registry(
    monkeypatch, tmp_path: Path
) -> None:
    from automated_security_helper.config.config_linter import (
        ConfigLinter,
        LintCategory,
    )

    monkeypatch.setattr(command_names, "CONFIG_LINT", SENTINEL)
    config = _write(
        tmp_path / ".ash.yaml",
        {
            "global_settings": {
                "suppressions": [
                    {
                        "rule_id": "B101",
                        "path": "src/app.py",
                        "reason": "reviewed",
                        "expiration": "2099-01-01",
                    }
                ]
            }
        },
    )

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues

    (issue,) = [i for i in issues if i.category == LintCategory.DEPRECATED_SPELLING]
    assert f"{SENTINEL} --fix" in issue.message


def _printed_strings(source: str) -> Iterator[Tuple[int, str]]:
    """Each string literal in ``source`` that a program can print, with its line.

    A string that is a whole statement (a docstring, or a string used as a
    comment) is left out; every other literal is in, the literal parts of an
    f-string included. Adjacent literals are one literal here, as the parser
    joins them.
    """
    tree = ast.parse(source)
    statements = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in statements
        ):
            yield node.lineno, node.value


def test_the_scan_finds_a_printed_name_and_leaves_out_a_docstring() -> None:
    """The control: the scan below can fail."""
    name = command_names.REGISTERED[0]
    source = (
        "def hint():\n"
        f'    """Say {name} in a docstring."""\n'
        f'    return f"run {{1}} or {name} --fix"\n'
    )

    printed = [text for _, text in _printed_strings(source)]

    assert [text for text in printed if name in text] == [f" or {name} --fix"]


def test_no_printed_string_outside_the_registry_spells_a_listed_name() -> None:
    """A printed command reads its name from the registry, so a rename is one
    edit and a hint can only name what the CLI registers."""
    registry = Path(command_names.__file__).resolve()
    package = registry.parents[1]
    found: List[str] = []
    for path in sorted(package.rglob("*.py")):
        if path.resolve() == registry:
            continue
        source = path.read_text(encoding="utf-8")
        for line, text in _printed_strings(source):
            found.extend(
                f"{path.relative_to(package.parent)}:{line}: {name}"
                for name in command_names.REGISTERED
                if name in text
            )

    assert found == []
