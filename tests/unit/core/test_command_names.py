"""The commands a hint or a message prints come from one registry below the CLI.

``core/command_names.py`` names each ``ash`` command that a hint outside the CLI
prints, so a hint never names a command the CLI does not register, and a
rename is one edit. It lists only commands the CLI registers; the walk below
fails for any other. The loader, the models and lint read it, and it imports
nothing from the CLI, which imports them.
"""

from pathlib import Path
from typing import Any, Dict

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
