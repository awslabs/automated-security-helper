"""The commands a hint or a message prints come from one registry below the CLI.

``config/command_names.py`` names each ``ash`` command that a hint outside the CLI
prints, with the options and flags a printed one may carry, so a hint never names
a command, an option or a flag the CLI does not register, and a rename is one
edit. The walk below fails for any other. The loader, the models and lint read
it, and it imports nothing from the CLI, which imports them.

A printed command is built by ``render_command``. It returns the line only when
every value the line carries is made of ASCII letters, digits and ``_ . / : -``
(the rule lint_hint has always applied) and no positional starts with ``-``, and
returns nothing otherwise: such a line reads alike in POSIX shells, cmd.exe and
PowerShell, and no one quoting does. A command to run is ``command_argv``, the
same words with each value exactly as given. A name a message shows goes through
the package's one rule for showing text (``terminal_text``). No string literal in
the package spells a listed name outside the registry.
"""

import ast
import dataclasses
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
import typer.main
import yaml

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.config import command_names
from automated_security_helper.utils.terminal_text import ShownText, shown_on_one_line

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

SENTINEL_TEXT = "ash-registry-sentinel lint"

#: A command the tests print with every kind of word; no hint names it.
EXAMPLE = command_names.Command(
    text="ash example run",
    options=frozenset({"--to"}),
    flags=frozenset({"--accept"}),
)


def _sentinel() -> command_names.Command:
    """The lint command under another name, with the same options and flags."""
    return dataclasses.replace(command_names.CONFIG_LINT, text=SENTINEL_TEXT)


def _click_command(text: str) -> Optional[Any]:
    """The command the CLI registers under ``text``, or None.

    Walked by duck type, through each group's ``commands``: typer builds its
    commands and options from its own copy of click, so they are not instances
    of any click class a test imports.
    """
    program, *words = text.split()
    if program != "ash" or not words:
        return None
    command: Any = typer.main.get_command(ash_app)
    for word in words:
        commands = getattr(command, "commands", None)
        sub = commands.get(word) if commands is not None else None
        if sub is None:
            return None
        command = sub
    return command


def _is_an_option(param: Any, name: str) -> bool:
    return getattr(param, "param_type_name", "") == "option" and name in (
        *param.opts,
        *param.secondary_opts,
    )


def _takes_a_value(command: Any, name: str) -> bool:
    return any(
        _is_an_option(param, name)
        and name in param.opts
        and not param.is_flag
        and not param.count
        and param.nargs == 1
        for param in command.params
    )


def _is_a_flag(command: Any, name: str) -> bool:
    return any(
        _is_an_option(param, name) and param.is_flag and param.is_bool_flag
        for param in command.params
    )


REGISTERED_IDS = [command.text for command in command_names.REGISTERED]


@pytest.mark.parametrize("command", command_names.REGISTERED, ids=REGISTERED_IDS)
def test_every_listed_command_is_one_the_cli_registers(
    command: command_names.Command,
) -> None:
    assert _click_command(command.text) is not None, command.text


def test_the_walk_refuses_a_command_the_cli_does_not_register() -> None:
    """The control: the walk can fail."""
    assert _click_command("ash config no-such-command") is None
    assert _click_command("ash") is None


@pytest.mark.parametrize("command", command_names.REGISTERED, ids=REGISTERED_IDS)
def test_every_listed_option_takes_a_value_and_every_flag_takes_none(
    command: command_names.Command,
) -> None:
    cli = _click_command(command.text)
    assert cli is not None

    assert [name for name in command.options if not _takes_a_value(cli, name)] == []
    assert [name for name in command.flags if not _is_a_flag(cli, name)] == []


def test_the_word_checks_can_fail() -> None:
    """The control: each check can fail."""
    cli = _click_command(command_names.CONFIG_LINT.text)
    assert cli is not None

    assert not _takes_a_value(cli, "--no-such-option")
    assert not _takes_a_value(cli, "--fix")
    assert not _is_a_flag(cli, "--config")
    assert not _is_a_flag(cli, "--no-such-option")


def test_the_lint_command_lists_the_words_its_hints_print() -> None:
    assert command_names.CONFIG_LINT.text == "ash config lint"
    assert {"--config", "--source-dir"} <= command_names.CONFIG_LINT.options
    assert "--fix" in command_names.CONFIG_LINT.flags


def test_every_listed_command_is_in_the_list_the_walk_reads() -> None:
    listed = {
        value
        for name, value in vars(command_names).items()
        if name.isupper() and isinstance(value, command_names.Command)
    }

    assert listed == set(command_names.REGISTERED)


def test_the_registry_imports_nothing_from_the_cli() -> None:
    source = Path(command_names.__file__).read_text(encoding="utf-8")

    assert "automated_security_helper.cli" not in source
    assert "typer" not in source
    assert "click" not in source


def test_the_registry_never_quotes() -> None:
    """No quoting reads alike in every shell, so the module has none."""
    source = Path(command_names.__file__).read_text(encoding="utf-8")

    assert "shlex" not in source


@pytest.mark.parametrize(
    "words,expected",
    [
        ({}, "ash config lint"),
        ({"flags": ("--fix",)}, "ash config lint --fix"),
        (
            {"options": (("--config", "cfg/.ash.yaml"),)},
            "ash config lint --config cfg/.ash.yaml",
        ),
        (
            {"options": (("--config", "C:/repo/.ash.yaml"),)},
            "ash config lint --config C:/repo/.ash.yaml",
        ),
        (
            {
                "options": (
                    ("--config", "cfg/.ash.yaml"),
                    ("--source-dir", "/srv/repo"),
                )
            },
            "ash config lint --config cfg/.ash.yaml --source-dir /srv/repo",
        ),
        (
            {"options": (("--config", "-odd-.yaml"),)},
            "ash config lint --config -odd-.yaml",
        ),
    ],
    ids=["bare", "flag", "option", "drive", "two-options", "option-value-dash"],
)
def test_a_command_prints_each_word_as_it_is(
    words: Dict[str, Any], expected: str
) -> None:
    """A value a command carries is one no shell reads specially, so it is
    printed as it is, and every shell reads the line alike. An option's value may
    start with "-": the option takes the next word whatever it is."""
    assert command_names.render_command(command_names.CONFIG_LINT, **words) == expected


def test_a_command_prints_positionals_then_options_then_flags() -> None:
    rendered = command_names.render_command(
        EXAMPLE,
        positionals=("s-1a2b3c4d",),
        options=(("--to", "src/new.py"),),
        flags=("--accept",),
    )

    assert rendered == "ash example run s-1a2b3c4d --to src/new.py --accept"


#: Built from code points, so no file holds the characters themselves.
BACKSLASH = chr(92)
ESCAPE = chr(0x1B)
CARRIAGE_RETURN = chr(13)
RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
LEFT_TO_RIGHT_MARK = chr(0x200E)
NEWLINE = chr(10)

#: Values no command prints: each holds a character some shell reads, or one not
#: worth the doubt.
UNPASTEABLE = {
    "metacharacters": "a;curl x|sh;.yaml",
    "cmd-separator": "x & calc & .py",
    "space": "dir with space/.ash.yaml",
    "quote": "it's.yaml",
    "cmd-variable": "%PATH%.yaml",
    "powershell-splat": "@args",
    "comma": "a,b.yaml",
    "control": "cfg" + ESCAPE + ".yaml",
    "newline": "cfg" + NEWLINE + ".yaml",
    "non-ascii": "caf" + chr(0xE9) + ".yaml",
    "empty": "",
}

#: Names that hold a command separator, a terminal escape with a carriage return,
#: or a right-to-left override: each prints no command, and its argv is as given.
HOSTILE = {
    "cmd-separator": "x & calc & .py",
    "escape-and-return": "cfg" + ESCAPE + "[31m" + CARRIAGE_RETURN + ".yaml",
    "override": "cfg" + RIGHT_TO_LEFT_OVERRIDE + "lmay.yaml",
}


@pytest.mark.parametrize("value", list(UNPASTEABLE.values()), ids=list(UNPASTEABLE))
def test_a_command_with_an_option_value_some_shell_reads_is_not_printed(
    value: str,
) -> None:
    """No one quoting is safe in POSIX shells, cmd.exe and PowerShell alike, so a
    line that would carry such a value is not printed at all."""
    rendered = command_names.render_command(
        command_names.CONFIG_LINT, options=(("--config", value),)
    )

    assert rendered is None


@pytest.mark.parametrize("value", list(UNPASTEABLE.values()), ids=list(UNPASTEABLE))
def test_a_command_with_a_positional_some_shell_reads_is_not_printed(
    value: str,
) -> None:
    assert command_names.render_command(EXAMPLE, positionals=(value,)) is None


@pytest.mark.parametrize("value", ["--accept", "-x.yaml", "-"])
def test_a_command_with_a_positional_that_reads_as_an_option_is_not_printed(
    value: str,
) -> None:
    """A positional that starts with "-" is read as an option, so the line would
    run something other than what it says."""
    assert command_names.render_command(EXAMPLE, positionals=(value,)) is None


@pytest.mark.parametrize(
    "value",
    [*HOSTILE.values(), "--accept"],
    ids=[*HOSTILE, "positional-accept"],
)
def test_a_hostile_name_prints_no_command_and_runs_as_given(value: str) -> None:
    assert command_names.render_command(EXAMPLE, positionals=(value,)) is None
    assert command_names.command_argv(EXAMPLE, positionals=(value,)) == [
        "ash",
        "example",
        "run",
        value,
    ]


@pytest.mark.parametrize("value", list(HOSTILE.values()), ids=list(HOSTILE))
def test_a_hostile_option_value_prints_no_command_and_runs_as_given(
    value: str,
) -> None:
    options = (("--config", value),)

    assert (
        command_names.render_command(command_names.CONFIG_LINT, options=options) is None
    )
    assert command_names.command_argv(command_names.CONFIG_LINT, options=options) == [
        "ash",
        "config",
        "lint",
        "--config",
        value,
    ]


@pytest.mark.parametrize(
    "words",
    [
        {"positionals": "cfg"},
        {"options": "--config"},
        {"flags": "--fix"},
    ],
    ids=["positionals", "options", "flags"],
)
@pytest.mark.parametrize(
    "build",
    [command_names.render_command, command_names.command_argv],
    ids=["render", "argv"],
)
def test_a_group_of_words_given_as_text_is_refused(
    build: Any, words: Dict[str, Any]
) -> None:
    """Text iterates as its characters, so "--fix" given as the flags would print
    a line of single characters, or nothing."""
    with pytest.raises(TypeError):
        build(command_names.CONFIG_LINT, **words)


@pytest.mark.parametrize(
    "build",
    [command_names.render_command, command_names.command_argv],
    ids=["render", "argv"],
)
def test_the_words_are_given_by_keyword(build: Any) -> None:
    """A flag passed by position would land among the positionals. The words go
    as a tuple, so only the keyword-only rule refuses them: bare text would meet
    the group-as-text check first."""
    with pytest.raises(TypeError):
        build(command_names.CONFIG_LINT, ("--fix",))


@pytest.mark.parametrize(
    "words",
    [
        {"options": (("--no-such-option", "x"),)},
        {"flags": ("--no-such-flag",)},
        {"options": (("--fix", "x"),)},
        {"flags": ("--config",)},
    ],
    ids=["option", "flag", "flag-as-option", "option-as-flag"],
)
@pytest.mark.parametrize(
    "build",
    [command_names.render_command, command_names.command_argv],
    ids=["render", "argv"],
)
def test_a_word_the_registry_does_not_list_is_a_coding_error(
    build: Any, words: Dict[str, Any]
) -> None:
    """Option names and flags are code, never a repository's text, so one the
    registry does not list is an error, not a line left unprinted."""
    with pytest.raises(ValueError):
        build(command_names.CONFIG_LINT, **words)


@pytest.mark.parametrize(
    "build",
    [command_names.render_command, command_names.command_argv],
    ids=["render", "argv"],
)
def test_a_value_that_is_not_text_is_refused(build: Any) -> None:
    """The registry's own check refuses it, by its message: a regex given a path
    raises a TypeError too, and that one would pass a bare ``pytest.raises``."""
    value = Path("a.yaml")
    expected = f"a command's values are text, not {type(value).__name__}"
    with pytest.raises(TypeError, match=re.escape(expected)):
        build(command_names.CONFIG_LINT, options=(("--config", value),))


@pytest.mark.parametrize(
    "command,words",
    [
        (command_names.CONFIG_LINT, {}),
        (command_names.CONFIG_LINT, {"flags": ("--fix",)}),
        (command_names.CONFIG_LINT, {"options": (("--config", "cfg/.ash.yaml"),)}),
        (
            command_names.CONFIG_LINT,
            {
                "options": (
                    ("--config", "C:/repo/.ash.yaml"),
                    ("--source-dir", "/srv/repo"),
                )
            },
        ),
        (
            EXAMPLE,
            {
                "positionals": ("s-1a2b3c4d",),
                "options": (("--to", "src/new.py"),),
                "flags": ("--accept",),
            },
        ),
    ],
    ids=["bare", "flag", "option", "two-options", "every-kind"],
)
def test_a_printed_command_has_the_words_of_the_command_to_run(
    command: command_names.Command, words: Dict[str, Any]
) -> None:
    """No word of a printed line is quoted, so its words split at the spaces are
    the argv the command runs with."""
    printed = command_names.render_command(command, **words)

    assert printed is not None
    assert printed.split(" ") == command_names.command_argv(command, **words)


@pytest.mark.parametrize("value", list(UNPASTEABLE.values()), ids=list(UNPASTEABLE))
def test_a_command_to_run_keeps_any_value_as_given(value: str) -> None:
    """A command that is run is never read by a shell, so any name is one
    argument, exactly as given, never quoted."""
    assert command_names.command_argv(
        command_names.CONFIG_LINT, options=(("--config", value),)
    ) == ["ash", "config", "lint", "--config", value]
    assert command_names.command_argv(EXAMPLE, positionals=(value,)) == [
        "ash",
        "example",
        "run",
        value,
    ]


#: lint_hint's line when either of two paths is outside the plain set.
BOTH_POINTED_AT = (
    "Run: ash config lint --config <the file named above>"
    " --source-dir <the directory the scan scanned>"
)

#: lint_hint's output for each path: a path the plain set holds is printed, and
#: when any printed path is outside it, neither is, and the line ends in ">",
#: which no shell runs.
LINT_HINTS = [
    ("cfg/.ash.yaml", None, "Run: ash config lint --config cfg/.ash.yaml"),
    ("C:/repo/.ash.yaml", None, "Run: ash config lint --config C:/repo/.ash.yaml"),
    ("-odd-.yaml", None, "Run: ash config lint --config -odd-.yaml"),
    (
        "cfg/.ash.yaml",
        "/srv/repo",
        "Run: ash config lint --config cfg/.ash.yaml --source-dir /srv/repo",
    ),
    (
        "x & calc & .py",
        None,
        "Run: ash config lint --config <the file named above>",
    ),
    ("dir with space/.ash.yaml", "/srv/repo", BOTH_POINTED_AT),
    ("cfg/.ash.yaml", "/srv/my repo", BOTH_POINTED_AT),
]


@pytest.mark.parametrize(
    "config,source_dir,expected",
    LINT_HINTS,
    ids=[
        "path",
        "drive",
        "dash",
        "two-paths",
        "unpasteable",
        "unpasteable-config",
        "unpasteable-source-dir",
    ],
)
def test_lint_hint_prints_what_main_prints(
    config: str, source_dir: Optional[str], expected: str
) -> None:
    from automated_security_helper.config.resolve_config import lint_hint

    assert lint_hint(Path(config), source_dir) == expected


@pytest.mark.parametrize("name", list(HOSTILE.values()), ids=list(HOSTILE))
def test_lint_hint_never_prints_a_hostile_name(name: str) -> None:
    """The guard: such a name is pointed at, never printed."""
    from automated_security_helper.config.resolve_config import lint_hint

    hint = lint_hint(Path(name))

    assert hint == "Run: ash config lint --config <the file named above>"


@pytest.mark.parametrize(
    "config", ["cfg/.ash.yaml", "x & calc & .py"], ids=["printed", "pointed-at"]
)
def test_a_refusals_lint_hint_takes_its_command_from_the_registry(
    monkeypatch, config: str
) -> None:
    from automated_security_helper.config.resolve_config import lint_hint

    monkeypatch.setattr(command_names, "CONFIG_LINT", _sentinel())

    assert lint_hint(Path(config)).startswith(f"Run: {SENTINEL_TEXT} --config ")


def test_lint_hint_builds_its_command_with_render_command(monkeypatch) -> None:
    from automated_security_helper.config.resolve_config import lint_hint

    calls: List[Tuple[Any, ...]] = []

    def spy(command: Any, *, positionals=(), options=(), flags=()) -> str:
        calls.append(
            (
                command,
                tuple(positionals),
                tuple(tuple(pair) for pair in options),
                tuple(flags),
            )
        )
        return "SPY-COMMAND"

    monkeypatch.setattr(command_names, "render_command", spy)

    assert lint_hint(Path("cfg/.ash.yaml"), "/srv/repo") == "Run: SPY-COMMAND"
    assert calls == [
        (
            command_names.CONFIG_LINT,
            (),
            (("--config", "cfg/.ash.yaml"), ("--source-dir", "/srv/repo")),
            (),
        )
    ]


def test_lint_hint_points_at_the_file_when_render_command_prints_nothing(
    monkeypatch,
) -> None:
    from automated_security_helper.config.resolve_config import lint_hint

    def nothing(command: Any, **words: Any) -> None:
        return None

    monkeypatch.setattr(command_names, "CONFIG_LINT", _sentinel())
    monkeypatch.setattr(command_names, "render_command", nothing)

    assert lint_hint(Path("cfg/.ash.yaml")) == (
        f"Run: {SENTINEL_TEXT} --config <the file named above>"
    )


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

    monkeypatch.setattr(command_names, "CONFIG_LINT", _sentinel())
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
    assert f"{SENTINEL_TEXT} --fix" in issue.message


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
    name = command_names.REGISTERED[0].text
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
                f"{path.relative_to(package.parent)}:{line}: {command.text}"
                for command in command_names.REGISTERED
                if command.text in text
            )

    assert found == []


#: Control characters (C0, delete and C1), bidirectional marks, overrides and
#: isolates, and the line and paragraph separators, each with the escape
#: terminal_text writes it as.
ESCAPED = {
    "tab": (0x09, "x09"),
    "line-feed": (0x0A, "x0a"),
    "carriage-return": (0x0D, "x0d"),
    "escape": (0x1B, "x1b"),
    "delete": (0x7F, "x7f"),
    "c1": (0x9B, "x9b"),
    "left-to-right-mark": (0x200E, "u200e"),
    "right-to-left-override": (0x202E, "u202e"),
    "left-to-right-isolate": (0x2066, "u2066"),
    "pop-directional-isolate": (0x2069, "u2069"),
    "line-separator": (0x2028, "u2028"),
    "paragraph-separator": (0x2029, "u2029"),
}


@pytest.mark.parametrize("code_point,escape", list(ESCAPED.values()), ids=list(ESCAPED))
def test_terminal_text_writes_out_each_listed_character(
    code_point: int, escape: str
) -> None:
    shown = command_names.terminal_text("cfg" + chr(code_point) + ".yaml")

    assert shown == "cfg" + BACKSLASH + escape + ".yaml"


def test_terminal_text_doubles_a_backslash_that_reads_as_an_escape() -> None:
    """Text that spells an escape is not one, and reads as text."""
    shown = command_names.terminal_text("cfg" + BACKSLASH + "x1b.yaml")

    assert shown == "cfg" + BACKSLASH + BACKSLASH + "x1b.yaml"


@pytest.mark.parametrize(
    "value",
    [
        "cfg" + ESCAPE + "[31m.yaml",
        "cfg" + RIGHT_TO_LEFT_OVERRIDE + "lmay.yaml",
        "cfg" + LEFT_TO_RIGHT_MARK + ".yaml",
        "cfg" + NEWLINE + "::error::x.yaml",
        "cfg" + BACKSLASH + "x1b.yaml",
    ],
    ids=["escape", "override", "mark", "newline", "escape-text"],
)
def test_terminal_text_shows_a_name_by_the_packages_one_rule(value: str) -> None:
    """A name a repository chose is shown by the rule every sink in the package
    applies (utils/terminal_text.py), not by a second one, and as text shown
    once, which a sink then leaves as it is."""
    shown = command_names.terminal_text(value)

    assert shown == shown_on_one_line(value)
    assert isinstance(shown, ShownText)


@pytest.mark.parametrize(
    "value", ["cfg.yaml", "dir/sub-name_1.yml", "caf" + chr(0xE9) + ".yaml"]
)
def test_terminal_text_keeps_an_ordinary_name(value: str) -> None:
    assert command_names.terminal_text(value) == value


#: The package's escapes, after a backslash: x and two hex digits, u and four, or
#: U and eight.
_ESCAPE = re.compile(r"x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}")


def _source_of(shown: str) -> str:
    """The one text that ``shown`` shows, read by the package's escape rules.

    A run of n backslashes before text that reads as an escape stands for n // 2
    backslashes, and when n is odd its last backslash starts the escape. Any
    other run of backslashes stands for itself.
    """
    out: List[str] = []
    at = 0
    while at < len(shown):
        if shown[at] != BACKSLASH:
            out.append(shown[at])
            at += 1
            continue
        end = at
        while end < len(shown) and shown[end] == BACKSLASH:
            end += 1
        run = end - at
        escape = _ESCAPE.match(shown, end)
        if escape is None:
            out.append(BACKSLASH * run)
        else:
            out.append(BACKSLASH * (run // 2))
            if run % 2:
                out.append(chr(int(escape.group()[1:], 16)))
                end = escape.end()
        at = end
    return "".join(out)


#: Source texts, each with the escape vocabulary in mind.
READ_BACK = {
    "windows-path": "C:" + BACKSLASH + "repo" + BACKSLASH + "a.yaml",
    "escape-text": BACKSLASH + "x41",
    "two-backslashes-then-escape-text": BACKSLASH * 2 + "x41",
    "letter": "A",
    "escape": ESCAPE + "[31m",
    "backslash-then-escape": BACKSLASH + ESCAPE,
    "trailing-backslash": "dir" + BACKSLASH,
    "backslash-then-plain-text": "a" + BACKSLASH + "xyz",
    "override": RIGHT_TO_LEFT_OVERRIDE + "cfg",
    "override-text": BACKSLASH + "u202e",
    "layout": "tab" + chr(9) + "line" + NEWLINE + "end" + CARRIAGE_RETURN,
    "line-separator": "cfg" + chr(0x2028) + "x",
    "astral-format": "cfg" + chr(0xE0001),
    "astral-escape-text": BACKSLASH + "U000e0001",
    "lone-surrogate": "cfg" + chr(0xDC80),
    "private-use": "cfg" + chr(0xE000),
    "ci-command": "::error::x",
    "ci-command-text": BACKSLASH + "x3a:error::x",
    "ci-group": "##[group]x",
}


@pytest.mark.parametrize("source", list(READ_BACK.values()), ids=list(READ_BACK))
def test_every_shown_text_reads_back_as_one_source_text(source: str) -> None:
    """Under the package's escapes a shown text reads back as exactly one source
    text, so two names never show alike and none can pose as another."""
    assert _source_of(command_names.terminal_text(source)) == source


@pytest.mark.parametrize(
    "first,second",
    [
        ("A", BACKSLASH + "x41"),
        (ESCAPE, BACKSLASH + "x1b"),
        (BACKSLASH + ESCAPE, BACKSLASH * 2 + "x1b"),
        ("::x", BACKSLASH + "x3a:x"),
        (RIGHT_TO_LEFT_OVERRIDE, BACKSLASH + "u202e"),
    ],
    ids=["letter", "escape", "backslash-escape", "ci-command", "override"],
)
def test_a_character_and_the_text_of_its_escape_show_apart(
    first: str, second: str
) -> None:
    assert command_names.terminal_text(first) != command_names.terminal_text(second)


def test_a_windows_path_is_shown_as_it_is() -> None:
    """A backslash that cannot read as an escape is kept single, so it reads back
    as itself."""
    path = "C:" + BACKSLASH + "repo" + BACKSLASH + "a.yaml"

    assert command_names.terminal_text(path) == path


def test_text_that_spells_an_escape_shows_its_backslash_doubled() -> None:
    shown = command_names.terminal_text(BACKSLASH + "x41")

    assert shown == BACKSLASH * 2 + "x41"
    assert _source_of(shown) == BACKSLASH + "x41"
