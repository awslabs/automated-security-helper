"""The ``ash`` commands that a hint or a message outside the command line may name.

A message that tells a reader to run a command takes the command from here, with
the options and flags it may carry, so it can only name what the program
registers (a test walks this list against the real command tree) and a rename is
one edit. Only registered commands are listed.

This module sits below the command line: the loader, the models and lint read it,
and the command line imports them, so it imports nothing from the package but
``utils/terminal_text.py``, which imports nothing from it.

A command is built by :func:`render_command`. It returns the line only when every
value the line carries is :func:`pasteable` (ASCII letters, digits and
``_ . / : -``, which no shell reads specially) and no positional starts with
``-``, which the command would read as an option. Otherwise it returns nothing.
It does not quote: no quoting of a name reads the same in POSIX shells,
``cmd.exe`` and PowerShell, so a caller that gets nothing says what to do without
a command. A command that is run and not printed is :func:`command_argv`: the same
words as a list, each value exactly as given.

A call site that shows a whole one-line message itself, with a name a repository
chose in it, passes the message through :func:`terminal_text`, the package's one
rule for showing text it did not write. A message that goes on to a sink (the log,
the console, a refusal) is not passed through it: the sink shows the whole text
once, and a part shown here first would be shown twice.

Callers read the registry through the module when they run, as in
``command_names.render_command(command_names.CONFIG_LINT, ...)``, and never import
a name from it: a test that replaces one then sees it everywhere.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from automated_security_helper.utils.terminal_text import shown_on_one_line


@dataclass(frozen=True)
class Command:
    """A command a message may name, and the words it may be printed with.

    ``text`` is the command as it is typed. ``options`` are the names of the
    options that take a value, and ``flags`` the names of those that take none: a
    test walks each against the command the program registers. There is no
    ``__str__``: a command is named through ``text``, so a ``Command`` is never
    taken for the text it prints.
    """

    text: str
    options: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()


#: The command that reads a config file and reports what is wrong with it.
CONFIG_LINT = Command(
    text="ash config lint",
    options=frozenset({"--config", "--source-dir"}),
    flags=frozenset({"--fix"}),
)

#: Every command named above, for the test that walks each one against the
#: command tree. A command added above is added here.
REGISTERED = (CONFIG_LINT,)


# The characters a value of a printed command may hold: ASCII letters and
# digits, `_ . / : -`. No shell (POSIX shells, cmd.exe, PowerShell) reads any of
# them specially. The set is deliberately narrow: a character outside it is not
# necessarily special, but a space, `&`, `;`, a quote, `~`, `+`, `@`, a comma or
# non-ASCII text either is in some shell or is not worth the doubt.
_PASTEABLE = re.compile(r"[A-Za-z0-9_./:-]+")


def pasteable(text: str) -> bool:
    """Whether ``text`` is one bare word in every shell, so a command may print it.

    True for a non-empty ``text`` made only of ASCII letters and digits and
    ``_ . / : -``. Any other text is a name this module never prints.
    """
    return bool(_PASTEABLE.fullmatch(text))


def _words(
    command: Command,
    positionals: Sequence[str],
    options: Sequence[tuple[str, str]],
    flags: Sequence[str],
) -> list[str]:
    """The words a call carries after the command's text, in print order: the
    positionals, then each option's name and value, then the flags.

    The checks, in this order. A group given as text is a ``TypeError``: text
    iterates as its characters, so ``"--fix"`` given as the flags would be four
    flags of one character. An option or a flag the command does not list is a
    ``ValueError``: the names are code, never a repository's text, so one that is
    not listed is a coding error and not a line to leave unprinted. A value (a
    positional, or an option's value) that is not text is a ``TypeError``.
    """
    if any(isinstance(group, str) for group in (positionals, options, flags)):
        raise TypeError("positionals, options and flags are sequences, not text")
    for name, _ in options:
        if name not in command.options:
            raise ValueError(f"{name!r} is not an option of {command.text!r}")
    for flag in flags:
        if flag not in command.flags:
            raise ValueError(f"{flag!r} is not a flag of {command.text!r}")
    values = [*positionals, *(given for _, given in options)]
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"a command's values are text, not {type(value).__name__}")
    return [*positionals, *(word for pair in options for word in pair), *flags]


def render_command(
    command: Command,
    *,
    positionals: Sequence[str] = (),
    options: Sequence[tuple[str, str]] = (),
    flags: Sequence[str] = (),
) -> str | None:
    """``command`` and its words, joined by single spaces, as one printed line, or
    None when some value cannot be printed.

    The words are the ``positionals``, then each of the ``options`` (its name and
    its value), then the ``flags``, each group given by keyword. A value is
    printed as it is, so every one must be :func:`pasteable`: one bare word in
    POSIX shells, ``cmd.exe`` and PowerShell alike. No positional may start with
    ``-``, which the command would read as an option; an option's value may, since
    the option takes the next word whatever it is. When a value fails either rule
    the result is None, so a line is never printed that runs something other than
    what it says. A call with no value always prints.

    The checks of :func:`command_argv` come first, and a call that fails one
    raises instead of returning None.
    """
    words = _words(command, positionals, options, flags)
    values = [*positionals, *(value for _, value in options)]
    if not all(pasteable(value) for value in values):
        return None
    if any(value.startswith("-") for value in positionals):
        return None
    return " ".join([command.text, *words])


def command_argv(
    command: Command,
    *,
    positionals: Sequence[str] = (),
    options: Sequence[tuple[str, str]] = (),
    flags: Sequence[str] = (),
) -> list[str]:
    """The words of ``command`` as the list a program is run with.

    The command :func:`render_command` prints, for a caller that runs it instead,
    in the same order and under the same checks of a group given as text, of an
    option or flag the command does not list and of a value that is not text. A
    list is run and never printed, so each value is any text, exactly as given,
    and is held neither to :func:`pasteable` nor to the rule on a leading ``-``.
    For values :func:`render_command` prints, the printed line split at its spaces
    is this list.
    """
    return [*command.text.split(), *_words(command, positionals, options, flags)]


def terminal_text(value: str) -> str:
    """``value`` as the package shows text it did not write, on one line.

    ``shown_on_one_line`` of ``utils/terminal_text.py``, the package's one
    definition of that rule, so an ordinary name such as ``cfg.yaml`` comes out as
    it went in. The rule writes out the C0 controls (the tab and the line feed
    included), DEL, the C1 controls, the Unicode format characters (the
    bidirectional controls among them) and the line and paragraph separators, each
    as a backslash and its code point: ``x`` and two hex digits up to U+00FF, ``u``
    and four up to U+FFFF, ``U`` and eight beyond. A backslash that would read as
    one of those escapes is doubled, so text that spells an escape reads as text
    and never as the character. The package's rule goes past that list: it writes
    out lone surrogates and private-use and unassigned code points the same way,
    and it breaks the two forms of a CI command a line could start with.

    For a call site that shows a WHOLE one-line message itself, as every sink does.
    A part shown here and then put into a message a sink shows is shown twice: the
    sink doubles the backslash of each escape written here, and the name no longer
    reads as what it is. A message that goes on to a sink names a file as it is
    given (``config_sources.describe_config_path`` says why).
    """
    return shown_on_one_line(value)
