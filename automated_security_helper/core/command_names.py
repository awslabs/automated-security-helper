"""The ``ash`` commands that a hint or a message outside the command line may name.

A message that tells a reader to run a command takes the command from here, so it
can only name one the program registers (a test walks this list against the real
command tree) and a rename is one edit. Only registered commands are listed.

This module sits below the command line: the loader, the models and lint read it,
and the command line imports them, so it imports nothing from the package but
``utils/terminal_text.py``, which imports nothing from it.

A command is built by :func:`render_command`, which prints each text argument as
it is and takes only one that :func:`pasteable` holds for: letters, digits and
``_ . / : -``, which no shell reads specially. It does not quote. ``shlex.quote``
quotes for POSIX shells only, and no one quoting of a name reads the same in
those, in ``cmd.exe`` and in PowerShell, so a name a repository chose is printed
only when it is made of those characters. Any other is pointed at instead: a
part that stands for a value the message names elsewhere is a
:class:`Placeholder`, printed as ``<what it stands for>``, and a command that
holds one ends in one, which no shell runs. A command that is run and not printed
is :func:`command_argv`: the same words as a list, each argument exactly as given.

A call site that shows a whole one-line message itself, with a name a repository
chose in it, passes the message through :func:`terminal_text`, the package's one
rule for showing text it did not write. A message that goes on to a sink (the log,
the console, a refusal) is not passed through it: the sink shows the whole text
once, and a part shown here first would be shown twice.

Callers read the registry through the module when they run, as in
``command_names.render_command(command_names.CONFIG_LINT, ...)``, and never import
either name from it: a test that replaces one then sees it everywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from automated_security_helper.utils.terminal_text import shown_on_one_line

#: The command that reads a config file and reports what is wrong with it.
CONFIG_LINT = "ash config lint"

#: Every command named above, for the test that walks each one against the
#: command tree. A command added above is added here.
REGISTERED = (CONFIG_LINT,)


@dataclass(frozen=True)
class Placeholder:
    """A part of a command that stands for a value the message names elsewhere.

    Printed as ``<text>`` and never quoted: it is not something to paste.
    """

    text: str

    def __str__(self) -> str:
        return f"<{self.text}>"


# The characters an argument of a printed command may hold: ASCII letters and
# digits, `_ . / : -`. No shell (POSIX shells, cmd.exe, PowerShell) reads any of
# them specially. The set is deliberately narrow: a character outside it is not
# necessarily special, but a space, `&`, `;`, a quote, `~`, `+`, `@`, a comma or
# non-ASCII text either is in some shell or is not worth the doubt.
_PASTEABLE = re.compile(r"[A-Za-z0-9_./:-]+")


def pasteable(text: str) -> bool:
    """Whether ``text`` is one bare word in every shell, so a command may print it.

    True for a non-empty ``text`` made only of ASCII letters and digits and
    ``_ . / : -``. Any other text is a name this module points at and never prints.
    """
    return bool(_PASTEABLE.fullmatch(text))


def render_command(name: str, *arguments: str | Placeholder) -> str:
    """``name`` and each argument, joined by single spaces, as one printed line.

    A ``str`` argument is printed as it is and must be :func:`pasteable`, so it
    is one bare word in POSIX shells, ``cmd.exe`` and PowerShell alike. It is not
    quoted: ``shlex.quote`` quotes for POSIX shells only (``cmd.exe`` reads a
    single quote as a plain character), so no quoting of another name is safe in
    every shell. A ``str`` argument that is not pasteable is a ``ValueError``
    whose text names no argument, because the argument is a name a repository
    chose; the caller passes a :class:`Placeholder` for it, which is printed as
    itself.

    A line that holds a :class:`Placeholder` ends in one, so it ends in ``>``, a
    redirection with no target, which no shell runs. A ``str`` argument after the
    last :class:`Placeholder` would end the line in text instead, so it is a
    ``ValueError`` too.
    """
    words = [name]
    last_placeholder = -1
    for position, argument in enumerate(arguments):
        if isinstance(argument, Placeholder):
            words.append(str(argument))
            last_placeholder = position
        elif pasteable(argument):
            words.append(argument)
        else:
            raise ValueError(
                "a command argument is empty or holds a character some shell "
                "reads specially; pass a Placeholder for it"
            )
    if 0 <= last_placeholder < len(arguments) - 1:
        raise ValueError(
            "a command that holds a Placeholder must end in one, so that no shell "
            "runs it"
        )
    return " ".join(words)


def command_argv(name: str, *arguments: str | Placeholder) -> list[str]:
    """The words of ``name`` and each argument, as the list a program is run with.

    The command :func:`render_command` prints, for a caller that runs it instead.
    A list is run and never printed, so each argument is any text, exactly as it
    was given, and is not held to :func:`pasteable`: for arguments that are
    pasteable, ``shlex.split(render_command(name, *arguments))`` is this list. A
    :class:`Placeholder` stands for a value the message names elsewhere, so there
    is nothing to run: it is a ``TypeError``.
    """
    words = name.split()
    for argument in arguments:
        if not isinstance(argument, str):
            raise TypeError(
                f"a command to run takes text arguments, not {type(argument).__name__}"
            )
        words.append(argument)
    return words


def terminal_text(value: str) -> str:
    """``value`` as the package shows text it did not write, on one line.

    ``shown_on_one_line`` of ``utils/terminal_text.py``, the package's one
    definition of that rule, so an ordinary name such as ``cfg.yaml`` comes out as
    it went in.

    For a call site that shows a WHOLE one-line message itself, as every sink does.
    A part shown here and then put into a message a sink shows is shown twice: the
    sink doubles the backslash of each escape written here, and the name no longer
    reads as what it is. A message that goes on to a sink names a file as it is
    given (``config_sources.describe_config_path`` says why).
    """
    return shown_on_one_line(value)
