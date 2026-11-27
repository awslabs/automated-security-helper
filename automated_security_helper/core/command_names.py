"""The ``ash`` commands that a hint or a message outside the command line may name.

A message that tells a reader to run a command takes the command from here, so it
can only name one the program registers (a test walks this list against the real
command tree) and a rename is one edit. Only registered commands are listed.

This module sits below the command line: the loader, the models and lint read it,
and the command line imports them, so it imports nothing from the package but
``utils/terminal_text.py``, which imports nothing from it.

A command is built by :func:`render_command`, which quotes each argument. A name a
repository chose (a file name with ``;`` or ``|`` in it) is then one word of the
command when the text is pasted into a shell, never shell syntax. A part that
stands for a value the message names elsewhere is a :class:`Placeholder`, printed
as ``<what it stands for>``. A command that is run and not printed is
:func:`command_argv`: the same words as a list, each argument exactly as given.

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

import shlex
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


def render_command(name: str, *arguments: str | Placeholder) -> str:
    """``name`` and each argument, joined by single spaces.

    A ``str`` argument goes through :func:`shlex.quote`: plain text such as a flag
    or a path of ordinary characters stays as it is, and one that holds a space, a
    quote or a shell operator is printed as one quoted word. A
    :class:`Placeholder` is printed as itself.
    """
    words = [name]
    for argument in arguments:
        if isinstance(argument, Placeholder):
            words.append(str(argument))
        else:
            words.append(shlex.quote(argument))
    return " ".join(words)


def command_argv(name: str, *arguments: str | Placeholder) -> list[str]:
    """The words of ``name`` and each argument, as the list a program is run with.

    The command :func:`render_command` prints, for a caller that runs it instead:
    for text arguments ``shlex.split(render_command(name, *arguments))`` is this
    list. Each argument is the text it was given and is never quoted. A
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
