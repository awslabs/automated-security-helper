"""The ``ash`` commands that a hint or a message outside the command line may name.

A message that tells a reader to run a command takes the command from here, so it
can only name one the program registers (a test walks this list against the real
command tree) and a rename is one edit. Only registered commands are listed.

This module sits below the command line: the loader, the models and lint read it,
and the command line imports them, so it imports nothing from the package.

A command is built by :func:`render_command`, which quotes each argument. A name a
repository chose (a file name with ``;`` or ``|`` in it) is then one word of the
command when the text is pasted into a shell, never shell syntax. A part that
stands for a value the message names elsewhere is a :class:`Placeholder`, printed
as ``<what it stands for>``. A command that is run and not printed is
:func:`command_argv`: the same words as a list, each argument exactly as given.

A name a repository chose that a message prints (a file name) goes through
:func:`terminal_text` first, which writes out every character a terminal would act
on, so the name cannot move the cursor, recolor the line or reorder the text.

Callers read the registry through the module when they run, as in
``command_names.render_command(command_names.CONFIG_LINT, ...)``, and never import
either name from it: a test that replaces one then sees it everywhere.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

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


def _written_out(character: str) -> str:
    code = ord(character)
    if code < 0x20 or 0x7F <= code <= 0x9F:
        return f"\\x{code:02x}"
    if 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069 or code in (0x2028, 0x2029):
        return "\\u" + f"{code:04x}"
    return character


def terminal_text(value: str) -> str:
    """``value`` with every character a terminal or a reader would act on written out.

    A control character (U+0000 to U+001F, so escape and newline too, U+007F and
    U+0080 to U+009F) becomes a backslash, ``x`` and two lowercase hex digits. A
    bidirectional formatting character (U+202A to U+202E, U+2066 to U+2069) and the
    line and paragraph separators (U+2028, U+2029) become a backslash, ``u`` and
    four lowercase hex digits. Every other character is kept, so an ordinary name
    such as ``cfg.yaml`` comes out as it went in.
    """
    return "".join(_written_out(character) for character in value)
