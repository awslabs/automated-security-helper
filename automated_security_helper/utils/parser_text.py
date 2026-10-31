# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A parser's message, printed with its own lines and a name it quotes on one line.

A YAML parser's message spans lines of its own ("while parsing a flow sequence",
then the place it names on the next line) and quotes the file it parsed by its
name. A printer keeps the parser's lines. A newline inside the quoted name is the
name's, the caller's text, and printed as it is it starts a line of the name's
choosing inside the message. So the message is split only at the newlines
outside each name (:func:`own_lines`), and a printer shows each line on one
line (utils/terminal_text.py shown_on_one_line), the name's newline written as
``\\x0a``.

Only names that hold a newline matter here; any other character a name holds is
shown as an escape when its line is shown.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any, List, Set, Union

#: A name as a message can quote it: text, or a path.
Name = Union[str, "os.PathLike[str]"]


def _quoted_forms(name: Name) -> Set[str]:
    """The texts a message can quote *name* by: a str as it is, and a path as
    given, absolute and resolved, since a loader may open it by any of them.

    The absolute and the resolved form need the working directory, which can be
    gone while a refusal is being printed; a form that cannot be made is left
    out rather than raised from the printer.
    """
    if isinstance(name, str):
        return {name}
    path = Path(name)
    forms = {str(path), path.as_posix()}
    for spelled in (path.absolute, path.resolve):
        try:
            forms.add(str(spelled()))
        except (OSError, RuntimeError):
            pass
    return forms


def refusal_own_lines(error: Any, text: str) -> List[str]:
    """``text``, a refusal of ``error``'s config file, as the lines a printer
    shows.

    A parser's message (``error.parser_message``) keeps the lines the parser
    laid out, split at the newlines outside the file's name
    (``error.ash_config_file``), so a newline in the name starts none. Without
    the name, or for any other refusal, the whole text is one line: the split
    could not tell a name's newlines from the parser's. The one rule for the
    scan's refusal and the workspace plan's
    (interactions/run_ash_scan._printed_config_refusal,
    cli/scan._fail_workspace_config); both attributes are declared on
    ASHConfigValidationError (core/exceptions.py).
    """
    if not error.parser_message or error.ash_config_file is None:
        return [text]
    return own_lines(text, [error.ash_config_file])


def own_lines(text: str, names: Iterable[Name]) -> List[str]:
    """*text*, a message that quotes *names*, split at its own newlines: those
    outside each name. The lines are as *text* holds them, not shown."""
    inside: Set[int] = set()
    for name in names:
        for form in _quoted_forms(name):
            if "\n" not in form:
                continue
            start = text.find(form)
            while start != -1:
                inside.update(range(start, start + len(form)))
                start = text.find(form, start + 1)
    lines = []
    begin = 0
    for index, character in enumerate(text):
        if character == "\n" and index not in inside:
            lines.append(text[begin:index])
            begin = index + 1
    lines.append(text[begin:])
    return lines
