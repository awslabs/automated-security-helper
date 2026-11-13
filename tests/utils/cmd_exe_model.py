# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A model of how cmd.exe reads the command line of a batch program.

On Windows ``CreateProcess`` starts a ``.bat`` or ``.cmd`` file through cmd.exe, and
the batch file then passes its arguments on with ``%*``, so cmd.exe reads the same
text twice:

1. the first read is the command line ASH's argument list was written into
   (``subprocess.list2cmdline``). Outside double quotes ``< > | &`` are operators and
   ``^`` is the escape character, which is dropped as it is read; inside double quotes
   they are plain text. A percent sign starts a variable expansion wherever it stands,
   double quotes included, and a caret does not stop it inside quotes.
2. the second read is the line in the batch file that holds ``%*``. The arguments are
   put into it as the first read left them: the quotes are still there, the carets
   are gone, and an operator that a caret protected in the first read is now bare.

A parenthesis is an operator in the second read. A batch wrapper can put ``%*`` inside
a parenthesized block, ``@IF EXIST ... ( ... %* ) ELSE ( ... %* )``, where a bare
``)`` from an argument closes the block early and a bare ``(`` opens one.
An argument that the first read leaves bare is bare in the second read as well, so the
model lists ``(`` and ``)`` like the other operators in either read, and a caret before
one protects it in the first read only.

Not modeled: ``!``. With delayed expansion on (the ``DelayedExpansion`` registry
setting, or ``cmd /v:on``), ``!name!`` is replaced in the batch file's second read as
``%name%`` is in the first, and nothing in the argument list written by
``list2cmdline`` escapes it. The setting is off unless the machine turns it on, and
ASH neither refuses nor protects ``!``; this is a known limitation.

The model is the rules the tests rely on, written down once. The tests that use it run
on every host and start no cmd.exe. One test runs only on Windows
(``test_a_real_batch_file_receives_each_accepted_argument_as_it_was_given`` in
``test_batch_program_argument_protection.py``): it starts a real batch file with the
arguments ASH accepts and compares what the program receives with these rules, so that
test, on the Windows leg of the test workflow, is the measurement of the model.
"""

#: What cmd.exe acts on outside double quotes. The parentheses act in the second read.
OPERATORS = "<>|&()"


def first_read(command_line: str) -> tuple[list[str], str]:
    """What one read of ``command_line`` acts on, and the text it hands on.

    Returned: the characters cmd.exe acts on in this read, and the text a batch file
    receives as ``%*`` (carets consumed, quotes kept). A caret before an operator, a
    caret or a percent sign protects it and is dropped. A caret before anything else
    is also dropped, which changes the argument, so it is listed as acted on.
    """
    acting: list[str] = []
    handed: list[str] = []
    quoted = False
    index = 0
    while index < len(command_line):
        char = command_line[index]
        if char == '"':
            quoted = not quoted
            handed.append(char)
        elif not quoted and char == "^":
            following = command_line[index + 1 : index + 2]
            if following and following in OPERATORS + "^%":
                handed.append(following)
                index += 1
            else:
                acting.append(char)
        elif not quoted and char in OPERATORS:
            acting.append(char)
            handed.append(char)
        else:
            handed.append(char)
        index += 1
    return acting, "".join(handed)


def reads_as_a_command(command_line: str) -> list[str]:
    """The characters in ``command_line`` that cmd.exe would act on, in either read.

    The second read is of the text the first one handed on, as a batch file's ``%*``
    puts it into the line that runs the program. An empty list means no operator acts
    and no caret changes an argument. A percent sign is listed when the line holds two
    or more of them: cmd.exe looks for ``%name%`` across the whole line, a lone one
    names nothing, and a pair names a variable (double quotes do not prevent it, and
    a caret inside them is plain text).
    """
    found, handed = first_read(command_line)
    again, _ = first_read(handed)
    found = found + again
    if command_line.count("%") > 1:
        found.append("%")
    return list(dict.fromkeys(found))


def delivered(command_line: str) -> str:
    """The text the program ends up with after both reads of ``command_line``.

    Equal to ``command_line`` when cmd.exe consumes nothing from it. A caret that
    protected an operator in the first read is gone in the second, so a line written
    with carets is not delivered as it was written.
    """
    _, handed = first_read(command_line)
    _, again = first_read(handed)
    return again
