# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Compatibility spellings kept from the deleted root ``ash`` bash script.

That script parsed its own flag surface and forwarded the rest to the Python
CLI. Two of its spellings had no Python equivalent, so removing the script would
have broken any caller using them. They are accepted here and announce the name
that replaced them.

A warning that only says "deprecated" makes the reader go looking for the
replacement, so each entry maps to the canonical spelling and the message names
it. The mapping is data rather than a string per call site because both ``scan``
and ``build-image`` accept these options, and two hand-written messages drift
apart.
"""

import sys
from typing import Iterable, Optional, TextIO

# Deprecated spelling -> the canonical spelling that replaces it.
DEPRECATED_OPTION_SPELLINGS = {
    "--ash-revision": "--ash-revision-to-install",
    "-rev": "--ash-revision-to-install",
}


def warn_deprecated_option_spellings(
    argv: Optional[Iterable[str]] = None, stream: Optional[TextIO] = None
) -> None:
    """Warn once for each deprecated option spelling present in ``argv``.

    Matched against ``argv`` rather than against the parsed value because click
    reports the value it bound, not the spelling the caller typed, and the whole
    point is to name the spelling back to them.

    Call this from a command body after the ``ctx.invoked_subcommand`` guard, not
    from an option callback. The root callback and the ``scan`` command share one
    function, so during ``ash scan ...`` its parameters are parsed twice and an
    option callback would emit the warning twice.

    Comparison is exact. A substring match would fire on
    ``--ash-revision-to-install`` itself, which is the spelling being
    recommended.
    """
    args = sys.argv[1:] if argv is None else list(argv)
    out = stream if stream is not None else sys.stderr
    warned: set[str] = set()
    for token in args:
        # Split so `--ash-revision=v1` is recognized as well as `--ash-revision v1`.
        spelling = token.split("=", 1)[0]
        replacement = DEPRECATED_OPTION_SPELLINGS.get(spelling)
        if replacement is not None and spelling not in warned:
            warned.add(spelling)
            print(
                f"warning: '{spelling}' is deprecated and is scheduled for "
                f"removal; use '{replacement}' instead.",
                file=out,
            )


#: The console script v4 installs as the canonical command. Everything that
#: names the command in a message reads it from here, so a rename is one edit.
CANONICAL_CLI_NAME = "ashx"

# Deprecated console-script name -> the command that replaces it. ``ash`` was the
# v3 name and keeps working through v4 so existing scripts and CI jobs do not
# break on upgrade. ``ashv3`` pins a version number in the command itself, so it
# reads wrong now that v4 exists. ``automated-security-helper`` is absent on
# purpose: it is the silent escape hatch for hosts where a short name resolves to
# something else (MSYS2 and Alpine ship the Almquist shell as ``ash``).
DEPRECATED_COMMAND_ALIASES = {
    "ash": CANONICAL_CLI_NAME,
    "ashv3": CANONICAL_CLI_NAME,
}


def deprecated_command_message(alias: str) -> str:
    """Return the one-line notice for the deprecated console script ``alias``."""
    replacement = DEPRECATED_COMMAND_ALIASES[alias]
    return (
        f"warning: the '{alias}' command is deprecated and is scheduled for "
        f"removal; use '{replacement}' instead."
    )


def warn_deprecated_command_alias(alias: str, stream: Optional[TextIO] = None) -> None:
    """Print the deprecation notice for ``alias`` as exactly one stderr line.

    Written to stderr so it cannot corrupt a scan's stdout, which callers pipe
    into report tooling. It prints and returns; it never raises and never exits,
    so the command's exit code is whatever the CLI itself returns.

    Call it once, from the console script's own entry point, not from a Typer
    callback: a callback would also fire for the canonical name, and group
    callbacks can run more than once for a single command line.
    """
    print(deprecated_command_message(alias), file=stream or sys.stderr)
