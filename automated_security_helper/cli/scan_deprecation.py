# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The deprecation lines for the scan spellings that ``ash scan fs`` replaces.

Three spellings run the same scan as ``ash scan fs <path>`` and are removed in ASH
v4.0: bare ``ash [options]``, ``ash scan [options]`` with no subject, and
``--source-dir`` as the way to name the directory. Each prints one line to stderr,
as ``ash dependencies install --tool <old name>`` does, so a script that parses
stdout is not handed a line it has never seen, and the exit code is unchanged.

Kept apart from ``cli.scan`` and ``cli.scan_group`` because both need it and
neither may import the other's heavy parts; this module imports nothing at module
scope beyond the standard library.
"""

from __future__ import annotations

from typing import Any

#: ``ctx.meta`` key set to the subject (``"fs"``) when the scan was reached by name.
SCAN_NOUN_META = "ash.scan_noun"
#: ``ctx.meta`` key set to ``"scan"`` when ``ash scan`` was given with no subject.
SCAN_FORM_META = "ash.scan_form"

REMOVAL = "ASH v4.0"

BARE_ASH_LINE = (
    "`ash` without a subcommand runs a scan; that form is deprecated and will be "
    f"removed in {REMOVAL}. Use `ash scan fs <path>`."
)
SCAN_WITHOUT_SUBJECT_LINE = (
    "`ash scan` without a subject is deprecated and will be removed in "
    f"{REMOVAL}. Use `ash scan fs <path>`."
)
SOURCE_DIR_LINE = (
    "`--source-dir` is deprecated and will be removed in "
    f"{REMOVAL}. Give the directory as the argument: `ash scan fs <path>`."
)


def warn_deprecated(message: str) -> None:
    """Print ``Deprecated: <message>`` to stderr, once per call."""
    from rich.markup import escape

    from automated_security_helper.utils.console import ash_console
    from automated_security_helper.utils.ui_theme import rich_theme

    ash_console(stderr=True, theme=rich_theme()).print(
        f"[bold yellow]Deprecated:[/bold yellow] {escape(message)}",
        highlight=False,
    )


def warn_if_legacy_scan_form(ctx: Any) -> None:
    """Warn when the scan about to run was not reached through ``ash scan <subject>``."""
    if ctx.meta.get(SCAN_NOUN_META) is not None:
        return
    if ctx.meta.get(SCAN_FORM_META) == "scan":
        warn_deprecated(SCAN_WITHOUT_SUBJECT_LINE)
    else:
        warn_deprecated(BARE_ASH_LINE)
