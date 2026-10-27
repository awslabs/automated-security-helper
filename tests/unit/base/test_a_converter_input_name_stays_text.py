# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter's failed and refused input lines print a tag-like name as text.

The name in "Could not convert '<name>'" and "Skipped converter input '<name>'"
is a file name the scanned tree chose. ASH's console handler is built with
markup off, and both records also pass NO_MARKUP, so the line stays text if a
handler is ever built with markup on. Rich reads "[/x]" in a markup message as
a closing tag with nothing open and raises MarkupError inside the handler, so
the error line itself would be lost. The cells build that handler and require
the line, with the name as written.
"""

from __future__ import annotations

import io
import logging

import pytest
from rich.console import Console

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.utils.log import ConsoleHandler
from automated_security_helper.utils.scanned_tree import TreeInputRefused

NAMES = ["[/x].ipynb", "[bold]y[/bold].ipynb"]


@pytest.fixture
def markup_console():
    """A console handler with markup on, attached to ASH's logger."""
    stream = io.StringIO()
    console = Console(file=stream, width=400, color_system=None, soft_wrap=True)
    handler = ConsoleHandler(
        console=console, markup=True, show_time=False, show_path=False
    )
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


@pytest.mark.parametrize("name", NAMES)
def test_a_failed_input_line_shows_its_name_as_written(
    test_plugin_context, markup_console, name
):
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_failed_input(
        test_plugin_context.source_dir / name, "the tool exited 1"
    )

    shown = markup_console.getvalue()
    assert f"Could not convert '{name}': the tool exited 1" in shown, shown


@pytest.mark.parametrize("name", NAMES)
def test_a_refused_input_line_shows_its_name_as_written(
    test_plugin_context, markup_console, name
):
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_refused_input(
        TreeInputRefused(f"lib/{name}", "it is a symbolic link")
    )

    shown = markup_console.getvalue()
    assert f"Skipped converter input 'lib/{name}': it is a symbolic link" in shown, (
        shown
    )


@pytest.mark.parametrize("name", NAMES)
def test_a_refused_member_line_shows_its_name_as_written(
    test_plugin_context, markup_console, name
):
    """The member branch of the warning, pinned like the input branch: an
    archive member's name is the archive's content's."""
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    converter.record_refused_input(
        TreeInputRefused("lib/a.tar", "it is a symbolic link"), member=name
    )

    shown = markup_console.getvalue()
    assert (
        f"Skipped member '{name}' of archive 'lib/a.tar': it is a symbolic link"
        in shown
    ), shown
