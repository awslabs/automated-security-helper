# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--color/--no-color`` is declared once, in ``cli.params``.

Fifteen command bodies each carried the same option and the same ten-line comment
about click's ``"  /-C"`` whitespace. The declaration now lives in one place and
every command takes it from there.
"""

import typer
import typer.main
import pytest

from automated_security_helper.cli.main import app
from automated_security_helper.cli.params import ColorOption, color_option

pytestmark = pytest.mark.unit


def _commands(group, prefix=()):
    for name, command in sorted(getattr(group, "commands", {}).items()):
        yield prefix + (name,), command
        yield from _commands(command, prefix + (name,))


def test_the_shared_option_keeps_the_whitespace_form_of_the_short_decl():
    info = color_option(True)
    assert info.param_decls == ("--color/--no-color", "  /-C")
    assert info.default is True


def test_the_annotated_alias_carries_that_option():
    (info,) = ColorOption.__metadata__
    assert info.param_decls == ("--color/--no-color", "  /-C")


def test_every_command_that_takes_color_binds_both_spellings_and_short_c():
    group = typer.main.get_command(app)
    seen = []
    for path, command in _commands(group):
        params = [p for p in getattr(command, "params", []) if p.name == "color"]
        if not params:
            continue
        seen.append(path)
        (param,) = params
        assert "--color" in param.opts
        assert "--no-color" in param.secondary_opts
        assert "-C" in param.secondary_opts
        assert "/-C" not in param.opts + param.secondary_opts
    assert len(seen) >= 5, f"expected the shared option on the commands, saw {seen}"
