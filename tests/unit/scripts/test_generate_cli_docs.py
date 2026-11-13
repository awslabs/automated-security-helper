# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/generate_cli_docs.py: the Default column and the table row.

* an option whose author set a string ``show_default`` renders that text, not
  the value resolved on the generator's host;
* every column of a parameter row has its pipes escaped, so a ``|`` in a type
  name, a default or a help sentence cannot split the row.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def cli_docs(script_loader):
    return script_loader("generate_cli_docs")


def _option(**fields):
    base = {
        "param_type_name": "option",
        "name": "bin_path",
        "opts": ["--bin-path", "-b"],
        "secondary_opts": [],
        "type": SimpleNamespace(name="text"),
        "required": False,
        "default": "/home/someone-else/.ash/bin",
        "show_default": None,
        "envvar": None,
        "help": "Path to install binaries to.",
        "hidden": False,
        "is_flag": False,
        "is_bool_flag": False,
        "multiple": False,
        "nargs": 1,
        "expose_value": True,
    }
    base.update(fields)
    return SimpleNamespace(**base)


class TestShowDefault:
    def test_a_string_show_default_is_what_the_page_shows(self, cli_docs):
        """At the base the import-time value, another host's home, was published."""
        shown = cli_docs.format_default(_option(show_default="~/.ash/bin"))
        assert shown == "`~/.ash/bin`"

    def test_without_show_default_the_value_is_rendered(self, cli_docs):
        shown = cli_docs.format_default(_option(default="plain"))
        assert shown == "`plain`"


class TestTableCells:
    def test_a_pipe_outside_a_code_span_is_escaped(self, cli_docs):
        assert cli_docs.table_cell("str | Path") == r"str \| Path"

    def test_an_already_escaped_pipe_is_not_doubled(self, cli_docs):
        assert cli_docs.table_cell(r"a \| b") == r"a \| b"

    def test_a_pipe_inside_a_code_span_is_left_alone(self, cli_docs):
        """python-markdown keeps a column whole across a pipe in backticks and would
        render the backslash, as md_prose already relies on."""
        assert cli_docs.table_cell("use `a | b` here") == "use `a | b` here"

    def test_a_row_with_a_pipe_in_the_type_keeps_five_columns(self, cli_docs):
        """At the base the Type column was interpolated unescaped."""
        import re

        param = _option(type=SimpleNamespace(name="str | Path"), default="plain")
        row = cli_docs._param_row(["scan"], param, set())
        # Split on unescaped pipes only: the leading and trailing ones frame
        # five columns.
        columns = re.split(r"(?<!\\)\|", row)
        assert len(columns) == 7, row
        assert r"str \| path" in row
