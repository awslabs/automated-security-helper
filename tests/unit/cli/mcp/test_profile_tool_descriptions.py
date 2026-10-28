# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""list_profiles and select_profile describe where profiles come from, correctly.

Why this file exists
--------------------
Both tools told clients that profiles are registered with
`ash mcp --profile NAME=path`, and `ash mcp` refused that option ("No such
option: --profile") until the wrapper in cli/main.py declared it. The
descriptions are a client's only documentation of the tool, and the option they
name is the only source of profiles, so they are checked here against the
option `ash mcp` actually declares: its name, its NAME=path form, and that it
repeats. The path hash is described as a hash of the path, which is what
profile_registry computes; an earlier guide said it detected a rotated file,
which a hash of the path cannot.
"""

from __future__ import annotations

import typer.main

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.main import app as ash_app


def _profile_option():
    command = typer.main.get_command(ash_app).commands["mcp"]
    (option,) = [p for p in command.params if "--profile" in p.opts]
    return option


def test_ash_mcp_declares_the_option_the_descriptions_name():
    option = _profile_option()
    assert option.multiple, "--profile must be repeatable, as the descriptions say"
    assert "NAME=path/to/ash.yaml" in (option.help or "")


def test_the_descriptions_give_the_options_form():
    for tool in (mcp_server.list_profiles, mcp_server.select_profile):
        doc = tool.__doc__ or ""
        assert "--profile NAME=path/to/ash.yaml" in doc, tool.__name__
        assert "ash mcp" in doc, tool.__name__
        assert "repeatable" in doc, tool.__name__


def test_list_profiles_says_what_the_hash_is_of():
    doc = mcp_server.list_profiles.__doc__ or ""
    assert "absolute path" in doc
    assert "not the path or the contents" in doc
