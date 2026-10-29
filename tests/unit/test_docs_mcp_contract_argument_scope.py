# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/_mcp_contract.py reads a helper's argument in the function that makes
the call, not in the calling module.

Why this file exists
--------------------
A helper that raises an exception with the type its caller names (``_step(url,
kind)``) gets its ``error_type`` values from every call of it. The reader used to
evaluate each passed argument in the calling MODULE's scope, so a name the calling
FUNCTION binds was looked up as a module name. A local ``kind = "local_kind"`` that
shadows a module-level ``kind`` read as the module's value, and a parameter named
like a module name read as that module value instead of as unread. Either way the
contract listed a type the tool never returns and left out the one it does.

The planted package below has a module-level name that a function-local assignment
and a parameter each shadow, and a third function that passes the module name
itself. Every input is a plain name lookup; nothing is executed.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"


def _reader():
    name = "_ash_mcp_contract"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / "_mcp_contract.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PLANTED_SERVER = """
from automated_security_helper.cli.tools import mcp_const, mcp_local, mcp_param

mcp = object()


@mcp.tool()
def local(url):
    return mcp_local(url)


@mcp.tool()
def param(url):
    return mcp_param(url)


@mcp.tool()
def const(url):
    return mcp_const(url)
"""

PLANTED_TOOLS = """
kind = "module_kind"


class Typed(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type


class LocalErr(Typed):
    pass


class ParamErr(Typed):
    pass


class ConstErr(Typed):
    pass


def _local_step(url, error_type):
    raise LocalErr("local", error_type)


def _param_step(url, error_type):
    raise ParamErr("param", error_type)


def _const_step(url, error_type):
    raise ConstErr("const", error_type)


def mcp_local(url):
    kind = "local_kind"
    try:
        _local_step(url, kind)
    except LocalErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_param(url, kind="param_default"):
    try:
        _param_step(url, kind)
    except ParamErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_const(url):
    try:
        _const_step(url, kind)
    except ConstErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}
"""


@pytest.fixture
def planted_contracts(tmp_path: Path):
    package = tmp_path / "automated_security_helper"
    (package / "cli").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "mcp_server.py").write_text(
        textwrap.dedent(PLANTED_SERVER).lstrip("\n"), encoding="utf-8"
    )
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(PLANTED_TOOLS).lstrip("\n"), encoding="utf-8"
    )
    return _reader().tool_contracts(package)


def test_a_local_that_shadows_a_module_name_is_read_as_the_local(planted_contracts):
    """``kind = "local_kind"`` inside the function is what the call passes."""
    local = planted_contracts["local"]

    assert local.error_types == ("local_kind",)
    assert local.error_types_unread == ()


def test_a_parameter_that_shadows_a_module_name_is_unread(planted_contracts):
    """The call passes the function's parameter, whose value the call site does
    not fix, so nothing is claimed for it: not the module's value, and not a
    guess."""
    param = planted_contracts["param"]

    assert param.error_types == ()
    assert param.error_types_unread != ()


def test_the_module_value_is_never_claimed_for_a_shadowed_name(planted_contracts):
    for tool in ("local", "param"):
        assert "module_kind" not in planted_contracts[tool].error_types


def test_a_module_name_passed_from_inside_a_function_is_still_read(
    planted_contracts,
):
    """Control: a function that binds nothing of that name reads the module's."""
    const = planted_contracts["const"]

    assert const.error_types == ("module_kind",)
    assert const.error_types_unread == ()
