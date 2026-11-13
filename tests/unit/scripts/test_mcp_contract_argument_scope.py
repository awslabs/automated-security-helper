# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/_mcp_contract.py reads a helper's argument where the call sits.

Why this file exists
--------------------
A helper that raises an exception with the type its caller names (``_step(url,
kind)``) gets its ``error_type`` values from every call of it. The reader used to
evaluate each passed argument in the calling MODULE's scope, so a name the calling
FUNCTION binds was looked up as a module name. A local ``kind = "local_kind"`` that
shadows a module-level ``kind`` read as the module's value, and a parameter named
like a module name read as that module value instead of as unread. Either way the
contract listed a type the tool never returns and left out the one it does.

The rules the reader follows now, each with a case below:

* a call in a function's body reads the function's own bindings: a local
  assignment is the value passed, a parameter is unread, and a module name the
  function does not rebind is the module's;
* a call in a function's header (a default value) is read in the scope around the
  function, where Python evaluates it, not in the function's;
* a nested function reads the enclosing function's locals;
* a class body between a method and the module is passed over, so a method reads
  the module's name and not a class attribute of the same name;
* a call inside a lambda's body, a comprehension or a class body reads a literal
  and leaves a name unread, on the caller's side and on the callee's (the raising
  helper's own parameter is never read as the module name it shadows);
* a parameter that shadows the helper's name is not the helper, so the helper's
  uses outnumber its calls and nothing is claimed for it;
* a handler local assigned from the caught exception and passed back into a
  construction of the same class is read once: the second read of that caught
  type, inside the first, is unread, so the reading ends instead of feeding
  itself (a second planted package, below the first).

The planted package below holds one module-level ``kind`` that every case shadows
or reads. Every input is a plain name lookup or a literal; nothing is executed.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

PLANTED_SERVER = """
from automated_security_helper.cli.tools import (
    get_tool,
    mcp_comp,
    mcp_const,
    mcp_header,
    mcp_holder,
    mcp_local,
    mcp_nested,
    mcp_param,
    mcp_sh_real,
    mcp_sh_shadow,
    mcp_shadow,
)

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


@mcp.tool()
def header(url):
    return mcp_header(url)


@mcp.tool()
def comp(url):
    return mcp_comp(url)


@mcp.tool()
def shadow(url):
    return mcp_shadow(url)


@mcp.tool()
def nested(url):
    return mcp_nested(url)


@mcp.tool()
def method(url):
    return get_tool().run(url)


@mcp.tool()
def holder(url):
    return mcp_holder(url)


@mcp.tool()
def sh_real(url):
    return mcp_sh_real(url)


@mcp.tool()
def sh_shadow(url):
    return mcp_sh_shadow(url)
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


class HeaderErr(Typed):
    pass


class CompErr(Typed):
    pass


class ShadowErr(Typed):
    pass


class NestedErr(Typed):
    pass


class MethodErr(Typed):
    pass


class HolderErr(Typed):
    pass


class ShErr(Typed):
    pass


def _local_step(url, error_type):
    raise LocalErr("local", error_type)


def _param_step(url, error_type):
    raise ParamErr("param", error_type)


def _const_step(url, error_type):
    raise ConstErr("const", error_type)


def _header_step(url, error_type):
    raise HeaderErr("header", error_type)


def _comp_step(url, error_type):
    raise CompErr("comp", error_type)


def _shadow_step(url, kind):
    raise ShadowErr("shadow", kind)


def _nested_step(url, error_type):
    raise NestedErr("nested", error_type)


def _method_step(url, error_type):
    raise MethodErr("method", error_type)


def _holder_step(url, kind):
    raise HolderErr("holder", kind)


def _sh_step(url, error_type):
    raise ShErr("sh", error_type)


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


def mcp_header(url, kind, probe=_header_step("u", kind)):
    try:
        raise probe
    except HeaderErr as e:
        return {"success": False, "error_type": e.error_type}


def mcp_comp(urls):
    try:
        [_comp_step(u, "comp_kind") for u in urls]
    except CompErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_shadow(url):
    make = lambda u, k: _shadow_step(u, k)
    try:
        make(url, "lam_kind")
    except ShadowErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_nested(url):
    kind = "outer_kind"

    def inner():
        _nested_step(url, kind)

    try:
        inner()
    except NestedErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


class Tool:
    kind = "class_kind"

    def run(self, url):
        try:
            _method_step(url, kind)
        except MethodErr as e:
            return {"success": False, "error_type": e.error_type}
        return {"success": True}


def get_tool() -> Tool:
    return Tool()


class Holder:
    probe = _holder_step("u", kind)


def mcp_holder(url):
    try:
        raise Holder.probe
    except HolderErr as e:
        return {"success": False, "error_type": e.error_type}


def mcp_sh_real(url):
    try:
        _sh_step(url, "real_kind")
    except ShErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_sh_shadow(url, _sh_step):
    try:
        _sh_step(url, "not_the_helper")
    except ShErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}
"""

# A handler whose local is built from the caught exception and raised again.
# Reading ``e`` builds every ``CycleErr(...)``; the second one passes ``kind``,
# whose value reads ``e`` again.

CYCLE_SERVER = """
from automated_security_helper.cli.tools import mcp_cycle

mcp = object()


@mcp.tool()
def cycle(url):
    return mcp_cycle(url)
"""

CYCLE_TOOLS = """
class CycleErr(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type


def _cycle_step(url):
    raise CycleErr("cycle", "probe_kind")


def mcp_cycle(url):
    try:
        _cycle_step(url)
    except CycleErr as e:
        kind = e.error_type or "fallback_kind"
        if url is None:
            raise CycleErr("cycle", kind)
        return {"success": False, "error_type": e.error_type}
    return {"success": True}
"""


def _plant(tmp_path: Path, server: str, tools: str) -> Path:
    package = tmp_path / "automated_security_helper"
    (package / "cli").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "mcp_server.py").write_text(
        textwrap.dedent(server).lstrip("\n"), encoding="utf-8"
    )
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(tools).lstrip("\n"), encoding="utf-8"
    )
    return package


@pytest.fixture
def planted_contracts(tmp_path: Path, script_loader):
    package = _plant(tmp_path, PLANTED_SERVER, PLANTED_TOOLS)
    return script_loader("_mcp_contract").tool_contracts(package)


@pytest.fixture
def cycle_contracts(tmp_path: Path, script_loader):
    package = _plant(tmp_path, CYCLE_SERVER, CYCLE_TOOLS)
    return script_loader("_mcp_contract").tool_contracts(package)


# The body of a function.


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
    for tool in ("local", "param", "shadow", "holder"):
        assert "module_kind" not in planted_contracts[tool].error_types


def test_a_module_name_passed_from_inside_a_function_is_still_read(
    planted_contracts,
):
    """Control: a function that binds nothing of that name reads the module's."""
    const = planted_contracts["const"]

    assert const.error_types == ("module_kind",)
    assert const.error_types_unread == ()


# The header of a function.


def test_a_call_in_a_default_value_is_read_in_the_scope_around_the_function(
    planted_contracts,
):
    """``def mcp_header(url, kind, probe=_header_step("u", kind))``: Python binds
    the default at definition time, where ``kind`` is the module's, not the
    parameter beside it."""
    header = planted_contracts["header"]

    assert header.error_types == ("module_kind",)
    assert header.error_types_unread == ()


# Scopes this reader does not follow: a literal is read, a name is not.


def test_a_literal_passed_inside_a_comprehension_is_read(planted_contracts):
    comp = planted_contracts["comp"]

    assert comp.error_types == ("comp_kind",)
    assert comp.error_types_unread == ()


def test_a_name_passed_inside_a_lambda_is_unread_on_both_sides(planted_contracts):
    """``lambda u, k: _shadow_step(u, k)``: the lambda's parameter is not read on
    the caller's side, and the helper's own parameter ``kind`` is not read as
    the module's ``kind`` on the callee's side."""
    shadow = planted_contracts["shadow"]

    assert shadow.error_types == ()
    assert shadow.error_types_unread != ()


def test_a_name_passed_in_a_class_body_is_unread(planted_contracts):
    """``class Holder: probe = _holder_step("u", kind)``: the class body is a
    scope this reader does not follow, and the helper's parameter ``kind`` is
    not read as the module's."""
    holder = planted_contracts["holder"]

    assert holder.error_types == ()
    assert holder.error_types_unread != ()


# Scopes the reader does follow.


def test_a_nested_function_reads_the_enclosing_functions_local(planted_contracts):
    nested = planted_contracts["nested"]

    assert nested.error_types == ("outer_kind",)
    assert nested.error_types_unread == ()


def test_a_method_reads_the_module_name_and_not_the_class_attribute(
    planted_contracts,
):
    """``class Tool: kind = "class_kind"``: inside ``run`` a bare ``kind`` is the
    module's, since a class body is not a scope for the names in its methods."""
    method = planted_contracts["method"]

    assert method.error_types == ("module_kind",)
    assert method.error_types_unread == ()


# A parameter that shadows the helper itself.


def test_a_parameter_named_like_the_helper_is_not_a_call_of_the_helper(
    planted_contracts,
):
    """``def mcp_sh_shadow(url, _sh_step): _sh_step(url, "not_the_helper")`` calls
    the parameter, so that type is never the helper's; the helper's uses then
    outnumber the calls the reader can place, and it claims nothing for either
    tool rather than guess."""
    for tool in ("sh_real", "sh_shadow"):
        assert "not_the_helper" not in planted_contracts[tool].error_types
    assert planted_contracts["sh_real"].error_types_unread != ()


# A caught type whose constructions read the caught value again.


def test_a_handler_local_built_from_the_caught_exception_is_read_once(
    cycle_contracts,
):
    """``except CycleErr as e: kind = e.error_type or "fallback_kind"; raise
    CycleErr("cycle", kind)``: reading ``e`` builds ``CycleErr("cycle", kind)``,
    whose ``kind`` reads ``e`` again. The second read is unread, so the reader
    returns, lists the types the constructions do fix and leaves the self-fed
    one unread. Before this guard the reading never ended."""
    cycle = cycle_contracts["cycle"]

    assert "probe_kind" in cycle.error_types
    assert "fallback_kind" in cycle.error_types
    assert cycle.error_types_unread != ()
