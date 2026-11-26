# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP server spells each ``error_type`` once: in ``McpErrorType``.

Why this file exists
--------------------
A client branches on ``error_type``. Before ``McpErrorType`` the values were 27
module constants spread over five modules plus a dozen raw literals, two of them
spelled both ways (``clone_url_not_permitted``, ``config_input_not_permitted``),
so a rename or a typo changed the protocol with no check noticing. The enum is
the one place a spelling is written; this module keeps it so.

Two modes, one per kind of claim (decision row O8 of the enum design):

* A NEGATIVE scan. ``error_type`` spellings are distinctive
  (``"config_input_not_permitted"``), so an ``ast`` walk of the MCP surface
  (``automated_security_helper/cli``) flags any string constant, outside
  docstrings and the enum's own module, that equals a member's value. Comments
  never reach the AST. Tests that assert WIRE BYTES are outside the scanned
  tree and keep spelling the strings, which is their job.
* A POSITIVE shape pin on the field itself. Every place the surface writes an
  ``error_type`` (a dict key, a subscript assignment, a keyword) must write one
  of the shapes the contract reader in ``scripts/_mcp_contract.py`` follows: a
  member's ``.value``, an exception's ``error_type`` attribute, a name bound to
  one of those (a helper's parameter), a conditional of those, or the recorded
  open arm ``type(e).__name__`` (the exception's class name, which no enum can
  close). A bare string constant is neither, and is flagged even when it spells
  no member, so a new refusal cannot ship as a raw literal.

The planted-positive controls run the same scanners over a fixture tree holding
one stray spelling and one stray shape each, so a scan that silently stopped
walking reads as a failure, not as a clean tree.

The wire spellings are pinned byte for byte below. That pin is the only place in
the test tree that lists them all.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

from automated_security_helper.cli.mcp.error_types import McpErrorType

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCOPE = REPO_ROOT / "automated_security_helper" / "cli"
ENUM_MODULE = SCOPE / "mcp" / "error_types.py"

#: (path relative to SCOPE, reason). Nothing is allowlisted today: the open arm is
#: carved out by SHAPE in ``_value_shape_problem``, not by file.
ALLOWLIST: Tuple[Tuple[str, str], ...] = ()

#: The wire spellings, byte for byte. Renaming one is a protocol change.
WIRE_SPELLINGS = frozenset(
    {
        "bound_profile_unavailable",
        "clone_host_not_permitted",
        "clone_ref_not_permitted",
        "clone_refused",
        "clone_timed_out",
        "clone_too_large",
        "clone_tree_unreadable",
        "clone_url_not_permitted",
        "committed_output_files",
        "config_check_failed",
        "config_env_not_resolved",
        "config_field_denied",
        "config_input_not_permitted",
        "config_policy_unreadable",
        "delivered_image_missing",
        "delivered_source_missing",
        "delivered_image_missing",
        "DirectoryNotFound",
        "environment_value_in_longer_string",
        "git_checkout_failed",
        "git_clone_failed",
        "image_registry_not_permitted",
        "invalid_clone_depth",
        "invalid_expiration",
        "invalid_session_id",
        "local_clone_source_refused",
        "no_source_delivered",
        "output_dir_not_permitted",
        "output_dir_not_usable",
        "path_not_expressible",
        "plugin_module_refused",
        "results_not_comparable",
        "scan_not_found",
        "scan_start_failure",
        "scan_target_not_permitted",
        "session_busy",
        "session_change_in_progress",
        "session_identity_required",
        "session_scan_limit",
        "session_source_mismatch",
        "session_workspace_busy",
        "session_workspace_unavailable",
        "source_delivery_busy",
        "source_dir_not_usable",
        "ssh_key_not_registered",
        "suppression_not_specific",
    }
)


#: Callees whose error type is a positional argument, with its index:
#: ``refused(error, error_type)`` in ``mcp_tools``, ``GitCommandError(message,
#: error_type)`` and ``_config_problem(field, message, kind)``.
POSITIONAL_SINKS = {"refused": 1, "GitCommandError": 1, "_config_problem": 2}

#: The ``type`` spellings ``validate_config`` gives a message it classifies by the
#: validator's own prefixes. They are an open vocabulary of that tool, not
#: ``McpErrorType`` members, so a literal in this set is the one allowed bare
#: spelling at the ``_config_problem`` sink; any other literal there is flagged.
CONFIG_PROBLEM_KINDS = frozenset(
    {
        "denied_by_runtime_policy",
        "duplicate_field",
        "extends_error",
        "file_not_found",
        "internal_field",
        "invalid_field",
        "json_parse_error",
        "missing_required_field",
        "toml_parse_error",
        "unknown_field",
        "validation_error",
        "yaml_parse_error",
    }
)


def _callee_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _python_files(root: Path) -> Iterator[Path]:
    yield from sorted(p for p in root.rglob("*.py") if p.is_file())


def _docstring_ids(tree: ast.AST) -> set:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def stray_spellings(
    root: Path, values: frozenset, skip: Path | None = None
) -> List[str]:
    """``path:line`` of each non-docstring string constant under ``root`` that
    equals one of ``values``."""
    allowed = {rel for rel, _ in ALLOWLIST}
    found = []
    for path in _python_files(root):
        if skip is not None and path == skip:
            continue
        if str(path.relative_to(root)) in allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in values
                and id(node) not in docstrings
            ):
                found.append(f"{path.relative_to(root)}:{node.lineno}: {node.value!r}")
    return found


def _is_member_value(node: ast.expr) -> bool:
    """``McpErrorType.NAME.value``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "value"
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "McpErrorType"
    )


def _value_shape_problem(node: ast.expr) -> str | None:
    """Why ``node`` is not a shape an ``error_type`` may be written as, or None."""
    if _is_member_value(node):
        return None
    if isinstance(node, ast.Attribute) and node.attr == "error_type":
        return None  # an exception's own error_type
    if isinstance(node, ast.Name):
        return None  # a parameter or local bound at a site this scan also reads
    if isinstance(node, ast.IfExp):
        return _value_shape_problem(node.body) or _value_shape_problem(node.orelse)
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "__name__"
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "type"
    ):
        return None  # the recorded open arm: the exception's class name
    return f"{ast.unparse(node)[:70]}"


def bad_error_type_writes(root: Path) -> List[str]:
    """``path:line`` of each ``error_type`` write under ``root`` whose value is
    not one of the allowed shapes."""
    found = []
    for path in _python_files(root):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        checks: List[ast.expr] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == "error_type":
                        checks.append(value)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "error_type"
                    ) or (isinstance(target, ast.Name) and target.id == "error_type"):
                        checks.append(node.value)
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "error_type":
                        checks.append(keyword.value)
                # The positional sinks: the helpers whose error_type is an
                # argument, not a keyword, so a literal there is as live as a
                # dict value.
                index = POSITIONAL_SINKS.get(_callee_name(node))
                if index is not None and len(node.args) > index:
                    value = node.args[index]
                    if not (
                        _callee_name(node) == "_config_problem"
                        and isinstance(value, ast.Constant)
                        and value.value in CONFIG_PROBLEM_KINDS
                    ):
                        checks.append(value)
        for value in checks:
            problem = _value_shape_problem(value)
            if problem is not None:
                found.append(f"{path.relative_to(root)}:{value.lineno}: {problem}")
    return found


# --- the enum itself ---------------------------------------------------------


def test_the_wire_spellings_are_pinned_byte_for_byte():
    assert {m.value for m in McpErrorType} == WIRE_SPELLINGS


def test_each_value_is_one_member_and_a_plain_str():
    values = [m.value for m in McpErrorType]
    # Iterating an Enum skips aliases, so the member count of the iteration can
    # never differ from the distinct values; ``__members__`` lists the aliases.
    assert len(McpErrorType.__members__) == len(values)
    assert len(values) == len(set(values)) == len(WIRE_SPELLINGS)
    for member in McpErrorType:
        assert isinstance(member, str)
        assert member == member.value
        assert type(member.value) is str


def test_the_enum_refuses_an_alias_member():
    # The control for the alias check above: the same declaration with a second
    # name for one spelling must not construct.
    import enum

    planted = enum.Enum("_Planted", [("FIRST", "x"), ("SECOND", "x")], type=str)
    with pytest.raises(ValueError):
        enum.unique(planted)

    source = ENUM_MODULE.read_text(encoding="utf-8")
    assert "@unique\nclass McpErrorType" in source


def test_a_member_value_serializes_as_the_bare_string():
    payload = {"success": False, "error_type": McpErrorType.CLONE_TOO_LARGE.value}

    assert json.dumps(payload) == '{"success": false, "error_type": "clone_too_large"}'
    assert json.dumps({"k": McpErrorType.CLONE_TOO_LARGE}) == (
        '{"k": "clone_too_large"}'
    )


def test_a_member_is_looked_up_from_its_wire_spelling():
    assert McpErrorType("session_identity_required") is (
        McpErrorType.SESSION_IDENTITY_REQUIRED
    )
    with pytest.raises(ValueError):
        McpErrorType("ValueError")


def test_the_enum_module_imports_nothing_from_the_package():
    tree = ast.parse(ENUM_MODULE.read_text(encoding="utf-8"))
    imported = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]

    assert not [m for m in imported if m.startswith("automated_security_helper")]


def test_every_member_is_written_somewhere_on_the_surface():
    """A member nothing writes is a spelling the protocol no longer carries."""
    used = set()
    for path in _python_files(SCOPE):
        if path == ENUM_MODULE:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "McpErrorType"
            ):
                used.add(node.attr)

    assert sorted(set(McpErrorType.__members__) - used) == []


# --- the surface -------------------------------------------------------------


def test_no_mcp_module_spells_an_error_type_outside_the_enum():
    assert stray_spellings(SCOPE, WIRE_SPELLINGS, skip=ENUM_MODULE) == []


def test_every_error_type_the_surface_writes_has_an_allowed_shape():
    assert bad_error_type_writes(SCOPE) == []


# --- planted positives: a dead scan must not read as a clean tree ------------


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    (tmp_path / "stray.py").write_text(
        # A docstring that IS a member's spelling: only the docstring skip keeps
        # it out of the report, so dropping the skip fails the control below.
        '"""config_input_not_permitted"""\n'
        "\n"
        "\n"
        "def refuse():\n"
        '    return {"success": False, "error_type": "config_input_not_permitted"}\n'
        "\n"
        "\n"
        "def unlisted():\n"
        '    return {"success": False, "error_type": "a_new_refusal"}\n'
        "\n"
        "\n"
        "def fine(exc):\n"
        '    return {"error_type": type(exc).__name__}\n',
        encoding="utf-8",
    )
    return tmp_path


def test_the_spelling_scan_flags_a_planted_literal_and_skips_the_docstring(planted):
    found = stray_spellings(planted, WIRE_SPELLINGS)

    assert found == ["stray.py:5: 'config_input_not_permitted'"]


def test_the_shape_scan_flags_a_planted_literal_the_enum_does_not_know(planted):
    found = bad_error_type_writes(planted)

    assert [re.sub(r"^stray.py:", "", f) for f in found] == [
        "5: 'config_input_not_permitted'",
        "9: 'a_new_refusal'",
    ]


@pytest.mark.parametrize(
    ("sink", "line"),
    [
        ("refused", 'return refused(e, "a_new_refusal")\n'),
        ("git-command-error", 'raise GitCommandError("msg", "a_new_refusal")\n'),
        ("config-problem", 'return _config_problem("", raw, "a_new_refusal")\n'),
        ("method-call", 'return self.refused(e, "a_new_refusal")\n'),
    ],
)
def test_the_shape_scan_flags_a_planted_positional_literal_per_sink(
    tmp_path, sink, line
):
    (tmp_path / f"{sink}.py").write_text(
        f"def site(e, raw):\n    {line}", encoding="utf-8"
    )

    found = bad_error_type_writes(tmp_path)

    assert [re.sub(r"^[^:]+:", "", f) for f in found] == ["2: 'a_new_refusal'"], sink


def test_the_shape_scan_leaves_the_allowed_positional_shapes_alone(tmp_path):
    (tmp_path / "fine.py").write_text(
        "def site(e, raw, kind):\n"
        "    refused(e, McpErrorType.CLONE_REFUSED.value)\n"
        "    refused(e, e.error_type)\n"
        "    GitCommandError('msg', kind)\n"
        "    _config_problem('', raw, 'validation_error')\n"
        "    _config_problem('', raw, McpErrorType.SCAN_NOT_FOUND.value)\n"
        "    other_helper(e, 'a_literal_at_an_unwatched_callee')\n",
        encoding="utf-8",
    )

    assert bad_error_type_writes(tmp_path) == []


def test_the_scan_walks_the_real_tree():
    """Control on the denominator: the scope holds the modules the cure touched."""
    names = {p.name for p in _python_files(SCOPE)}

    assert {"mcp_tools.py", "mcp_server.py", "source_delivery.py", "sessions.py"} <= (
        names
    )
