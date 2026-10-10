#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate docs/content/reference/configuration.md from the AshConfig model tree.

Usage:
    uv run python scripts/generate_config_reference.py            # rewrite the page
    uv run python scripts/generate_config_reference.py --check    # exit 1 with a diff if stale
    uv run python scripts/generate_config_reference.py --missing-descriptions PATH

What is derived, and from where
-------------------------------
* Every key, its type, default, allowed values and description: walked from
  ``AshConfig.model_fields`` recursively, through nested models, lists of models
  and optional models. The key is the alias where a field declares one
  (``mcp-resource-management``), because that is the spelling the model writes;
  ``populate_by_name`` also accepts the field name, and the page says so.
* Allowed values: ``Literal`` and ``Enum`` members, and the numeric and length
  bounds pydantic records in ``FieldInfo.metadata``.
* A default read from the environment at import time (``project_name`` from
  ``ASH_PROJECT_NAME``, ``global_settings.severity_threshold`` from
  ``ASH_DEFAULT_SEVERITY_LEVEL``) is found by parsing the model's own source, not
  assumed, and its Default cell reads "from ``ASH_PROJECT_NAME``, else
  ``ash-scan``". The value after "else" is the default with nothing set; the
  generator removes every variable the code reads before importing ASH.
* Where config files are found: by running
  ``config_sources.discover_config_source`` on a scratch directory holding every
  candidate file, so the order printed is the order the code applies, not a
  restatement of the constants it reads. The workspace policy file's locations are
  found the same way through ``workspace.policy.discover_workspace_policy_file``.

The plugin sections (``scanners``, ``reporters``, ``converters``) are listed here
by name with the keys every plugin has; each plugin's ``options`` are on the
scanners, reporters and converters reference pages, generated from the same
models, so they are written once.

Default cells
-------------
The Default column of every key and option table on the reference pages has one
of these forms, and nothing else, because the docs checks compare prose tables
against these ones (see :func:`default_cell`):

* ``VALUE``: one code span whose content, read with ``yaml.safe_load``, is the
  default. A string is written plain when it reads back as the same string, and
  JSON-quoted otherwise (``"true"``, ``""``); lists and mappings are JSON.
* ``from `NAME`, else VALUE``, with one ``else from `NAME``` per fallback
  variable: the default is read from the first of those variables that is set.
* ``VALUE on Linux and macOS; VALUE on Windows``: computed from the platform.
* A bare phrase: ``required``, ``computed at run time``, ``see the section``,
  ``depends on the platform``; and, in the table of keys every plugin has,
  ``the plugin's own name`` and ``the plugin's defaults``.

Missing descriptions
--------------------
A field with no ``description`` (and, for a nested model, no class docstring) is
rendered with the visible marker ``No description in the code.`` and counted in
the ``--check`` summary. Descriptions are never invented here: adding one is a
change to the model, which is where it belongs. ``--missing-descriptions PATH``
writes the list of such fields, with the model and field name, to PATH.
"""

from __future__ import annotations

import argparse
import ast
import datetime as _dt
import enum
import inspect
import json
import sys
import tempfile
import textwrap
import types
import typing
from pathlib import Path
from typing import Any, Iterator, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (  # noqa: E402
    NO_DESCRIPTION,
    add_docs_root_argument,
    banner,
    code,
    generated_note,
    md_prose,
    normalize_paths,
    prepare_environment,
    reference_dir,
    write_or_check,
)

GENERATOR = "scripts/generate_config_reference.py"
PAGE = "configuration.md"

#: The sentence that explains the "from ..., else ..." Default form, on every page
#: that can show it.
ENV_DEFAULT_NOTE = (
    "A default written as from `NAME`, else `value` is read from that environment "
    "variable when ASH starts; `value` applies when the variable is not set."
)

#: The page each plugin kind's options are documented on, and the config segment.
PLUGIN_SECTIONS = (
    ("scanners", "scanners.md", "scanner"),
    ("reporters", "reporters.md", "reporter"),
    ("converters", "converters.md", "converter"),
)


# ---------------------------------------------------------------------------
# Type and value rendering
# ---------------------------------------------------------------------------


def _strip_annotated(annotation: Any) -> Any:
    while typing.get_origin(annotation) is typing.Annotated:
        annotation = typing.get_args(annotation)[0]
    return annotation


def _is_model(annotation: Any) -> bool:
    from pydantic import BaseModel

    return isinstance(annotation, type) and issubclass(annotation, BaseModel)


def _union_args(annotation: Any) -> Optional[list]:
    origin = typing.get_origin(annotation)
    if origin is typing.Union or isinstance(annotation, types.UnionType):
        return list(typing.get_args(annotation))
    return None


def type_text(annotation: Any, link=None) -> str:
    """A reader's description of the values ``annotation`` accepts.

    ``link`` maps a model class to an in-page anchor, so a nested section can be
    linked from the row that holds it.
    """
    annotation = _strip_annotated(annotation)
    args = _union_args(annotation)
    if args is not None:
        nullable = type(None) in args
        parts = [type_text(a, link) for a in args if a is not type(None)]
        seen: list[str] = []
        for part in parts:
            if part not in seen:
                seen.append(part)
        text = " or ".join(seen)
        return f"{text} or null" if nullable else text
    origin = typing.get_origin(annotation)
    if origin is typing.Literal:
        return "one of " + ", ".join(
            code(_scalar(v)) for v in typing.get_args(annotation)
        )
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return "one of " + ", ".join(code(_scalar(m.value)) for m in annotation)
    if origin in (list, tuple, set, frozenset) or annotation in (list, tuple, set):
        inner = typing.get_args(annotation)
        inner = [a for a in inner if a is not Ellipsis]
        return "list of " + (type_text(inner[0], link) if inner else "any")
    if origin is dict or annotation is dict:
        inner = typing.get_args(annotation)
        if len(inner) == 2:
            return (
                f"mapping of {type_text(inner[0], link)} to {type_text(inner[1], link)}"
            )
        return "mapping"
    if _is_model(annotation):
        anchor = link(annotation) if link else None
        return f"[section](#{anchor})" if anchor else code(annotation.__name__)
    return {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        Path: "path",
        _dt.date: "date",
        _dt.datetime: "date and time",
        Any: "any",
        type(None): "null",
    }.get(annotation, getattr(annotation, "__name__", str(annotation)))


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def constraints_text(field) -> str:
    """Bounds and patterns pydantic recorded for the field, as a phrase."""
    parts = []
    for item in field.metadata:
        name = type(item).__name__
        for attr, label in (
            ("ge", "at least"),
            ("gt", "greater than"),
            ("le", "at most"),
            ("lt", "less than"),
            ("min_length", "length at least"),
            ("max_length", "length at most"),
        ):
            value = getattr(item, attr, None)
            if value is not None:
                parts.append(f"{label} {value}")
        pattern = getattr(item, "pattern", None)
        if pattern:
            parts.append(f"matches {code(pattern)}")
        if name == "Strict":
            parts.append("strict type")
    return ", ".join(parts)


#: (label, platform.system(), sys.platform, os.name) for each platform ASH supports.
PLATFORMS = (
    ("Linux", "Linux", "linux", "posix"),
    ("macOS", "Darwin", "darwin", "posix"),
    ("Windows", "Windows", "win32", "nt"),
)


def platform_defaults(model: type) -> dict[str, list[tuple[str, Any]]]:
    """Fields whose default the class computes from the platform, evaluated per platform.

    ``SemgrepScannerConfig.enabled`` is ``platform.system().lower() != "windows"``:
    evaluated once, at import, it is ``True`` on the machine that generated the page
    and ``False`` on a Windows one, so the page would differ by where it was built
    and say something false on the other. The class source is parsed, and a default
    expression that names ``platform``, ``sys`` or ``os`` is evaluated against each
    platform in :data:`PLATFORMS`. One that cannot be evaluated that way is reported
    with the value ``None``, rendered as "depends on the platform".
    """
    import types as _types

    found: dict[str, list[tuple[str, Any]]] = {}
    seen: set[str] = set()
    for klass in model.__mro__:
        if klass is object or "model_fields" not in dir(klass):
            continue
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(klass)))
        except (OSError, TypeError, SyntaxError):
            continue
        class_def = tree.body[0]
        for stmt in getattr(class_def, "body", []):
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(
                stmt.target, ast.Name
            ):
                continue
            name = stmt.target.id
            if name in seen:
                continue
            seen.add(name)
            if stmt.value is None:
                continue
            if not _reads_platform(stmt.value):
                continue
            values = []
            for label, system, sys_platform, os_name in PLATFORMS:
                namespace = {
                    "platform": _types.SimpleNamespace(system=lambda s=system: s),
                    "sys": _types.SimpleNamespace(platform=sys_platform),
                    # An environment read in the same expression sees nothing set,
                    # as everywhere else on these pages.
                    "os": _types.SimpleNamespace(
                        name=os_name,
                        environ={},
                        getenv=lambda _key, default=None: default,
                    ),
                }
                try:
                    value = eval(  # noqa: S307 - the model's own default expression
                        compile(ast.Expression(stmt.value), "<default>", "eval"),
                        {"__builtins__": {}},
                        namespace,
                    )
                except Exception:
                    value = None
                values.append((label, value))
            if len({repr(v) for _l, v in values}) > 1 or any(
                v is None for _l, v in values
            ):
                found[name] = values
    return found


#: Attribute chains that read the platform. ``os.environ`` is not one: a default
#: read from the environment is the same expression on every platform.
_PLATFORM_READS = {"platform.system", "platform.machine", "sys.platform", "os.name"}


def _reads_platform(expr: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Attribute) and ast.unparse(node) in _PLATFORM_READS
        for node in ast.walk(expr)
    )


def per_platform_text(values: list[tuple[str, Any]], render) -> str:
    """``[(platform, value)]`` as "x on Linux and macOS; y on Windows"."""
    if any(v is None for _l, v in values):
        return "depends on the platform"
    groups: dict[str, list[str]] = {}
    for label, value in values:
        groups.setdefault(render(value), []).append(label)
    parts = []
    for shown, labels in groups.items():
        where = (
            labels[0]
            if len(labels) == 1
            else ", ".join(labels[:-1]) + " and " + labels[-1]
        )
        parts.append(f"{shown} on {where}")
    return "; ".join(parts)


def yaml_value(value: Any) -> str:
    """``value`` as the code-span content of a Default cell (see "Default cells").

    ``yaml.safe_load`` of the result gives ``value`` back: a string that YAML would
    read as something else (``true``, ``5``, ``~``, ``""``) is JSON-quoted.
    """
    import yaml

    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        try:
            plain = yaml.safe_load(value) == value and value == value.strip()
        except yaml.YAMLError:
            plain = False
        return value if plain and value else json.dumps(value)
    return json.dumps(value, sort_keys=isinstance(value, dict))


def default_text(field, per_platform: Optional[list] = None) -> str:
    """The default as it would be written in a YAML config."""
    from pydantic import BaseModel
    from pydantic_core import PydanticUndefined

    if per_platform:
        return per_platform_text(per_platform, lambda v: code(yaml_value(v)))
    if field.is_required():
        return "required"
    if field.default_factory is not None:
        try:
            value = field.default_factory()
        except TypeError:
            return "computed at run time"
    else:
        value = field.default
    if value is PydanticUndefined:
        return "required"
    if isinstance(value, BaseModel):
        return "see the section"
    if isinstance(value, enum.Enum):
        value = value.value
    if isinstance(value, Path):
        value = value.as_posix()
    if isinstance(value, (list, tuple, set, frozenset, dict)):
        value = _jsonable(value)
    elif not isinstance(value, (str, int, float, bool, type(None))):
        value = repr(value)
    return code(yaml_value(_normalized(value)))


def _normalized(value: Any) -> Any:
    """``value`` with :func:`normalize_paths` applied to every string in it."""
    if isinstance(value, str):
        return normalize_paths(value)
    if isinstance(value, dict):
        return {k: _normalized(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalized(v) for v in value]
    return value


def default_cell(
    field, per_platform: Optional[list] = None, env_chain: Optional[list] = None
) -> str:
    """The Default cell: :func:`default_text`, after the variables it is read from."""
    shown = default_text(field, per_platform)
    if not env_chain:
        return shown
    return "".join(f"from {code(n)}, else " for n in env_chain) + shown


def _jsonable(value: Any) -> Any:
    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        # A set's iteration order changes between interpreter runs.
        return sorted((_jsonable(v) for v in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Path):
        return value.as_posix()
    return value


def _own_docstring(cls: type) -> Optional[str]:
    doc = cls.__dict__.get("__doc__")
    if not doc:
        return None
    return " ".join(inspect.cleandoc(doc).split("\n\n")[0].split())


# ---------------------------------------------------------------------------
# Environment-derived defaults
# ---------------------------------------------------------------------------


def _env_key(call: ast.AST) -> Optional[str]:
    """The literal key of an ``os.environ.get``/``os.getenv`` call, if ``call`` is one."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    func = call.func
    chain = ast.unparse(func)
    if chain not in ("os.environ.get", "environ.get", "os.getenv", "getenv"):
        return None
    key = call.args[0]
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return None


def _env_chain(expr: ast.AST) -> list[str]:
    """The variables an expression's default is read from, first one first.

    ``os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "x"))`` is
    ``["AWS_REGION", "AWS_DEFAULT_REGION"]``: the outermost read in the expression
    (``Field(default_factory=lambda: ...)`` included), then each read in its
    fallback argument.
    """
    call = next((n for n in ast.walk(expr) if _env_key(n)), None)
    chain: list[str] = []
    while call is not None and _env_key(call):
        chain.append(_env_key(call))
        fallback = call.args[1] if len(call.args) > 1 else None
        call = fallback if fallback is not None and _env_key(fallback) else None
    return chain


def _default_expressions(stmt: ast.AnnAssign) -> list[ast.AST]:
    """The expressions a field's default comes from, in the class body's syntax.

    The assigned value, or the ``default``/``default_factory`` of a ``Field(...)``
    that is assigned or sits in an ``Annotated[...]`` annotation. Nothing else in
    a ``Field`` call (a description that mentions a variable) counts.
    """
    found: list[ast.AST] = []
    for part in (stmt.value, stmt.annotation):
        if part is None:
            continue
        for node in ast.walk(part):
            if not isinstance(node, ast.Call) or not ast.unparse(node.func).endswith(
                "Field"
            ):
                continue
            found += node.args[:1]
            found += [
                kw.value
                for kw in node.keywords
                if kw.arg in ("default", "default_factory")
            ]
    value = stmt.value
    if value is not None and not (
        isinstance(value, ast.Call) and ast.unparse(value.func).endswith("Field")
    ):
        found.append(value)
    return found


def _module_env_constants(module) -> dict[str, list[str]]:
    """Module-level names whose value is computed from an environment read."""
    try:
        tree = ast.parse(inspect.getsource(module))
    except (OSError, TypeError, SyntaxError):
        return {}
    found = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            chain = _env_chain(stmt.value)
            for target in targets:
                if isinstance(target, ast.Name) and chain:
                    found[target.id] = chain
    return found


def env_defaults(model: type) -> dict[str, list[str]]:
    """Field name -> the variables its default is read from, for ``model`` and its bases.

    The nearest class that assigns a field decides, as in pydantic.
    """
    found: dict[str, list[str]] = {}
    seen: set[str] = set()
    for cls in model.__mro__:
        if cls is object or "model_fields" not in dir(cls):
            continue
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
        except (OSError, TypeError, SyntaxError):
            continue
        module = sys.modules.get(cls.__module__)
        class_def = tree.body[0]
        for stmt in getattr(class_def, "body", []):
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(
                stmt.target, ast.Name
            ):
                continue
            name = stmt.target.id
            if name in seen:
                continue
            seen.add(name)
            chain: list[str] = []
            for expr in _default_expressions(stmt):
                chain = _env_chain(expr)
                if not chain and isinstance(expr, ast.Name) and module is not None:
                    origin = _defining_module(module, expr.id)
                    mapping = _module_env_constants(origin) if origin else {}
                    chain = mapping.get(expr.id, [])
                if chain:
                    break
            if chain:
                found[name] = chain
    return found


def _defining_module(module, ref: str):
    """The module ``ref`` is assigned in: ``module`` itself, or the one it imports it from."""
    import importlib

    if ref in _source_names(module):
        return module
    try:
        tree = ast.parse(inspect.getsource(module))
    except (OSError, TypeError, SyntaxError):
        return None
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom) and stmt.module and not stmt.level:
            for alias in stmt.names:
                if (alias.asname or alias.name) == ref:
                    try:
                        return importlib.import_module(stmt.module)
                    except ImportError:
                        return None
    return None


def _source_names(module) -> set[str]:
    try:
        tree = ast.parse(inspect.getsource(module))
    except (OSError, TypeError, SyntaxError):
        return set()
    names = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


# ---------------------------------------------------------------------------
# Model walk
# ---------------------------------------------------------------------------


class Section:
    def __init__(
        self, path: str, model: type, description: Optional[str], is_list: bool
    ):
        self.path = path
        self.model = model
        self.description = description
        self.is_list = is_list
        self.rows: list[dict] = []


def _models_in(annotation: Any) -> Iterator[tuple[type, bool]]:
    """Yield ``(model, inside_list)`` for every model class reachable in an annotation."""
    annotation = _strip_annotated(annotation)
    args = _union_args(annotation)
    if args is not None:
        for arg in args:
            yield from _models_in(arg)
        return
    origin = typing.get_origin(annotation)
    if origin in (list, tuple, set, frozenset):
        for arg in typing.get_args(annotation):
            for model, _ in _models_in(arg):
                yield model, True
        return
    if origin is dict:
        args = typing.get_args(annotation)
        if len(args) == 2:
            for model, _ in _models_in(args[1]):
                yield model, False
        return
    if _is_model(annotation):
        yield annotation, False


def anchor_for(path: str) -> str:
    return path.replace("[]", "")


def walk_config(root: type) -> tuple[list[Section], list[str]]:
    """Every section of the config model tree, in page order, and the fields with no description."""
    from automated_security_helper.base.plugin_base import PluginBase
    from automated_security_helper.base.plugin_config import PluginConfigBase

    sections: list[Section] = []
    missing: list[str] = []
    seen: set[type] = set()

    def visit(model: type, path: str, description: Optional[str], is_list: bool):
        section = Section(path, model, description, is_list)
        sections.append(section)
        seen.add(model)
        from_env = env_defaults(model)
        by_platform = platform_defaults(model)
        children = []
        for name, field in model.model_fields.items():
            key = field.alias or name
            prefix = f"{path}[]" if is_list else path
            full = f"{prefix}.{key}" if prefix else key
            nested = [
                (m, in_list)
                for m, in_list in _models_in(field.annotation)
                if not issubclass(m, (PluginBase, PluginConfigBase))
            ]
            description_text = field.description
            if not description_text and nested:
                description_text = _own_docstring(nested[0][0])
            if not description_text:
                missing.append(f"{full}  ({model.__module__}.{model.__name__}.{name})")
            section.rows.append(
                {
                    "key": key,
                    "full": full,
                    "name": name,
                    "field": field,
                    "description": description_text,
                    "env_default": from_env.get(name),
                    "platform": by_platform.get(name),
                    "excluded_on_dump": bool(field.exclude),
                }
            )
            for nested_model, in_list in nested:
                if nested_model not in seen:
                    children.append((nested_model, full, in_list))
        for nested_model, full, in_list in children:
            if nested_model not in seen:
                visit(nested_model, full, _own_docstring(nested_model), in_list)

    visit(root, "", _own_docstring(root), False)
    return sections, missing


def _section_anchor(section: Section) -> str:
    return "section-" + (anchor_for(section.path).replace(".", "-") or "top-level")


# ---------------------------------------------------------------------------
# Discovery, measured
# ---------------------------------------------------------------------------


def discovery_order() -> list[str]:
    """Every config source the scan root can hold, in the precedence the code applies."""
    from automated_security_helper.config.config_sources import discover_config_source
    from automated_security_helper.core.constants import (
        ASH_CONFIG_FILE_NAMES,
        ASH_PYPROJECT_FILE_NAME,
        ASH_RC_FILE_NAMES,
    )

    with tempfile.TemporaryDirectory(prefix="ash-config-discovery-") as tmp:
        root = Path(tmp)
        (root / ".ash").mkdir()
        candidates = [root / n for n in ASH_CONFIG_FILE_NAMES]
        candidates += [root / ".ash" / n for n in ASH_CONFIG_FILE_NAMES]
        candidates += [root / n for n in ASH_RC_FILE_NAMES]
        candidates += [root / ".ash" / n for n in ASH_RC_FILE_NAMES]
        for path in candidates:
            path.write_text(
                "{}\n" if path.suffix != ".toml" else "\n", encoding="utf-8"
            )
        for parent in (root, root / ".ash"):
            (parent / ASH_PYPROJECT_FILE_NAME).write_text(
                '[tool.ash]\nproject_name = "x"\n', encoding="utf-8"
            )
        discovery = discover_config_source(root)
        ordered = [discovery.selected, *discovery.ignored]
        return [s.path.relative_to(root).as_posix() for s in ordered if s is not None]


def pyproject_needs_table() -> bool:
    """Whether a pyproject.toml without a [tool.ash] table is passed over, measured."""
    from automated_security_helper.config.config_sources import discover_config_source
    from automated_security_helper.core.constants import ASH_PYPROJECT_FILE_NAME

    with tempfile.TemporaryDirectory(prefix="ash-config-pyproject-") as tmp:
        root = Path(tmp)
        (root / ASH_PYPROJECT_FILE_NAME).write_text(
            '[project]\nname = "x"\n', encoding="utf-8"
        )
        return discover_config_source(root).selected is None


def _workspace_locations_text(found: list[str]) -> list[str]:
    """The policy file's locations as a sentence.

    Not a list: ``verify_docs_freshness.py`` treats any list of config file names as
    the project-config discovery inventory, and these are a different file's names.
    """
    names = [p for p in found if "/" not in p]
    nested = [p.split("/", 1)[1] for p in found if p.startswith(".ash/")]
    if names and names == nested and len(names) + len(nested) == len(found):
        return [
            "ASH looks for it at the workspace root and then in `.ash/`, under any of "
            "these names: " + ", ".join(code(n) for n in names) + "."
        ]
    return ["ASH looks for it at: " + ", ".join(code(p) for p in found) + "."]


def workspace_policy_locations() -> tuple[list[str], bool]:
    """Each location a workspace policy file is found at, and whether two are refused."""
    from automated_security_helper.workspace.policy import (
        WORKSPACE_POLICY_FILE_NAMES,
        discover_workspace_policy_file,
    )

    found = []
    with tempfile.TemporaryDirectory(prefix="ash-workspace-policy-") as tmp:
        root = Path(tmp)
        for parent in ("", ".ash"):
            for name in WORKSPACE_POLICY_FILE_NAMES:
                candidate = root / parent / name
                candidate.parent.mkdir(exist_ok=True)
                candidate.write_text("{}\n", encoding="utf-8")
                hit = discover_workspace_policy_file(root)
                if hit is not None:
                    found.append(
                        Path(hit).resolve().relative_to(root.resolve()).as_posix()
                    )
                candidate.unlink()
        first = root / WORKSPACE_POLICY_FILE_NAMES[0]
        second = root / ".ash" / WORKSPACE_POLICY_FILE_NAMES[0]
        first.write_text("{}\n", encoding="utf-8")
        second.write_text("{}\n", encoding="utf-8")
        try:
            discover_workspace_policy_file(root)
            refuses_two = False
        except Exception:  # WorkspaceDefinitionError; any refusal counts
            refuses_two = True
    return found, refuses_two


def explicit_config_option() -> list[str]:
    """``--config`` spellings and their environment variable, read from the scan command."""
    import typer.main

    from automated_security_helper.cli.main import app

    scan = typer.main.get_command(app).commands["scan"]
    for param in scan.params:
        if "--config" in getattr(param, "opts", []):
            envvar = param.envvar if isinstance(param.envvar, str) else None
            return [*param.opts, *([envvar] if envvar else [])]
    return []


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


def _row(row: dict, link) -> str:
    field = row["field"]
    kind = type_text(field.annotation, link)
    bounds = constraints_text(field)
    if bounds:
        kind = f"{kind}, {bounds}"
    description = md_prose(row["description"]) if row["description"] else NO_DESCRIPTION
    notes = []
    if row["name"] != row["key"]:
        notes.append(f"Also accepted as {code(row['name'])}.")
    if row["excluded_on_dump"]:
        notes.append(
            "Read when the file is loaded and not written back when a config is saved."
        )
    if notes:
        if description and description[-1] not in ".!?:":
            description += "."
        description = f"{description} {' '.join(notes)}"
    anchor = anchor_for(row["full"])
    return (
        f'| <a id="{anchor}"></a>{code(row["key"])} | {kind} | '
        f"{default_cell(field, row.get('platform'), row['env_default'])} | {description} |"
    )


def unknown_keys_text(model: type) -> str:
    """What loading does with a key the model does not declare, from ``model_config``.

    pydantic's default is "ignore", and that is the case worth stating: a misspelled
    key in such a section is dropped without an error.
    """
    extra = model.model_config.get("extra") or "ignore"
    return {
        "forbid": "A key not listed here is an error when the configuration is loaded.",
        "allow": "A key not listed here is accepted and kept, without validation.",
        "ignore": "A key not listed here is ignored, without an error, when the "
        "configuration is loaded.",
    }[extra]


def _plugin_section_rows(
    segment_name: str, page: str, kind: str, segment_model
) -> list[str]:
    """The plugin keys a segment declares, each linked to its options on ``page``."""
    rows = [
        f"| Key | Enabled by default | {kind.capitalize()} options |",
        "|-----|--------------------|---------------|",
    ]
    for name, field in segment_model.model_fields.items():
        key = field.alias or name
        config_cls = _strip_annotated(field.annotation)
        per_platform = platform_defaults(config_cls).get("enabled")
        try:
            enabled = getattr(config_cls(), "enabled", True)
        except Exception:
            enabled = None
        enabled_text = "yes" if enabled else "no" if enabled is not None else "unknown"
        if per_platform:
            enabled_text = per_platform_text(
                per_platform, lambda v: "yes" if v else "no"
            )
        rows.append(
            f'| <a id="{segment_name}.{key}"></a>{code(key)} | {enabled_text} | '
            f"[{code(key)} options]({page}#{key}) |"
        )
    return rows


def generate() -> tuple[str, dict]:
    from automated_security_helper.base.plugin_config import PluginConfigBase
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.ash_workspace_config import AshWorkspaceConfig
    from automated_security_helper.core.constants import (
        ASH_CONFIG_EXTENDS_MAX_DEPTH,
        ASH_CONFIG_EXTENDS_MAX_FILES,
        ASH_PYPROJECT_FILE_NAME,
        ASH_RC_FILE_NAMES,
    )

    sections, missing = walk_config(AshConfig)
    ws_sections, ws_missing = walk_config(AshWorkspaceConfig)
    by_model = {s.model: _section_anchor(s) for s in sections}
    ws_by_model = {s.model: "workspace-" + _section_anchor(s) for s in ws_sections}

    plugin_segments = {name for name, _page, _kind in PLUGIN_SECTIONS}
    order = discovery_order()
    ws_locations, ws_refuses = workspace_policy_locations()
    explicit = explicit_config_option()
    keys = sum(len(s.rows) for s in sections) + sum(len(s.rows) for s in ws_sections)

    lines = banner(
        GENERATOR,
        "the AshConfig and AshWorkspaceConfig pydantic models",
        extra=[
            "",
            "Anchors: every key has <a id> equal to its dotted path with [] removed,",
            "e.g. #global_settings.severity_threshold, #global_settings.suppressions.rule_id.",
        ],
    )
    lines += [
        "# Configuration reference",
        "",
        generated_note(GENERATOR, "the configuration models in the ASH source code"),
        "",
        (
            "Every key is listed with its type, default and the description the model "
            "carries. A key whose model has no description says so. Keys inside a list "
            "are written `key[].field`: `global_settings.suppressions[].rule_id` is the "
            "`rule_id` of one entry in the `suppressions` list. " + ENV_DEFAULT_NOTE
        ),
        "",
        "## Where ASH finds its configuration",
        "",
    ]
    if explicit:
        options = [o for o in explicit if o.startswith("-")]
        envs = [o for o in explicit if not o.startswith("-")]
        sentence = "A path given with " + " or ".join(code(o) for o in options)
        if envs:
            sentence += (
                " or the " + ", ".join(code(e) for e in envs) + " environment variable"
            )
        lines += [sentence + " is used as is, and nothing is discovered.", ""]
    lines += [
        (
            "Otherwise ASH looks in the scan's source directory and uses the first of "
            "these it finds. Sources are never merged: every other one that exists is "
            "ignored, with a warning naming it."
        ),
        "",
    ]
    # Bare items only: scripts/verify_docs_freshness.py reads a list whose items
    # are exactly one file name as a published discovery inventory and checks it
    # against the constants, so a note inside an item would hide that item from it.
    lines += [f"{index}. {code(path)}" for index, path in enumerate(order, start=1)]
    lines += [""]
    if pyproject_needs_table():
        lines += [
            (
                f"{code(ASH_PYPROJECT_FILE_NAME)} counts only when it has a `[tool.ash]` "
                "table; one without it is not a configuration source."
            ),
            "",
        ]
    root_only = [
        n
        for n in [*ASH_RC_FILE_NAMES, ASH_PYPROJECT_FILE_NAME]
        if n in order and f".ash/{n}" not in order
    ]
    if root_only:
        lines += [
            "These are read from the source directory only, never from `.ash/`: "
            + ", ".join(code(n) for n in root_only)
            + ".",
            "",
        ]
    lines += [
        (
            f"A config file can name base files with `extends`. A chain may be at most "
            f"{ASH_CONFIG_EXTENDS_MAX_DEPTH} levels deep and read at most "
            f"{ASH_CONFIG_EXTENDS_MAX_FILES} files."
        ),
        "",
        "## Top-level keys",
        "",
    ]

    def emit(section: Section, anchors: dict, heading_prefix: str = "") -> None:
        nonlocal lines
        if section.path:
            label = f"{section.path}[]" if section.is_list else section.path
            anchor = anchors[section.model]
            lines += [f'### <a id="{anchor}"></a>{heading_prefix}{code(label)}', ""]
            if section.description:
                lines += [md_prose(section.description), ""]
            if section.is_list:
                lines += ["Each entry in the list has these keys.", ""]
        lines += [unknown_keys_text(section.model), ""]
        lines += [
            "| Key | Type | Default | Description |",
            "|-----|------|---------|-------------|",
        ]
        for row in section.rows:
            lines.append(_row(row, lambda m: anchors.get(m)))
        lines.append("")

    top = sections[0]
    emit(top, by_model)
    lines += ["## Sections", ""]
    for section in sections[1:]:
        if section.path in plugin_segments:
            continue
        emit(section, by_model)

    lines += ["## Plugin sections", ""]
    common = PluginConfigBase.model_fields
    lines += [
        (
            "`scanners`, `reporters` and `converters` each map a plugin name to that "
            "plugin's configuration. Every plugin's entry has these keys; what goes "
            "under `options` is specific to the plugin and is listed on its reference "
            "page."
        ),
        "",
        "| Key | Type | Default | Description |",
        "|-----|------|---------|-------------|",
    ]
    for name, field in common.items():
        desc = md_prose(field.description) if field.description else NO_DESCRIPTION
        if not field.description:
            missing.append(f"<plugin>.{name}  (PluginConfigBase.{name})")
        kind = type_text(field.annotation)
        bounds = constraints_text(field)
        if bounds:
            kind = f"{kind}, {bounds}"
        default = default_text(field) if name != "options" else "the plugin's defaults"
        if name == "name":
            default = "the plugin's own name"
        lines.append(f"| {code(name)} | {kind} | {default} | {desc} |")
    lines.append("")
    for segment_name, page, kind in PLUGIN_SECTIONS:
        segment = next((s for s in sections if s.path == segment_name), None)
        if segment is None:
            continue
        lines += [f'### <a id="section-{segment_name}"></a>{code(segment_name)}', ""]
        extra = segment.model.model_config.get("extra")
        lines += [
            f"The {kind}s ASH declares a configuration for. "
            + (
                f"Other {kind} names are accepted too (the section allows extra keys), "
                f"for {kind}s loaded from `ash_plugin_modules`."
                if extra == "allow"
                else f"No other {kind} names are accepted."
            ),
            "",
            *_plugin_section_rows(segment_name, page, kind, segment.model),
            "",
        ]

    lines += [
        "## Workspace policy file",
        "",
        (
            "In workspace mode, policy that applies to every project lives in its own "
            "file, separate from any project's configuration."
        ),
        "",
        *_workspace_locations_text(ws_locations),
        "",
    ]
    if ws_refuses:
        lines += [
            (
                "Exactly one may exist: when ASH finds more than one, it refuses the "
                "workspace rather than choose."
            ),
            "",
        ]
    emit_ws = ws_sections[0]
    lines += ["### Workspace policy keys", "", unknown_keys_text(emit_ws.model), ""]
    lines += [
        "| Key | Type | Default | Description |",
        "|-----|------|---------|-------------|",
    ]
    for row in emit_ws.rows:
        lines.append(
            _row(
                {**row, "full": "workspace-policy." + row["full"]},
                lambda m: ws_by_model.get(m),
            )
        )
    lines.append("")
    for section in ws_sections[1:]:
        label = f"{section.path}[]" if section.is_list else section.path
        anchor = ws_by_model[section.model]
        lines += [f'### <a id="{anchor}"></a>Workspace policy {code(label)}', ""]
        if section.description:
            lines += [md_prose(section.description), ""]
        if section.is_list:
            lines += ["Each entry in the list has these keys.", ""]
        lines += [unknown_keys_text(section.model), ""]
        lines += [
            "| Key | Type | Default | Description |",
            "|-----|------|---------|-------------|",
        ]
        for row in section.rows:
            lines.append(
                _row(
                    {**row, "full": "workspace-policy." + row["full"]},
                    lambda m: ws_by_model.get(m),
                )
            )
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    stats = {
        "keys": keys,
        "missing": missing + [f"workspace policy: {m}" for m in ws_missing],
    }
    return "\n".join(lines) + "\n", stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="Exit 1 with a diff if stale."
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path, or '-' for stdout. Default: <docs root>/docs/content/reference/{PAGE}",
    )
    parser.add_argument(
        "--missing-descriptions",
        default=None,
        help="Also write the fields that have no description to this path.",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()

    prepare_environment(Path(args.docs_root))
    output = Path(args.output) if args.output else reference_dir(args.docs_root) / PAGE
    content, stats = generate()
    summary = f"{stats['keys']} keys, {len(stats['missing'])} with no description in the model."
    if args.missing_descriptions:
        Path(args.missing_descriptions).write_text(
            "\n".join(stats["missing"]) + "\n", encoding="utf-8"
        )
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
