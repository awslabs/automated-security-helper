# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What each MCP tool returns, read from the server's source without importing it.

Why this exists
---------------
The MCP pages tell a client which ``error_type`` a refusal carries
(``config_field_denied``, ``output_dir_not_permitted``, ...) and show example
responses, and both are claims about the dicts the tools return. Nothing compared
them with the code: a renamed ``error_type`` literal or a renamed response key
passed every check, because the only statement of either was the prose. This
module reads the return statements of every ``@mcp.tool`` and of the functions
they call, so the MCP tools reference can list each tool's error types and the
docs checks can hold the prose and the examples to them.

What it reads
-------------
Each tool function's ``return`` values are evaluated over the AST, through:

* dict literals, ``**`` spreads, ``dict(...)``, conditionals and ``or``;
* local variables, with the keys later added by ``x["key"] = ...``,
  ``x.update(...)`` and ``x.setdefault(...)``, and the items ``x.append(...)``
  adds;
* calls to functions anywhere in the package, with informative arguments bound
  to their parameters, nested functions, methods on ``self``, and methods on a
  variable whose class follows from a constructor or a return annotation;
* attributes of an object built in the package (``_Result(error={...})``);
* a comprehension over a list: a lone name that iterates it is each item of the
  list, whatever the filters drop; any other target, and an iterable that is not
  a list, are unread;
* ``except K as e`` ... ``e.error_type``: the argument of every construction of
  ``K`` and its package subclasses, read in the construction's module, plus two
  forms that scope cannot place. An undecorated module-level helper's parameter
  (``raise K(msg, error_type)``) is what every call of the helper passes, when
  every use of the helper's name in the package is a call this reader resolves
  (no ``import ... as``, no alias, no spread argument, not in a lambda or
  comprehension). ``raise K(msg, e.error_type)`` inside ``except K as e`` adds
  nothing when ``__init__`` stores the parameter as the bare ``self.error_type
  = error_type``; a class built only that way reads as unread;
* module string constants, imported ones included, enum members' ``.value``, and
  ``type(e).__name__``, which is recorded as "the class name of an exception";
* a guard on a ``return``: under ``if r.get("error_type") in (A, B):`` the
  value returned is only those of ``r``'s dicts whose ``error_type`` can be A or B;
* a conditional, or an ``if`` around a ``return`` (or before it, with a branch
  that always returns), whose test is a constant, or a parameter of the function
  that nothing rebinds and whose values here are constants of one truth (a flag
  the caller passes as ``True``, or leaves at a constant default): only the
  branch it selects, so a helper called with ``output=True`` does not list its
  other branch's type. Any other name reads both branches: this reader does not
  follow an attribute store from another module or ``globals()[...]``, so no
  module global's value is ever certain, however it is bound in its own module;
* ``r["K"]``, the K value of each dict ``r`` can be, narrowed by the test it is
  read under, an ``if`` around the ``return`` or a conditional expression's own
  (inline, or a local set once, ``kept = r.get("K") in (A, B)``): there
  ``r["K"]`` is A or B, and in the other branch of one ``in`` test it is neither.
  That needs nothing to change ``r`` between the test and the read: the
  function sets ``r`` by one plain assignment (it is not a parameter, a caught
  exception, a loop or ``with`` target or an element of an unpacking) and
  nothing there changes it, and ``kept`` is set the same way, after ``r`` and
  before the test. ``r["K"]`` is unread when that does not
  hold, when narrowing leaves K nothing to be, and when the test is about ``r``
  (or a local computed from it) in a way not understood, unless it is only about
  keys the branch does not read. A function ``r`` is passed to, and an alias of
  ``r``, are not followed;
* ``a, b = f(...)``, ``a, b = await f(...)`` and ``a, b = x, y``: each name is that
  element of each tuple. ``f`` is a function bound once where the call finds it,
  every ``return`` of which is a tuple literal of as many elements, and which
  cannot end without one; anything else, and a starred or nested target, leaves
  the names unread.

Each value is a :class:`Shape`, a set of alternatives: one dict literal is one
alternative, so a check can ask whether one response has every key of an example
rather than whether the keys appear somewhere across all of them. A value the
evaluator cannot follow is never guessed at; it is an unread alternative with its
``path:line``, and a dict that can gain keys the source does not name records
where, so a caller can tell a key that is absent from one it could not see.

Error types are the values of a response's ``error_type`` key. ``validate_config``
also returns a list of errors, each with a ``type``: the entries' types.

Nothing here imports ASH, so it runs against any checkout's source: the
generator passes the package it documents, the docs checks the package their
interpreter would import, and the tests a planted tree.
"""

from __future__ import annotations

import ast
import builtins
import itertools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional, Union

PACKAGE = "automated_security_helper"
SERVER_MODULE = f"{PACKAGE}.cli.mcp_server"
#: ``@mcp.tool()`` registers a tool on the server object named ``mcp``.
SERVER_OBJECT = "mcp"
TOOL_DECORATOR = "tool"
ERROR_TYPE_KEY = "error_type"
#: validate_config's response: ``{"valid": ..., "errors": [{"type": ...}, ...]}``.
ENTRY_LIST_KEY = "errors"
ENTRY_TYPE_KEY = "type"
#: How deep calls are followed; the deepest chain in the server is about eight.
MAX_CALL_DEPTH = 24
#: Past this many alternatives a value's dicts are merged into one, so that a
#: chain of spreads cannot grow without bound. Narrowing is then less precise.
MAX_VARIANTS = 64
#: How many expressions one :class:`Evaluator` evaluates before it stops with
#: :class:`ContractWorkBudgetExceeded`. MAX_CALL_DEPTH bounds the depth of a walk,
#: not its width, so a call chain that is read again for every caller grows without
#: bound; a generous cap turns that into an error naming where it was reading,
#: where a run would otherwise never return.
MAX_EVALUATIONS = 20_000_000
#: Package functions that run their first argument, a callable, with the keyword
#: arguments that follow it and return what it returns: ``await _run_clone(f,
#: **kw)`` is ``f(**kw)`` on a thread pool. They reach ``f`` through
#: ``run_in_executor(executor, functools.partial(...))``, which this module does
#: not follow, so the response of a tool that calls them would otherwise be an
#: unread value and the error types ``f`` returns would be listed under no tool.
CALLABLE_RUNNERS = frozenset(
    {f"{SERVER_MODULE}._run_clone", f"{SERVER_MODULE}._run_delivery"}
)
#: Standard-library functions that run their first argument, a callable, with
#: every argument that follows it and return what it returns: ``await
#: asyncio.to_thread(f, a, k=v)`` is ``f(a, k=v)`` on a worker thread. The
#: package hands a registry method's result through it (``await
#: asyncio.to_thread(registry.check_scan_progress, scan_id, **scoped)``), so a
#: reader that stopped at the call would list that tool's response as an unread
#: value and miss every key the method's dict carries. Named by dotted path;
#: both ``import asyncio`` and ``from asyncio import to_thread`` reach it.
STDLIB_RUNNERS = frozenset({"asyncio.to_thread"})
#: Builtin exceptions, which ``type(e).__name__`` can also name.
BUILTIN_EXCEPTIONS = frozenset(
    name
    for name in dir(builtins)
    if isinstance(getattr(builtins, name), type)
    and issubclass(getattr(builtins, name), BaseException)
)


class ContractWorkBudgetExceeded(RuntimeError):
    """The evaluator read more expressions than ``MAX_EVALUATIONS`` allows."""


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DictV:
    """A dict, with the shape of each key's value."""

    keys: tuple[tuple[str, "Shape"], ...] = ()
    #: Where the dict can get keys the source does not name: ``path:line`` each.
    open_at: tuple[str, ...] = ()

    def key_map(self) -> dict[str, "Shape"]:
        return dict(self.keys)


@dataclass(frozen=True)
class ListV:
    """A list, tuple or set, with the shape of its items."""

    items: "Shape"
    #: A tuple literal's elements, in order; None for anything else.
    elements: Optional[tuple["Shape", ...]] = None


@dataclass(frozen=True)
class StrV:
    """A string constant."""

    value: str


@dataclass(frozen=True)
class ClassNameV:
    """``type(e).__name__``: the class name of an exception."""


@dataclass(frozen=True)
class ObjectV:
    """An instance of a package class, with the attributes it was built with."""

    cls: str
    attrs: tuple[tuple[str, "Shape"], ...] = ()


@dataclass(frozen=True)
class UnreadV:
    """A value the source does not let this module read, and where."""

    site: str


@dataclass(frozen=True)
class LiteralV:
    """A constant that is not a string: True, False, None or a number."""

    value: Union[bool, int, float, None]


Variant = Union[DictV, ListV, StrV, ClassNameV, ObjectV, UnreadV, LiteralV]


@dataclass(frozen=True)
class Shape:
    """What an expression can evaluate to: each alternative the source gives."""

    variants: tuple[Variant, ...] = ()

    def __hash__(self) -> int:
        # The call memo keys on shapes, which nest; hashing one at every call
        # would walk it every time, so the hash is kept on the instance.
        cached = self.__dict__.get("_hash")
        if cached is None:
            cached = hash(self.variants)
            object.__setattr__(self, "_hash", cached)
        return cached

    def dicts(self) -> list[DictV]:
        return [v for v in self.variants if isinstance(v, DictV)]

    @property
    def strings(self) -> frozenset[str]:
        return frozenset(v.value for v in self.variants if isinstance(v, StrV))

    @property
    def class_name(self) -> bool:
        return any(isinstance(v, ClassNameV) for v in self.variants)

    @property
    def unread(self) -> tuple[str, ...]:
        return tuple(v.site for v in self.variants if isinstance(v, UnreadV))

    @property
    def is_dict(self) -> bool:
        return any(isinstance(v, DictV) for v in self.variants)

    @property
    def is_list(self) -> bool:
        return any(isinstance(v, ListV) for v in self.variants)

    @property
    def informative(self) -> bool:
        """Anything but unread alternatives and constants: worth binding to a
        parameter. A constant is bound only to a parameter used as a flag."""
        return any(not isinstance(v, (UnreadV, LiteralV)) for v in self.variants)

    @property
    def literal(self) -> bool:
        """Only constants that are not strings (True, None, 0)."""
        return bool(self.variants) and all(
            isinstance(v, LiteralV) for v in self.variants
        )

    def items(self) -> "Shape":
        return union(*(v.items for v in self.variants if isinstance(v, ListV)))

    def value_of(self, key: str) -> "Shape":
        """The union of ``key``'s value over every dict alternative that has it."""
        return union(*(d.key_map()[key] for d in self.dicts() if key in d.key_map()))

    def keys(self) -> list[str]:
        """Every key some dict alternative names, in first-seen order."""
        return list(dict.fromkeys(k for d in self.dicts() for k, _ in d.keys))

    def attr(self, name: str, site: str) -> "Shape":
        parts: list[Shape] = []
        for v in self.variants:
            if isinstance(v, ObjectV):
                attrs = dict(v.attrs)
                parts.append(attrs[name] if name in attrs else unread(site))
            elif isinstance(v, UnreadV):
                parts.append(unread(site))
        return union(*parts) if parts else unread(site)


NOTHING = Shape()


def union(*shapes: Optional[Shape]) -> Shape:
    """One shape that is any of ``shapes``."""
    present = [s for s in shapes if s is not None and s.variants]
    if not present:
        return NOTHING
    if len(present) == 1:
        return present[0]
    variants = tuple(dict.fromkeys(v for s in present for v in s.variants))
    return _cap(Shape(variants))


def _cap(shape: Shape) -> Shape:
    """Merge a shape's dicts when it has too many alternatives.

    Dicts with an error_type key merge apart from those without: one refusal
    among many success alternatives would otherwise give the merged dict an
    error_type, and the success alternatives' open sites would read as covered
    by it."""
    if len(shape.variants) <= MAX_VARIANTS:
        return shape
    buckets: dict[bool, tuple[dict[str, Shape], list[str]]] = {}
    for d in shape.dicts():
        merged, open_at = buckets.setdefault(
            any(key == ERROR_TYPE_KEY for key, _ in d.keys), ({}, [])
        )
        for key, value in d.keys:
            merged[key] = union(merged.get(key), value)
        open_at += d.open_at
    rest = tuple(v for v in shape.variants if not isinstance(v, DictV))
    return Shape(
        rest
        + tuple(
            DictV(tuple(merged.items()), _unique(open_at))
            for merged, open_at in buckets.values()
        )
    )


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def one(variant: Variant) -> Shape:
    return Shape((variant,))


def unread(site: str) -> Shape:
    return one(UnreadV(site))


def dict_shape(keys: dict[str, Shape], open_at: Iterable[str] = ()) -> Shape:
    return one(DictV(tuple(keys.items()), _unique(open_at)))


def with_keys(base: Shape, keys: dict[str, Shape], open_at: Iterable[str]) -> Shape:
    """``base`` after keys are added to it: each dict gets them, an unread one becomes one."""
    open_at = tuple(open_at)
    if not keys and not open_at:
        return base
    variants: list[Variant] = []
    for v in base.variants:
        if isinstance(v, DictV):
            merged = v.key_map()
            for key, value in keys.items():
                merged[key] = union(merged.get(key), value)
            variants.append(DictV(tuple(merged.items()), _unique(v.open_at + open_at)))
        elif isinstance(v, UnreadV):
            variants.append(DictV(tuple(keys.items()), _unique((v.site,) + open_at)))
        else:
            variants.append(v)
    if not variants:
        variants.append(DictV(tuple(keys.items()), open_at))
    return _cap(Shape(tuple(dict.fromkeys(variants))))


# ---------------------------------------------------------------------------
# The package's source
# ---------------------------------------------------------------------------


@dataclass
class _Module:
    name: str
    rel: str
    tree: ast.Module
    is_package: bool
    #: Top-level functions and classes, assignments and imports, by name.
    defs: dict[str, ast.AST] = field(default_factory=dict)
    assigns: dict[str, list[ast.expr]] = field(default_factory=dict)
    imports: dict[str, tuple[str, Optional[str]]] = field(default_factory=dict)


def _import_target(
    node: Union[ast.ImportFrom, ast.Import], module: _Module
) -> list[tuple[str, tuple[str, Optional[str]]]]:
    """``(bound name, (module, attribute or None))`` for each name an import binds."""
    found: list[tuple[str, tuple[str, Optional[str]]]] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                found.append((alias.asname, (alias.name, None)))
            else:
                head = alias.name.split(".")[0]
                found.append((head, (head, None)))
        return found
    base = node.module or ""
    if node.level:
        parts = module.name.split(".")
        if not module.is_package:
            parts = parts[:-1]
        if node.level > 1:
            parts = parts[: len(parts) - (node.level - 1)]
        base = ".".join([*parts, *([base] if base else [])])
    for alias in node.names:
        found.append((alias.asname or alias.name, (base, alias.name)))
    return found


class Source:
    """The package's modules, parsed on first use."""

    def __init__(self, package_dir: Path):
        self.package_dir = Path(package_dir)
        self.root = self.package_dir.parent
        self._modules: dict[str, Optional[_Module]] = {}

    def module(self, name: str) -> Optional[_Module]:
        if name in self._modules:
            return self._modules[name]
        found = None
        if name == PACKAGE or name.startswith(PACKAGE + "."):
            base = self.package_dir.joinpath(*name.split(".")[1:])
            for path, is_package in (
                (base / "__init__.py", True),
                (base.with_suffix(".py"), False),
            ):
                if path.is_file():
                    found = self._parse(name, path, is_package)
                    break
        self._modules[name] = found
        return found

    def _parse(self, name: str, path: Path, is_package: bool) -> Optional[_Module]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return None
        module = _Module(
            name=name,
            rel=path.relative_to(self.root).as_posix(),
            tree=tree,
            is_package=is_package,
        )
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                module.defs[node.name] = node
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        module.assigns.setdefault(target.id, []).append(node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if isinstance(node.target, ast.Name):
                    module.assigns.setdefault(node.target.id, []).append(node.value)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for bound, target in _import_target(node, module):
                    module.imports[bound] = target
        return module

    def all_modules(self) -> list[_Module]:
        """Every module of the package, in path order."""
        found = []
        for path in sorted(self.package_dir.rglob("*.py")):
            parts = list(path.relative_to(self.root).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            module = self.module(".".join(parts))
            if module is not None:
                found.append(module)
        return found


# ---------------------------------------------------------------------------
# Function bodies
# ---------------------------------------------------------------------------

#: A ``return`` and the ``if`` tests it sits under: (test, True in its body).
#: The handlers it sits in bind exception names: (name, the handler's type).
Guarded = tuple[
    ast.Return,
    tuple[tuple[ast.expr, bool], ...],
    tuple[tuple[str, ast.expr], ...],
]

_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
#: Scopes between a construction and its function in which a name can be bound by
#: something this reader does not follow (a comprehension's loop variable).
_OPAQUE_SCOPES = (
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_MUTATORS = frozenset({"update", "setdefault", "append", "extend", "insert"})


@dataclass
class _Locals:
    params: set[str] = field(default_factory=set)
    assigns: dict[str, list[ast.expr]] = field(default_factory=dict)
    #: Names bound by for/with/unpacking, which are not followed: their line.
    unread: dict[str, int] = field(default_factory=dict)
    #: What each of those is bound from: the loop's iterable, the ``with``
    #: item's expression, the unpacked value; None where nothing names it.
    sources: dict[str, list[Optional[ast.expr]]] = field(default_factory=dict)
    #: ``except X as name``: the handler's type expression, per name.
    caught: dict[str, list[ast.expr]] = field(default_factory=dict)
    #: ``x["key"] = value``: (key or None, value, line).
    key_sets: dict[str, list[tuple[Optional[str], ast.expr, int]]] = field(
        default_factory=dict
    )
    #: ``x.update(...)``, ``x.setdefault(...)``, ``x.append(...)``, ``x.extend(...)``.
    calls: dict[str, list[ast.Call]] = field(default_factory=dict)
    imports: dict[str, tuple[str, Optional[str]]] = field(default_factory=dict)
    defs: dict[str, ast.AST] = field(default_factory=dict)
    returns: list[Guarded] = field(default_factory=list)
    #: Per ``return`` (by id): the always-returning ``if`` tests before it, with
    #: the outcome that reaches it.
    passed: dict[int, tuple[tuple[ast.expr, bool], ...]] = field(default_factory=dict)
    yields: bool = False


def _is_self_attribute(node: ast.AST, attr: str) -> bool:
    """Whether ``node`` is ``self.<attr>``."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr == attr
    )


def _own_nodes(func: ast.AST) -> Iterator[ast.AST]:
    """Every node of a function's body, without the bodies of functions inside it."""
    stack = list(reversed(getattr(func, "body", [])))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, _NESTED):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _names_bound_by(node: ast.AST, module: Optional[_Module] = None) -> list[str]:
    """The names one node binds, for the binding counts: a ``def`` or class, a
    store or delete of a plain name (an assignment, loop or ``with`` target,
    ``del``, an augmented assignment's target), an import, ``except ... as``
    and the ``match`` captures (``as``, ``*``, ``**rest``). One list, so the
    counting call sites cannot drift apart on a new binding form again."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
        return [node.id]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        if module is not None:
            return [bound for bound, _ in _import_target(node, module)]
        return [alias.asname or alias.name.split(".")[0] for alias in node.names]
    if isinstance(node, ast.ExceptHandler) and node.name:
        return [node.name]
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        return [node.name]
    if isinstance(node, ast.MatchMapping) and node.rest:
        return [node.rest]
    return []


def _guarded_returns(
    body: list[ast.stmt],
    guards: tuple[tuple[ast.expr, bool], ...] = (),
    caught: tuple[tuple[str, ast.expr], ...] = (),
    passed: Optional[dict[int, tuple[tuple[ast.expr, bool], ...]]] = None,
    after: tuple[tuple[ast.expr, bool], ...] = (),
) -> Iterator[Guarded]:
    """Each ``return`` with the ``if`` tests around it and the handlers it is in.

    ``passed`` records, per ``return``, the tests of the ``if`` statements before
    it in its blocks whose taken branch always returns, with the outcome that
    lets it be reached: after ``if quiet: return A``, ``return B`` needs
    ``quiet`` false. Only reachability reads them; nothing is narrowed by them.
    """
    for stmt in body:
        if isinstance(stmt, ast.Return):
            if passed is not None:
                passed[id(stmt)] = after
            yield stmt, guards, caught
        elif isinstance(stmt, _NESTED):
            continue
        elif isinstance(stmt, ast.If):
            yield from _guarded_returns(
                stmt.body, guards + ((stmt.test, True),), caught, passed, after
            )
            yield from _guarded_returns(
                stmt.orelse, guards + ((stmt.test, False),), caught, passed, after
            )
            if _always_returns(stmt.body):
                after = after + ((stmt.test, False),)
            elif stmt.orelse and _always_returns(stmt.orelse):
                after = after + ((stmt.test, True),)
        else:
            for name in ("body", "orelse", "finalbody"):
                yield from _guarded_returns(
                    getattr(stmt, name, []) or [], guards, caught, passed, after
                )
            for handler in getattr(stmt, "handlers", []) or []:
                bound = caught
                if handler.name and handler.type is not None:
                    bound = caught + ((handler.name, handler.type),)
                yield from _guarded_returns(handler.body, guards, bound, passed, after)
            for case in getattr(stmt, "cases", []) or []:
                yield from _guarded_returns(case.body, guards, caught, passed, after)


#: The attribute an unpacking's element node carries: how many names the target has.
_UNPACK_ARITY = "_contract_unpack_arity"

#: The attribute marking an ``update`` call synthesized from ``x |= v``: unlike a
#: written ``x.update(v)``, it REBINDS ``x``, so a non-dict left side (a set, a
#: flag) must come out partly unread rather than keep its old binding.
_AUG_MERGE = "_contract_aug_merge"


def _element_of(value: ast.expr, index: int, target: ast.AST) -> ast.expr:
    """``value[index]`` as an unpacking target of ``arity`` names reads it.

    A node of its own, marked with the target's length, so the evaluator takes
    element ``index`` of each tuple ``value`` can be and nothing else.
    """
    node = ast.Subscript(value=value, slice=ast.Constant(index), ctx=ast.Load())
    ast.copy_location(node, target)
    setattr(node, _UNPACK_ARITY, len(target.elts))  # type: ignore[attr-defined]
    return node


def _bind_target(
    locals_: _Locals,
    target: ast.AST,
    value: Optional[ast.expr],
    source: Optional[ast.expr] = None,
) -> None:
    """Record what ``target = value`` binds; ``source`` is what a name bound
    without a value (a loop target, an element of a starred unpacking) comes from."""
    if isinstance(target, ast.Name):
        if value is None:
            locals_.unread.setdefault(target.id, getattr(target, "lineno", 0))
            locals_.sources.setdefault(target.id, []).append(source)
        else:
            locals_.assigns.setdefault(target.id, []).append(value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        if value is not None and all(isinstance(e, ast.Name) for e in target.elts):
            # ``a, b = f(...)``: each name is that element of what the value is.
            for index, element in enumerate(target.elts):
                _bind_target(locals_, element, _element_of(value, index, target))
            return
        for element in target.elts:
            _bind_target(locals_, element, None, value if value is not None else source)
    elif isinstance(target, ast.Starred):
        _bind_target(
            locals_, target.value, None, value if value is not None else source
        )
    elif (
        isinstance(target, ast.Subscript)
        and isinstance(target.value, ast.Name)
        and value is not None
    ):
        key = target.slice
        text = (
            key.value
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
            else None
        )
        locals_.key_sets.setdefault(target.value.id, []).append(
            (text, value, target.lineno)
        )


def _locals_of(func: ast.AST, module: _Module) -> _Locals:
    found = _Locals()
    args = getattr(func, "args", None)
    if args is not None:
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
            found.params.add(arg.arg)
        for arg in (args.vararg, args.kwarg):
            if arg is not None:
                found.params.add(arg.arg)
    for node in _own_nodes(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _bind_target(found, target, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            _bind_target(found, node.target, node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            # ``x |= v`` merges into x like ``x.update(v)``, so every
            # alternative keeps both sides' keys, rather than reading as two
            # alternative responses with one key each. Any other ``x op= v``
            # is read as ``x = x op v``: list ``+`` already unions like the
            # extend record would, arithmetic comes out unread, and the
            # dependence on the right-hand side stays visible to the narrows.
            if isinstance(node.op, ast.BitOr):
                call = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id=node.target.id, ctx=ast.Load()),
                        attr="update",
                        ctx=ast.Load(),
                    ),
                    args=[node.value],
                    keywords=[],
                )
                ast.copy_location(call, node)
                ast.copy_location(call.func, node)
                ast.copy_location(call.func.value, node.target)
                setattr(call, _AUG_MERGE, True)
                found.calls.setdefault(node.target.id, []).append(call)
            else:
                combined = ast.BinOp(
                    left=ast.Name(id=node.target.id, ctx=ast.Load()),
                    op=node.op,
                    right=node.value,
                )
                ast.copy_location(combined, node)
                ast.copy_location(combined.left, node.target)
                found.assigns.setdefault(node.target.id, []).append(combined)
        elif isinstance(node, ast.NamedExpr):
            _bind_target(found, node.target, node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            _bind_target(found, node.target, None, node.iter)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _bind_target(found, item.optional_vars, None, item.context_expr)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            if node.type is None:
                found.unread.setdefault(node.name, node.lineno)
            else:
                found.caught.setdefault(node.name, []).append(node.type)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            # A ``match`` capture binds whatever matched, which this reader
            # does not model, so the name's value gains an unread part.
            found.unread.setdefault(node.name, node.lineno)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            # ``case {**rest}:`` binds the unmatched mapping items, also
            # unmodelled here.
            found.unread.setdefault(node.rest, node.lineno)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for bound, target in _import_target(node, module):
                found.imports[bound] = target
        elif isinstance(node, _NESTED) and not isinstance(node, ast.Lambda):
            found.defs[node.name] = node
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            found.yields = True
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr in _MUTATORS
        ):
            found.calls.setdefault(node.func.value.id, []).append(node)
    found.returns = list(
        _guarded_returns(getattr(func, "body", []), passed=found.passed)
    )
    return found


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Ref:
    """What a name refers to: a function, a class, a module or a value."""

    kind: str  # "function", "class", "module", "value"
    module: Optional[_Module] = None
    node: Optional[ast.AST] = None
    owner: Optional[ast.ClassDef] = None
    owner_module: Optional[_Module] = None
    dotted: str = ""
    scope: Optional["_Scope"] = None
    name: str = ""


@dataclass(eq=False)
class _Scope:
    module: _Module
    func: Optional[ast.AST] = None
    owner: Optional[ast.ClassDef] = None
    owner_module: Optional[_Module] = None
    parent: Optional["_Scope"] = None
    bindings: dict[str, Shape] = field(default_factory=dict)
    locals: Optional[_Locals] = None
    #: Names whose ``name["K"]`` reads are unread here: a condition on them that
    #: this module does not follow decides the value. Name to the test's site and why.
    poisoned: dict[str, str] = field(default_factory=dict)
    #: A scope a test made: its bindings narrow the function's own names.
    conditioned: bool = False
    #: Where the call that made this function scope sits on the evaluator's stack.
    frame: int = -1

    def site(self, node: ast.AST) -> str:
        return f"{self.module.rel}:{getattr(node, 'lineno', 0)}"

    def poisoned_at(self, name: str) -> Optional[str]:
        current: Optional[_Scope] = self
        while current is not None:
            if name in current.bindings and name not in current.poisoned:
                return None
            if name in current.poisoned:
                return current.poisoned[name]
            current = current.parent
        return None


#: ``Evaluator._guard_floor`` when no guard has answered.
_NO_GUARD = 1 << 30


def _str_constant(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class Evaluator:
    """Evaluates expressions of the package's source to a :class:`Shape`."""

    def __init__(self, source: Source, max_evaluations: int = MAX_EVALUATIONS):
        self.source = source
        self.max_evaluations = max_evaluations
        self._evaluations = 0
        self._returns: dict[int, Shape] = {}
        #: Calls that carry bindings or a parent scope, by what :meth:`_call_key`
        #: makes of them; only results that no recursion guard shaped are kept. An
        #: entry is (result, the functions and names its read went through, the
        #: deepest the stack got below the call, itself included); see
        #: :meth:`returns` for when it may be used.
        self._bound_returns: dict[tuple, tuple[Shape, frozenset, int]] = {}
        #: What the running call has read so far: the ids of the functions it
        #: called and the (scope, name) keys it evaluated, and the deepest the stack
        #: has been. Each call hands these up to its caller when it ends.
        self._reads: set = set()
        self._peak = 0
        #: The lowest stack position a recursion or depth guard answered for since
        #: the call being read began; see :meth:`_note_guard`.
        self._guard_floor = _NO_GUARD
        self._locals: dict[int, _Locals] = {}
        self._stack: list[int] = []
        #: The ``path:line`` of each function on ``_stack``, for the budget error.
        self._sites: list[str] = []
        self._names_in_progress: set[tuple[int, str]] = set()
        self._calls_by_name: Optional[dict[str, list[tuple[_Module, ast.Call]]]] = None
        self._caught_memo: dict[int, Shape] = {}
        #: Caught classes whose constructions are being read right now; a second
        #: read of one, inside the first, is unread. See :meth:`_caught`.
        self._caught_in_progress: set[int] = set()
        #: Parent of each node, per module tree, for :meth:`_construction_site`.
        self._parents: dict[int, dict[int, ast.AST]] = {}
        #: How often each name is used in the package, and the names an import
        #: renames; see :meth:`_passed_through`.
        self._name_uses: Optional[dict[str, int]] = None
        self._renamed_imports: frozenset[str] = frozenset()
        self._passed_memo: dict[tuple[int, str], Optional[Shape]] = {}
        #: (call node, caught class node) of the constructions that raise a caught
        #: exception again with its own attribute; see :meth:`_caught`.
        self._reraise_calls: set[tuple[int, int]] = set()
        self._rebound_memo: dict[int, frozenset[str]] = {}
        self._rebindable_memo: dict[int, frozenset[str]] = {}
        self._flags_memo: dict[int, frozenset[str]] = {}

    # -- names ----------------------------------------------------------------

    def _locals_for(self, func: ast.AST, module: _Module) -> _Locals:
        if id(func) not in self._locals:
            self._locals[id(func)] = _locals_of(func, module)
        return self._locals[id(func)]

    def _module_ref(self, module: _Module, name: str) -> Optional[_Ref]:
        node = module.defs.get(name)
        if isinstance(node, ast.ClassDef):
            return _Ref("class", module=module, node=node)
        if node is not None:
            return _Ref("function", module=module, node=node)
        if name in module.assigns:
            return _Ref("value", module=module, scope=_Scope(module=module), name=name)
        if name in module.imports:
            return self._import_ref(*module.imports[name])
        return None

    def _import_ref(self, dotted: str, attr: Optional[str]) -> Optional[_Ref]:
        if attr is None:
            return _Ref("module", dotted=dotted)
        target = self.source.module(dotted)
        if target is not None:
            found = self._module_ref(target, attr)
            if found is not None:
                return found
        if self.source.module(f"{dotted}.{attr}") is not None:
            return _Ref("module", dotted=f"{dotted}.{attr}")
        return None

    def lookup(self, scope: _Scope, name: str) -> Optional[_Ref]:
        current: Optional[_Scope] = scope
        while current is not None:
            if name in current.bindings:
                return _Ref("value", scope=current, name=name)
            local = current.locals
            if current.func is not None and local is not None:
                if (
                    name in local.params
                    or name in local.assigns
                    or name in local.unread
                    or name in local.caught
                    or name in local.key_sets
                ):
                    return _Ref("value", scope=current, name=name)
                if name in local.defs:
                    node = local.defs[name]
                    kind = "class" if isinstance(node, ast.ClassDef) else "function"
                    return _Ref(kind, module=current.module, node=node, scope=current)
                if name in local.imports:
                    return self._import_ref(*local.imports[name])
            current = current.parent
        return self._module_ref(scope.module, name)

    def _ref_of(self, node: ast.AST, scope: _Scope) -> Optional[_Ref]:
        if isinstance(node, ast.Name):
            return self.lookup(scope, node.id)
        if isinstance(node, ast.Attribute):
            owner = self._ref_of(node.value, scope)
            if owner is not None and owner.kind == "module":
                target = self.source.module(owner.dotted)
                if target is not None:
                    return self._module_ref(target, node.attr)
                return _Ref("module", dotted=f"{owner.dotted}.{node.attr}")
        return None

    def name_value(self, ref: _Ref) -> Shape:
        scope, name = ref.scope, ref.name
        if scope is None:
            return NOTHING
        if name in scope.bindings and (
            scope.func is None or scope.locals is None or not self._mutated(scope, name)
        ):
            return scope.bindings[name]
        key = (id(scope) if scope.func is not None else id(scope.module), name)
        if key in self._names_in_progress:
            # The partial value stands for a read that is already under way, which
            # only the function that owns the name (or no function: a module name)
            # can tell from the outside.
            self._guard_floor = min(
                self._guard_floor, scope.frame if scope.func is not None else -1
            )
            return scope.bindings.get(name, NOTHING)
        self._names_in_progress.add(key)
        self._reads.add(key)
        try:
            if scope.func is None or scope.locals is None:
                return union(
                    *(
                        self.evaluate(e, scope)
                        for e in scope.module.assigns.get(name, [])
                    )
                )
            return self._local_value(scope, name)
        finally:
            self._names_in_progress.discard(key)

    def _mutated(self, scope: _Scope, name: str) -> bool:
        """Whether the function can change what ``name`` is bound to, so the
        caller's binding alone cannot stand for it: an assignment, a key set or
        a mutating call, a loop, ``with`` or ``match`` target, ``except ... as``,
        or a ``global``/``nonlocal`` that can reach this function's ``name``."""
        local = scope.locals
        if local is None:
            return False
        return bool(
            local.assigns.get(name)
            or local.key_sets.get(name)
            or local.calls.get(name)
            or name in local.unread
            or name in local.caught
            or self._rebindable(scope, name)
        )

    def _rebindable(self, scope: _Scope, name: str) -> bool:
        """Whether a ``global`` or ``nonlocal`` statement can rebind this
        function's ``name``: a ``nonlocal`` in a function nested inside it, or
        a ``global`` the function's own body declares, which makes the name the
        module's. A ``nonlocal`` can only rebind a name in its own enclosing
        function, and a ``global`` elsewhere can never rebind a local, so the
        rest of the module says nothing here."""
        return scope.func is not None and self._func_rebindable(scope.func, name)

    def _func_rebindable(self, func: ast.AST, name: str) -> bool:
        key = id(func)
        if key not in self._rebindable_memo:
            nonlocals = frozenset(
                n
                for node in ast.walk(func)
                if isinstance(node, ast.Nonlocal)
                for n in node.names
            )
            globals_ = frozenset(
                n
                for node in _own_nodes(func)
                if isinstance(node, ast.Global)
                for n in node.names
            )
            self._rebindable_memo[key] = nonlocals | globals_
        return name in self._rebindable_memo[key]

    def _local_value(self, scope: _Scope, name: str) -> Shape:
        local = scope.locals
        if local is None or scope.func is None:
            return scope.bindings.get(name, NOTHING)
        parts: list[Shape] = []
        if name in scope.bindings:
            parts.append(scope.bindings[name])
        elif name in local.params:
            parts.append(unread(f"{scope.site(scope.func)} parameter {name}"))
        if name in local.unread:
            parts.append(unread(f"{scope.module.rel}:{local.unread[name]}"))
        if self._rebindable(scope, name):
            # A ``global`` or ``nonlocal`` that reaches this function's name
            # lets it rebind between any two reads, so no one binding stands
            # for it.
            parts.append(unread(f"{scope.site(scope.func)} rebindable {name}"))
        for caught in local.caught.get(name, []):
            parts.append(self._caught(caught, scope))
        parts += [self.evaluate(e, scope) for e in local.assigns.get(name, [])]
        base = union(*parts)
        added: dict[str, Shape] = {}
        open_at: list[str] = []
        for key_text, value, line in local.key_sets.get(name, []):
            if key_text is None:
                open_at.append(f"{scope.module.rel}:{line}")
            else:
                added[key_text] = union(
                    added.get(key_text), self.evaluate(value, scope)
                )
        items: list[Shape] = []
        merged_unread: list[Shape] = []
        for call in local.calls.get(name, []):
            method = call.func.attr  # type: ignore[attr-defined]
            if method in ("update", "setdefault"):
                part = self._update_keys(call, scope)
                for d in part.dicts():
                    for k, v in d.keys:
                        added[k] = union(added.get(k), v)
                    open_at += d.open_at
                if getattr(call, _AUG_MERGE, False) and any(
                    isinstance(v, LiteralV) and v.value is not None
                    for v in base.variants
                ):
                    # ``x |= v`` REBINDS a bool or number x (a flag left at a
                    # constant default) to a value the key merge cannot carry,
                    # so that alternative is unread: the old binding must not
                    # stand for the name, or ``_known_truth`` prunes a branch
                    # the merge can select at runtime. Only such a flag needs
                    # it: a None or string alternative raises at the ``|=``
                    # and never survives it, and a set literal, read as a list
                    # of items, answers no truth test, so no branch can be
                    # pruned through either.
                    merged_unread.append(unread(scope.site(call)))
            elif method in ("append", "insert") and call.args:
                items.append(self.evaluate(call.args[-1], scope))
            elif method == "extend" and call.args:
                extended = self.evaluate(call.args[0], scope)
                items.append(
                    extended.items() if extended.is_list else unread(scope.site(call))
                )
        result = (
            with_keys(base, added, open_at)
            if base.is_dict or added or open_at
            else base
        )
        if items:
            result = union(result, one(ListV(union(*items))))
        if merged_unread:
            result = union(result, *merged_unread)
        return result

    def _update_keys(self, call: ast.Call, scope: _Scope) -> Shape:
        """The keys ``x.update(...)``, ``x.setdefault(...)`` or ``dict(...)`` gives."""
        method = getattr(call.func, "attr", "update")
        if method == "setdefault":
            key = _str_constant(call.args[0]) if call.args else None
            if key is None:
                return dict_shape({}, [scope.site(call)])
            value = (
                self.evaluate(call.args[1], scope) if len(call.args) > 1 else NOTHING
            )
            return dict_shape({key: value})
        keys: dict[str, Shape] = {}
        open_at: list[str] = []
        sources = [*call.args, *(k.value for k in call.keywords if k.arg is None)]
        for value_node in sources:
            value = self.evaluate(value_node, scope)
            for d in value.dicts():
                for k, v in d.keys:
                    keys[k] = union(keys.get(k), v)
                open_at += d.open_at
            open_at += value.unread
        for keyword in call.keywords:
            if keyword.arg is not None:
                keys[keyword.arg] = self.evaluate(keyword.value, scope)
        return dict_shape(keys, open_at)

    # -- expressions ----------------------------------------------------------

    def evaluate(self, node: Optional[ast.AST], scope: _Scope) -> Shape:
        if node is None:
            return NOTHING
        self._evaluations += 1
        if self._evaluations > self.max_evaluations:
            raise ContractWorkBudgetExceeded(
                f"scripts/_mcp_contract.py: Evaluator.evaluate read more than"
                f" {self.max_evaluations} expressions without finishing, while"
                f" reading {' -> '.join(self._sites[-6:]) or 'the module level'}"
                f" (innermost last); the walk over the server's return statements"
                f" is not converging"
            )
        method = getattr(self, f"_eval_{type(node).__name__}", None)
        if method is None:
            return unread(scope.site(node))
        return method(node, scope)

    def _eval_Constant(self, node: ast.Constant, scope: _Scope) -> Shape:
        if isinstance(node.value, str):
            return one(StrV(node.value))
        if node.value is None or isinstance(node.value, (bool, int, float)):
            return one(LiteralV(node.value))
        return NOTHING

    def _known_truth(self, test: ast.expr, scope: _Scope) -> Optional[bool]:
        """Whether ``test`` is true, when the source says, or None, which reads
        both outcomes.

        A constant True, False, None or number says. So does a parameter of the
        function being read whose values here are constants of one truth: a flag
        the call passed as a constant, or left at a constant default. A rebinding
        of the parameter (a reassignment, a loop, ``with`` or ``match`` target,
        ``except ... as``, a ``global`` or ``nonlocal``) makes its value partly
        unread in ``evaluate``, so it says nothing here. Any other name says
        nothing either: this reader does not follow an attribute store from
        another module (``server.FLAG = True``) or ``globals()[...]``, so no
        module global's value is ever certain, however it is bound in its own
        module. ``not`` of either is followed.
        """
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner = self._known_truth(test.operand, scope)
            return None if inner is None else not inner
        if isinstance(test, ast.Constant):
            if test.value is None or isinstance(test.value, (bool, int, float)):
                return bool(test.value)
            return None
        if not isinstance(test, ast.Name):
            return None
        current: Optional[_Scope] = scope
        while current is not None and current.func is None:
            if test.id in current.bindings or test.id in current.poisoned:
                # A value a test made, not the function's own parameter.
                return None
            current = current.parent
        if (
            current is None
            or current.func is None
            or current.locals is None
            or test.id not in current.locals.params
        ):
            return None
        value = self.evaluate(test, scope)
        if not value.variants or not all(
            isinstance(v, LiteralV) for v in value.variants
        ):
            return None
        truths = {bool(v.value) for v in value.variants}  # type: ignore[union-attr]
        return truths.pop() if len(truths) == 1 else None

    def _eval_Dict(self, node: ast.Dict, scope: _Scope) -> Shape:
        # Each spread contributes its alternatives; the literal is one dict per
        # combination of them, built in source order: at runtime a spread can
        # override any key set before it, so such a key's value gains the
        # spread's uncertainty instead of reading as fixed.
        entries: list[tuple[str, object, Optional[Shape]]] = []
        spreads: list[list[tuple[dict[str, Shape], tuple[str, ...]]]] = []
        for key, value in zip(node.keys, node.values):
            if key is None:
                spread = self.evaluate(value, scope)
                options = [(d.key_map(), d.open_at) for d in spread.dicts()]
                options += [({}, (site,)) for site in spread.unread]
                spreads.append(options or [({}, ())])
                entries.append(("spread", len(spreads) - 1, None))
                continue
            names = self.evaluate(key, scope)
            if names.strings and not names.unread:
                value_shape = self.evaluate(value, scope)
                # A key that is certainly ONE string replaces what a spread or
                # an earlier duplicate set, as at runtime; a key that could be
                # one of several strings, or might not be a string at all,
                # only widens each candidate, since at runtime it can land on
                # another key and leave the earlier value standing.
                certain = len(names.variants) == 1
                for text in names.strings:
                    entries.append(("key" if certain else "maybe", text, value_shape))
            else:
                entries.append(("open", scope.site(key), None))
        if not spreads:
            own: dict[str, Shape] = {}
            open_at: list[str] = []
            for kind, found, value_shape in entries:
                if kind == "key":
                    own[found] = value_shape
                elif kind == "maybe":
                    own[found] = union(own.get(found), value_shape)
                else:
                    open_at.append(found)
            return dict_shape(own, open_at)
        variants: list[Variant] = []
        for combination in itertools.islice(itertools.product(*spreads), MAX_VARIANTS):
            keys: dict[str, Shape] = {}
            sites: list[str] = []
            for kind, found, value_shape in entries:
                if kind == "key":
                    keys[found] = value_shape
                elif kind == "maybe":
                    keys[found] = union(keys.get(found), value_shape)
                elif kind == "open":
                    sites.append(found)
                else:
                    spread_keys, spread_open = combination[found]
                    keys.update(spread_keys)
                    sites += spread_open
                    if spread_open:
                        # The spread's unnamed keys can override anything set
                        # before it.
                        uncertainty = union(*(unread(site) for site in spread_open))
                        for text in list(keys):
                            if text not in spread_keys:
                                keys[text] = union(keys[text], uncertainty)
            variants.append(DictV(tuple(keys.items()), _unique(sites)))
        return _cap(Shape(tuple(dict.fromkeys(variants))))

    def _eval_DictComp(self, node: ast.DictComp, scope: _Scope) -> Shape:
        return dict_shape({}, [scope.site(node)])

    def _sequence(self, elements: list[ast.expr], scope: _Scope) -> Shape:
        items = []
        for element in elements:
            if isinstance(element, ast.Starred):
                inner = self.evaluate(element.value, scope)
                items.append(
                    inner.items() if inner.is_list else unread(scope.site(element))
                )
            else:
                items.append(self.evaluate(element, scope))
        return one(ListV(union(*items)))

    def _eval_List(self, node: ast.List, scope: _Scope) -> Shape:
        return self._sequence(node.elts, scope)

    _eval_Set = _eval_List

    def _eval_Tuple(self, node: ast.Tuple, scope: _Scope) -> Shape:
        """A tuple literal, with its elements in order for an unpacking to take."""
        if any(isinstance(e, ast.Starred) for e in node.elts):
            return self._sequence(node.elts, scope)
        elements = tuple(self.evaluate(e, scope) for e in node.elts)
        return one(ListV(union(*elements), elements))

    def _eval_Subscript(self, node: ast.Subscript, scope: _Scope) -> Shape:
        """``x["K"]``: K's value in each dict ``x`` can be. An unpacking's element.

        A dict without K that can get keys the source does not name, and a value
        that is not read, give an unread alternative. Any other subscript is unread.
        """
        site = scope.site(node)
        arity = getattr(node, _UNPACK_ARITY, None)
        if arity is not None:
            index = node.slice.value  # type: ignore[attr-defined]
            value = self._unpacked(node.value, arity, scope, site)
            parts: list[Shape] = []
            for v in value.variants:
                if (
                    isinstance(v, ListV)
                    and v.elements is not None
                    and len(v.elements) == arity
                ):
                    parts.append(v.elements[index])
                else:
                    # An unread value keeps its own site and reason.
                    parts.append(one(v) if isinstance(v, UnreadV) else unread(site))
            return union(*parts)
        key = _str_constant(node.slice)
        if key is None:
            return unread(site)
        if isinstance(node.value, ast.Name):
            poisoned = scope.poisoned_at(node.value.id)
            if poisoned is not None:
                return unread(poisoned)
        return _key_of(self.evaluate(node.value, scope), key, site)

    def _unpacked(self, value: ast.expr, arity: int, scope: _Scope, site: str) -> Shape:
        """What ``a, b = value`` unpacks: a tuple literal, or the tuples a function returns.

        The function is called by a name bound once, in the function the call is
        in (or one around it) or in the module, to one ``def`` that is not a
        generator, is awaited when it is async, returns a tuple literal of
        ``arity`` elements from every ``return`` and cannot end without one.
        Anything else is unread, with the reason.
        """
        if isinstance(value, ast.Tuple):
            return self.evaluate(value, scope)
        awaited = isinstance(value, ast.Await)
        call = value.value if isinstance(value, ast.Await) else value
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)):
            return unread(f"{site} (unpacks neither a tuple nor a function's tuples)")
        name = call.func.id
        ref = self.lookup(scope, name)
        problem = self._tuple_function_problem(ref, name, arity, awaited, scope)
        if problem is not None:
            return unread(f"{site} ({name} {problem})")
        return self.call(ref, call, scope)  # type: ignore[arg-type]

    def _tuple_function_problem(
        self,
        ref: Optional[_Ref],
        name: str,
        arity: int,
        awaited: bool,
        scope: _Scope,
    ) -> Optional[str]:
        """Why calling ``name`` cannot be unpacked into ``arity`` names, or None."""
        if ref is None or ref.kind != "function" or ref.node is None:
            return "is not a function"
        if ref.module is None or not isinstance(
            ref.node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return "is not a function"
        # Bound once where the call finds it, and, when that is an import, defined
        # once in the module it comes from.
        if ref.scope is not None and ref.scope.func is not None:
            homes = [(ref.scope.func, ref.scope.module, name)]
        else:
            homes = [(scope.module.tree, scope.module, name)]
            if ref.module is not scope.module:
                homes.append((ref.module.tree, ref.module, ref.node.name))
        for owner, module, bound in homes:
            if self._binding_count(owner, bound, module) != 1:
                return "is bound more than once"
        func = ref.node
        if isinstance(func, ast.AsyncFunctionDef) != awaited:
            return "is async and not awaited" if not awaited else "is not async"
        local = self._locals_for(func, ref.module)
        if local.yields:
            return "is a generator"
        for ret, _, _ in local.returns:
            value = ret.value
            if not (
                isinstance(value, ast.Tuple)
                and len(value.elts) == arity
                and not any(isinstance(e, ast.Starred) for e in value.elts)
            ):
                return (
                    f"can return something other than {arity} values"
                    f" ({ref.module.rel}:{ret.lineno})"
                )
        if not _always_returns(func.body):
            return "can end without a return"
        return None

    def _binding_count(self, owner: ast.AST, name: str, module: _Module) -> int:
        """How many times ``owner``'s own statements bind ``name``.

        Each name a statement binds (``_names_bound_by``) and each parameter
        counts. For a module owner, a ``global`` (or ``nonlocal``) of the name
        anywhere in the module counts as another binding, since any function
        can then rebind the module's name; for a function owner, only a
        ``nonlocal`` nested inside it or a ``global`` its own body declares
        can.
        """
        if owner is module.tree:
            if name in self._rebound(module):
                return 2
        elif self._func_rebindable(owner, name):
            return 2
        count = 0
        args = getattr(owner, "args", None)
        if args is not None:
            params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            params += [a for a in (args.vararg, args.kwarg) if a is not None]
            count += sum(a.arg == name for a in params)
        for node in _own_nodes(owner):
            count += sum(bound == name for bound in _names_bound_by(node, module))
        return count

    def _rebound(self, module: _Module) -> frozenset[str]:
        """Every name a ``global`` or ``nonlocal`` statement in ``module`` names."""
        if id(module) not in self._rebound_memo:
            self._rebound_memo[id(module)] = frozenset(
                name
                for node in ast.walk(module.tree)
                if isinstance(node, (ast.Global, ast.Nonlocal))
                for name in node.names
            )
        return self._rebound_memo[id(module)]

    def _comprehension(self, node, scope: _Scope) -> Shape:
        names: dict[str, Shape] = {}
        inner = _Scope(
            module=scope.module,
            owner=scope.owner,
            owner_module=scope.owner_module,
            parent=scope,
            bindings=names,
        )
        for position, generator in enumerate(node.generators):
            # A lone name iterating a list is each item of that list: the filters
            # only drop items, so the items are a superset of what is yielded. The
            # first iterable is read where the comprehension stands, as Python
            # does; a later one can name an earlier target. Any other target (a
            # tuple, an attribute) and any iterable that is not a list is unread.
            iterable = self.evaluate(generator.iter, scope if position == 0 else inner)
            for target in ast.walk(generator.target):
                if isinstance(target, ast.Name):
                    names[target.id] = unread(scope.site(target))
            if isinstance(generator.target, ast.Name) and iterable.is_list:
                names[generator.target.id] = iterable.items()
        return one(ListV(self.evaluate(node.elt, inner)))

    _eval_ListComp = _comprehension
    _eval_SetComp = _comprehension
    _eval_GeneratorExp = _comprehension

    def _eval_IfExp(self, node: ast.IfExp, scope: _Scope) -> Shape:
        """Each branch, with the names the test narrows narrowed for it; only the
        one the test selects when it is a known constant."""
        truth = self._known_truth(node.test, scope)
        if truth is not None:
            return self.evaluate(node.body if truth else node.orelse, scope)
        site = scope.site(node)
        body = self._conditioned(scope, node.test, True, node.body, site)
        orelse = self._conditioned(scope, node.test, False, node.orelse, site)
        return union(self.evaluate(node.body, body), self.evaluate(node.orelse, orelse))

    # -- conditions -----------------------------------------------------------

    def _conditioned(
        self, scope: _Scope, test: ast.expr, holds: bool, expr: ast.AST, site: str
    ) -> _Scope:
        """The scope ``expr`` is read in when ``test`` is ``holds``.

        Only the function's own names that ``expr`` reads with ``name["K"]`` are
        affected, so every other value reads as before. :meth:`_narrowed` says
        what becomes of each: narrowed, left as it is, or its ``name["K"]`` reads
        unread, with the reason.
        """
        reads = _subscript_reads(expr)
        if not reads:
            return scope
        bindings: dict[str, Shape] = {}
        poisoned: dict[str, str] = {}
        for name, keys_read in reads.items():
            owner = self._value_scope(scope, name)
            if owner is None or scope.poisoned_at(name) is not None:
                continue
            outcome = self._narrowed(scope, owner, test, holds, name, keys_read, site)
            if isinstance(outcome, str):
                poisoned[name] = outcome
            elif outcome is not None:
                bindings[name] = outcome
        if not bindings and not poisoned:
            return scope
        return _Scope(
            module=scope.module,
            owner=scope.owner,
            owner_module=scope.owner_module,
            parent=scope,
            bindings=bindings,
            poisoned=poisoned,
            conditioned=True,
        )

    def _narrowed(
        self,
        scope: _Scope,
        owner: _Scope,
        test: ast.expr,
        holds: bool,
        name: str,
        keys_read: set[str],
        site: str,
    ) -> Union[Shape, str, None]:
        """``name`` where ``test`` is ``holds``: its narrowed shape, None to leave
        it as it is, or the unread site and the reason.

        The test may be a condition variable set once in the function, which is
        read as its value. ``name`` is narrowed when the test is one
        ``_condition_specs`` understands, the function (``owner``) sets ``name``
        by one plain assignment and nothing there changes it, and the condition
        variable is set after ``name`` and before the test; narrowing a key to nothing is
        unread rather than "none". It is left as it is when the test says nothing
        about it, or tests only keys the branch does not read. Anything else is
        unread: a test that decides the value is never ignored.
        """
        effective, predicate = self._resolve_condition(test, scope, owner)
        for other in dict.fromkeys(_names_in(effective)):
            if other != name and self._depends_on(other, name, scope, set()):
                return f"{site} ({other} depends on {name} in a way not followed)"
        if not _mentions(effective, name):
            return None
        tested = _test_keys(effective, name)
        about_read = tested is None or bool(tested & keys_read)
        specs = self._condition_specs(effective, name, scope)
        current = self._eval_Name(ast.Name(id=name, ctx=ast.Load()), scope)
        narrowed = _narrow_by(current, specs, holds) if specs is not None else None
        if narrowed is None:
            return (
                f"{site} (a test on {name} the reader does not follow)"
                if about_read
                else None
            )
        bound = _set_once(owner.func, name)  # type: ignore[arg-type]
        plain = owner.locals is not None and _set_by_one_assignment(owner.locals, name)
        in_order = (
            bound is not None
            and plain
            and (predicate is None or bound < predicate[1] < getattr(test, "lineno", 0))
        )
        if not in_order:
            if not about_read:
                return None
            if bound is None:
                return f"{site} ({name} can change between the test and the read)"
            if not plain:
                return f"{site} ({name} is not set by one assignment in the function)"
            variable = predicate[0] if predicate is not None else name
            return f"{site} ({variable} is not set after {name} and before the test)"
        for key in sorted(keys_read):
            if _key_of(narrowed, key, site).variants:
                continue
            # Only now are the test's values that ``name`` never has named: when
            # some value passes, they are dropped without a word.
            allowed: set[str] = set()
            for kind, tested_key, values in specs or []:
                if kind == "in" and tested_key == key:
                    allowed |= values
            never = (
                sorted(allowed - _key_of(current, key, site).strings) if holds else []
            )
            said = f'; {name}["{key}"] is never {" or ".join(never)}' if never else ""
            return f'{site} (the test leaves {name}["{key}"] nothing to be{said})'
        return narrowed

    def _value_scope(self, scope: _Scope, name: str) -> Optional[_Scope]:
        """The function scope whose own local ``name`` is, past the scopes a test
        made; None for anything else (a module name, a loop variable of a
        comprehension, a caught exception, a function)."""
        current: Optional[_Scope] = scope
        while current is not None:
            if name in current.bindings or name in current.poisoned:
                if current.func is not None:
                    return current
                if not current.conditioned:
                    return None
            elif current.func is not None and current.locals is not None:
                local = current.locals
                if (
                    name in local.params
                    or name in local.assigns
                    or name in local.unread
                    or name in local.caught
                    or name in local.key_sets
                ):
                    return current
                if name in local.defs or name in local.imports:
                    return None
            current = current.parent
        return None

    def _depends_on(self, other: str, name: str, scope: _Scope, seen: set[str]) -> bool:
        """Whether the local ``other`` can hold something computed from ``name``.

        It can when what it is bound from reads ``name``, directly or through
        other locals: an assignment, a store or update of one of its keys, the
        iterable of a loop that binds it, a ``with`` item. A caught exception, and
        a name bound from nothing the source names, can. A parameter cannot, here.
        """
        if other in seen:
            return False
        seen.add(other)
        current: Optional[_Scope] = scope
        while current is not None and current.func is None:
            if other in current.bindings and not current.conditioned:
                # A comprehension's loop variable or a caught exception.
                return True
            current = current.parent
        owner = self._value_scope(scope, other)
        if owner is None or owner.locals is None:
            return False
        local = owner.locals
        sources = local.sources.get(other, [])
        if other in local.caught or any(source is None for source in sources):
            return True
        values = [
            *local.assigns.get(other, []),
            *(value for _, value, _ in local.key_sets.get(other, [])),
            *local.calls.get(other, []),
            *(source for source in sources if source is not None),
        ]
        return any(
            used == name or self._depends_on(used, name, owner, seen)
            for value in values
            for used in _names_in(value)
        )

    def _resolve_condition(
        self, test: ast.expr, scope: _Scope, owner: _Scope
    ) -> tuple[ast.expr, Optional[tuple[str, int]]]:
        """``test``, or the value of the condition variable it is, with its name
        and line: a name ``owner``'s function sets once, by one assignment, and
        nothing there changes."""
        if (
            not isinstance(test, ast.Name)
            or self._value_scope(scope, test.id) is not owner
        ):
            return test, None
        local = owner.locals
        if local is None or not _set_by_one_assignment(local, test.id):
            return test, None
        line = _set_once(owner.func, test.id)  # type: ignore[arg-type]
        if line is None:
            return test, None
        return local.assigns[test.id][0], (test.id, line)

    def _condition_specs(
        self, test: ast.expr, name: str, scope: _Scope
    ) -> Optional[list[tuple[str, str, frozenset[str]]]]:
        """What ``test`` says about ``name``, or None when it is not understood.

        ``name.get(K) in (A, B)``, ``name[K] in (A, B)``, ``name.get(K) == A`` and
        ``"K" in name``, alone or joined by ``and``; parts that do not mention
        ``name`` say nothing about it. Values must be read strings.
        """
        if not _mentions(test, name):
            return []
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            specs: list[tuple[str, str, frozenset[str]]] = []
            for value in test.values:
                part = self._condition_specs(value, name, scope)
                if part is None:
                    return None
                specs += part
            return specs
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
            return None
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if (
            isinstance(op, ast.In)
            and isinstance(right, ast.Name)
            and right.id == name
            and _str_constant(left) is not None
        ):
            return [("has", _str_constant(left), frozenset())]  # type: ignore[list-item]
        key = _subscript_key(left, name)
        if (
            key is None
            or not isinstance(op, (ast.In, ast.Eq))
            or _mentions(right, name)
        ):
            return None
        allowed = self.evaluate(right, scope)
        if isinstance(op, ast.In):
            members = allowed.items()
            if not allowed.is_list or members.unread or not members.strings:
                return None
            return [("in", key, members.strings)]
        if allowed.unread or not allowed.strings:
            return None
        return [("in", key, allowed.strings)]

    def _eval_BoolOp(self, node: ast.BoolOp, scope: _Scope) -> Shape:
        return union(*(self.evaluate(v, scope) for v in node.values))

    def _eval_BinOp(self, node: ast.BinOp, scope: _Scope) -> Shape:
        left = self.evaluate(node.left, scope)
        right = self.evaluate(node.right, scope)
        if isinstance(node.op, ast.Add) and (left.is_list or right.is_list):
            return union(left, right)
        if isinstance(node.op, ast.BitOr) and (left.is_dict or right.is_dict):
            return union(left, right)
        return unread(scope.site(node))

    def _eval_Await(self, node: ast.Await, scope: _Scope) -> Shape:
        return self.evaluate(node.value, scope)

    def _eval_NamedExpr(self, node: ast.NamedExpr, scope: _Scope) -> Shape:
        return self.evaluate(node.value, scope)

    def _eval_Name(self, node: ast.Name, scope: _Scope) -> Shape:
        ref = self.lookup(scope, node.id)
        if ref is not None and ref.kind == "value":
            return self.name_value(ref)
        return unread(scope.site(node))

    def _eval_Attribute(self, node: ast.Attribute, scope: _Scope) -> Shape:
        if (
            node.attr == "__name__"
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "type"
            and self.lookup(scope, "type") is None
        ):
            return one(ClassNameV())
        if node.attr == "value" and isinstance(node.value, ast.Attribute):
            # SomeEnum.MEMBER.value
            owner = self._ref_of(node.value.value, scope)
            if owner is not None and owner.kind == "class" and owner.module is not None:
                member = _class_assign(owner.node, node.value.attr)
                if member is not None:
                    return self.evaluate(member, _Scope(module=owner.module))
        owner = self._ref_of(node.value, scope)
        if owner is not None and owner.kind == "module":
            target = self.source.module(owner.dotted)
            ref = self._module_ref(target, node.attr) if target is not None else None
            if ref is not None and ref.kind == "value":
                return self.name_value(ref)
            return unread(scope.site(node))
        if owner is not None and owner.kind in ("class", "function"):
            return unread(scope.site(node))
        return self.evaluate(node.value, scope).attr(node.attr, scope.site(node))

    def _eval_Call(self, node: ast.Call, scope: _Scope) -> Shape:
        func = node.func
        if self._is_stdlib_runner(func, scope):
            return self._run_on_thread(node, scope)
        if isinstance(func, ast.Name) and self.lookup(scope, func.id) is None:
            return self._builtin_call(func.id, node, scope)
        if isinstance(func, ast.Attribute):
            if func.attr == "copy" and not node.args:
                return self.evaluate(func.value, scope)
            method = self._method_ref(func, scope)
            if method is not None:
                return self.call(method, node, scope)
        ref = self._ref_of(func, scope)
        if ref is not None and ref.kind == "function":
            if self._is_runner(ref):
                return self._run_callable(node, scope)
            return self.call(ref, node, scope)
        if ref is not None and ref.kind == "class":
            return self._instance(ref, node, scope)
        return unread(scope.site(node))

    def _is_runner(self, ref: _Ref) -> bool:
        name = getattr(ref.node, "name", "")
        return (
            ref.module is not None and f"{ref.module.name}.{name}" in CALLABLE_RUNNERS
        )

    def _run_callable(self, node: ast.Call, scope: _Scope) -> Shape:
        """``runner(f, **kw)``: what ``f(**kw)`` returns, with ``kw`` bound.

        A callable that is not a package function, or a call that passes anything
        but ``f`` and keywords, is unread.
        """
        if len(node.args) != 1 or isinstance(node.args[0], ast.Starred):
            return unread(scope.site(node))
        target = self._ref_of(node.args[0], scope)
        if target is None or target.kind != "function":
            return unread(scope.site(node))
        forwarded = ast.copy_location(
            ast.Call(func=node.args[0], args=[], keywords=node.keywords), node
        )
        return self.call(target, forwarded, scope)

    def _is_stdlib_runner(self, func: ast.AST, scope: _Scope) -> bool:
        """Whether ``func`` names a :data:`STDLIB_RUNNERS` function.

        ``asyncio.to_thread`` reads as a module attribute whose module the
        package does not hold; ``to_thread`` after ``from asyncio import
        to_thread`` is an import that resolves to no package object, so it is
        read from the import tables the way :meth:`lookup` reads them.
        """
        if isinstance(func, ast.Attribute):
            ref = self._ref_of(func, scope)
            return (
                ref is not None
                and ref.kind == "module"
                and ref.dotted in STDLIB_RUNNERS
            )
        if not isinstance(func, ast.Name):
            return False
        current: Optional[_Scope] = scope
        while current is not None:
            local = current.locals
            if current.func is not None and local is not None:
                if func.id in local.params or func.id in local.assigns:
                    return False
                if func.id in local.imports:
                    dotted, attr = local.imports[func.id]
                    return attr is not None and f"{dotted}.{attr}" in STDLIB_RUNNERS
            current = current.parent
        if func.id in scope.module.imports:
            dotted, attr = scope.module.imports[func.id]
            return attr is not None and f"{dotted}.{attr}" in STDLIB_RUNNERS
        return False

    def _run_on_thread(self, node: ast.Call, scope: _Scope) -> Shape:
        """``asyncio.to_thread(f, *args, **kw)``: what ``f(*args, **kw)`` returns.

        The call is read as if ``f`` had been called in place, so ``f`` may be a
        package function, a method on an object the source names
        (``registry.check_scan_progress``) or a nested function, and the
        arguments after it bind as they would on a direct call. A call with no
        callable, or one that spreads its callable, is unread.
        """
        if not node.args or isinstance(node.args[0], ast.Starred):
            return unread(scope.site(node))
        forwarded = ast.copy_location(
            ast.Call(func=node.args[0], args=node.args[1:], keywords=node.keywords),
            node,
        )
        return self._eval_Call(forwarded, scope)

    def _builtin_call(self, name: str, node: ast.Call, scope: _Scope) -> Shape:
        if name == "dict":
            return self._update_keys(node, scope)
        if name in ("list", "tuple", "sorted") and node.args:
            inner = self.evaluate(node.args[0], scope)
            return one(
                ListV(inner.items() if inner.is_list else unread(scope.site(node)))
            )
        return unread(scope.site(node))

    def _instance(
        self,
        ref: _Ref,
        node: ast.Call,
        scope: _Scope,
        family: Optional[list[ast.AST]] = None,
    ) -> Shape:
        """An instance of a package class: what its ``__init__`` sets on ``self``.

        A class without its own ``__init__`` in the package (a NamedTuple, a
        dataclass) is built from its annotated fields instead.

        ``family`` is given when :meth:`_caught` builds the instance of a caught
        exception: the class nodes the handler catches (the class and its
        package subclasses). An argument is then read by
        :meth:`_construction_argument` first.
        """
        cls = ref.node
        if not isinstance(cls, ast.ClassDef) or ref.module is None:
            return unread(scope.site(node))
        init = self._find_method(cls, ref.module, "__init__", set())
        if init is None or init.module is None or init.node is None:
            return self._construct(ref, node, scope)
        args = init.node.args  # type: ignore[attr-defined]
        positional = [a.arg for a in [*args.posonlyargs, *args.args]][1:]
        bindings: dict[str, Shape] = {}
        for name, value in zip(positional, node.args):
            if isinstance(value, ast.Starred):
                break
            bindings[name] = self._argument(value, name, init, scope, node, family)
        for keyword in node.keywords:
            if keyword.arg is not None:
                bindings[keyword.arg] = self._argument(
                    keyword.value, keyword.arg, init, scope, node, family
                )
        init_scope = _Scope(
            module=init.module,
            func=init.node,
            owner=init.owner,
            owner_module=init.module,
            bindings=bindings,
            locals=self._locals_for(init.node, init.module),
        )
        attrs: dict[str, Shape] = {}
        for stmt in _own_nodes(init.node):
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                ):
                    value = self.evaluate(stmt.value, init_scope)
                    attrs[target.attr] = union(attrs.get(target.attr), value)
        for name, value in self._class_attributes(ref).items():
            attrs.setdefault(name, value)
        return one(ObjectV(cls.name, tuple(attrs.items())))

    def _argument(
        self,
        value: ast.expr,
        param: str,
        init: _Ref,
        scope: _Scope,
        call: ast.Call,
        family: Optional[list[ast.AST]],
    ) -> Shape:
        """What a construction passes for ``__init__``'s ``param``.

        For a caught exception's construction that :meth:`_construction_argument`
        does not place, a plain name is read where the construction sits: a
        parameter of the raising function is then unread and a local assignment
        is its value, never the module name either happens to shadow; a name
        the function does not bind is still the module's. A name passed inside a
        lambda's body, a comprehension or a class body is unread. Anything else
        (a literal, an attribute, a call) is read as before, in ``scope``.
        """
        if family is not None:
            found = self._construction_argument(
                value, param, init, scope.module, call, family
            )
            if found is not None:
                return found
            if isinstance(value, ast.Name):
                site = self._call_scope(scope.module, call)
                if site is None:
                    return unread(f"{scope.module.rel}:{getattr(call, 'lineno', 0)}")
                local = site.locals
                if (
                    site.func is not None
                    and local is not None
                    and (value.id in local.params or value.id in local.assigns)
                    and value.id not in local.caught
                ):
                    return self.evaluate(value, site)
        return self.evaluate(value, scope)

    def _construction_argument(
        self,
        value: ast.expr,
        param: str,
        init: _Ref,
        module: _Module,
        call: ast.Call,
        family: list[ast.AST],
    ) -> Optional[Shape]:
        """An argument of a caught exception's construction that the module's own
        scope cannot place but the source fully determines, or None.

        * A parameter of the function that builds the exception (a helper that
          raises it with the type its caller names): what every call of that
          function passes for it, see :meth:`_passed_through`.
        * ``e.<param>`` in a handler of ``except K as e`` where ``K`` is the
          exception being collected or one of its package subclasses, ``e`` is
          bound only by handlers, and ``__init__`` stores ``<param>`` only as the
          bare ``self.<param> = <param>``: the exception is raised again with the
          type the caught one carries. That type is one of the types some other
          construction in the family passes, and those are in the result already,
          so this argument adds nothing. :meth:`_caught` reads a family with no
          such other construction as unread.
        """
        func, handlers = self._construction_site(module, call)
        if func is None:
            return None
        if isinstance(value, ast.Name):
            return self._passed_through(value.id, func, module)
        if (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.attr == param
            and self._reraises(
                value.value.id, param, func, handlers, module, init, family
            )
        ):
            self._reraise_calls.add((id(call), id(family[0])))
            return NOTHING
        return None

    def _parent_map(self, module: _Module) -> dict[int, ast.AST]:
        key = id(module.tree)
        if key not in self._parents:
            parents: dict[int, ast.AST] = {}
            for parent in ast.walk(module.tree):
                for child in ast.iter_child_nodes(parent):
                    parents[id(child)] = parent
            self._parents[key] = parents
        return self._parents[key]

    def _construction_site(
        self, module: _Module, call: ast.Call
    ) -> tuple[Optional[ast.AST], tuple[tuple[str, ast.expr], ...]]:
        """The function a call sits in, and the ``except K as name`` handlers
        around it, nearest first. None for a call outside a function, and for
        one inside a lambda, a comprehension or a nested class, where a name
        can be bound by something this reader does not follow."""
        parents = self._parent_map(module)
        handlers: list[tuple[str, ast.expr]] = []
        child: ast.AST = call
        node = parents.get(id(call))
        while node is not None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node, tuple(handlers)
            if isinstance(node, _OPAQUE_SCOPES):
                return None, ()
            if (
                isinstance(node, ast.ExceptHandler)
                and node.name
                and node.type is not None
                and any(child is stmt for stmt in node.body)
            ):
                handlers.append((node.name, node.type))
            child, node = node, parents.get(id(node))
        return None, ()

    def _plain_parameter(self, name: str, func: ast.AST, module: _Module) -> bool:
        """Whether ``name`` is a parameter of ``func`` that nothing in it rebinds."""
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        args = func.args
        if name not in {
            a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        }:
            return False
        return not self._rebinds(func, module, name)

    def _rebinds(
        self, func: ast.AST, module: _Module, name: str, caught_ok: bool = False
    ) -> bool:
        """Whether ``func`` can bind ``name`` by anything this reader does not
        follow to one value: an assignment, a key set or mutating call, a loop,
        ``with`` or ``match`` target, a local import or ``def``, a ``global`` or
        ``nonlocal``, and (unless ``caught_ok``) an ``except ... as name``."""
        local = self._locals_for(func, module)
        return bool(
            local.assigns.get(name)
            or local.key_sets.get(name)
            or local.calls.get(name)
            or name in local.unread
            or name in local.imports
            or name in local.defs
            or (name in local.caught and not caught_ok)
            or self._func_rebindable(func, name)
        )

    def _index_names(self) -> dict[str, int]:
        """How many ``Name`` and ``Attribute`` nodes of the package spell each
        name, and (as ``_renamed_imports``) the names an ``import ... as`` renames."""
        if self._name_uses is None:
            uses: dict[str, int] = {}
            renamed: set[str] = set()
            for module in self.source.all_modules():
                for node in ast.walk(module.tree):
                    if isinstance(node, ast.Name):
                        uses[node.id] = uses.get(node.id, 0) + 1
                    elif isinstance(node, ast.Attribute):
                        uses[node.attr] = uses.get(node.attr, 0) + 1
                    elif (
                        isinstance(node, ast.alias)
                        and node.asname
                        and node.asname != node.name
                    ):
                        renamed.add(node.name)
            self._name_uses = uses
            self._renamed_imports = frozenset(renamed)
        return self._name_uses

    def _passed_through(
        self, name: str, func: ast.AST, module: _Module
    ) -> Optional[Shape]:
        """What every call of ``func`` passes for its parameter ``name``, or None.

        ``func`` must be an undecorated function at module level, and every use of
        its name in the package a call of it that this reader places (not an
        alias, a reference passed on, a method of that name or a spread
        argument), so that the calls found are all the calls there are. A
        call that leaves the parameter out gives the parameter's default.
        Each argument is read in the scope of the function the call sits in, the
        module's for a call at module level or in a function's header
        (:meth:`_call_scope`), so a name the calling function binds is read as
        that function's and never as a module name it shadows. A call inside a
        lambda's body, a comprehension or a class body leaves the parameter unread
        unless what it passes is a literal, which needs no scope.
        """
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if not self._plain_parameter(name, func, module):
            return None
        if module.defs.get(func.name) is not func or func.decorator_list:
            return None
        key = (id(func), name)
        if key in self._passed_memo:
            return self._passed_memo[key]
        self._passed_memo[key] = None
        uses = self._index_names()
        calls = [
            (m, c)
            for m, c in self._constructions(func.name)
            if self._names_function(c, m, func)
        ]
        found: Optional[Shape] = None
        if func.name not in self._renamed_imports and uses.get(func.name, 0) == len(
            calls
        ):
            found = self._call_arguments(name, func, module, calls)
        self._passed_memo[key] = found
        return found

    def _names_function(self, call: ast.Call, module: _Module, func: ast.AST) -> bool:
        """Whether ``call`` calls ``func``, resolved where the call sits, so a
        parameter or local that shadows the function's name is not the function
        (a call this reader cannot place then makes the name's use count exceed
        its calls, and :meth:`_passed_through` gives up)."""
        scope = self._call_scope(module, call) or _Scope(module=module)
        ref = self._ref_of(call.func, scope)
        return ref is not None and ref.kind == "function" and ref.node is func

    def _call_arguments(
        self,
        name: str,
        func: ast.AST,
        module: _Module,
        calls: list[tuple[_Module, ast.Call]],
    ) -> Optional[Shape]:
        args = func.args  # type: ignore[attr-defined]
        positional = [a.arg for a in [*args.posonlyargs, *args.args]]
        every = [*args.posonlyargs, *args.args]
        default: Optional[ast.expr] = None
        for arg, value in zip(every[len(every) - len(args.defaults) :], args.defaults):
            if arg.arg == name:
                default = value
        for arg, value in zip(args.kwonlyargs, args.kw_defaults):
            if arg.arg == name:
                default = value
        parts: list[Shape] = []
        for call_module, call in calls:
            if any(isinstance(a, ast.Starred) for a in call.args) or any(
                k.arg is None for k in call.keywords
            ):
                return None
            passed = next((k.value for k in call.keywords if k.arg == name), None)
            if passed is None and name in positional:
                index = positional.index(name)
                if index < len(call.args):
                    passed = call.args[index]
            if passed is None:
                if default is None:
                    return None
                # A default is bound where the function is defined.
                parts.append(self.evaluate(default, _Scope(module=module)))
                continue
            scope = self._call_scope(call_module, call)
            if scope is None:
                # A literal needs no scope; anything that names something does.
                if any(isinstance(n, ast.Name) for n in ast.walk(passed)):
                    return None
                scope = _Scope(module=call_module)
            parts.append(self.evaluate(passed, scope))
        return union(*parts) if parts else None

    def _call_scope(self, module: _Module, call: ast.Call) -> Optional[_Scope]:
        """The scope an argument of ``call`` is read in, or None.

        The module's for a call at module level. For a call inside a function's
        body, that function's, with each function around it as a parent, so a
        name the function binds (a parameter, an assignment, a loop target) is
        read as the function's own and not as the module name it shadows; a
        parameter, whose value this scope does not carry, is unread. A call in a
        function's header (a default value, a decorator, an annotation) is read in
        the scope around the function, where Python evaluates it, and so is a call
        in a class's bases, keywords or decorators. A class body between a method
        and the module is passed over, since its names are not in scope inside
        the method. None for a call inside a lambda's body, a comprehension or a
        class body itself, where a name can be bound by something this reader
        does not follow.
        """
        parents = self._parent_map(module)
        funcs: list[ast.AST] = []
        child: ast.AST = call
        node = parents.get(id(call))
        while node is not None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_header = (
                    child is node.args
                    or child is getattr(node, "returns", None)
                    or any(child is d for d in getattr(node, "decorator_list", []))
                )
                if not in_header:
                    if isinstance(node, ast.Lambda):
                        return None
                    funcs.append(node)
            elif isinstance(node, ast.ClassDef):
                in_header = any(
                    child is n
                    for n in [*node.bases, *node.keywords, *node.decorator_list]
                )
                if not in_header and not funcs:
                    return None
            elif isinstance(node, _OPAQUE_SCOPES):
                return None
            child, node = node, parents.get(id(node))
        scope = _Scope(module=module)
        for func in reversed(funcs):
            scope = _Scope(
                module=module,
                func=func,
                parent=scope,
                locals=self._locals_for(func, module),
            )
        return scope

    def _reraises(
        self,
        name: str,
        param: str,
        func: ast.AST,
        handlers: tuple[tuple[str, ast.expr], ...],
        module: _Module,
        init: _Ref,
        family: list[ast.AST],
    ) -> bool:
        """Whether ``name.<param>`` is the type of an exception of ``family`` the
        enclosing handler caught, handed on to the same attribute of a new one."""
        caught = next((kind for bound, kind in handlers if bound == name), None)
        if caught is None:
            return False
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if name in self._locals_for(func, module).params or self._rebinds(
                func, module, name, caught_ok=True
            ):
                return False
        scope = _Scope(module=module)
        types = caught.elts if isinstance(caught, ast.Tuple) else [caught]
        for type_expr in types:
            kind = self._ref_of(type_expr, scope)
            if (
                kind is None
                or kind.kind != "class"
                or not any(kind.node is node for node in family)
            ):
                return False
        # The caught object's attribute must come out the same on the new one:
        # ``__init__`` stores the parameter as ``self.<param> = <param>``, the
        # bare name, and uses it nowhere else in a store. A transform
        # (``f"step_{p}"``, ``CODES[p]``) or another attribute makes the new
        # object carry a value no construction passes.
        for stmt in _own_nodes(init.node):  # type: ignore[arg-type]
            if isinstance(stmt, ast.AugAssign):
                targets, stored = [stmt.target], stmt.value
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value:
                targets = (
                    stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                )
                stored = stmt.value
            else:
                continue
            into_param = any(_is_self_attribute(t, param) for t in targets)
            mentions = any(
                isinstance(n, ast.Name) and n.id == param for n in ast.walk(stored)
            )
            if isinstance(stmt, ast.AugAssign):
                if into_param or mentions:
                    return False
            elif mentions and not (
                all(_is_self_attribute(t, param) for t in targets)
                and isinstance(stored, ast.Name)
                and stored.id == param
            ):
                return False
        return True

    def _caught(self, type_node: ast.expr, scope: _Scope) -> Shape:
        """``e`` in ``except X as e``: every ``X(...)`` the package builds.

        Each construction's arguments are read in its module's scope, so a
        module constant passed to the exception is followed and a local
        variable is unread, with two exceptions that
        :meth:`_construction_argument` states: a parameter of the module-level
        helper that raises, and a caught exception's attribute raised again. The
        package's subclasses of ``X`` count too, since
        ``except X`` catches them; each carries the class attributes it sets
        (``error_type = "..."``). Exceptions the package does not define are
        unread.

        A construction's plain-name argument is read where the construction
        sits (:meth:`_argument`), so a handler that assigns a local from the
        caught exception and raises the class again with that local makes the
        caught value need the construction and the construction need the caught
        value. The second read of a class whose constructions are already being
        read is unread; the first read then completes, and the memo it leaves
        carries that unread part.
        """
        types = type_node.elts if isinstance(type_node, ast.Tuple) else [type_node]
        parts: list[Shape] = []
        for type_expr in types:
            ref = self._ref_of(type_expr, scope)
            if ref is None or ref.kind != "class" or ref.module is None:
                parts.append(unread(scope.site(type_expr)))
                continue
            key = id(ref.node)
            if key in self._caught_in_progress:
                parts.append(
                    unread(f"{scope.site(type_expr)} (caught type under resolution)")
                )
                continue
            if key not in self._caught_memo:
                self._caught_in_progress.add(key)
                try:
                    kinds = [ref, *self._subclasses(ref)]
                    family = [kind.node for kind in kinds if kind.node is not None]
                    built = [
                        (
                            call,
                            self._instance(kind, call, _Scope(module=module), family),
                        )
                        for kind in kinds
                        for module, call in self._constructions(kind.node.name)  # type: ignore[union-attr]
                        if self._is_class(call.func, module, kind.node)  # type: ignore[arg-type]
                    ]
                    # A construction that only raises a caught exception again
                    # adds no value of its own. Without one that does, the
                    # exceptions come from somewhere this reader does not see (an
                    # alias of the class, ``cls(...)``, a partial), so nothing is
                    # known.
                    grounded = [
                        c for c, _ in built if (id(c), key) not in self._reraise_calls
                    ]
                    self._caught_memo[key] = (
                        union(*(shape for _, shape in built))
                        if grounded
                        else unread(
                            f"{ref.module.rel}:{getattr(ref.node, 'lineno', 0)}"
                            f" (never built, or only raised again from a caught one)"
                        )
                    )
                finally:
                    self._caught_in_progress.discard(key)
            parts.append(self._caught_memo[key])
        return union(*parts)

    def _subclasses(self, ref: _Ref) -> list[_Ref]:
        """Every package class that derives from ``ref``'s class, nearest first."""
        found: list[_Ref] = []
        pending = [ref]
        while pending:
            parent = pending.pop(0)
            for module in self.source.all_modules():
                for node in module.defs.values():
                    if not isinstance(node, ast.ClassDef) or any(
                        kind.node is node for kind in found
                    ):
                        continue
                    scope = _Scope(module=module)
                    for base in node.bases:
                        target = self._ref_of(base, scope)
                        if (
                            target is not None
                            and target.kind == "class"
                            and target.node is parent.node
                        ):
                            child = _Ref("class", module=module, node=node)
                            found.append(child)
                            pending.append(child)
                            break
        return found

    def _class_attributes(self, ref: _Ref) -> dict[str, Shape]:
        """The plain class attributes (``error_type = "x"``) of a package class.

        The class's own come first and win over its package bases'.
        """
        attrs: dict[str, Shape] = {}
        seen: set[int] = set()
        pending = [ref]
        while pending:
            current = pending.pop(0)
            cls = current.node
            if not isinstance(cls, ast.ClassDef) or current.module is None:
                continue
            if id(cls) in seen:
                continue
            seen.add(id(cls))
            scope = _Scope(module=current.module)
            for stmt in cls.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id not in attrs:
                        attrs[target.id] = self.evaluate(stmt.value, scope)
            for base in cls.bases:
                parent = self._ref_of(base, scope)
                if parent is not None and parent.kind == "class":
                    pending.append(parent)
        return attrs

    def _constructions(self, class_name: str) -> list[tuple[_Module, ast.Call]]:
        """Every call in the package spelled like a call of ``class_name``."""
        if self._calls_by_name is None:
            index: dict[str, list[tuple[_Module, ast.Call]]] = {}
            for module in self.source.all_modules():
                for node in ast.walk(module.tree):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    name = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else None
                    )
                    if name:
                        index.setdefault(name, []).append((module, node))
            self._calls_by_name = index
        return self._calls_by_name.get(class_name, [])

    def _is_class(self, func: ast.expr, module: _Module, cls: ast.AST) -> bool:
        """Whether ``func``, in ``module``, names ``cls``: at module level, or by a
        local import of the same name, which this reader does not place."""
        ref = self._ref_of(func, _Scope(module=module))
        if ref is not None:
            return ref.kind == "class" and ref.node is cls
        return isinstance(func, ast.Name)

    def _construct(self, ref: _Ref, node: ast.Call, scope: _Scope) -> Shape:
        """An instance of a package class, with the fields it is built with.

        Fields are the class body's annotated names, in order, as for a NamedTuple
        or a dataclass; one not passed has its default.
        """
        cls = ref.node
        if not isinstance(cls, ast.ClassDef) or ref.module is None:
            return unread(scope.site(node))
        fields: list[str] = []
        defaults: dict[str, ast.expr] = {}
        for stmt in cls.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fields.append(stmt.target.id)
                if stmt.value is not None:
                    defaults[stmt.target.id] = stmt.value
        attrs: dict[str, Shape] = {}
        for name, value in zip(fields, node.args):
            attrs[name] = self.evaluate(value, scope)
        for keyword in node.keywords:
            if keyword.arg is not None:
                attrs[keyword.arg] = self.evaluate(keyword.value, scope)
        class_scope = _Scope(module=ref.module)
        for name in fields:
            if name not in attrs and name in defaults:
                attrs[name] = self.evaluate(defaults[name], class_scope)
        for name, value in self._class_attributes(ref).items():
            attrs.setdefault(name, value)
        return one(ObjectV(cls.name, tuple(attrs.items())))

    # -- calls ----------------------------------------------------------------

    def _class_of(self, node: ast.AST, scope: _Scope, depth: int = 0) -> Optional[_Ref]:
        """The class of the object ``node`` evaluates to, when the source says it."""
        if depth > 4:
            return None
        if isinstance(node, ast.Name):
            if node.id == "self" and scope.owner is not None:
                return _Ref("class", module=scope.owner_module, node=scope.owner)
            ref = self.lookup(scope, node.id)
            if ref is not None and ref.kind == "value" and ref.scope is not None:
                exprs = (
                    ref.scope.locals.assigns.get(ref.name, [])
                    if ref.scope.locals is not None
                    else ref.scope.module.assigns.get(ref.name, [])
                )
                for expr in exprs:
                    found = self._class_of(expr, ref.scope, depth + 1)
                    if found is not None:
                        return found
            return None
        if isinstance(node, ast.Await):
            return self._class_of(node.value, scope, depth + 1)
        if isinstance(node, ast.Call):
            ref = self._ref_of(node.func, scope)
            if ref is None:
                return None
            if ref.kind == "class":
                return ref
            if ref.kind == "function":
                return self._annotation_class(getattr(ref.node, "returns", None), ref)
        return None

    def _annotation_class(
        self, annotation: Optional[ast.AST], ref: _Ref
    ) -> Optional[_Ref]:
        if annotation is None or ref.module is None:
            return None
        text = _str_constant(annotation)
        if text is not None:
            try:
                annotation = ast.parse(text, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(annotation, ast.Subscript):  # Optional[X]
            annotation = annotation.slice
        found = self._ref_of(annotation, _Scope(module=ref.module))
        return found if found is not None and found.kind == "class" else None

    def _method_ref(self, func: ast.Attribute, scope: _Scope) -> Optional[_Ref]:
        owner = self._class_of(func.value, scope)
        if owner is None or owner.node is None or owner.module is None:
            return None
        return self._find_method(owner.node, owner.module, func.attr, set())

    def _find_method(
        self, cls: ast.AST, module: _Module, name: str, seen: set[int]
    ) -> Optional[_Ref]:
        if id(cls) in seen or not isinstance(cls, ast.ClassDef):
            return None
        seen.add(id(cls))
        for node in cls.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
            ):
                return _Ref(
                    "function", module=module, node=node, owner=cls, owner_module=module
                )
        for base in cls.bases:
            ref = self._ref_of(base, _Scope(module=module))
            if ref is not None and ref.kind == "class" and ref.module is not None:
                found = self._find_method(ref.node, ref.module, name, seen)
                if found is not None:
                    return found
        return None

    def _flag_params(self, func: ast.AST) -> frozenset[str]:
        """The parameters ``func`` tests as a bare name: ``if p:``, ``x if p else
        y``, either under ``not``. None for a decorated function, and none that a
        nested function names in ``nonlocal``."""
        if id(func) not in self._flags_memo:
            args = getattr(func, "args", None)
            params = (
                {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
                if args is not None
                else set()
            )
            if getattr(func, "decorator_list", None):
                # A decorator can call it with other arguments than the call names.
                params = set()
            found: set[str] = set()
            for node in _own_nodes(func):
                if not isinstance(node, (ast.If, ast.IfExp)):
                    continue
                test = node.test
                while isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    test = test.operand
                if isinstance(test, ast.Name) and test.id in params:
                    found.add(test.id)
            # A nested function can rebind one with ``nonlocal``, out of sight.
            for node in ast.walk(func):
                if isinstance(node, ast.Nonlocal):
                    found.difference_update(node.names)
            self._flags_memo[id(func)] = frozenset(found)
        return self._flags_memo[id(func)]

    def call(self, ref: _Ref, node: ast.Call, scope: _Scope) -> Shape:
        """What calling ``ref`` returns, with its informative arguments bound."""
        func = ref.node
        args = getattr(func, "args", None)
        if func is None or args is None or ref.module is None:
            return unread(scope.site(node))
        positional = [a.arg for a in [*args.posonlyargs, *args.args]]
        if ref.owner is not None and positional and positional[0] in ("self", "cls"):
            positional = positional[1:]
        bindings: dict[str, Shape] = {}
        for name, value in zip(positional, node.args):
            if isinstance(value, ast.Starred):
                break
            bindings[name] = self.evaluate(value, scope)
        for keyword in node.keywords:
            if keyword.arg is not None:
                bindings[keyword.arg] = self.evaluate(keyword.value, scope)
        # A flag (a parameter the function tests as ``if p:`` or ``... if p else``)
        # keeps a constant it is passed or left at by default (True, None, 0),
        # unless a spread could have passed it. Other constants are not bound, so a
        # call that passes nothing else informative is read once for all callers.
        flags = self._flag_params(func)
        spread = any(isinstance(v, ast.Starred) for v in node.args) or any(
            k.arg is None for k in node.keywords
        )
        if flags and not spread:
            every = [*args.posonlyargs, *args.args]
            defaults = list(
                zip(every[len(every) - len(args.defaults) :], args.defaults)
            )
            defaults += [
                (arg, default)
                for arg, default in zip(args.kwonlyargs, args.kw_defaults)
                if default is not None
            ]
            for arg, default in defaults:
                if arg.arg in flags and arg.arg not in bindings and _literal(default):
                    bindings[arg.arg] = one(LiteralV(default.value))  # type: ignore[attr-defined]
        informative = {
            k: v
            for k, v in bindings.items()
            if v.informative or (k in flags and v.literal)
        }
        return self.returns(
            ref.module,
            func,
            owner=ref.owner,
            owner_module=ref.owner_module,
            parent=ref.scope,
            bindings=informative,
        )

    def returns(
        self,
        module: _Module,
        func: ast.AST,
        owner: Optional[ast.ClassDef] = None,
        owner_module: Optional[_Module] = None,
        parent: Optional[_Scope] = None,
        bindings: Optional[dict[str, Shape]] = None,
    ) -> Shape:
        """The union of everything ``func`` can return.

        A call with no bindings and no parent scope is read once for all callers.
        One that carries either is read once per distinct (function, bindings,
        parent scope). Read afresh for every caller, and again for every name an
        unpacking binds from it, the work grows with the number of call paths to
        it, which is exponential in the depth of a chain of such calls. Its result
        is kept only when no recursion or depth guard shaped it from outside the
        call (:meth:`_note_guard`). A kept result is also tied to what the read went
        through: the functions it called, the names it evaluated and how deep it got.
        It is used only where none of those is in progress and the depth still fits,
        since a fresh read there would be cut off at the one that is, so the result
        of a read does not depend on which one came first.
        """
        site = f"{module.rel}:{getattr(func, 'lineno', 0)}"
        if id(func) in self._stack or len(self._stack) >= MAX_CALL_DEPTH:
            self._note_guard(id(func))
            return unread(f"{site} (recursive or too deep)")
        memo = not bindings and parent is None
        if memo and id(func) in self._returns:
            self._reads.add(id(func))
            return self._returns[id(func)]
        key = None
        if not memo:
            key = self._call_key(func, owner, owner_module, parent, bindings)
        kept = self._bound_returns.get(key) if key is not None else None
        if kept is not None:
            shape, reads, height = kept
            if (
                reads.isdisjoint(self._stack)
                and reads.isdisjoint(self._names_in_progress)
                and len(self._stack) + height <= MAX_CALL_DEPTH
            ):
                self._reads |= reads
                self._peak = max(self._peak, len(self._stack) + height)
                return shape
        position = len(self._stack)
        outer_floor, self._guard_floor = self._guard_floor, _NO_GUARD
        outer_reads, self._reads = self._reads, {id(func)}
        outer_peak, self._peak = self._peak, position + 1
        self._stack.append(id(func))
        self._sites.append(site)
        try:
            local = self._locals_for(func, module)
            scope = _Scope(
                module=module,
                func=func,
                owner=owner,
                owner_module=owner_module or module,
                parent=parent,
                bindings=dict(bindings or {}),
                locals=local,
                frame=position,
            )
            if local.yields:
                result = unread(f"{site} (a generator)")
            else:
                result = union(
                    *(
                        self._narrow(
                            self.evaluate(
                                ret.value,
                                self._guarded_scope(scope, ret, guards, caught),
                            ),
                            ret,
                            guards,
                            scope,
                        )
                        for ret, guards, caught in local.returns
                        if self._reachable(
                            guards + local.passed.get(id(ret), ()), scope
                        )
                    )
                )
        finally:
            self._stack.pop()
            self._sites.pop()
            floor = self._guard_floor
            self._guard_floor = min(outer_floor, floor)
            reads, self._reads = self._reads, outer_reads
            height, self._peak = self._peak - position, max(outer_peak, self._peak)
            outer_reads |= reads
        if memo:
            self._returns[id(func)] = result
        elif key is not None and floor >= position:
            self._bound_returns[key] = (result, frozenset(reads), height)
        return result

    def _note_guard(self, func_id: int) -> None:
        """Record that a guard answered "recursive or too deep" for ``func_id``.

        What a read returns then depends on what is on the stack above it. A guard
        for a function on the stack answers for the call at that position, so only
        calls above it depend on the stack; the depth limit answers for the depth
        of the whole stack, which is position -1 here, so no call is kept.
        """
        position = self._stack.index(func_id) if func_id in self._stack else -1
        self._guard_floor = min(self._guard_floor, position)

    def _call_key(
        self,
        func: ast.AST,
        owner: Optional[ast.ClassDef],
        owner_module: Optional[_Module],
        parent: Optional[_Scope],
        bindings: Optional[dict[str, Shape]],
    ) -> Optional[tuple]:
        """What a call's result depends on, as a key; None when it cannot be one.

        Shapes are frozen dataclasses of tuples, strings and constants, so they
        hash. One that did not would make the call uncached, read afresh each time,
        rather than be keyed on its ``repr`` or ``id``. A parent scope is keyed by
        identity: it is the scope of one read of the function around the nested one.
        """
        key = (
            id(func),
            id(owner),
            id(owner_module),
            parent,
            tuple(sorted((bindings or {}).items(), key=lambda item: item[0])),
        )
        try:
            hash(key)
        except TypeError:
            return None
        return key

    def _reachable(
        self, guards: tuple[tuple[ast.expr, bool], ...], scope: _Scope
    ) -> bool:
        """False when an ``if`` test around a ``return`` is a known constant that
        rules it out (``if quiet:`` with ``quiet`` True, for the ``else``)."""
        for test, in_body in guards:
            truth = self._known_truth(test, scope)
            if truth is not None and truth != in_body:
                return False
        return True

    def _guarded_scope(
        self,
        scope: _Scope,
        ret: ast.Return,
        guards: tuple[tuple[ast.expr, bool], ...],
        caught: tuple[tuple[str, ast.expr], ...],
    ) -> _Scope:
        """The scope a ``return`` is read in: its handler's, then each ``if`` test
        around it applied to the names it reads with ``name["K"]``."""
        current = self._handler_scope(scope, caught)
        if ret.value is None:
            return current
        for test, in_body in guards:
            current = self._conditioned(
                current, test, in_body, ret.value, scope.site(test)
            )
        return current

    def _handler_scope(
        self, scope: _Scope, caught: tuple[tuple[str, ast.expr], ...]
    ) -> _Scope:
        """Inside ``except X as e``, ``e`` is an ``X``, whatever other handlers of
        the function bind to the same name."""
        if not caught:
            return scope
        return _Scope(
            module=scope.module,
            owner=scope.owner,
            owner_module=scope.owner_module,
            parent=scope,
            bindings={name: self._caught(kind, scope) for name, kind in caught},
        )

    # -- guards ---------------------------------------------------------------

    def _narrow(
        self,
        value: Shape,
        ret: ast.Return,
        guards: tuple[tuple[ast.expr, bool], ...],
        scope: _Scope,
    ) -> Shape:
        """Keep the alternatives of ``return name`` that the ``if`` tests around it allow."""
        if not isinstance(ret.value, ast.Name):
            return value
        name = ret.value.id
        for test, in_body in guards:
            if not in_body:
                continue
            for keep in self._predicates(test, name, scope):
                value = Shape(tuple(v for v in value.variants if keep(v)))
        return value

    def _predicates(self, test: ast.expr, name: str, scope: _Scope) -> list:
        """Tests on ``name`` this module understands, as filters over alternatives.

        ``name.get(K) in (A, B)``, ``name[K] == A`` and ``"K" in name``, alone or
        joined by ``and``. Any other test narrows nothing.
        """
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            return [p for v in test.values for p in self._predicates(v, name, scope)]
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
            return []
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if (
            isinstance(op, ast.In)
            and isinstance(right, ast.Name)
            and right.id == name
            and _str_constant(left) is not None
        ):
            wanted_key = _str_constant(left)
            return [
                lambda v: (
                    isinstance(v, UnreadV)
                    or (isinstance(v, DictV) and wanted_key in v.key_map())
                )
            ]
        key = _subscript_key(left, name)
        if key is None or not isinstance(op, (ast.In, ast.Eq)):
            return []
        allowed = self.evaluate(right, scope)
        values = allowed.items().strings if isinstance(op, ast.In) else allowed.strings
        if not values or (isinstance(op, ast.In) and allowed.items().unread):
            return []

        def keep(variant: Variant) -> bool:
            if isinstance(variant, UnreadV):
                return True
            if not isinstance(variant, DictV) or key not in variant.key_map():
                return False
            shape = variant.key_map()[key]
            return bool(shape.strings & values) or bool(shape.unread)

        return [keep]


def _literal(node: Optional[ast.AST]) -> bool:
    """Whether ``node`` is a constant True, False, None or number."""
    return isinstance(node, ast.Constant) and (
        node.value is None or isinstance(node.value, (bool, int, float))
    )


def _mentions(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _names_in(node: ast.AST) -> Iterator[str]:
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            yield n.id


def _key_of(shape: Shape, key: str, site: str) -> Shape:
    """``x["key"]`` for each alternative ``x`` can be.

    A dict without the key that can get keys the source does not name, an
    object and an unread value give an unread alternative; any other dict
    without it gives nothing.
    """
    parts: list[Shape] = []
    for v in shape.variants:
        if isinstance(v, DictV):
            keys = v.key_map()
            if key in keys:
                parts.append(keys[key])
            elif v.open_at:
                parts.append(unread(site))
        elif isinstance(v, (UnreadV, ObjectV)):
            parts.append(unread(site))
    return union(*parts)


def _set_by_one_assignment(local: _Locals, name: str) -> bool:
    """Whether the function binds ``name`` by one plain assignment and nothing
    else: not a parameter, a caught exception, a loop or ``with`` target, an
    element of an unpacking, or a name an ``x |= v`` rebinds."""
    assigns = local.assigns.get(name, [])
    return (
        name not in local.params
        and name not in local.caught
        and name not in local.unread
        and len(assigns) == 1
        and getattr(assigns[0], _UNPACK_ARITY, None) is None
        and not any(
            getattr(call, _AUG_MERGE, False) for call in local.calls.get(name, ())
        )
    )


#: Methods that read a dict without changing it.
_READERS = frozenset({"get", "keys", "values", "items", "copy"})


def _base_name(node: ast.AST) -> Optional[str]:
    """``x`` for ``x``, ``x["a"]``, ``x.a`` and any chain of them."""
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _set_once(func: ast.AST, name: str) -> Optional[int]:
    """The line ``func`` binds ``name`` on, 0 for a parameter, when that is its
    only binding and nothing in ``func``, or a function inside it, changes it.

    A change is another binding (a ``def``, an import, a nested function's
    parameter of that name included), ``del``, a store or delete of one of its
    items or attributes, a method call on it other than a read, and a ``global``
    or ``nonlocal`` of it. A function it is passed to, and an alias of it, are
    not followed.
    """
    lines: list[int] = []
    args = getattr(func, "args", None)
    if args is not None:
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        params += [a for a in (args.vararg, args.kwarg) if a is not None]
        lines += [0 for a in params if a.arg == name]
    for node in (n for stmt in getattr(func, "body", []) for n in ast.walk(stmt)):
        if isinstance(node, ast.Name) and node.id == name:
            if isinstance(node.ctx, ast.Del):
                return None
            if isinstance(node.ctx, ast.Store):
                lines.append(node.lineno)
        elif isinstance(node, (ast.Subscript, ast.Attribute)):
            if not isinstance(node.ctx, ast.Load) and _base_name(node) == name:
                return None
        elif isinstance(node, ast.Call):
            target = node.func
            if (
                isinstance(target, ast.Attribute)
                and _base_name(target) == name
                and target.attr not in _READERS
            ):
                return None
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            if name in node.names:
                return None
        elif isinstance(node, ast.arg) and node.arg == name:
            lines.append(node.lineno)
        elif name in _names_bound_by(node):
            lines.append(node.lineno)
    return lines[0] if len(lines) == 1 else None


def _always_returns(body: list[ast.stmt]) -> bool:
    """Whether running ``body`` always ends in a ``return`` or a ``raise``.

    Read from its last statement: a ``return`` or ``raise``; an ``if`` whose
    branches both always return; a ``with`` whose body does; a ``try`` whose
    ``finally`` does, or whose body (or ``else``) and every handler do.
    Anything else, a loop included, can fall off the end.
    """
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return _always_returns(last.body) and _always_returns(last.orelse)
    if isinstance(last, (ast.With, ast.AsyncWith)):
        return _always_returns(last.body)
    if isinstance(last, (ast.Try, getattr(ast, "TryStar", ast.Try))):
        if _always_returns(last.finalbody):
            return True
        return (_always_returns(last.body) or _always_returns(last.orelse)) and all(
            _always_returns(handler.body) for handler in last.handlers
        )
    return False


def _subscript_reads(expr: ast.AST) -> dict[str, set[str]]:
    """Each name ``expr`` reads with ``name["K"]``, and the keys it reads."""
    reads: dict[str, set[str]] = {}
    for node in ast.walk(expr):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and getattr(node, _UNPACK_ARITY, None) is None
        ):
            key = _str_constant(node.slice)
            reads.setdefault(node.value.id, set())
            if key is not None:
                reads[node.value.id].add(key)
    return reads


def _test_keys(test: ast.AST, name: str) -> Optional[set[str]]:
    """The keys ``test`` looks at in ``name``, or None when it uses ``name`` whole.

    ``name.get(K)``, ``name[K]`` and ``"K" in name`` (or ``not in``) look at K;
    any other use of ``name`` (``len(name)``, ``name is None``, a call) looks at
    the whole value.
    """
    keys: set[str] = set()
    keyed: set[int] = set()
    for node in ast.walk(test):
        key = None
        holder: Optional[ast.AST] = None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == name
        ):
            key = _str_constant(node.args[0]) if node.args else None
            holder = node.func.value
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == name
        ):
            key, holder = _str_constant(node.slice), node.value
        elif (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], (ast.In, ast.NotIn))
            and isinstance(node.comparators[0], ast.Name)
            and node.comparators[0].id == name
        ):
            key, holder = _str_constant(node.left), node.comparators[0]
        if holder is not None and key is not None:
            keys.add(key)
            keyed.add(id(holder))
    for node in ast.walk(test):
        if isinstance(node, ast.Name) and node.id == name and id(node) not in keyed:
            return None
    return keys


def _narrow_by(
    shape: Shape, specs: list[tuple[str, str, frozenset[str]]], holds: bool
) -> Optional[Shape]:
    """``shape`` where the tests ``specs`` describe are ``holds``, or None.

    Holding, each test keeps the dicts it can be true for, and a key's value
    keeps only the strings the test allows. Not holding is read only for one
    ``in``/``==`` test, whose strings the key then cannot be. An unread
    alternative is always kept, so nothing it could be is lost.
    """
    if not holds and (len(specs) != 1 or specs[0][0] != "in"):
        return None
    for kind, key, values in specs:
        variants: list[Variant] = []
        for v in shape.variants:
            if isinstance(v, UnreadV):
                variants.append(v)
                continue
            if not isinstance(v, DictV):
                if not holds:
                    variants.append(v)
                continue
            keys = v.key_map()
            if kind == "has":
                if key in keys or v.open_at:
                    variants.append(v)
                continue
            if key not in keys:
                if not holds or v.open_at:
                    variants.append(v)
                continue
            kept: list[Variant] = []
            for value in keys[key].variants:
                if isinstance(value, StrV):
                    if (value.value in values) == holds:
                        kept.append(value)
                elif isinstance(value, ClassNameV):
                    # A class name is CamelCase: it can be in the set only if
                    # the set holds one.
                    if not holds or any(text[:1].isupper() for text in values):
                        kept.append(value)
                elif isinstance(value, UnreadV) or not holds:
                    kept.append(value)
            if not kept:
                continue
            keys[key] = Shape(tuple(kept))
            variants.append(DictV(tuple(keys.items()), v.open_at))
        shape = Shape(tuple(dict.fromkeys(variants)))
    return shape


def _subscript_key(node: ast.AST, name: str) -> Optional[str]:
    """K for ``name.get(K)`` or ``name[K]``."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == name
        and node.args
    ):
        return _str_constant(node.args[0])
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == name
    ):
        return _str_constant(node.slice)
    return None


def _class_assign(cls: Optional[ast.AST], name: str) -> Optional[ast.expr]:
    for node in getattr(cls, "body", []):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return node.value
    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolContract:
    """What one tool's return statements say it returns."""

    name: str
    #: ``path:line`` of the tool's definition.
    origin: str
    #: Every value the tool can return.
    response: Shape
    #: The string constants ``error_type`` can be, sorted.
    error_types: tuple[str, ...]
    #: ``error_type`` can be the class name of an exception.
    error_class_name: bool
    #: Where an ``error_type`` value could not be read.
    error_types_unread: tuple[str, ...]
    #: The ``type`` of an entry of the response's ``errors`` list, sorted.
    entry_types: tuple[str, ...]
    entry_class_name: bool
    entry_types_unread: tuple[str, ...]
    #: Where a whole response alternative could not be read: such an alternative
    #: could be a dict carrying an ``error_type`` the lists above miss.
    response_unread: tuple[str, ...] = ()


def _tool_name(decorator: ast.AST) -> Optional[str]:
    """The name ``@mcp.tool`` registers, "" for the function's own, or None if it is not one."""
    call = decorator if isinstance(decorator, ast.Call) else None
    target = call.func if call is not None else decorator
    if not (
        isinstance(target, ast.Attribute)
        and target.attr == TOOL_DECORATOR
        and isinstance(target.value, ast.Name)
        and target.value.id == SERVER_OBJECT
    ):
        return None
    for keyword in call.keywords if call is not None else []:
        if keyword.arg == "name" and _str_constant(keyword.value) is not None:
            return _str_constant(keyword.value)
    return ""


def _strings_of(shape: Shape) -> tuple[tuple[str, ...], bool, tuple[str, ...]]:
    return tuple(sorted(shape.strings)), shape.class_name, shape.unread


def tool_contracts(package_dir: Path) -> dict[str, ToolContract]:
    """Every registered tool's contract, by tool name, from ``package_dir``'s source."""
    source = Source(package_dir)
    server = source.module(SERVER_MODULE)
    if server is None:
        raise FileNotFoundError(
            f"{SERVER_MODULE} is not in {package_dir}; there is no server to read"
        )
    evaluator = Evaluator(source)
    contracts: dict[str, ToolContract] = {}
    for node in server.tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = [n for n in map(_tool_name, node.decorator_list) if n is not None]
        if not names:
            continue
        name = names[0] or node.name
        response = evaluator.returns(server, node)
        entries = response.value_of(ENTRY_LIST_KEY).items()
        error_types, error_class, error_unread = _strings_of(
            response.value_of(ERROR_TYPE_KEY)
        )
        entry_types, entry_class, entry_unread = _strings_of(
            entries.value_of(ENTRY_TYPE_KEY)
        )
        contracts[name] = ToolContract(
            name=name,
            origin=f"{server.rel}:{node.lineno}",
            response=response,
            error_types=error_types,
            error_class_name=error_class,
            error_types_unread=error_unread,
            entry_types=entry_types,
            entry_class_name=entry_class,
            entry_types_unread=entry_unread,
            response_unread=response.unread,
        )
    return contracts


def enum_values(package_dir: Path, class_name: str) -> set[str]:
    """The string values of every class named ``class_name`` in the package."""
    found: set[str] = set()
    for module in Source(package_dir).all_modules():
        node = module.defs.get(class_name)
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and _str_constant(stmt.value) is not None:
                found.add(stmt.value.value)  # type: ignore[attr-defined]
    return found


def exception_class_names(package_dir: Path) -> set[str]:
    """The builtin exceptions, every exception class the package defines, and
    every other class an ``except`` clause in the package names.

    A class is an exception when one of its bases is, by name: a builtin exception
    or another exception class of the package. A class from another library
    (``zipfile.BadZipFile``) is one the package names in an ``except`` clause: the
    tool that lets it out returns its name as ``type(e).__name__``. This is a
    superset of what any one tool lets out, as the rest of the class-name rule is.
    An imported alias is not the class's name, and a name that is not CapWords
    (a constant holding a tuple of classes) is not a class's.
    """
    bases: dict[str, set[str]] = {}
    caught: set[str] = set()
    for module in Source(package_dir).all_modules():
        aliases = {
            alias.asname
            for node in ast.walk(module.tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
            if alias.asname
        }
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ClassDef):
                bases.setdefault(node.name, set()).update(
                    b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", "")
                    for b in node.bases
                )
            elif isinstance(node, ast.ExceptHandler) and node.type is not None:
                named = (
                    node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
                )
                for expr in named:
                    if isinstance(expr, ast.Attribute):
                        caught.add(expr.attr)
                    elif isinstance(expr, ast.Name) and expr.id not in aliases:
                        caught.add(expr.id)
    found = set(BUILTIN_EXCEPTIONS)
    found |= {n for n in caught if n[:1].isupper() and not n.isupper()}
    changed = True
    while changed:
        changed = False
        for name, parents in bases.items():
            if name not in found and parents & found:
                found.add(name)
                changed = True
    return found


# ---------------------------------------------------------------------------
# Example responses
# ---------------------------------------------------------------------------

#: An example's keys: each maps to the keys of its value, ``None`` for a scalar,
#: and a list's items are under ``"[]"``.
ExampleKeys = dict[str, Optional[dict]]
LIST_ITEMS = "[]"


def example_keys(text: str) -> ExampleKeys:
    """The keys of a response example, JSON or a sketch of it.

    A sketch is JSON with placeholders in it (``bool``, ``[...]``,
    ``{ ... per-target progress ... }``): only quoted strings followed by a colon
    are keys, so whatever else a value holds is skipped. The items of a list share
    one set of keys.
    """
    root: dict = {}
    #: ("obj" or "arr", the dict that container's keys go in)
    stack: list[tuple[str, dict]] = []
    pending: Optional[str] = None

    def opened() -> dict:
        """The dict a ``{`` or ``[`` opened here puts its keys in."""
        if not stack:
            return root
        kind, top = stack[-1]
        if kind == "arr":
            return top
        if pending is None:
            return {}
        existing = top.get(pending)
        if not isinstance(existing, dict):
            existing = {}
            top[pending] = existing
        return existing

    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < len(text) and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            word = text[i + 1 : j]
            k = j + 1
            while k < len(text) and text[k] in " \t\r\n":
                k += 1
            if k < len(text) and text[k] == ":" and stack and stack[-1][0] == "obj":
                stack[-1][1].setdefault(word, None)
                pending = word
            i = j + 1
            continue
        if ch == "{":
            stack.append(("obj", opened()))
            pending = None
        elif ch == "[":
            stack.append(("arr", opened().setdefault(LIST_ITEMS, {})))
            pending = None
        elif ch in "}]":
            if stack:
                stack.pop()
            pending = None
        elif ch == ",":
            pending = None
        i += 1
    return root


def missing_keys(example: dict, shape: Shape, path: str = "") -> Optional[list[str]]:
    """The example's keys no single response alternative has, or None if one has them all.

    An alternative covers the example when it names every key, and every nested
    example the alternative's value can be read for. A key written as a
    placeholder (``<scanner_name>``) stands for any key.
    """
    own = {k: v for k, v in example.items() if not _placeholder(k)}
    if not own:
        return None
    best: Optional[tuple[int, int, list[str]]] = None
    for variant in shape.dicts():
        keys = variant.key_map()
        missing = [f"{path}{k}" for k in own if k not in keys]
        for key, nested in own.items():
            if key in keys and isinstance(nested, dict) and nested:
                inner = _nested_missing(nested, keys[key], f"{path}{key}.")
                missing += inner or []
        if not missing:
            return None
        # The closest response: fewest keys missing, then most of the example's
        # own keys named, so a report points at the response the example shows.
        rank = (len(missing), -sum(k in keys for k in own))
        if best is None or rank < best[:2]:
            best = (*rank, missing)
    return best[2] if best is not None else [f"{path}{k}" for k in own]


def _nested_missing(example: dict, shape: Shape, path: str) -> Optional[list[str]]:
    """Missing keys under one key; a value the source does not spell out is not checked."""
    if shape.unread or any(isinstance(v, ObjectV) for v in shape.variants):
        return None
    if LIST_ITEMS in example:
        items = example[LIST_ITEMS]
        rest = {k: v for k, v in example.items() if k != LIST_ITEMS}
        if rest:
            return _nested_missing(rest, shape, path)
        if not items or not shape.is_list:
            return None
        inner = shape.items()
        if not inner.is_dict or inner.unread:
            return None
        return missing_keys(items, inner, f"{path}[].")
    if not shape.is_dict:
        return None
    return missing_keys(example, shape, path)


def _placeholder(key: str) -> bool:
    return key.startswith("<") and key.endswith(">")
