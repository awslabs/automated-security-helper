# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Find every directory walk the test run performs whose tree can hold a per-run directory.

Why this exists
---------------
``tests/pytest-temp`` is the tests' scratch tree, inside the checkout. Under
``pytest -n`` other workers create and remove directories there all the time, so a
walk that descends into it races them: ``rglob`` raises FileNotFoundError from inside
its own descent on Python 3.10 to 3.12, and every walker returns whatever the other
workers happened to have written. See tests/unit/test_repo_walkers_skip_scratch.py
for the history.

The first guard matched ``REPO_ROOT.rglob`` and ``repo_root.glob`` by name, in tests/
only. Two walks it could not see raced in CI: one bound the root to ``REPO``, and two
lived in scripts that tests run on the real checkout (``collect_md_files`` in
scripts/verify_docs_freshness.py, ``find_orphans`` in
.github/scripts/check-snapshot-trailers.py, the second reaching the root through a
parameter). So this resolves what each walk's receiver is instead of matching names.

How it decides
--------------
Every ``glob`` with ``**``, ``rglob``, ``Path.walk``, ``os.walk``, ``os.fwalk`` and
``shutil.copytree`` is a walk. Its receiver is evaluated by an explicit abstract
evaluator over the AST: nothing is imported or executed. A value is one of

* ``InRepo``: a path in the checkout, relative to its root;
* ``Private``: a directory no other worker touches (``tmp_path``, ``ash_temp_path``,
  ``tmp_path_factory.mktemp()``, ``tempfile`` directories, the home directory);
* ``Unknown``: anything the evaluator cannot follow, with the reason.

Names are followed through module and function assignments, ``for`` and
comprehension targets, ``with`` targets, tuple unpacking, parameter defaults,
same-module fixtures, the arguments at every call site, return values, and constants
imported from other modules in the checkout. A walk is flagged when any value its
receiver can take is ``Unknown`` (fail closed), or is an ``InRepo`` directory that a
per-run directory lies under.

Which code is checked: every module under tests/, and every function in scripts/ or
.github/scripts/ that the tests reach. A script is reached when a test loads it
(``spec_from_file_location``, or an import of ``scripts.<name>``) or runs it in a
subprocess; within it, the functions reached are those a test calls through the
loaded module, everything they call, and ``main`` plus module-level code when the
script is run or imported. A call from a test supplies its arguments to the script
function's parameters, which is how ``find_orphans(REPO_ROOT)`` is told apart from
``find_orphans(tmp_path)``.

What it does not do
-------------------
It does not know that a test monkeypatches a walker away before calling the code
that would run it; such a walk is still checked. Attribute chains (``self.x``,
``context.output_dir``) and values computed at run time are ``Unknown``, so a walk
over one is flagged and has to be exempted with a reason in the test that uses this.
"""

from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Per-run directories, relative to the checkout: the tests' scratch tree, the scan
#: output ASH writes by default, and the project's virtual environment.
#: ``per_run_dirs()`` adds a ``node_modules`` beside every tracked package.json.
PER_RUN_DIRS = ("tests/pytest-temp", ".ash/ash_output", ".venv")

#: Fixture and parameter names whose value is a directory private to one test.
PRIVATE_NAMES = frozenset({"tmp_path", "tmpdir", "ash_temp_path"})

#: Calls that return a fresh private directory, by the last name in the call.
PRIVATE_CALLS = frozenset(
    {"mktemp", "mkdtemp", "TemporaryDirectory", "get_ash_temp_path", "getbasetemp"}
)

#: The directories checked for scripts the tests reach.
SCRIPT_DIRS = (PurePosixPath("scripts"), PurePosixPath(".github/scripts"))

_PATH_TYPES = frozenset(
    {"Path", "PurePath", "PurePosixPath", "PureWindowsPath", "PosixPath", "WindowsPath"}
)
_PRESERVING_METHODS = frozenset({"resolve", "absolute", "expanduser"})
_PRESERVING_FUNCS = frozenset(
    {
        "str",
        "fspath",
        "abspath",
        "realpath",
        "normpath",
        "sorted",
        "list",
        "tuple",
        "set",
    }
)
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "check_output", "check_call", "call"})
_ROOT = PurePosixPath(".")
_MAX_DEPTH = 40


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InRepo:
    rel: PurePosixPath


@dataclass(frozen=True)
class Private:
    origin: str


@dataclass(frozen=True)
class Unknown:
    why: str


@dataclass(frozen=True)
class ModuleRef:
    """A module: a stdlib one by name, or one in the checkout with its source."""

    name: str


@dataclass(frozen=True)
class Text:
    value: str


@dataclass(frozen=True)
class Built:
    """What a call the evaluator cannot follow returned. Unresolved, except that
    ``.name`` reads back a ``name=`` keyword argument the call was given, which is
    how ``PluginContext(output_dir=tmp_path / "out").output_dir`` resolves."""

    key: int
    why: str


@dataclass(frozen=True)
class Seq:
    """A tuple or list literal, element by element, each a set of values."""

    items: Tuple[FrozenSet[object], ...]


Values = FrozenSet[object]
Kind = Tuple[Any, ...]


def _one(value: object) -> Values:
    return frozenset({value})


def _normalize(rel: PurePosixPath) -> Optional[PurePosixPath]:
    """``rel`` with ``.`` and ``..`` folded, or None if it climbs out of the checkout."""
    parts: List[str] = []
    for part in rel.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath(*parts) if parts else _ROOT


def _as_path(value: object) -> object:
    """A string value read as a path: relative ones are relative to the checkout,
    because the tests run from its root."""
    if not isinstance(value, Text):
        return value
    if not value.value:
        return Unknown("an empty string used as a path")
    text = value.value.replace("\\", "/")
    if text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        try:
            rel = Path(value.value).resolve().relative_to(REPO_ROOT)
        except ValueError:
            return Private("an absolute path outside the checkout")
        return InRepo(PurePosixPath(rel.as_posix()))
    normal = _normalize(PurePosixPath(text))
    return InRepo(normal) if normal is not None else Private("above the checkout")


def _join(left: Values, right: Values) -> Values:
    out: Set[object] = set()
    for base in left:
        base = _as_path(base)
        for part in right:
            if isinstance(base, Unknown):
                out.add(base)
            elif isinstance(part, Text) and (
                part.value.startswith("/") or part.value[1:2] == ":"
            ):
                out.add(_as_path(part))
            elif isinstance(part, InRepo):
                # Joining onto an absolute path gives that path.
                out.add(part)
            elif isinstance(base, Private):
                out.add(base)
            elif isinstance(base, InRepo) and isinstance(part, Text):
                normal = _normalize(base.rel / part.value.replace("\\", "/"))
                out.add(InRepo(normal) if normal is not None else Private("above"))
            elif isinstance(part, Unknown):
                out.add(Unknown(f"a path joined with {part.why}"))
            else:
                out.add(
                    Unknown(f"{type(base).__name__} joined with {type(part).__name__}")
                )
    return frozenset(out)


def _concat(left: Values, right: Values) -> Values:
    """``left`` followed by ``right``, as an f-string writes them."""
    out: Set[object] = set()
    for a in left:
        for b in right:
            if isinstance(a, Text) and isinstance(b, Text):
                out.add(Text(a.value + b.value))
            elif isinstance(a, Text) and not a.value:
                out.add(b)
            elif isinstance(b, Text) and b.value[:1] in ("/", "\\"):
                out |= _join(_one(a), _one(Text(b.value.lstrip("/\\"))))
            elif isinstance(b, Text) and not b.value:
                out.add(a)
            elif isinstance(a, Unknown):
                out.add(a)
            elif isinstance(b, Unknown):
                out.add(b)
            else:
                out.add(Unknown("an f-string that is not a path with literal segments"))
    return frozenset(out)


def _parent(values: Values, levels: int = 1) -> Values:
    out: Set[object] = set()
    for value in values:
        value = _as_path(value)
        if isinstance(value, InRepo):
            rel = value.rel
            for _ in range(levels):
                if rel == _ROOT:
                    out.add(Private("above the checkout"))
                    break
                rel = rel.parent if rel.parent != PurePosixPath("") else _ROOT
            else:
                out.add(InRepo(rel))
        elif isinstance(value, (Private, Unknown)):
            out.add(value)
        else:
            out.add(Unknown(f".parent of {type(value).__name__}"))
    return frozenset(out)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

_Func = Union[ast.FunctionDef, ast.AsyncFunctionDef]
_ScopeNode = Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda]
_Scope = Optional[_ScopeNode]  # None is the module


class Source:
    """One parsed file, its scopes, imports and functions."""

    def __init__(self, rel: PurePosixPath, text: str):
        self.rel = rel
        self.tree = ast.parse(text, filename=str(rel))
        self.parent: Dict[ast.AST, ast.AST] = {}
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
        self.functions: Dict[str, List[_Func]] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, []).append(node)
        self.imports: Dict[str, str] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.imports[alias.asname] = alias.name
                    else:
                        head = alias.name.split(".")[0]
                        self.imports[head] = head
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = (
                        f"{node.module}.{alias.name}"
                    )
        self._bindings: Dict[int, Dict[str, List[Kind]]] = {}

    @classmethod
    def from_file(cls, path: Path) -> "Source":
        rel = PurePosixPath(path.resolve().relative_to(REPO_ROOT).as_posix())
        return cls(rel, path.read_text(encoding="utf-8"))

    def scope_of(self, node: ast.AST) -> _Scope:
        current = self.parent.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return current
            current = self.parent.get(current)
        return None

    def enclosing_scope(self, scope: _Scope) -> _Scope:
        return None if scope is None else self.scope_of(scope)

    def function_name(self, node: ast.AST) -> str:
        scope = self.scope_of(node)
        while isinstance(scope, ast.Lambda):
            scope = self.scope_of(scope)
        return scope.name if scope is not None else "<module>"

    def bindings(self, scope: _Scope) -> Dict[str, List[Kind]]:
        """Every binding of every name in ``scope``, flow-insensitively."""
        key = id(scope)
        if key in self._bindings:
            return self._bindings[key]
        out: Dict[str, List[Kind]] = {}

        def bind(target: ast.AST, kind: Kind) -> None:
            if isinstance(target, ast.Name):
                out.setdefault(target.id, []).append(kind)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for index, element in enumerate(target.elts):
                    if isinstance(element, ast.Starred):
                        bind(element.value, ("unknown", "a starred target"))
                    else:
                        bind(element, ("index", kind, index))

        stack: List[ast.AST]
        if scope is None:
            stack = list(self.tree.body)
        elif isinstance(scope, ast.Lambda):
            stack = [scope.body]
        else:
            stack = list(scope.body)
        while stack:
            node = stack.pop()
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                if not isinstance(node, ast.Lambda):
                    out.setdefault(node.name, []).append(("def", node))
                continue
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    bind(target, ("expr", node.value))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                bind(node.target, ("expr", node.value))
            elif isinstance(node, ast.AugAssign):
                bind(node.target, ("unknown", "an augmented assignment"))
            elif isinstance(node, ast.NamedExpr):
                bind(node.target, ("expr", node.value))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                bind(node.target, ("iter", ("expr", node.iter)))
            elif isinstance(node, ast.comprehension):
                bind(node.target, ("iter", ("expr", node.iter)))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        bind(item.optional_vars, ("with", item.context_expr))
            elif isinstance(node, ast.ExceptHandler) and node.name:
                out.setdefault(node.name, []).append(("unknown", "an exception"))
            stack.extend(ast.iter_child_nodes(node))
        self._bindings[key] = out
        return out


def _params(func: _ScopeNode) -> List[str]:
    args = func.args
    return [a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]]


def _default(func: _ScopeNode, name: str) -> Optional[ast.expr]:
    args = func.args
    positional = [*args.posonlyargs, *args.args]
    offset = len(positional) - len(args.defaults)
    for index, arg in enumerate(positional):
        if arg.arg == name and index >= offset:
            return args.defaults[index - offset]
    for arg, kw_default in zip(args.kwonlyargs, args.kw_defaults):
        if arg.arg == name:
            return kw_default
    return None


def _is_fixture(func: _Func) -> bool:
    for decorator in getattr(func, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr == "fixture":
            return True
        if isinstance(target, ast.Name) and target.id == "fixture":
            return True
    return False


# ---------------------------------------------------------------------------
# The evaluator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallSite:
    source: Source
    call: ast.Call
    #: Positional arguments to skip, for a call through a module or an instance.
    skip: int = 0


class Evaluator:
    """Evaluates expressions in the checkout's sources to sets of abstract values."""

    def __init__(self, sources: Iterable[Source]):
        self.sources: Dict[PurePosixPath, Source] = {s.rel: s for s in sources}
        self.external_sites: Dict[Tuple[PurePosixPath, str], List[CallSite]] = {}
        self._active: Set[Tuple[Any, ...]] = set()
        self._memo: Dict[Tuple[Any, ...], Values] = {}
        self._built: Dict[int, Tuple[Source, ast.Call, _Scope]] = {}

    def conftests_for(self, source: Source) -> List[Source]:
        """The conftest.py files whose fixtures ``source`` can use, nearest first."""
        out = []
        directory = source.rel.parent
        while True:
            candidate = directory / "conftest.py"
            if candidate != source.rel:
                found = self.sources.get(candidate)
                if found is None and (REPO_ROOT / candidate).is_file():
                    found = Source.from_file(REPO_ROOT / candidate)
                    self.sources[found.rel] = found
                if found is not None:
                    out.append(found)
            if directory in (_ROOT, PurePosixPath("")):
                break
            directory = directory.parent
        return out

    # -- modules ----------------------------------------------------------

    def source_for_module(self, dotted: str) -> Optional[Source]:
        base = PurePosixPath(*dotted.split("."))
        for candidate in (base.with_suffix(".py"), base / "__init__.py"):
            if candidate in self.sources:
                return self.sources[candidate]
            path = REPO_ROOT / candidate
            if path.is_file():
                source = Source.from_file(path)
                self.sources[source.rel] = source
                return source
        return None

    def _imported(self, dotted: str) -> Values:
        if self.source_for_module(dotted) is not None:
            return _one(ModuleRef(dotted))
        module, _, member = dotted.rpartition(".")
        if module:
            owner = self.source_for_module(module)
            if owner is not None:
                return self.lookup(member, owner, None)
        return _one(ModuleRef(dotted))

    # -- names ------------------------------------------------------------

    def lookup(
        self, name: str, source: Source, scope: _Scope, depth: int = 0
    ) -> Values:
        while True:
            bindings = source.bindings(scope)
            if name in bindings:
                return self._kinds(bindings[name], source, scope, depth)
            if scope is not None and name in _params(scope):
                return self.param(source, scope, name, depth)
            if scope is None:
                break
            scope = source.enclosing_scope(scope)
        if name == "__file__":
            return _one(InRepo(source.rel))
        if name in source.imports:
            return self._imported(source.imports[name])
        return _one(Unknown(f"the unbound name {name!r}"))

    def _kinds(
        self, kinds: List[Kind], source: Source, scope: _Scope, depth: int
    ) -> Values:
        out: Set[object] = set()
        for kind in kinds:
            out |= self._kind(kind, source, scope, depth)
        return frozenset(out)

    def _kind(self, kind: Kind, source: Source, scope: _Scope, depth: int) -> Values:
        tag = kind[0]
        if tag == "expr":
            return self.value_of(kind[1], source, scope, depth)
        if tag == "with":
            return self.value_of(kind[1], source, scope, depth)
        if tag == "iter":
            return self._elements(self._kind(kind[1], source, scope, depth))
        if tag == "index":
            return self._index(self._kind(kind[1], source, scope, depth), kind[2])
        if tag == "def":
            return _one(Unknown(f"the function {kind[1].name!r}"))
        return _one(Unknown(kind[1]))

    def _elements(self, values: Values) -> Values:
        out: Set[object] = set()
        for value in values:
            if isinstance(value, Seq):
                for item in value.items:
                    out |= item
            elif isinstance(value, Unknown):
                out.add(value)
            else:
                out.add(Unknown(f"an element of {type(value).__name__}"))
        return frozenset(out)

    def _index(self, values: Values, index: int) -> Values:
        out: Set[object] = set()
        for value in values:
            if isinstance(value, Seq) and -len(value.items) <= index < len(value.items):
                out |= value.items[index]
            elif isinstance(value, Unknown):
                out.add(value)
            else:
                out.add(Unknown(f"item {index} of {type(value).__name__}"))
        return frozenset(out)

    # -- parameters -------------------------------------------------------

    def call_sites(self, source: Source, func: _Func) -> List[CallSite]:
        sites = [
            CallSite(source, node)
            for node in ast.walk(source.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == func.name
        ]
        sites += self.external_sites.get((source.rel, func.name), [])
        return sites

    def param(self, source: Source, func: _ScopeNode, name: str, depth: int) -> Values:
        if name in PRIVATE_NAMES:
            return _one(Private(name))
        if isinstance(func, ast.Lambda):
            return _one(Unknown(f"the lambda parameter {name!r}"))
        key = ("param", source.rel, id(func), name)
        if key in self._memo:
            return self._memo[key]
        if key in self._active or depth > _MAX_DEPTH:
            return _one(Unknown(f"a cycle through the parameter {name!r}"))
        self._active.add(key)
        try:
            out: Set[object] = set()
            default = _default(func, name)
            if default is not None:
                out |= self.value_of(default, source, source.scope_of(func), depth + 1)
            for fixture in source.functions.get(name, []):
                if _is_fixture(fixture):
                    out |= self.returns(source, fixture, depth + 1)
            if not any(_is_fixture(f) for f in source.functions.get(name, [])):
                for conftest in self.conftests_for(source):
                    fixtures = [
                        f for f in conftest.functions.get(name, []) if _is_fixture(f)
                    ]
                    for fixture in fixtures:
                        out |= self.returns(conftest, fixture, depth + 1)
                    if fixtures:
                        break
            index = _params(func).index(name)
            for site in self.call_sites(source, func):
                argument = self._argument(site, name, index)
                if argument is not None:
                    caller = site.source.scope_of(site.call)
                    out |= self.value_of(argument, site.source, caller, depth + 1)
                elif default is None:
                    out.add(Unknown(f"a call to {func.name}() without {name!r}"))
            if not out:
                out.add(
                    Unknown(
                        f"the parameter {name!r} of "
                        f"{func.name}(), which has no "
                        f"resolvable caller"
                    )
                )
            result = frozenset(out)
            self._memo[key] = result
            return result
        finally:
            self._active.discard(key)

    @staticmethod
    def _argument(site: CallSite, name: str, index: int) -> Optional[ast.expr]:
        for keyword in site.call.keywords:
            if keyword.arg == name:
                return keyword.value
        position = index - site.skip
        positional = site.call.args
        if 0 <= position < len(positional) and not any(
            isinstance(a, ast.Starred) for a in positional[: position + 1]
        ):
            return positional[position]
        return None

    def returns(self, source: Source, func: _Func, depth: int) -> Values:
        key = ("returns", source.rel, id(func))
        if key in self._memo:
            return self._memo[key]
        if key in self._active or depth > _MAX_DEPTH:
            return _one(Unknown(f"a cycle through {func.name}()"))
        self._active.add(key)
        try:
            out: Set[object] = set()
            stack: List[ast.AST] = list(func.body)
            while stack:
                node = stack.pop()
                if isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
                ):
                    continue
                if isinstance(node, (ast.Return, ast.Yield)) and node.value is not None:
                    out |= self.value_of(node.value, source, func, depth + 1)
                stack.extend(ast.iter_child_nodes(node))
            result = frozenset(out) or _one(Unknown(f"{func.name}() returns nothing"))
            self._memo[key] = result
            return result
        finally:
            self._active.discard(key)

    # -- expressions ------------------------------------------------------

    def value_of(
        self, node: ast.AST, source: Source, scope: _Scope, depth: int = 0
    ) -> Values:
        if depth > _MAX_DEPTH:
            return _one(Unknown("an expression nested too deeply to follow"))
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return _one(Text(node.value))
            return _one(Unknown(f"the constant {node.value!r}"))
        if isinstance(node, ast.Name):
            return self.lookup(node.id, source, scope, depth + 1)
        if isinstance(node, (ast.Tuple, ast.List)):
            return _one(
                Seq(
                    tuple(self.value_of(e, source, scope, depth + 1) for e in node.elts)
                )
            )
        if isinstance(node, ast.Set):
            return _one(
                Seq(
                    tuple(self.value_of(e, source, scope, depth + 1) for e in node.elts)
                )
            )
        if isinstance(node, ast.Dict):
            return _one(
                Seq(
                    tuple(
                        self.value_of(v, source, scope, depth + 1)
                        for v in node.values
                        if v is not None
                    )
                )
            )
        if isinstance(node, ast.IfExp):
            return self.value_of(node.body, source, scope, depth + 1) | self.value_of(
                node.orelse, source, scope, depth + 1
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return _join(
                self.value_of(node.left, source, scope, depth + 1),
                self.value_of(node.right, source, scope, depth + 1),
            )
        if isinstance(node, ast.Attribute):
            return self._attribute(node, source, scope, depth)
        if isinstance(node, ast.Subscript):
            return self._subscript(node, source, scope, depth)
        if isinstance(node, ast.Call):
            return self._call(node, source, scope, depth)
        if isinstance(node, ast.Starred):
            return self._elements(self.value_of(node.value, source, scope, depth + 1))
        if isinstance(node, ast.JoinedStr):
            acc: Values = _one(Text(""))
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    piece = _one(Text(part.value))
                elif (
                    isinstance(part, ast.FormattedValue)
                    and part.conversion == -1
                    and part.format_spec is None
                ):
                    piece = self.value_of(part.value, source, scope, depth + 1)
                else:
                    return _one(Unknown("an f-string with a conversion or format spec"))
                acc = _concat(acc, piece)
            return acc
        if isinstance(node, ast.Await):
            return _one(Unknown("the result of an await"))
        return _one(Unknown(f"a {type(node).__name__} expression"))

    def _attribute(
        self, node: ast.Attribute, source: Source, scope: _Scope, depth: int
    ) -> Values:
        if node.attr == "parent":
            return _parent(self.value_of(node.value, source, scope, depth + 1))
        receiver = self.value_of(node.value, source, scope, depth + 1)
        out: Set[object] = set()
        for value in receiver:
            if isinstance(value, ModuleRef):
                module = self.source_for_module(value.name)
                if module is None:
                    out.add(ModuleRef(f"{value.name}.{node.attr}"))
                elif node.attr == "__file__":
                    out.add(InRepo(module.rel))
                else:
                    out |= self.lookup(node.attr, module, None, depth + 1)
            elif isinstance(value, Built):
                origin, call, call_scope = self._built[value.key]
                given = [k.value for k in call.keywords if k.arg == node.attr]
                if given:
                    out |= self.value_of(given[0], origin, call_scope, depth + 1)
                else:
                    out.add(Unknown(f"the attribute .{node.attr} of {value.why}"))
            elif isinstance(value, Unknown):
                out.add(value)
            else:
                out.add(Unknown(f"the attribute .{node.attr}"))
        return frozenset(out)

    def _subscript(
        self, node: ast.Subscript, source: Source, scope: _Scope, depth: int
    ) -> Values:
        index = node.slice
        if isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
            if isinstance(index, ast.Constant) and type(index.value) is int:
                base = self.value_of(node.value.value, source, scope, depth + 1)
                return _parent(base, index.value + 1)
            return _one(Unknown("a .parents index that is not a literal"))
        values = self.value_of(node.value, source, scope, depth + 1)
        if isinstance(index, ast.Constant) and type(index.value) is int:
            return self._index(values, index.value)
        # A dict or tuple read with a key the evaluator cannot know: any element.
        return self._elements(values)

    def _call(
        self, node: ast.Call, source: Source, scope: _Scope, depth: int
    ) -> Values:
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else None
        )

        def arg(i: int) -> Values:
            return self.value_of(node.args[i], source, scope, depth + 1)

        if name in PRIVATE_CALLS or name == "home":
            return _one(Private(f"{name}()"))
        if name in _PATH_TYPES:
            if not node.args:
                return _one(InRepo(_ROOT))
            acc = frozenset(_as_path(v) for v in arg(0))
            for i in range(1, len(node.args)):
                acc = _join(acc, arg(i))
            return acc
        if name in ("cwd", "getcwd"):
            return _one(InRepo(_ROOT))
        if isinstance(func, ast.Attribute):
            receiver = self.value_of(func.value, source, scope, depth + 1)
            modules = {v.name for v in receiver if isinstance(v, ModuleRef)}
            if name in _PRESERVING_METHODS and not modules:
                return frozenset(_as_path(v) for v in receiver)
            if name == "joinpath":
                acc = receiver
                for i in range(len(node.args)):
                    acc = _join(acc, arg(i))
                return acc
            if name == "join" and modules & {"os.path"} and node.args:
                acc = frozenset(_as_path(v) for v in arg(0))
                for i in range(1, len(node.args)):
                    acc = _join(acc, arg(i))
                return acc
            if name == "dirname" and modules & {"os.path"} and node.args:
                return _parent(arg(0))
            if name in _PRESERVING_FUNCS and modules and node.args:
                return arg(0)
            out: Set[object] = set()
            for value in receiver:
                if isinstance(value, ModuleRef):
                    module = self.source_for_module(value.name)
                    if module is not None and name in module.functions:
                        for target in module.functions[name]:
                            out |= self.returns(module, target, depth + 1)
                        continue
                out.add(Unknown(f"a call to .{name}()"))
            return frozenset(out)
        if isinstance(func, ast.Name):
            if name in _PRESERVING_FUNCS and node.args:
                return arg(0)
            if name in source.functions:
                local: Set[object] = set()
                for target in source.functions[name]:
                    local |= self.returns(source, target, depth + 1)
                return frozenset(local)
            if name in source.imports:
                dotted = source.imports[name]
                module_name, _, member = dotted.rpartition(".")
                module = self.source_for_module(module_name) if module_name else None
                if module is not None and member in module.functions:
                    imported: Set[object] = set()
                    for target in module.functions[member]:
                        imported |= self.returns(module, target, depth + 1)
                    return frozenset(imported)
        self._built[id(node)] = (source, node, scope)
        return _one(Built(id(node), f"a call to {ast.unparse(func)}()"))


# ---------------------------------------------------------------------------
# Walks and the sweep
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Walk:
    source: Source
    call: ast.Call
    receiver: ast.AST
    #: The literal directory part of a ``**`` glob pattern, walked from the receiver.
    prefix: Optional[str] = None
    #: A glob pattern that is not a literal, judged by the values it can take.
    pattern: Optional[ast.AST] = None

    @property
    def function(self) -> str:
        return self.source.function_name(self.call)

    @property
    def where(self) -> str:
        return f"{self.source.rel}:{self.call.lineno}"


def _glob_prefix(pattern: str) -> Optional[str]:
    """The directories before the first wildcard, or None if ``pattern`` has no ``**``."""
    if "**" not in pattern:
        return None
    fixed = []
    for part in pattern.replace("\\", "/").split("/"):
        if any(c in part for c in "*?["):
            break
        fixed.append(part)
    return "/".join(fixed)


def walks_in(evaluator: Evaluator, source: Source) -> Iterator[Walk]:
    """Every call in ``source`` that walks a directory tree."""
    for node in ast.walk(source.tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr = node.func.attr
        receiver = node.func.value
        scope = source.scope_of(node)
        if attr in ("walk", "fwalk", "copytree", "glob", "iglob"):
            owner = evaluator.value_of(receiver, source, scope)
            modules = {v.name for v in owner if isinstance(v, ModuleRef)}
            if modules:
                if modules & {"os"} and attr in ("walk", "fwalk") and node.args:
                    yield Walk(source, node, node.args[0])
                elif modules & {"shutil"} and attr == "copytree" and node.args:
                    yield Walk(source, node, node.args[0])
                elif modules & {"glob"} and attr in ("glob", "iglob") and node.args:
                    recursive = any(
                        k.arg == "recursive"
                        and not (
                            isinstance(k.value, ast.Constant) and not k.value.value
                        )
                        for k in node.keywords
                    )
                    pattern = node.args[0]
                    if recursive:
                        if isinstance(pattern, ast.Constant) and isinstance(
                            pattern.value, str
                        ):
                            prefix = _glob_prefix(pattern.value)
                            if prefix is not None:
                                yield Walk(source, node, ast.Constant(prefix or "."))
                        else:
                            yield Walk(source, node, ast.Constant("."), pattern=pattern)
                continue
        if attr == "rglob" or (attr == "walk" and not node.args):
            yield Walk(source, node, receiver)
        elif attr == "glob" and node.args:
            pattern = node.args[0]
            if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str):
                prefix = _glob_prefix(pattern.value)
                if prefix is not None:
                    yield Walk(source, node, receiver, prefix=prefix)
            else:
                yield Walk(source, node, receiver, pattern=pattern)


def per_run_dirs(root: Path = REPO_ROOT) -> Tuple[PurePosixPath, ...]:
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*package.json"],
        capture_output=True,
        check=True,
    )
    node_modules = {
        PurePosixPath(entry.decode()).parent / "node_modules"
        for entry in listing.stdout.split(b"\0")
        if entry and entry.decode().endswith("/package.json")
    }
    if listing.stdout.split(b"\0")[0] == b"package.json":
        node_modules.add(PurePosixPath("node_modules"))
    return tuple(sorted({PurePosixPath(d) for d in PER_RUN_DIRS} | node_modules))


def verdict(
    evaluator: Evaluator, walk: Walk, per_run: Tuple[PurePosixPath, ...]
) -> Optional[str]:
    """Why ``walk`` can enter a per-run directory, or None if it cannot."""
    scope = walk.source.scope_of(walk.call)
    values = evaluator.value_of(walk.receiver, walk.source, scope)
    if walk.prefix:
        values = _join(values, _one(Text(walk.prefix)))
    if walk.pattern is not None:
        patterns = evaluator.value_of(walk.pattern, walk.source, scope)
        unreadable = sorted(
            {
                getattr(p, "why", type(p).__name__)
                for p in patterns
                if not isinstance(p, Text)
            }
        )
        if unreadable:
            return (
                "its glob pattern is not a literal and may be "
                + "; ".join(unreadable)
                + ", so where it descends is unknown"
            )
        prefixes = {_glob_prefix(p.value) for p in patterns if isinstance(p, Text)}
        prefixes.discard(None)
        if not prefixes:
            return None  # every value the pattern takes is a fixed-depth glob
        values = frozenset(
            v for prefix in prefixes for v in _join(values, _one(Text(prefix or ".")))
        )
    reasons = []
    for value in sorted(values, key=repr):
        value = _as_path(value)
        if isinstance(value, Unknown):
            reasons.append(f"its receiver may be {value.why}, which cannot be resolved")
        elif isinstance(value, InRepo):
            under = [
                d
                for d in per_run
                if value.rel == _ROOT or value.rel == d or value.rel in d.parents
            ]
            if under:
                reasons.append(
                    f"it walks {value.rel.as_posix()}/, which holds {under[0].as_posix()}/"
                )
        elif isinstance(value, Built):
            reasons.append(f"its receiver may be {value.why}, which cannot be resolved")
        elif isinstance(value, (ModuleRef, Seq)):
            reasons.append(f"its receiver may be a {type(value).__name__}")
    return "; ".join(dict.fromkeys(reasons)) or None


@dataclass
class Reached:
    """A script the tests reach, and how: imported, run, or called into."""

    source: Source
    called: Set[str]
    imported: bool = False
    run_as_main: bool = False


def _is_main_guard(node: ast.AST) -> bool:
    test = getattr(node, "test", None)
    return (
        isinstance(node, ast.If)
        and isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and any(
            isinstance(c, ast.Constant) and c.value == "__main__"
            for c in test.comparators
        )
    )


def _module_level(tree: ast.Module, include_main: bool) -> Iterator[ast.AST]:
    """Nodes that run when the module runs: not function or class bodies, and the
    ``if __name__ == "__main__"`` block only when the script is run."""
    stack: List[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if _is_main_guard(node) and not include_main:
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


class Sweep:
    """The walks the test run performs: in tests/, and in the scripts it reaches."""

    def __init__(
        self, test_sources: Iterable[Source], script_sources: Iterable[Source]
    ):
        self.tests = list(test_sources)
        self.scripts = {s.rel: s for s in script_sources}
        self.evaluator = Evaluator([*self.tests, *self.scripts.values()])
        self.reached: Dict[PurePosixPath, Reached] = {}
        for test in self.tests:
            self._find_reach(test)

    @classmethod
    def of_checkout(cls, root: Path = REPO_ROOT) -> "Sweep":
        from tests.utils.helpers import iter_repo_files

        tests = [
            Source.from_file(p)
            for p in iter_repo_files(
                root / "tests", skip_dirs=frozenset({"__pycache__"})
            )
            if p.suffix == ".py"
        ]
        scripts = [
            Source.from_file(p)
            for directory in SCRIPT_DIRS
            for p in sorted((root / directory).glob("*.py"))
        ]
        return cls(tests, scripts)

    def _script_values(self, values: Values) -> List[Source]:
        out = []
        for value in values:
            value = _as_path(value)
            if isinstance(value, InRepo) and value.rel in self.scripts:
                out.append(self.scripts[value.rel])
        return out

    def _reach(self, script: Source) -> Reached:
        return self.reached.setdefault(script.rel, Reached(script, set()))

    def _find_reach(self, test: Source) -> None:
        evaluator = self.evaluator
        loaders: Dict[str, List[Source]] = {}
        for node in ast.walk(test.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", None)
            )
            scope = test.scope_of(node)
            if name == "spec_from_file_location":
                location = (
                    node.args[1]
                    if len(node.args) > 1
                    else next(
                        (k.value for k in node.keywords if k.arg == "location"), None
                    )
                )
                if location is None:
                    continue
                for script in self._script_values(
                    evaluator.value_of(location, test, scope)
                ):
                    self._reach(script).imported = True
                    owner = test.function_name(node)
                    loaders.setdefault(owner, []).append(script)
            elif name in _SUBPROCESS_FUNCS:
                for argument in [*node.args, *(k.value for k in node.keywords)]:
                    for part in ast.walk(argument):
                        if isinstance(part, ast.expr) and not isinstance(
                            part, (ast.Constant, ast.JoinedStr, ast.keyword)
                        ):
                            values = evaluator.value_of(part, test, scope)
                        elif isinstance(part, ast.Constant):
                            values = (
                                _one(Text(part.value))
                                if isinstance(part.value, str)
                                else frozenset()
                            )
                        else:
                            continue
                        for script in self._script_values(values):
                            self._reach(script).run_as_main = True
        # Imports of scripts.<name>: the imported names call into the script.
        for local, dotted in test.imports.items():
            parts = dotted.split(".")
            for depth in (len(parts), len(parts) - 1):
                if depth < 2:
                    continue
                rel = PurePosixPath(*parts[:depth]).with_suffix(".py")
                if rel in self.scripts:
                    reached = self._reach(self.scripts[rel])
                    reached.imported = True
                    if depth == len(parts) - 1:
                        self._register_name(reached, parts[-1], test, local)
                    else:
                        self._alias_calls(test, local, self.scripts[rel])
                    break
        # Names bound to a loaded module: the loader itself (a fixture or a helper),
        # and every name assigned from a call to it.
        for loader, scripts in loaders.items():
            if loader.startswith("<"):
                continue
            aliases = {loader}
            for node in ast.walk(test.tree):
                if (
                    isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == loader
                ):
                    aliases |= {t.id for t in node.targets if isinstance(t, ast.Name)}
            if loader == "<module>":
                for node in ast.walk(test.tree):
                    if (
                        isinstance(node, ast.Assign)
                        and isinstance(node.value, ast.Call)
                        and getattr(node.value.func, "attr", "") == "module_from_spec"
                    ):
                        aliases |= {
                            t.id for t in node.targets if isinstance(t, ast.Name)
                        }
            for script in scripts:
                for alias in aliases:
                    self._alias_calls(test, alias, script)

    def _alias_calls(self, test: Source, alias: str, script: Source) -> None:
        for node in ast.walk(test.tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == alias
            ):
                self._register(self._reach(script), node.func.attr, test, [node])

    def _register_name(
        self, reached: Reached, function: str, test: Source, local: str
    ) -> None:
        """A script function imported by name: every call to that name calls it."""
        calls = [
            n
            for n in ast.walk(test.tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == local
        ]
        self._register(reached, function, test, calls)

    def _register(
        self, reached: Reached, function: str, test: Source, calls: List[ast.Call]
    ) -> None:
        script = reached.source
        if function not in script.functions:
            return
        reached.called.add(function)
        for call in calls:
            self.evaluator.external_sites.setdefault((script.rel, function), []).append(
                CallSite(test, call)
            )

    def reached_functions(self, reached: Reached) -> Set[str]:
        """The functions of a reached script that the tests can run, and
        ``<module>`` when its module-level code runs."""
        script = reached.source
        todo = set(reached.called)
        if reached.imported or reached.run_as_main:
            todo.add("<module>")
        done: Set[str] = set()
        while todo:
            name = todo.pop()
            if name in done:
                continue
            done.add(name)
            if name == "<module>":
                nodes = list(_module_level(script.tree, reached.run_as_main))
            else:
                nodes = [n for f in script.functions.get(name, []) for n in ast.walk(f)]
            for node in nodes:
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in script.functions
                ):
                    todo.add(node.func.id)
        return done

    def walks(self) -> Iterator[Walk]:
        for test in self.tests:
            yield from walks_in(self.evaluator, test)
        for reached in self.reached.values():
            functions = self.reached_functions(reached)
            for walk in walks_in(self.evaluator, reached.source):
                if walk.function in functions or (
                    "<module>" in functions and walk.function == "<module>"
                ):
                    yield walk

    def offenders(
        self, per_run: Optional[Tuple[PurePosixPath, ...]] = None
    ) -> Dict[Tuple[str, str, str], List[str]]:
        """``(file, function, receiver)`` -> why each such walk can enter a per-run dir.

        The receiver is the walked expression as written, so an exemption names one
        walk rather than every walk in a function.
        """
        per_run = per_run if per_run is not None else per_run_dirs()
        found: Dict[Tuple[str, str, str], List[str]] = {}
        for walk in self.walks():
            why = verdict(self.evaluator, walk, per_run)
            if why:
                key = (
                    walk.source.rel.as_posix(),
                    walk.function,
                    ast.unparse(walk.receiver),
                )
                found.setdefault(key, []).append(f"{walk.where}: {why}")
        return found
