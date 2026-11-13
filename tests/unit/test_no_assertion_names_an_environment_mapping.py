# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No assertion puts an environment mapping, or values from one, where pytest
prints it.

pytest explains a failing ``assert`` by printing its operands, the receiver and
arguments of each call in it, and its message; a mock's ``assert_called_with``
prints the call it got. The root conftest redacts every environment value of
``MIN_REDACTED_LENGTH`` characters or more from each report that did not pass,
and from the live log, whatever printed it (``redact_environment_values`` and
``EnvironmentValuesRedacted`` in tests/utils/env_assertions.py;
tests/unit/test_failure_reports_redact_environment_values.py measures both).
This check is the cheap first line beside that backstop: it refuses, when a test
is written, the shapes that print values in plain sight, read from the
assertion's own text and the bindings of the scopes it is written in. It
follows no call, fixture, parameter, default, loop or lambda; what it does not
look for is left to the backstop (``_LEFT_TO_THE_BACKSTOP`` pins some).

The patterns it keeps, each a ``_PRINTS`` cell:

1. An environment mapping where an assertion prints it: ``os.environ`` or
   ``os.environb`` (through any name ``os`` is imported as, or ``environ`` /
   ``environb`` imported from ``os``, ``from os import *`` included), a
   ``NamesOnlyEnvironment(...)`` or ``checkout_env(...)``, a plain copy of one
   (2), an ``"env"`` item of anything (``x["env"]``, ``x.get("env")``, read as a
   recorded call's ``env``, a workflow step's ``env`` block too), or a name the
   scope binds to one. A named value's container is not printed
   (``os.environ["K"]``), nor a literal's item read by name (``{"K":
   os.environ.get("K")}``), but a ``.get``'s receiver is (``os.environ.get("K")
   == "x"`` prints it when K is unset).
2. A plain copy, written as one: ``dict``, ``collections.OrderedDict``,
   ``defaultdict``, ``Counter`` or ``UserDict`` given a mapping, ``**`` one, or
   an iterable of its items or values (3); ``.copy()`` of one other than a
   ``NamesOnlyEnvironment(...)``; ``{**...}``; a union with one (``|``, ``|=``);
   and a dict comprehension whose key or value reads a value (4).
3. An iterable of a mapping's items or values: ``.items()``, ``.values()``,
   ``list``, ``tuple``, ``sorted``, ``set``, ``frozenset`` or ``iter`` of one,
   ``zip`` with one, ``map`` or ``filter`` over one, a comprehension or a
   generator whose result reads a value (4), an item of one (``pairs[0]``), and
   a name the scope binds to one.
4. A comprehension's value targets: over an iterable of values each name its
   target binds, but the first of a two-name target over ``.items()``; over a
   mapping's names a result that reads the mapping (``[env[k] for k in env]``).
   So ``[k for k, v in os.environ.items()]`` keeps names and passes.
5. A string the test's code formats from a mapping or values: ``str``,
   ``repr``, ``format``, ``ascii``, ``json.dumps``, ``.format(...)``, ``%`` or an
   f-string field, bound to a name the assertion reads.
6. A mock assertion written with an ``env=`` argument: its message prints the
   call the mock got, its whole ``env`` with it.

Where an assertion prints: its test and message, but not inside a lambda or a
generator expression (shown by its repr), an ``IfExp``'s condition (shown by
the chosen branch), the left of ``... is not None`` (it failed only if None),
and not the arguments of a call that gives names (``set``, ``frozenset``,
``sorted``, ``list``, ``len``) when they hold no copy or values: a mapping whose
repr shows names only passes there (``"K" in set(os.environ)``). A comparison
pytest explains by the two values alone, both sides lists or tuples, both sets,
both dicts or both text (literals, and calls that give names:
``differing_names``, ``environ_names``), prints its literals' items only.

A name is read as Python resolves it in the scope the assertion is in: the
scope's own bindings (``=``, an annotated ``=``, ``:=``, ``|=``) when it binds
the name, else the enclosing function's, else the module's; a method skips the
class body. Any binding to a copy or to values makes a name one; it is
names-only when every binding gives a mapping whose repr shows names only. A
binding the source does not show (a parameter, a loop target, an import)
decides nothing, so such a name is not read.

Assert on names or named values instead: ``env["K"]``, ``environ_names``,
``environ_value`` and ``differing_names`` from tests/utils/env_assertions.py, or
a local narrowed first. test_environment_assertions_print_no_values.py measures
which shapes print, with and without the backstop.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
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

import pytest

from tests.utils.helpers import iter_repo_files

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "tests"

_MOCK_ASSERTS = frozenset(
    {
        "assert_called_with",
        "assert_called_once_with",
        "assert_any_call",
        "assert_has_calls",
    }
)
#: Calls that give a mapping's names, or their count: their argument is
#: printed only when it holds a copy or values.
_NAMES_ONLY = frozenset({"set", "frozenset", "sorted", "list", "len"})
_SEQUENCE_OF_NAMES = frozenset({"sorted", "list"})
_SET_OF_NAMES = frozenset({"set", "frozenset"})
#: Calls that give a mapping whose repr shows names only
#: (tests/utils/env_assertions.py's NamesOnlyEnvironment).
_NAMES_ONLY_REPR = frozenset({"checkout_env", "NamesOnlyEnvironment"})
#: dict and collections' mapping types, by the position of the mapping or
#: iterable of pairs each is built from (defaultdict's factory comes first).
_COPYING_CONSTRUCTORS = {
    "dict": 0,
    "OrderedDict": 0,
    "Counter": 0,
    "UserDict": 0,
    "defaultdict": 1,
}
#: Calls that give back the items of what they are given.
_KEEPING_ITEMS = frozenset({"list", "tuple", "sorted", "set", "frozenset", "iter"})
#: Calls that format their argument into text.
_FORMATTERS = frozenset({"str", "repr", "format", "ascii"})
_OS_ENVIRONS = frozenset({"environ", "environb"})
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

#: What a value is, as the checker reads it: os.environ (whose repr shows
#: names only, and whose ``.copy()`` is a plain dict), a NamesOnlyEnvironment
#: (whose ``.copy()`` keeps its type), a plain copy (whose repr shows values),
#: an iterable of a mapping's items (names, then values), any other iterable of
#: values, or text formatted from a mapping or values.
_NAMES_ONLY_MAPPING = "environ"
_NAMES_ONLY_ENVIRONMENT = "names-only-environment"
_COPY = "copy"
_ITEMS = "items"
_VALUES = "values"
_FORMATTED = "formatted"
#: The kinds whose repr shows values.
_SHOWS_VALUES = frozenset({_COPY, _ITEMS, _VALUES, _FORMATTED})
#: The mappings whose repr shows pytest's reporting names only.
_NAMES_ONLY_KINDS = frozenset({_NAMES_ONLY_MAPPING, _NAMES_ONLY_ENVIRONMENT})
#: The kinds that are mappings.
_MAPPINGS = _NAMES_ONLY_KINDS | {_COPY}


def _os_names(tree: ast.AST) -> Tuple[Set[str], Set[str]]:
    """The names a file binds to the os module (``os`` always), and those it
    binds to os.environ or os.environb by importing them from os."""
    module = {"os"}
    environ: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            module.update(
                alias.asname
                for alias in node.names
                if alias.name == "os" and alias.asname
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name == "*":
                    environ.update(_OS_ENVIRONS)
                elif alias.name in _OS_ENVIRONS:
                    environ.add(alias.asname or alias.name)
    return module, environ


@dataclass
class _Scope:
    """One scope's names, by the kinds of the values its bindings show."""

    node: ast.AST
    parent: Optional["_Scope"]
    bindings: Dict[str, List[Optional[ast.AST]]] = field(default_factory=dict)
    kinds: Dict[str, Optional[str]] = field(default_factory=dict)


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """The nodes of *scope*'s body that are its own: not those of a nested
    function, lambda or class, whose names are their own."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _bindings(scope: ast.AST) -> Dict[str, List[Optional[ast.AST]]]:
    """Each name *scope* binds, with each value it gets where the source shows
    one, None where it does not (a parameter, a loop target, an import)."""
    found: Dict[str, List[Optional[ast.AST]]] = {}

    def bind(target: ast.AST, value: Optional[ast.AST]) -> None:
        if isinstance(target, ast.Name):
            found.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                bind(element, None)
        elif isinstance(target, ast.Starred):
            bind(target.value, None)

    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *(a for a in (arguments.vararg, arguments.kwarg) if a is not None),
        ]:
            found.setdefault(argument.arg, []).append(None)
    for node in _own_nodes(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target, node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            # env |= os.environ: the name is its old value merged with this one.
            value = ast.BinOp(left=node.target, op=node.op, right=node.value)
            bind(node.target, value)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target, node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            if not isinstance(node, ast.comprehension):
                bind(node.target, None)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(item.optional_vars, None)
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                names = (
                    sorted(_OS_ENVIRONS)
                    if alias.name == "*"
                    else [alias.asname or alias.name]
                )
                for name in names:
                    # environ imported from os is os.environ.
                    found.setdefault(name, []).append(
                        ast.Attribute(value=ast.Name(id="os"), attr="environ")
                        if alias.name in _OS_ENVIRONS or alias.name == "*"
                        else None
                    )
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    name = alias.asname or alias.name.split(".")[0]
                    found.setdefault(name, []).append(None)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.setdefault(node.name, []).append(None)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            found.setdefault(node.name, []).append(None)
    return found


class _Reader:
    """What a node's value is, read in one scope: its kind (_NAMES_ONLY_MAPPING,
    _COPY, _ITEMS, _VALUES, _FORMATTED) or None."""

    def __init__(
        self,
        scope: _Scope,
        os_module: Set[str],
        environ: Set[str],
        targets: Optional[Dict[str, Optional[str]]] = None,
    ):
        self.scope = scope
        self.os_module = os_module
        self.environ = environ
        #: A comprehension's targets, by the kind of what each is bound to.
        self.targets = targets or {}

    def name_kind(self, name: str) -> Optional[str]:
        if name in self.targets:
            return self.targets[name]
        scope: Optional[_Scope] = self.scope
        while scope is not None:
            if name in scope.bindings:
                return scope.kinds.get(name)
            scope = scope.parent
        if name in self.environ:
            return _NAMES_ONLY_MAPPING
        return None

    def kind(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.NamedExpr):
            return self.kind(node.value)
        if isinstance(node, (ast.IfExp, ast.BoolOp)):
            return _strongest(
                self.kind(branch)
                for branch in (
                    [node.body, node.orelse]
                    if isinstance(node, ast.IfExp)
                    else node.values
                )
            )
        if isinstance(node, ast.Name):
            return self.name_kind(node.id)
        if isinstance(node, ast.Attribute):
            if (
                node.attr in _OS_ENVIRONS
                and isinstance(node.value, ast.Name)
                and node.value.id in self.os_module
            ):
                return _NAMES_ONLY_MAPPING
            return None
        if isinstance(node, ast.Subscript):
            if _is_env_key(node.slice):
                return _COPY
            if self.kind(node.value) in (_ITEMS, _VALUES):
                # An item of an iterable of values holds one.
                return _VALUES
            return None
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.BitOr) and (
                self.kind(node.left) in _MAPPINGS or self.kind(node.right) in _MAPPINGS
            ):
                return _COPY
            if (
                isinstance(node.op, ast.Mod)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and self.holds_any(node.right)
            ):
                return _FORMATTED
            return None
        if isinstance(node, ast.Dict):
            if any(
                key is None and self.kind(value) in _MAPPINGS
                for key, value in zip(node.keys, node.values)
            ):
                return _COPY
            if any(self.kind(value) in _SHOWS_VALUES for value in node.values):
                return _VALUES
            return None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            # A container of what shows values shows them.
            if any(self.kind(element) in _SHOWS_VALUES for element in node.elts):
                return _VALUES
            return None
        if isinstance(node, ast.JoinedStr):
            if any(
                isinstance(part, ast.FormattedValue) and self.holds_any(part.value)
                for part in node.values
            ):
                return _FORMATTED
            return None
        if isinstance(node, _COMPREHENSIONS):
            if self.comprehension_reads_values(node):
                return _COPY if isinstance(node, ast.DictComp) else _VALUES
            return None
        if isinstance(node, ast.Call):
            return self.call_kind(node)
        return None

    def call_kind(self, node: ast.Call) -> Optional[str]:
        func = node.func
        callee = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else None
        )
        if isinstance(func, ast.Attribute):
            receiver = self.kind(func.value)
            if func.attr == "copy" and not node.args:
                if receiver == _NAMES_ONLY_ENVIRONMENT:
                    # NamesOnlyEnvironment.copy keeps its type.
                    return _NAMES_ONLY_ENVIRONMENT
                return _COPY if receiver in _MAPPINGS else None
            if func.attr in ("items", "values") and not node.args:
                if receiver in _MAPPINGS:
                    return _ITEMS if func.attr == "items" else _VALUES
                return None
            if func.attr == "get" and node.args and _is_env_key(node.args[0]):
                return _COPY
            if func.attr == "format" and isinstance(func.value, ast.Constant):
                return _FORMATTED if self.any_argument_holds(node) else None
            if func.attr == "dumps" and self.any_argument_holds(node):
                return _FORMATTED
        if callee in _COPYING_CONSTRUCTORS:
            position = _COPYING_CONSTRUCTORS[callee]
            copied = node.args[position : position + 1]
            if any(
                self.kind(argument) in (_MAPPINGS | {_ITEMS, _VALUES})
                for argument in copied
            ) or any(
                keyword.arg is None and self.kind(keyword.value) in _MAPPINGS
                for keyword in node.keywords
            ):
                return _COPY
            return None
        if not isinstance(func, ast.Name):
            return None
        if func.id in _NAMES_ONLY_REPR:
            return _NAMES_ONLY_ENVIRONMENT
        if func.id in _FORMATTERS:
            return _FORMATTED if self.any_argument_holds(node) else None
        if not node.args:
            return None
        if func.id in _KEEPING_ITEMS:
            given = self.kind(node.args[0])
            return given if given in (_ITEMS, _VALUES) else None
        if func.id == "zip" and any(
            self.kind(argument) in (_ITEMS, _VALUES) for argument in node.args
        ):
            return _VALUES
        if func.id == "filter" and len(node.args) == 2:
            given = self.kind(node.args[1])
            return given if given in (_ITEMS, _VALUES) else None
        if func.id == "map" and any(
            self.kind(argument) in (_ITEMS, _VALUES) for argument in node.args[1:]
        ):
            return _VALUES
        return None

    def holds_any(self, node: ast.AST) -> bool:
        """Whether *node*, formatted by the test's code, holds a mapping or
        values: it is one, or a literal holding one. Code formatting a
        mapping whose repr shows names to pytest gets its values."""
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.holds_any(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.holds_any(value) for value in node.values) or (
                self.kind(node) is not None
            )
        return self.kind(node) is not None

    def any_argument_holds(self, node: ast.Call) -> bool:
        return any(
            self.holds_any(argument)
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]
        )

    def iterates_names(self, node: ast.AST) -> bool:
        """Whether iterating *node* gives a mapping's names: the mapping, its
        ``.keys()``, or a call of _NAMES_ONLY of those."""
        if self.kind(node) in _MAPPINGS:
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "keys"
            and not node.args
        ):
            return self.kind(node.func.value) in _MAPPINGS
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _NAMES_ONLY
            and len(node.args) == 1
            and self.iterates_names(node.args[0])
        )

    def mentions(self, node: ast.AST, kinds: FrozenSet[str] = _MAPPINGS) -> bool:
        """Whether *node*'s value reads one of *kinds*: an ``IfExp``'s
        condition, a lambda and a generator are not its value."""
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, (ast.Lambda, ast.GeneratorExp)):
                continue
            if self.kind(current) in kinds:
                return True
            if isinstance(current, ast.IfExp):
                stack.extend([current.body, current.orelse])
            else:
                stack.extend(ast.iter_child_nodes(current))
        return False

    def comprehension_reads_values(
        self, node: Union[ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp]
    ) -> bool:
        """Whether a comprehension's result holds a value (pattern 4): its
        result is read with each target bound to what iterating gives, a
        value, or a name for the first of a two-name target over
        ``.items()``; over a mapping's names, a result that reads the mapping
        holds every value."""
        targets: Dict[str, Optional[str]] = dict(self.targets)
        over_names = False
        for generator in node.generators:
            iterable = generator.iter
            target = generator.target
            names_bound = [
                sub.id for sub in ast.walk(target) if isinstance(sub, ast.Name)
            ]
            if self.iterates_names(iterable):
                over_names = True
                targets.update(dict.fromkeys(names_bound))
                continue
            given = self.kind(iterable)
            if given not in (_ITEMS, _VALUES):
                targets.update(dict.fromkeys(names_bound))
                continue
            targets.update(dict.fromkeys(names_bound, _VALUES))
            if (
                given == _ITEMS
                and isinstance(target, ast.Tuple)
                and len(target.elts) == 2
                and isinstance(target.elts[0], ast.Name)
            ):
                targets[target.elts[0].id] = None
        reader = _Reader(self.scope, self.os_module, self.environ, targets)
        results = (
            [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        )
        for result in results:
            if reader.kind(result) in _SHOWS_VALUES:
                return True
            if over_names and reader.mentions(result):
                # A value read by each name is every value.
                return True
        return False

    def gives_names(self, node: ast.AST) -> Optional[str]:
        """``"sequence"`` or ``"set"`` when *node* is a call that gives a
        mapping's names as a list or a set."""
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return None
        if node.keywords:
            return None
        if node.func.id == "differing_names":
            return "sequence"
        if node.func.id == "environ_names" and not node.args:
            return "set"
        if len(node.args) == 1 and self.iterates_names(node.args[0]):
            if node.func.id in _SEQUENCE_OF_NAMES:
                return "sequence"
            if node.func.id in _SET_OF_NAMES:
                return "set"
        return None


def _strongest(kinds: Iterable[Optional[str]]) -> Optional[str]:
    """The kind a value that is one of several has: one that shows values if
    any does; a NamesOnlyEnvironment only if every one is; otherwise
    os.environ's, whose copy is plain, if any is a names-only mapping."""
    found = [kind for kind in kinds if kind is not None]
    for kind in (_FORMATTED, _COPY, _VALUES, _ITEMS):
        if kind in found:
            return kind
    if found and all(kind == _NAMES_ONLY_ENVIRONMENT for kind in found):
        return _NAMES_ONLY_ENVIRONMENT
    return _NAMES_ONLY_MAPPING if found else None


def _is_env_key(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value == "env"


def _literal_kind(node: ast.AST) -> Optional[str]:
    """The kind of value a literal is, as pytest's ``==`` explanation groups
    them: ``"sequence"``, ``"set"``, ``"dict"`` or ``"text"``."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return "sequence"
    if isinstance(node, ast.Set):
        return "set"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _SET_OF_NAMES
        and not node.args
        and not node.keywords
    ):
        return "set"
    if isinstance(node, ast.Dict):
        return "dict"
    if isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))
    ):
        return "text"
    return None


def _literal_items(node: ast.AST) -> List[ast.AST]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    if isinstance(node, ast.Dict):
        return [item for item in [*node.keys, *node.values] if item is not None]
    if isinstance(node, ast.JoinedStr):
        return [
            part.value for part in node.values if isinstance(part, ast.FormattedValue)
        ]
    return []


class _Checker:
    """The refusals of one file, scope by scope."""

    def __init__(self, tree: ast.Module) -> None:
        self.os_module, self.environ = _os_names(tree)
        self.found: List[str] = []
        self.visit(tree, None)

    def visit(self, node: ast.AST, parent: Optional[_Scope]) -> None:
        scope = _Scope(node=node, parent=parent, bindings=_bindings(node))
        self.settle(scope)
        reader = _Reader(scope, self.os_module, self.environ)
        for own in _own_nodes(node):
            if isinstance(own, ast.Assert):
                self.refuse_assertion(own, reader)
            elif isinstance(own, ast.Call):
                self.refuse_mock_env(own)
            if isinstance(own, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                # A function skips an enclosing class body's names.
                enclosing: Optional[_Scope] = scope
                while enclosing is not None and isinstance(
                    enclosing.node, ast.ClassDef
                ):
                    enclosing = enclosing.parent
                self.visit(own, enclosing)
            elif isinstance(own, ast.ClassDef):
                self.visit(own, scope)

    def settle(self, scope: _Scope) -> None:
        """Each name's kind from its bindings: one that shows values if any
        binding gives one, names-only when every binding gives a names-only
        mapping, none when a binding is not shown."""
        reader = _Reader(scope, self.os_module, self.environ)
        for _ in range(len(scope.bindings) + 1):
            settled: Dict[str, Optional[str]] = {}
            for name, values in scope.bindings.items():
                kinds = [
                    None if value is None else reader.kind(value) for value in values
                ]
                showing = [kind for kind in kinds if kind in _SHOWS_VALUES]
                if showing:
                    settled[name] = _strongest(iter(showing))
                    if all(kind == _ITEMS for kind in kinds):
                        settled[name] = _ITEMS
                    elif _ITEMS in showing and settled[name] == _ITEMS:
                        settled[name] = _VALUES
                elif kinds and all(kind in _NAMES_ONLY_KINDS for kind in kinds):
                    settled[name] = _strongest(kinds)
                else:
                    settled[name] = None
            if settled == scope.kinds:
                return
            scope.kinds = settled

    def hit(self, node: ast.AST, what: str) -> None:
        self.found.append(f"{getattr(node, 'lineno', 0)} {what}")

    def refuse_mock_env(self, node: ast.Call) -> None:
        if not (
            isinstance(node.func, ast.Attribute) and node.func.attr in _MOCK_ASSERTS
        ):
            return
        written = [node] + [sub for sub in ast.walk(node) if isinstance(sub, ast.Call)]
        if any(keyword.arg == "env" for call in written for keyword in call.keywords):
            self.hit(node, f"{node.func.attr} given env=")

    def refuse_assertion(self, node: ast.Assert, reader: _Reader) -> None:
        """Refuse what pytest prints of a failing *node* that is a mapping or
        values: each value _shown names, and the message, shown whole."""
        for shown, in_names in _shown(node.test, reader, top=True):
            self.refuse_value(shown, reader, in_names)
        if node.msg is not None:
            self.refuse_value(node.msg, reader, False)

    def refuse_value(self, node: ast.AST, reader: _Reader, in_names: bool) -> None:
        kind = reader.kind(node)
        if kind in _SHOWS_VALUES or (kind in _NAMES_ONLY_KINDS and not in_names):
            self.hit(node, f"{_DESCRIBED[kind]} in an assertion")


def _names_call(node: ast.AST) -> bool:
    """Whether *node* is a call that gives a mapping's names or their count."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _NAMES_ONLY
        and len(node.args) == 1
        and all(keyword.arg in ("key", "reverse") for keyword in node.keywords)
    )


def _shown(
    node: ast.AST, reader: _Reader, top: bool = False, in_names: bool = False
) -> Iterator[Tuple[ast.AST, bool]]:
    """The parts of *node* whose value pytest shows when the assertion fails,
    each with whether it is the argument of a call that gives names, as
    pytest's assertion rewriter explains them: a name, an attribute or a
    call by its value, with a call's receiver and arguments and an
    attribute's object; a comparison by each operand's value; a ``BinOp``,
    ``BoolOp`` or ``UnaryOp`` by its operands; anything else (a literal, a
    subscript, an ``IfExp``, a comprehension, an f-string) by its value
    alone, and a lambda or a generator expression by a repr that holds none.
    The test itself is shown only when falsy (*top*), which holds no value.
    A comparison pytest explains by the two values alone (both sides lists or
    tuples, both sets, both dicts or both text: literals, and calls that give
    names) shows those values only, and the left of ``... is not None`` is
    shown only when it is None."""
    if isinstance(node, (ast.Lambda, ast.GeneratorExp)):
        return
    if isinstance(node, ast.Compare):
        if (
            len(node.ops) == 1
            and isinstance(node.ops[0], ast.IsNot)
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value is None
        ):
            return
        sides = [node.left, *node.comparators]
        if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            kinds = [_literal_kind(side) or reader.gives_names(side) for side in sides]
            if (
                kinds[0] is not None
                and kinds[0] == kinds[1]
                and any(_literal_kind(side) for side in sides)
            ):
                for side in sides:
                    if _literal_kind(side):
                        yield side, False
                return
        for side in sides:
            yield from _shown(side, reader)
        return
    if isinstance(node, ast.BoolOp):
        for operand in node.values:
            yield from _shown(operand, reader, in_names=in_names)
        return
    if isinstance(node, ast.BinOp):
        yield from _shown(node.left, reader, in_names=in_names)
        yield from _shown(node.right, reader, in_names=in_names)
        return
    if isinstance(node, ast.UnaryOp):
        yield from _shown(node.operand, reader, in_names=in_names)
        return
    if not top:
        yield node, in_names
    # Inside the argument of a call that gives names, a names-only mapping
    # is shown by its names-only repr at any depth.
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            yield from _shown(node.func.value, reader, in_names=in_names)
        given_names = in_names or _names_call(node)
        for argument in node.args:
            yield from _shown(argument, reader, in_names=given_names)
        for keyword in node.keywords:
            yield from _shown(keyword.value, reader, in_names=in_names)
    elif isinstance(node, ast.Attribute):
        yield from _shown(node.value, reader, in_names=in_names)


_DESCRIBED = {
    _NAMES_ONLY_ENVIRONMENT: "a names-only environment mapping",
    _NAMES_ONLY_MAPPING: "an environment mapping",
    _COPY: "a plain copy of an environment mapping",
    _ITEMS: "an iterable of an environment's items",
    _VALUES: "environment values",
    _FORMATTED: "text formatted from an environment mapping",
}


def findings(source: str) -> List[str]:
    """Each place in *source* where a failure would print an environment
    mapping or values from one, as ``<line> <what>``."""
    return _Checker(ast.parse(source)).found


def _test_files() -> List[Path]:
    return sorted(
        path
        for path in iter_repo_files(TESTS, skip_dirs=frozenset({"__pycache__"}))
        if path.suffix == ".py"
    )


def test_no_test_file_asserts_on_an_environment_mapping() -> None:
    found = []
    for path in _test_files():
        for finding in findings(path.read_text(encoding="utf-8")):
            found.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{finding}")
    assert found == [], (
        "these print the environment when they fail; assert on names or "
        "named values (tests/utils/env_assertions.py): " + "; ".join(found)
    )


def test_the_check_reads_the_test_files() -> None:
    """The control for the sweep above: it walked the tree and parsed files."""
    files = _test_files()
    assert len(files) > 100
    assert Path(__file__).resolve() in {path.resolve() for path in files}


def _cell(body: str, header: str = "import os\n") -> str:
    return header + "def test_x(ok, run, captured, kw, a, b):\n" + body


#: Each kept pattern, as a test writes it: each is refused.
_PRINTS = {
    # 1. An environment mapping where an assertion prints it.
    "the-environment-compared": _cell("    assert os.environ == {}\n"),
    "a-membership-in-the-environment": _cell("    assert 'K' in os.environ\n"),
    "a-named-get-compared": _cell("    assert os.environ.get('K') == 'x'\n"),
    "the-environment-in-the-message": _cell("    assert ok, os.environ\n"),
    "an-f-string-message": _cell("    assert ok, f'{os.environ}'\n"),
    "a-percent-format-message": _cell("    assert ok, '%s' % (os.environ,)\n"),
    "a-format-method-message": _cell("    assert ok, '{}'.format(os.environ)\n"),
    "a-formatted-environment": _cell("    assert 'x' in str(os.environ)\n"),
    "a-names-only-environment-compared": _cell(
        "    assert NamesOnlyEnvironment(os.environ) == {}\n",
        "import os\nfrom tests.utils.env_assertions import NamesOnlyEnvironment\n",
    ),
    "checkout-env-compared": _cell(
        "    assert checkout_env({}) == {}\n",
        "from tests.utils.helpers import checkout_env\n",
    ),
    "an-alias-of-the-environment-compared": _cell(
        "    alias = os.environ\n    assert alias == {}\n"
    ),
    "a-recorded-calls-env": _cell("    assert captured[0]['env'] == {}\n"),
    "a-recorded-env-by-get": _cell("    assert kw.get('env') == {}\n"),
    "an-environ-imported-from-os": _cell(
        "    assert dict(environ) == {}\n", "from os import environ\n"
    ),
    "a-star-import-of-os": _cell(
        "    assert dict(environ) == {}\n", "from os import *\n"
    ),
    "an-os-module-alias": _cell(
        "    assert o.environ.copy() == {}\n", "import os as o\n"
    ),
    "os-environb": _cell("    assert dict(os.environb) == {}\n"),
    # 2. A plain copy.
    "a-plain-copy-compared": _cell("    assert dict(os.environ) == {}\n"),
    "a-copy-method-compared": _cell("    assert os.environ.copy() == {}\n"),
    "a-splat-copy": _cell("    assert {**os.environ} == {}\n"),
    "a-union-with-the-environment": _cell("    assert (os.environ | {}) == {}\n"),
    "an-ordered-dict-copy": _cell(
        "    assert collections.OrderedDict(os.environ) == {}\n",
        "import collections\nimport os\n",
    ),
    "a-defaultdict-copy": _cell(
        "    assert defaultdict(str, os.environ) == {}\n",
        "import os\nfrom collections import defaultdict\n",
    ),
    "a-copy-by-keywords": _cell("    assert dict(**os.environ) == {}\n"),
    "a-copy-of-its-items": _cell("    assert dict(os.environ.items()) == {}\n"),
    "a-copy-of-its-sorted-items": _cell(
        "    assert dict(sorted(os.environ.items())) == {}\n"
    ),
    "a-copy-of-names-zipped-with-values": _cell(
        "    assert dict(zip(os.environ, os.environ.values())) == {}\n"
    ),
    "a-dict-comprehension-of-its-items": _cell(
        "    assert {k: v for k, v in os.environ.items()} == {}\n"
    ),
    "a-dict-comprehension-reading-each-value": _cell(
        "    assert {k: os.environ[k] for k in os.environ} == {}\n"
    ),
    "a-copys-get-compared": _cell("    assert dict(os.environ).get('K') == 'x'\n"),
    "the-length-of-a-copy": _cell("    assert len(dict(os.environ)) == 0\n"),
    "a-set-of-a-copy": _cell("    assert 'K' in set(dict(os.environ))\n"),
    "a-copy-in-a-literal": _cell("    assert [dict(os.environ)] == []\n"),
    "a-json-dump-of-a-copy": _cell(
        "    assert 'x' in json.dumps(dict(os.environ))\n", "import json\nimport os\n"
    ),
    # 3. Values, and 4. comprehensions reading them.
    "its-values-sorted": _cell("    assert sorted(os.environ.values()) == []\n"),
    "its-items-listed": _cell("    assert list(os.environ.items()) == []\n"),
    "a-comprehension-of-its-values": _cell(
        "    assert [v for k, v in os.environ.items()] == []\n"
    ),
    "a-generator-of-its-values-sorted": _cell(
        "    assert sorted(v for v in os.environ.values()) == []\n"
    ),
    "a-comprehension-reading-each-value": _cell(
        "    assert [os.environ[k] for k in os.environ] == []\n"
    ),
    # Bindings of the scope the assertion is in.
    "a-copy-bound-in-the-function": _cell(
        "    env = dict(os.environ)\n    assert env == {}\n"
    ),
    "a-copy-bound-through-another-name": _cell(
        "    first = dict(os.environ)\n    second = first\n    assert second == {}\n"
    ),
    "a-copy-bound-by-a-walrus": _cell("    assert (e := dict(os.environ)) == {}\n"),
    "a-copy-bound-at-module-level": (
        "import os\nCOPY = dict(os.environ)\ndef test_x():\n    assert COPY == {}\n"
    ),
    "a-union-in-place": _cell(
        "    env = {}\n    env |= os.environ\n    assert env == {}\n"
    ),
    "a-names-call-of-a-bound-copy": _cell(
        "    copy = dict(os.environ)\n    assert 'K' in set(copy)\n"
    ),
    "an-iterable-of-items-through-a-name": _cell(
        "    pairs = sorted(os.environ.items())\n    assert pairs == []\n"
    ),
    "an-item-of-an-iterable-of-items": _cell(
        "    pairs = sorted(os.environ.items())\n    assert pairs[0] == ('K', 'x')\n"
    ),
    "the-values-of-items-through-a-name": _cell(
        "    pairs = sorted(os.environ.items())\n"
        "    assert [v for k, v in pairs] == []\n"
    ),
    "the-first-of-pairs-that-are-not-all-items": _cell(
        "    pairs = sorted(os.environ.items())\n"
        "    pairs = list(zip(os.environ.values(), os.environ.values()))\n"
        "    assert [k for k, v in pairs] == []\n"
    ),
    "a-string-formatted-from-the-environment": _cell(
        "    text = str(os.environ)\n    assert 'x' in text\n"
    ),
    "a-copy-in-a-method": (
        "import os\nclass TestX:\n    def test_x(self):\n"
        "        env = dict(os.environ)\n        assert env == {}\n"
    ),
    # 6. A mock assertion written with env=.
    "a-mock-assertion-with-env": _cell(
        "    run.assert_called_once_with(['x'], env={})\n"
    ),
    "a-mock-has-calls-with-env": _cell(
        "    run.assert_has_calls([call(['x'], env={})])\n",
        "from unittest.mock import call\n",
    ),
}


@pytest.mark.parametrize("shape", sorted(_PRINTS))
def test_the_check_finds_each_shape_that_prints_the_environment(shape: str) -> None:
    assert findings(_PRINTS[shape]), shape


#: Shapes that print no value, each passing: names, named values, a copy where
#: pytest does not print it, and comprehensions that keep only names.
_PRINTS_NO_VALUE = {
    "a-name-in-a-set-of-the-environment": _cell("    assert 'K' in set(os.environ)\n"),
    "a-set-of-its-keys": _cell("    assert 'K' in set(os.environ.keys())\n"),
    "its-length": _cell("    assert len(os.environ) > 0\n"),
    "sorted-names-compared": _cell("    assert sorted(os.environ) == []\n"),
    "a-named-value": _cell("    assert os.environ['K'] == 'x'\n"),
    "a-copys-named-value": _cell("    assert dict(os.environ)['K'] == 'x'\n"),
    "a-named-get-in-a-literal": _cell("    assert {'K': os.environ.get('K')} == {}\n"),
    "environ-names-compared": _cell(
        "    assert environ_names() == set()\n",
        "from tests.utils.env_assertions import environ_names\n",
    ),
    "environ-value-compared": _cell(
        "    assert environ_value('K') == 'x'\n",
        "from tests.utils.env_assertions import environ_value\n",
    ),
    "differing-names-of-copies": _cell(
        "    assert differing_names(dict(os.environ), {}) == []\n",
        "import os\nfrom tests.utils.env_assertions import differing_names\n",
    ),
    "a-copy-on-the-left-of-is-not-none": _cell(
        "    assert dict(os.environ) is not None\n"
    ),
    "a-copy-in-an-ifexp-condition": _cell(
        "    assert (a if dict(os.environ) else b)\n"
    ),
    "a-copy-in-a-lambda": _cell("    assert (lambda: dict(os.environ))\n"),
    "a-generator-of-values-in-any": _cell(
        "    assert any(v for v in os.environ.values())\n"
    ),
    "names-of-items": _cell("    assert [k for k, v in os.environ.items()] == []\n"),
    "names-of-items-through-a-name": _cell(
        "    pairs = sorted(os.environ.items())\n"
        "    names = [k for k, v in pairs]\n    assert names == []\n"
    ),
    "a-set-of-names-of-items-through-a-name": _cell(
        "    pairs = sorted(os.environ.items())\n"
        "    assert {k for k, _ in pairs} == set()\n"
    ),
    "a-dict-comprehension-of-names-of-items-through-a-name": _cell(
        "    pairs = sorted(os.environ.items())\n"
        "    flags = {k: 1 for k, v in pairs}\n    assert 'K' in set(flags)\n"
    ),
    "a-dict-comprehension-of-names": _cell(
        "    assert {k: 1 for k in os.environ} == {}\n"
    ),
    "a-names-only-environment-in-a-set": _cell(
        "    assert 'K' in set(NamesOnlyEnvironment(os.environ))\n",
        "import os\nfrom tests.utils.env_assertions import NamesOnlyEnvironment\n",
    ),
    "an-alias-in-a-set": _cell(
        "    alias = os.environ\n    assert 'K' in set(alias)\n"
    ),
    "a-names-only-copy-in-a-set": _cell(
        "    env = NamesOnlyEnvironment(os.environ).copy()\n    assert 'K' in set(env)\n",
        "import os\nfrom tests.utils.env_assertions import NamesOnlyEnvironment\n",
    ),
    "a-mock-assertion-without-env": _cell("    run.assert_called_once_with(['x'])\n"),
    "a-module-copy-a-parameter-shadows": (
        "import os\nenv = dict(os.environ)\ndef test_x(env):\n    assert env == {}\n"
    ),
    "a-module-copy-the-function-rebinds": (
        "import os\nenv = dict(os.environ)\ndef test_x():\n"
        "    env = {'K': 'x'}\n    assert env == {}\n"
    ),
    "a-literal-copied": _cell("    assert dict({'K': 'x'}) == {}\n"),
    "a-literals-items": _cell("    assert list({'K': 'x'}.items()) == []\n"),
    "an-attribute-named-environ-of-another-object": _cell(
        "    assert ok.environ == {}\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(_PRINTS_NO_VALUE))
def test_control_a_shape_that_prints_no_value_passes(shape: str) -> None:
    assert findings(_PRINTS_NO_VALUE[shape]) == [], shape


#: Shapes that print the environment's values and that this check does not look
#: for, since it follows no call, fixture, parameter, loop or lambda: the
#: backstop redacts what they print. Pinned as passing, so a change that starts
#: refusing one is seen, and the module docstring's patterns updated with it.
_LEFT_TO_THE_BACKSTOP = {
    "a-copy-a-helper-returns": (
        "import os\ndef _env():\n    return dict(os.environ)\n"
        "def test_x():\n    assert _env() == {}\n"
    ),
    "a-copy-a-fixture-gives": (
        "import os, pytest\n@pytest.fixture\ndef env():\n    return dict(os.environ)\n"
        "def test_x(env):\n    assert env == {}\n"
    ),
    "a-copy-bound-by-a-loop": (
        "import os\ndef test_x():\n    for env in [dict(os.environ)]:\n"
        "        assert env == {}\n"
    ),
    "a-copy-a-lambda-returns": (
        "import os\n_env = lambda: dict(os.environ)\ndef test_x():\n"
        "    assert _env() == {}\n"
    ),
    "a-copy-handed-to-a-helper-as-a-frames-argument": (
        "import os\ndef _check(env):\n    assert env == {}\n"
        "def test_x():\n    _check(dict(os.environ))\n"
    ),
    "a-copy-a-mock-assertion-is-given": (
        "import os\ndef test_x(run):\n    run.assert_called_once_with(dict(os.environ))\n"
    ),
    "a-copy-a-unittest-assertion-is-given": (
        "import os, unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n"
        "        self.assertEqual(dict(os.environ), {})\n"
    ),
}


def test_what_the_check_leaves_to_the_backstop_passes() -> None:
    """The shapes this check does not look for pass it: the backstop, not
    this check, keeps their values out of a failure's report."""
    refused = [
        shape for shape, source in _LEFT_TO_THE_BACKSTOP.items() if findings(source)
    ]
    assert refused == [], (
        "the check now refuses a shape left to the backstop: name it among the "
        "module docstring's patterns and move it to _PRINTS"
    )
