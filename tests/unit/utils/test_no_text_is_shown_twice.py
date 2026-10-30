# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No text a call site has shown already is handed to a sink that shows it again.

The log sinks (the console handler, the live panel, ash.log, the stand-in for
logging's last resort), utils/console.py's echo, secho, prompt and confirm, and
escape_markup each show the text they are given: controls as escapes, CI commands
broken, and a run of backslashes before text that reads as an escape doubled.
Text that went through an escaper first and is then put into a plain message is
shown a second time, and the doubling makes each escape in it read as the text of
one: a name holding ESC and a newline logged as "a\\\\x1b[2Kb\\\\x0a" where
"a\\x1b[2Kb\\x0a" was meant. The one-pass form is the whole message, with raw
values, as one shown_not_obeyed or shown_on_one_line call (utils/terminal_text.py),
which the sinks pass on as it is.

What counts is worked out from the source, which the check reads and does not
import, starting from terminal_text's escapers:

- Shown text is what an escaper returns, or a function of the package that returns
  shown text (shown_shard_text, merge's _shown, a message builder), found to a
  fixpoint and keyed by module and name, so a function rewritten to return its
  values raw stops counting.
- A doubling sink is a log method (on a receiver whose name says "log", on a call
  of getLogger, get_logger, LoggerAdapter or getChild, or on a name the module
  binds to a logger: by such a call, by importing a name that says "log" under
  another, or by an assignment, walrus or tuple element of a logger), called on it
  or through a name or walrus bound to it (``lg = L.warning; lg(x)``,
  ``(m := L.info)(x)``), an escaper that doubles backslashes
  (shown_not_obeyed, shown_on_one_line, controls_shown), or a function of the
  package that passes an argument to a doubling sink (echo, escape_markup,
  shown_shard_text), for the positional arguments bound to a parameter that
  reaches one: a sender that calls the callable it is handed and logs only its
  label shows nothing twice, and neither does a cache that stores the result
  under a key and logs only the key (a container stored into is followed, its
  index is not). raw_controls_shown and only_controls_shown, terminal_text's
  rule for text whose values are shown already, double nothing, and neither does a
  wrapper over them.
- Within a function, locals are followed in line order, so a name rebound to raw
  text is raw again. A handler's variable is shown when the handler catches an
  exception class the package defines that some site raises with shown text,
  wherever that site is; or a kind the package does not define (a builtin, a
  library's) that the handler's try body raises with shown text, or reaches by
  calling a function of the package that does, up to _REACH_DEPTH calls down. One
  ``raise ValueError(<shown>)`` therefore makes no ``except ValueError`` elsewhere
  a handler of shown text. A name read only as ``type(x)`` or ``x.__class__`` is a
  class, not the value: it makes nothing shown.

Refused: a doubling sink given shown text. Allowed: the one-pass form (a log
call's whole message one shown_not_obeyed or shown_on_one_line call), the values
of a MARKUP log message escaped with escape_markup, and raise sites (a handler
that prints the message as Text shows it once). Rich's print is no sink: it adds
no pass, only the stream's CI-command check.

_OPEN lists the sites still waiting on their fix, each by file, function and a
fragment of the call's text, with the owner. The test fails on any site not
listed, and on a row that no longer matches exactly one offender: a fix removes
its row in the same commit.

Not seen: text that reaches a sink through an attribute (``self.text =
shown_not_obeyed(v)`` in one method, logged in another), a container, another
function's argument or a return value of a function outside the package; an
exception of a builtin or library kind that reaches its handler through a call the
check cannot resolve (a method of an object) or through more than _REACH_DEPTH
calls of the package; a local assigned, inside the handler, from the handler's
variable (the assignments are read before the handlers, so the local is not shown
text and is logged unflagged); a logger or a log method handed in as an argument,
kept in an attribute or a container, or returned by a function that is no maker; a
log method wrapped (functools.partial) or looked up by getattr; repr() and ascii()
of a value; and the TUI's widgets (cli/inspect), which have their own guard.
terminal_text itself is not read: its public functions and classes, and each of
its names that reaches an escaper or the maker (a private composer, an alias, a
lambda), must be in DOUBLING or NOT_DOUBLING, or show nothing (checked below), so
a new escaper there is counted.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pytest

from tests.unit.walked_package import package_sources

pytestmark = pytest.mark.unit

#: The package's own source, beside this test.
_PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

#: The module of the escapers, which composes them.
_TERMINAL_TEXT = "automated_security_helper/utils/terminal_text.py"

#: terminal_text's escapers that double a run of backslashes before text that
#: reads as an escape: given shown text, they show it again.
DOUBLING = frozenset({"shown_not_obeyed", "shown_on_one_line", "controls_shown"})

#: Escapers whose result is shown text, but which show nothing twice: the rule
#: for text whose values are shown already, keeping its lines or on one line (an
#: MCP tool's error), JSON's escapes, the command breakers,
#: the regex callbacks that write a matched character's escape (_layout_shown,
#: _outside_ascii_shown), and shown_in_ascii, which puts text shown already in
#: ASCII for the Windows log filter. controls_escaped is sandbox_grants' own, read
#: by name since it escapes with ascii(), which the check does not follow.
NOT_DOUBLING = frozenset(
    {
        "raw_controls_shown",
        "raw_controls_on_one_line",
        "only_controls_shown",
        "json_controls_shown",
        "commands_broken",
        "hash_command_broken",
        "escape_for",
        "_layout_shown",
        "_outside_ascii_shown",
        "controls_escaped",
        "shown_in_ascii",
    }
)

#: The whole message as one of these, with nothing else passed, is the one-pass form.
ONE_PASS = frozenset({"shown_not_obeyed", "shown_on_one_line"})

LOG_METHODS = frozenset(
    {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "exception",
        "critical",
        "verbose",
        "trace",
        "log",
    }
)

#: Calls that make a logger: a name bound to one is a log receiver.
_LOGGER_MAKERS = frozenset({"getLogger", "get_logger", "LoggerAdapter", "getChild"})

Site = Tuple[str, str, str]
Function = Tuple[str, str]

#: How many calls below a try body's own calls a raise of shown text may sit and
#: still count for its handler: the body calls a function of the package (depth 0),
#: which calls another (1), and so on up to this many levels. Past it the raise is
#: not seen, which is the cost of not counting every handler of a kind as shown.
_REACH_DEPTH = 3

#: The open sites, each (file, function, a fragment of the sink call's text) ->
#: the part of ASH whose fix it waits on. A row matches the one offending call in
#: that function whose text holds the fragment. The change that fixes one removes
#: its row in the same commit.
_OPEN: Dict[Site, str] = {}

#: Sites the check cannot tell are one pass, each with why it is. Matched and
#: kept current like _OPEN.
_BY_DESIGN: Dict[Site, str] = {
    # An MCP error response's "error" is shown text (create_error_response), and
    # the check takes a call whose result holds one for shown text whole. Each of
    # these reads another part of such a result, which is raw.
    (
        "automated_security_helper/cli/mcp_server.py",
        "run_ash_scan",
        "committed_entries_in_the_way(output_dir)",
    ): "output_dir is built from the resolved target's path, not its error response",
    (
        "automated_security_helper/cli/mcp_server.py",
        "run_ash_scan",
        "monitor_scan_progress(ctx, scan_id",
    ): "scan_id is the id the started scan returned, not its error response",
    (
        "automated_security_helper/core/resource_management/scan_management.py",
        "cleanup_scan_resources",
        "Failed to cancel scan",
    ): "it logs the cancel result's message, which is raw; only its error is shown",
    # get_scan_results returns the producer's result as it is when it carries an
    # error (`if "error" in results or results.get("success") is False: return
    # results`, the guard right after the mcp_get_scan_results(...) call), so the
    # two calls below run only on a success payload, which holds the scan's
    # findings and no shown text. `results` reads as shown text to the check only
    # because mcp_get_scan_results is a producer (its error response holds shown
    # text), and the two calls sit in the check's doubling set through a callee.
    (
        "automated_security_helper/cli/mcp_server.py",
        "get_scan_results",
        "filter_actionable_only(results)",
    ): "by design: no shown text reaches the filter, the guard after the producer "
    "call returns an error-holding result first",
    (
        "automated_security_helper/cli/mcp_server.py",
        "get_scan_results",
        "apply_content_filters(results, scanners, severities)",
    ): "by design: no shown text reaches the filter, the guard after the producer "
    "call returns an error-holding result first",
}


def _name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _Module:
    def __init__(self, path: str, tree: ast.Module, module_paths: Dict[str, str]):
        self.path = path
        self.tree = tree
        self.defs = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        self.imported: Dict[str, Function] = {}
        self.modules: Dict[str, str] = {}
        # Names a logger is bound to, whatever they say: a log call on one is a
        # sink as on a receiver whose name says "log". A name is bound to one by
        # a call of a maker, an import of a name that says "log" under another
        # name, or an assignment, walrus or tuple element whose value is a logger
        # (a maker's call, a name that says "log", or a name bound to one), to a
        # fixpoint. A maker imported under another name is a maker.
        self.makers: Set[str] = set(_LOGGER_MAKERS)
        self.loggers: Set[str] = set()
        pairs: List[Tuple[ast.AST, ast.AST]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if not alias.asname:
                        continue
                    if alias.name.rsplit(".", 1)[-1] in _LOGGER_MAKERS:
                        self.makers.add(alias.asname)
                    elif "log" in alias.name.lower():
                        self.loggers.add(alias.asname)
            targets: List[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                targets = [node.target]
            for target in targets:
                value = node.value  # type: ignore[attr-defined]
                if value is None:
                    continue
                if (
                    isinstance(target, (ast.Tuple, ast.List))
                    and isinstance(value, (ast.Tuple, ast.List))
                    and len(target.elts) == len(value.elts)
                ):
                    pairs += zip(target.elts, value.elts)
                else:
                    pairs.append((target, value))
        changed = True
        while changed:
            changed = False
            for target, value in pairs:
                name = _name(target)
                if name and name not in self.loggers and self.is_logger(value):
                    self.loggers.add(name)
                    changed = True
        # Names bound to a logger's log method (lg = L.warning, (m := L.info), a
        # tuple element), or to a name bound to one, to a fixpoint: a call of one
        # is a log call. Bound anywhere in the module, as loggers are.
        self.log_methods: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for target, value in pairs:
                name = _name(target)
                if (
                    isinstance(target, ast.Name)
                    and name not in self.log_methods
                    and self.is_log_method(value)
                ):
                    self.log_methods.add(name)
                    changed = True
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                source = module_paths.get(node.module)
                for alias in node.names:
                    target = module_paths.get(f"{node.module}.{alias.name}")
                    if target:
                        self.modules[alias.asname or alias.name] = target
                    elif source:
                        self.imported[alias.asname or alias.name] = (source, alias.name)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = module_paths.get(alias.name)
                    if target and alias.asname:
                        self.modules[alias.asname] = target

    def is_logger(self, value: ast.AST) -> bool:
        """Whether *value* is a logger: a maker's call, or a name that says "log"
        or is bound to a logger."""
        if isinstance(value, ast.Call):
            return _name(value.func) in self.makers
        name = _name(value)
        return bool(name) and ("log" in name.lower() or name in self.loggers)

    def is_log_method(self, value: ast.AST) -> bool:
        """Whether *value* is a logger's log method: ``<logger>.<method>`` with the
        receiver a logger (a name that says "log", one bound to a logger, a
        maker's call, or a walrus of one), or a name bound to such a method."""
        while isinstance(value, ast.NamedExpr):
            value = value.value
        if isinstance(value, ast.Name):
            return value.id in self.log_methods
        if not (isinstance(value, ast.Attribute) and value.attr in LOG_METHODS):
            return False
        receiver = value.value
        while isinstance(receiver, ast.NamedExpr):
            receiver = receiver.value
        return self.is_logger(receiver)

    def resolve(self, func: ast.AST) -> Optional[Function]:
        """What a call calls: (module, name), ("", name) for an unknown one."""
        if isinstance(func, ast.Name):
            if func.id in self.defs:
                return (self.path, func.id)
            if func.id in self.imported:
                return self.imported[func.id]
            return ("", func.id)
        if isinstance(func, ast.Attribute):
            value = func.value
            if isinstance(value, ast.Name):
                if value.id in ("self", "cls") and func.attr in self.defs:
                    return (self.path, func.attr)
                if value.id in self.modules:
                    return (self.modules[value.id], func.attr)
            return ("", func.attr)
        return None


def _is_escaper(target: Optional[Function], names: frozenset) -> bool:
    """An escaper of terminal_text's (by module, or by name when unresolved)."""
    if target is None or target[1] not in names:
        return False
    return target[0] in ("", _TERMINAL_TEXT) or target[1] == "controls_escaped"


def _functions(tree: ast.AST) -> List[ast.AST]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _parameters(function: ast.AST) -> Set[str]:
    arguments = function.args  # type: ignore[attr-defined]
    names = [
        a.arg for a in arguments.args + arguments.kwonlyargs + arguments.posonlyargs
    ]
    names += [a.arg for a in (arguments.vararg, arguments.kwarg) if a is not None]
    return {name for name in names if name not in ("self", "cls")}


def _positional(function: ast.AST) -> Tuple[List[str], Optional[str]]:
    """The names a call's positional arguments bind, in order, and the name of
    its ``*args``, if any. A method's self or cls is left out: it is bound by the
    receiver, not by an argument."""
    arguments = function.args  # type: ignore[attr-defined]
    names = [a.arg for a in arguments.posonlyargs + arguments.args]
    if names and names[0] in ("self", "cls"):
        names = names[1:]
    return names, arguments.vararg.arg if arguments.vararg is not None else None


def _bound_names(target: ast.AST) -> Iterable[str]:
    """The names a binding target binds or stores into: a name, each element
    of a tuple or list, and the container of a subscript or attribute, whose
    index is read, not bound (``store[key] = value`` stores into ``store``)."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _bound_names(element)
    elif isinstance(target, ast.Starred):
        yield from _bound_names(target.value)
    elif isinstance(target, (ast.Subscript, ast.Attribute)):
        yield from _bound_names(target.value)


def _derived_from(function: ast.AST, seeds: Set[str]) -> Set[str]:
    """*seeds* and every local bound from an expression that reads one of them,
    or holding one: a container stored into counts (``_bound_names``), its
    index does not."""
    derived = set(seeds)
    bindings = []
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            bindings.append((targets, node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            bindings.append(([node.target], node.iter))
    changed = True
    while changed:
        changed = False
        for targets, value in bindings:
            if any(
                isinstance(n, ast.Name) and n.id in derived for n in ast.walk(value)
            ):
                for target in targets:
                    for name in _bound_names(target):
                        if name not in derived:
                            derived.add(name)
                            changed = True
    return derived


def _is_a_class_read(node: ast.AST) -> bool:
    """``type(x)`` with one argument, or ``x.__class__``: the class of a value."""
    if isinstance(node, ast.Attribute):
        return node.attr == "__class__"
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "type"
        and len(node.args) == 1
        and not node.keywords
    )


def _walk_values(node: ast.AST) -> Iterable[ast.AST]:
    """``ast.walk`` that does not look inside the class of a value.

    ``type(error).__name__`` and ``error.__class__.__name__`` name a class: none of
    the text *error* holds is in them, so a shown *error* does not make the
    expression shown text.
    """
    pending = [node]
    while pending:
        inner = pending.pop()
        yield inner
        if not _is_a_class_read(inner):
            pending.extend(ast.iter_child_nodes(inner))


#: The try statements of the syntax tree (``try/except*`` too, where it exists).
_TRY = (ast.Try, getattr(ast, "TryStar", ast.Try))


class _Analysis:
    """Which functions return shown text, which show their argument, which
    exceptions carry shown text."""

    def __init__(self, sources: Dict[str, str]):
        module_paths = {}
        for path in sources:
            parts = list(Path(path).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            module_paths[".".join(parts)] = path
        self.modules = {
            path: _Module(path, ast.parse(source), module_paths)
            for path, source in sources.items()
        }
        self.producers: Set[Function] = set()
        # For each function that passes an argument to a doubling sink, the
        # parameters whose argument reaches one, and the positional parameters
        # (with *args) to map a call's arguments onto them.
        self.doubling: Dict[Function, Set[str]] = {}
        self.positional: Dict[Function, Tuple[List[str], Optional[str]]] = {}
        # Exception classes the package defines and raises with shown text: a
        # handler that catches one holds shown text wherever it is. A kind the
        # package does not define (a builtin, a library's: resolved to ("", name))
        # is not package-wide, since `raise ValueError(<shown>)` in one place says
        # nothing of an `except ValueError` elsewhere. Those are kept by function
        # instead (``shown_raises``: the lines of its raises of shown text, and
        # ``reach``: the kinds a function raises, or a function it calls, to
        # _REACH_DEPTH calls down), and a handler counts through its try body.
        self.exceptions: Set[Function] = set()
        self.shown_raises: Dict[Function, Set[Tuple[int, Function]]] = {}
        self.reach: List[Dict[Function, Set[Function]]] = [
            {} for _ in range(_REACH_DEPTH + 1)
        ]
        self.callees: Dict[Function, Set[Function]] = {}
        derived: Dict[Function, Dict[str, Set[str]]] = {}
        for path, module in self._checked():
            for function in _functions(module.tree):
                key = (path, function.name)
                self.positional[key] = _positional(function)
                derived[key] = {
                    parameter: _derived_from(function, {parameter})
                    for parameter in _parameters(function)
                }
        for path, module in self._checked():
            for function in _functions(module.tree):
                called = self.callees.setdefault((path, function.name), set())
                for node in ast.walk(function):
                    if isinstance(node, ast.Call):
                        target = module.resolve(node.func)
                        if target in self.positional:
                            called.add(target)
        changed = True
        while changed:
            changed = False
            for path, module in self._checked():
                for function in _functions(module.tree):
                    key = (path, function.name)
                    names = _Bindings(function, module, self)
                    for node in ast.walk(function):
                        if isinstance(node, ast.Return) and node.value is not None:
                            if key not in self.producers and self.shown_in(
                                node.value, module, names.at(node.lineno)
                            ):
                                self.producers.add(key)
                                changed = True
                        if isinstance(node, ast.Raise) and isinstance(
                            node.exc, ast.Call
                        ):
                            kind = module.resolve(node.exc.func)
                            if kind is not None and kind[0]:
                                if kind not in self.exceptions and self.shown_in(
                                    node.exc, module, names.at(node.lineno)
                                ):
                                    self.exceptions.add(kind)
                                    changed = True
                            elif kind is not None:
                                mark = (node.lineno, kind)
                                raised = self.shown_raises.setdefault(key, set())
                                if mark not in raised and self.shown_in(
                                    node.exc, module, names.at(node.lineno)
                                ):
                                    raised.add(mark)
                                    changed = True
                        if not isinstance(node, ast.Call):
                            continue
                        arguments = self.sink_arguments(node, module)
                        if not arguments:
                            continue
                        reaching = self.doubling.get(key, set())
                        for parameter, passed_on in derived[key].items():
                            if parameter not in reaching and any(
                                isinstance(inner, ast.Name) and inner.id in passed_on
                                for argument in arguments
                                for inner in ast.walk(argument)
                            ):
                                self.doubling.setdefault(key, set()).add(parameter)
                                changed = True
            if self._update_reach():
                changed = True

    def _update_reach(self) -> bool:
        """Grow ``reach``: level 0 holds the kinds a function raises with shown
        text itself, level n those and every kind the functions it calls hold at
        level n - 1. True when anything grew."""
        grew = False
        for depth in range(_REACH_DEPTH + 1):
            for key, called in self.callees.items():
                kinds = {kind for _, kind in self.shown_raises.get(key, ())}
                if depth:
                    for callee in called:
                        kinds |= self.reach[depth - 1].get(callee, set())
                if kinds != self.reach[depth].get(key, set()):
                    self.reach[depth][key] = kinds
                    grew = True
        return grew

    def raised_in_body(
        self, body: List[ast.stmt], key: Function, module: _Module
    ) -> Set[Function]:
        """The kinds of shown text raised in the statements *body* of a function
        *key*: raised in them, or by a function of the package they call (to
        _REACH_DEPTH calls down)."""
        first, last = body[0].lineno, max(s.end_lineno or s.lineno for s in body)
        kinds = {
            kind
            for line, kind in self.shown_raises.get(key, ())
            if first <= line <= last
        }
        for statement in body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Call):
                    target = module.resolve(node.func)
                    if target is not None:
                        kinds |= self.reach[_REACH_DEPTH].get(target, set())
        return kinds

    def handler_holds_shown_text(
        self,
        handler: ast.ExceptHandler,
        body: List[ast.stmt],
        key: Function,
        module: _Module,
    ) -> bool:
        """Whether the variable of *handler*, of a try whose statements are
        *body*, holds shown text: it catches an exception class of the package
        raised with shown text anywhere, or a kind the package does not define
        that the try body raises with shown text or reaches a function that does."""
        if handler.type is None:
            return False
        caught = (
            handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        )
        raised: Optional[Set[Function]] = None
        for element in caught:
            kind = module.resolve(element)
            if kind is None:
                continue
            if kind[0]:
                if kind in self.exceptions:
                    return True
                continue
            if raised is None:
                raised = self.raised_in_body(body, key, module)
            if kind in raised:
                return True
        return False

    def _checked(self) -> Iterable[Tuple[str, _Module]]:
        return ((p, m) for p, m in self.modules.items() if p != _TERMINAL_TEXT)

    def is_shown_call(self, call: ast.Call, module: _Module) -> bool:
        target = module.resolve(call.func)
        return _is_escaper(target, DOUBLING | NOT_DOUBLING) or target in self.producers

    def is_doubling(self, call: ast.Call, module: _Module) -> bool:
        return bool(self.sink_arguments(call, module))

    def sink_arguments(self, call: ast.Call, module: _Module) -> List[ast.AST]:
        """The positional arguments of *call* that reach a doubling sink: all of
        them for a log method or a doubling escaper, and for a function of the
        package, those bound to a parameter found to reach one (a starred
        argument, whose position is unknown, counts)."""
        if self._is_doubling_sink(call, module):
            return list(call.args)
        target = module.resolve(call.func)
        reaching = self.doubling.get(target) if target is not None else None
        if not reaching:
            return []
        names, rest = self.positional.get(target, ([], None))
        return [
            argument
            for index, argument in enumerate(call.args)
            if isinstance(argument, ast.Starred)
            or (names[index] if index < len(names) else rest) in reaching
        ]

    def _is_doubling_sink(self, call: ast.Call, module: _Module) -> bool:
        """A log method, or an escaper of terminal_text's that doubles."""
        func = call.func
        # A walrus as the callee, (m := L.info)(x): its value.
        while isinstance(func, ast.NamedExpr):
            func = func.value
        # A logger's log method called through a name bound to it: lg = L.warning.
        if isinstance(func, ast.Name) and func.id in module.log_methods:
            return True
        name = _name(func)
        receiver = ""
        if isinstance(func, ast.Attribute):
            value = func.value
            # A walrus as the receiver, (L := getLogger("ash")).warning: its value.
            while isinstance(value, ast.NamedExpr):
                value = value.value
            receiver = (
                _name(value)
                or (_name(value.func) if isinstance(value, ast.Call) else "")
                or ""
            )
            if name in LOG_METHODS and (
                "log" in receiver.lower()
                or receiver in module.loggers
                # A logger made and called in one expression: getChild('x').warning.
                or (isinstance(value, ast.Call) and module.is_logger(value))
            ):
                return True
        # Resolved: a call that is no escaper of terminal_text's (typer's and
        # click's echo, which write the text as given) is no sink of its own; a
        # function of the package found to show an argument is one through
        # sink_arguments.
        return _is_escaper(module.resolve(func), DOUBLING)

    def shown_in(self, node: ast.AST, module: _Module, shown: Set[str]) -> bool:
        for inner in _walk_values(node):
            if isinstance(inner, ast.Call) and self.is_shown_call(inner, module):
                return True
            if isinstance(inner, ast.Name) and inner.id in shown:
                return True
        return False

    def offenders(self) -> Set[Site]:
        found: Set[Site] = set()
        for path, module in self._checked():
            for function in _functions(module.tree):
                names = _Bindings(function, module, self)
                for node in ast.walk(function):
                    if not isinstance(node, ast.Call):
                        continue
                    arguments = self.sink_arguments(node, module)
                    if not arguments:
                        continue
                    if _is_one_pass(node, module, self):
                        continue
                    markup = any(
                        keyword.arg == "extra" and _name(keyword.value) == "MARKUP"
                        for keyword in node.keywords
                    )
                    shown = names.at(node.lineno)
                    for argument in arguments:
                        if markup and _only_escape_markup(argument, module, self):
                            continue
                        if self.shown_in(argument, module, shown):
                            found.add((path, function.name, ast.unparse(node)))
                            break
        return found


class _Bindings:
    """The locals of a function bound to shown text, by the line they are read on."""

    def __init__(self, function: ast.AST, module: _Module, analysis: "_Analysis"):
        self._events: List[Tuple[int, str, bool]] = []
        assignments = sorted(
            (
                node
                for node in ast.walk(function)
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                and node.value is not None
            ),
            key=lambda node: node.lineno,
        )
        for node in assignments:
            shown_before = self.at(node.lineno)
            is_shown = analysis.shown_in(node.value, module, shown_before)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    if isinstance(node, ast.AugAssign) and target.id in shown_before:
                        is_shown = True
                    self._events.append(
                        (node.end_lineno or node.lineno, target.id, is_shown)
                    )
        key = (module.path, function.name)
        for statement in ast.walk(function):
            if not isinstance(statement, _TRY):
                continue
            for handler in statement.handlers:
                if handler.name and handler.type:
                    # Bound by every handler that names it: shown when it catches
                    # a shown exception, raw otherwise, whatever an earlier one
                    # caught.
                    self._events.append(
                        (
                            handler.lineno,
                            handler.name,
                            analysis.handler_holds_shown_text(
                                handler, statement.body, key, module
                            ),
                        )
                    )
        self._events.sort()

    def at(self, lineno: int) -> Set[str]:
        """The names whose latest binding before *lineno* holds shown text."""
        latest: Dict[str, bool] = {}
        for line, name, is_shown in self._events:
            if line >= lineno:
                break
            latest[name] = is_shown
        return {name for name, is_shown in latest.items() if is_shown}


def _is_one_pass(call: ast.Call, module: _Module, analysis: _Analysis) -> bool:
    """A log or text sink given its whole message as one shown_not_obeyed or
    shown_on_one_line call: an escaper inside that call is checked on its own."""
    if _is_escaper(module.resolve(call.func), DOUBLING):
        return False
    return (
        len(call.args) == 1
        and isinstance(call.args[0], ast.Call)
        and _is_escaper(module.resolve(call.args[0].func), ONE_PASS)
    )


def _only_escape_markup(
    argument: ast.AST, module: _Module, analysis: _Analysis
) -> bool:
    """A MARKUP message's values escaped for Rich, and nothing else shown in it."""
    calls = [
        inner
        for inner in ast.walk(argument)
        if isinstance(inner, ast.Call) and analysis.is_shown_call(inner, module)
    ]
    return bool(calls) and all(_name(call.func) == "escape_markup" for call in calls)


def _package_sources(package: Path = _PACKAGE) -> Dict[str, str]:
    # Refused unless every part of the package is in the walk (walked_package).
    return {
        module.relative_to(package.parent).as_posix(): module.read_text("utf-8")
        for module in package_sources(package)
    }


def _check(sources: Dict[str, str], open_sites: Dict[Site, str]):
    """(new sites, stale entries) for *sources* against *open_sites*.

    A row is stale unless it matches exactly one offender: one that matches none
    was fixed, and one that matches two no longer says which it means.
    """
    found = _Analysis(sources).offenders()
    matched: Set[Site] = set()
    stale = []
    for row in sorted(open_sites):
        path, function, fragment = row
        hits = [
            site
            for site in found
            if site[0] == path and site[1] == function and fragment in site[2]
        ]
        if len(hits) == 1:
            matched.add(hits[0])
        else:
            stale.append(row)
    return sorted(found - matched), stale


def test_the_guard_refuses_a_tree_with_nothing_to_check(tmp_path):
    """Moved or pointed elsewhere, the guard would pass having read no module."""
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(AssertionError):
        _package_sources(tmp_path)


def test_no_site_is_left_open():
    """An open row lets a site that shows text twice pass: each one waits on its
    fix, and the table is empty when none does."""
    assert _OPEN == {}, sorted(_OPEN)


def test_no_text_is_shown_twice_in_the_package():
    new, stale = _check(_package_sources(), {**_OPEN, **_BY_DESIGN})

    assert not new, "shown twice:\n" + "\n".join(map(repr, new))
    assert not stale, "fixed, so remove from _OPEN:\n" + "\n".join(map(repr, stale))


# -- the check itself ---------------------------------------------------------

#: The escapers and sinks the cases use, as the package defines them.
_LIBRARY = {
    "automated_security_helper/utils/terminal_text.py": (
        "def controls_shown(text, keep_layout=True):\n    return text\n"
        "def shown_not_obeyed(text):\n    return text\n"
        "def shown_on_one_line(text):\n    return text\n"
        "def raw_controls_shown(text):\n    return text\n"
        "def shown_in_ascii(text, replacements):\n    return text\n"
    ),
    "automated_security_helper/core/sharding.py": (
        "from automated_security_helper.utils.terminal_text import controls_shown\n"
        "def shown_shard_text(value):\n    return controls_shown(str(value), False)\n"
    ),
    "automated_security_helper/utils/log.py": (
        "from automated_security_helper.utils.terminal_text import shown_not_obeyed\n"
        "ASH_LOGGER = None\nMARKUP = {}\n"
        "def escape_markup(value):\n    return '[' + shown_not_obeyed(str(value))\n"
    ),
    "automated_security_helper/utils/console.py": (
        "import typer\n"
        "from automated_security_helper.utils.terminal_text import shown_not_obeyed\n"
        "def _shown(message):\n    return shown_not_obeyed(str(message))\n"
        "def echo(message=None):\n    typer.echo(_shown(message))\n"
    ),
}

_HELPERS = """
from automated_security_helper.utils.terminal_text import (
    raw_controls_shown,
    shown_in_ascii,
    shown_not_obeyed,
    shown_on_one_line,
)
from automated_security_helper.core.sharding import shown_shard_text as _shown
from automated_security_helper.utils.log import ASH_LOGGER, MARKUP, escape_markup
from automated_security_helper.utils.console import echo
from rich.text import Text
import typer
"""

_CASES = {
    "logged": ("ASH_LOGGER.warning(f'Ignoring {_shown(name)}')", True),
    "logged-as-argument": ("ASH_LOGGER.warning('Ignoring %s', _shown(name))", True),
    "echoed": ("echo(f'Ignoring {shown_not_obeyed(name)}')", True),
    "escaped-for-markup": ("escape_markup(_shown(name))", True),
    "shown-again": ("shown_on_one_line(f'Ignoring {_shown(name)}')", True),
    "local": ("shown = _shown(name)\n    ASH_LOGGER.error(f'x {shown}')", True),
    "local-rebound-raw": (
        "shown = _shown(name)\n    shown = name\n    ASH_LOGGER.error(f'x {shown}')",
        False,
    ),
    "local-bound-after": (
        "ASH_LOGGER.error(f'x {shown}')\n    shown = _shown(name)",
        False,
    ),
    "one-pass": ("ASH_LOGGER.warning(shown_on_one_line(f'Ignoring {name}'))", False),
    "one-pass-with-shown-inside": (
        "ASH_LOGGER.warning(shown_not_obeyed(f'Ignoring {_shown(name)}'))",
        True,
    ),
    "markup-value": (
        "ASH_LOGGER.info(f'[bold]x[/bold] {escape_markup(name)}', extra=MARKUP)",
        False,
    ),
    "raw": ("ASH_LOGGER.warning(f'Ignoring {name}')", False),
    "typer-echo": ("typer.echo(_shown(name))", False),
    "raw-controls-over-shown": (
        "print(Text(raw_controls_shown(f'Refusing: {_shown(name)}')))",
        False,
    ),
    "raw-controls-result-logged": (
        "ASH_LOGGER.warning(raw_controls_shown(f'Refusing: {_shown(name)}'))",
        True,
    ),
    "ascii-result-in-a-message": (
        "ASH_LOGGER.warning(f'x {shown_in_ascii(name, {})}')",
        True,
    ),
    "ascii-given-shown": ("text = shown_in_ascii(shown_not_obeyed(name), {})", False),
}


def _with_library(sources: Dict[str, str]) -> Dict[str, str]:
    return {**_LIBRARY, **sources}


@pytest.mark.parametrize("body, offends", _CASES.values(), ids=list(_CASES))
def test_the_check_finds_text_shown_twice_and_only_that(body, offends):
    source = _HELPERS + f"\ndef site(name):\n    {body}\n"
    new, stale = _check(_with_library({"automated_security_helper/x.py": source}), {})

    assert [s[:2] for s in new] == (
        [("automated_security_helper/x.py", "site")] if offends else []
    ), new
    assert not stale


#: Functions of the module that log some of their arguments and not others.
_SENDERS = """
def send(factory, label):
    factory()
    ASH_LOGGER.debug(f'{label}: failed')
def report(factory):
    ASH_LOGGER.info(factory())
def log_all(*parts):
    ASH_LOGGER.info(' '.join(parts))
def cache(key, factory):
    result = factory()
    store[key] = result
    ASH_LOGGER.debug(f'{key}: cached')
    return result
def keep(key, factory):
    held = {}
    held[key] = factory()
    ASH_LOGGER.debug(held)
"""

#: A call of one of _SENDERS, and whether it shows text twice.
_ARGUMENT_CASES = {
    "the-logged-argument": ("send(None, _shown(name))", True),
    "an-argument-it-only-calls": ("send(_shown(name), 'label')", False),
    "a-lambda-it-only-calls": (
        "send(lambda: ctx.error(_shown(name)), 'label')",
        False,
    ),
    "a-callable-whose-result-it-logs": ("report(lambda: _shown(name))", True),
    "through-its-varargs": ("log_all('a', _shown(name))", True),
    # A cache that stores the callable's result under a key and logs the key:
    # the key is read by the store, not bound from the result.
    "a-cache-that-logs-only-its-key": ("cache('k', lambda: _shown(name))", False),
    # The container the result is stored in is bound from it, and is logged.
    "a-container-holding-the-result-it-logs": (
        "keep('k', lambda: _shown(name))",
        True,
    ),
}


@pytest.mark.parametrize(
    "body, offends", _ARGUMENT_CASES.values(), ids=list(_ARGUMENT_CASES)
)
def test_a_function_shows_again_only_the_arguments_it_logs(body, offends):
    """A function of the package is a sink for the arguments that reach its log
    call, not for every argument: a sender handed a lambda that writes shown text
    to the client, which logs only its label when the send fails, shows nothing
    twice."""
    source = _HELPERS + _SENDERS + f"\ndef site(name, ctx):\n    {body}\n"
    new, stale = _check(_with_library({"automated_security_helper/x.py": source}), {})

    assert [s[:2] for s in new] == (
        [("automated_security_helper/x.py", "site")] if offends else []
    ), new
    assert not stale


def test_a_function_returning_shown_text_is_followed_across_modules():
    producer = (
        "from automated_security_helper.core.sharding import shown_shard_text\n"
        "def detail(name):\n    return f'({shown_shard_text(name)})'\n"
    )
    consumer = (
        "from automated_security_helper.x import detail\n"
        "from automated_security_helper.utils.log import ASH_LOGGER\n"
        "def site(name):\n    ASH_LOGGER.warning('unselected: ' + detail(name))\n"
    )
    new, _ = _check(
        _with_library(
            {
                "automated_security_helper/x.py": producer,
                "automated_security_helper/y.py": consumer,
            }
        ),
        {},
    )

    assert [site[:2] for site in new] == [("automated_security_helper/y.py", "site")]


def test_a_function_is_judged_by_what_it_does_not_its_name():
    """A described() that returns its names raw is not an escaper; a _shown_lines
    over raw_controls_shown shows nothing twice; one over shown_shard_text does."""
    module = _HELPERS + (
        "def described(paths):\n    return ', '.join(paths)\n"
        "def _shown_lines(message):\n    return raw_controls_shown(message)\n"
        "def _shown_each(message):\n"
        "    return '\\n'.join(_shown(line) for line in message.split('\\n'))\n"
        "def raw_described(paths):\n"
        "    ASH_LOGGER.warning(shown_on_one_line(f'from {described(paths)}'))\n"
        "def kept(name):\n    print(_shown_lines(f'  {_shown(name)}'))\n"
        "def doubled(name):\n    print(_shown_each(f'  {_shown(name)}'))\n"
    )
    new, _ = _check(_with_library({"automated_security_helper/x.py": module}), {})

    assert [site[:2] for site in new] == [("automated_security_helper/x.py", "doubled")]


def test_an_exception_raised_with_shown_text_is_followed_into_its_handler():
    source = _HELPERS + (
        "class Refused(Exception):\n    pass\n"
        "def check(name):\n    raise Refused(f'no: {_shown(name)}')\n"
        "def site(name):\n"
        "    try:\n        check(name)\n"
        "    except Refused as exc:\n        echo(str(exc))\n"
        "    except ValueError as exc:\n        echo(str(exc))\n"
    )
    new, _ = _check(_with_library({"automated_security_helper/x.py": source}), {})

    assert [site[:2] for site in new] == [("automated_security_helper/x.py", "site")]
    assert len(new) == 1


def _sites(sources: Dict[str, str]) -> List[Tuple[str, str]]:
    """(file, function) of each new site of *sources*, with the library."""
    new, _ = _check(_with_library(sources), {})
    return [site[:2] for site in new]


#: A raise of shown text of a kind the package does not define, and a handler of
#: that kind that logs its variable.
_RAISE_VALUE_ERROR = "def refuse(name):\n    raise ValueError(f'no: {_shown(name)}')\n"


def test_a_builtin_kind_raised_with_shown_text_elsewhere_makes_no_handler_shown():
    """`raise ValueError(<shown>)` in one function says nothing of an `except
    ValueError` in another: only a try body that raises it, or reaches a raise of
    it, holds shown text in its handler's variable."""
    raiser = _HELPERS + _RAISE_VALUE_ERROR
    handler = (
        "from automated_security_helper.utils.log import ASH_LOGGER\n"
        "def raw(path):\n    return path\n"
        "def site(path):\n"
        "    try:\n        raw(path)\n"
        "    except ValueError as exc:\n"
        "        ASH_LOGGER.debug(f'cannot read {path} ({exc})')\n"
        "def unresolved(path, reader):\n"
        "    try:\n        reader.read(path)\n"
        "    except ValueError as exc:\n"
        "        ASH_LOGGER.debug(f'cannot read {path} ({exc})')\n"
    )

    assert not _sites(
        {
            "automated_security_helper/x.py": raiser,
            "automated_security_helper/y.py": handler,
        }
    )


def test_a_try_body_that_raises_the_kind_with_shown_text_holds_it_in_its_handler():
    source = _HELPERS + (
        "def site(name):\n"
        "    try:\n        raise ValueError(f'no: {_shown(name)}')\n"
        "    except ValueError as exc:\n        echo(str(exc))\n"
    )

    assert _sites({"automated_security_helper/x.py": source}) == [
        ("automated_security_helper/x.py", "site")
    ]


def test_a_try_body_that_calls_a_function_raising_it_holds_it_in_its_handler():
    handler = (
        "from automated_security_helper.utils.console import echo\n"
        "from automated_security_helper.x import refuse\n"
        "def site(name):\n"
        "    try:\n        refuse(name)\n"
        "    except (KeyError, ValueError) as exc:\n        echo(str(exc))\n"
    )

    assert _sites(
        {
            "automated_security_helper/x.py": _HELPERS + _RAISE_VALUE_ERROR,
            "automated_security_helper/y.py": handler,
        }
    ) == [("automated_security_helper/y.py", "site")]


@pytest.mark.parametrize(
    "depth, offends", [(_REACH_DEPTH, True), (_REACH_DEPTH + 1, False)]
)
def test_a_raise_is_followed_down_the_calls_of_the_package_to_the_bound(depth, offends):
    """The raise sits *depth* calls below the function the try body calls."""
    chain = "".join(f"def g{n}(name):\n    g{n + 1}(name)\n" for n in range(depth))
    chain += f"def g{depth}(name):\n    raise ValueError(f'no: {{_shown(name)}}')\n"
    source = (
        _HELPERS
        + chain
        + "def site(name):\n"
        + "    try:\n        g0(name)\n"
        + "    except ValueError as exc:\n        echo(str(exc))\n"
    )

    assert _sites({"automated_security_helper/x.py": source}) == (
        [("automated_security_helper/x.py", "site")] if offends else []
    )


def test_a_helper_that_logs_its_message_when_a_send_fails_shows_shown_text_twice():
    """The shape of mcp_server's `_tell_client` before it stopped logging the
    message: a helper that logs its message argument in the failed-send branch
    shows twice the shown text a caller hands it, and not the raw text."""
    source = _HELPERS + (
        "async def tell(ctx, level, message):\n"
        "    try:\n        await ctx.send(message)\n"
        "    except Exception:\n"
        "        ASH_LOGGER.warning(f'Failed to send {level} message: {message}')\n"
        "async def site(ctx, name):\n"
        "    await tell(ctx, 'error', raw_controls_shown(f'Refusing: {name}'))\n"
        "async def raw_site(ctx, name):\n"
        "    await tell(ctx, 'error', f'Refusing: {name}')\n"
    )

    assert _sites({"automated_security_helper/x.py": source}) == [
        ("automated_security_helper/x.py", "site")
    ]


#: What a handler of shown text (its try body raises a ValueError with shown text)
#: logs about its variable, and whether that shows text twice.
_CLASS_READ_CASES = {
    "type-name": ("{type(exc).__name__}", False),
    "dunder-class-name": ("{exc.__class__.__name__}", False),
    "class-name-and-the-text": ("{type(exc).__name__}: {exc}", True),
    "class-name-and-str-of-it": ("{type(exc).__name__}: {str(exc)}", True),
    "the-text": ("{exc}", True),
}


@pytest.mark.parametrize(
    "logged, offends", _CLASS_READ_CASES.values(), ids=list(_CLASS_READ_CASES)
)
def test_the_class_of_a_value_is_not_the_value(logged, offends):
    """A name read only as ``type(x)`` or ``x.__class__`` makes nothing shown, and
    does not hide a read of the value beside it."""
    source = _HELPERS + (
        "def site(name):\n"
        "    try:\n        raise ValueError(f'no: {_shown(name)}')\n"
        "    except ValueError as exc:\n"
        f"        ASH_LOGGER.debug(f'cannot read ({logged})')\n"
    )

    sites = _sites({"automated_security_helper/x.py": source})

    assert sites == ([("automated_security_helper/x.py", "site")] if offends else []), (
        sites
    )


def test_a_method_named_shown_that_escapes_nothing_makes_no_text_shown():
    """config_sources' `_ChainState.shown(path)` writes a path as the placeholder
    or as posix text and shows nothing: a method of an object resolves to its
    attribute name alone, which is no escaper and no producer of the check's, so
    an exception raised with it, and a handler logging that exception, offend
    nothing."""
    source = _HELPERS + (
        "class Refused(Exception):\n    pass\n"
        "def check(state, name):\n    raise Refused(f'no: {state.shown(name)}')\n"
        "def site(state, name):\n"
        "    try:\n        check(state, name)\n"
        "    except Refused as exc:\n        echo(str(exc))\n"
    )

    assert not _sites({"automated_security_helper/x.py": source})


def test_a_listed_site_that_no_longer_offends_fails():
    source = (
        _HELPERS + "\ndef site(name):\n    ASH_LOGGER.warning(f'Ignoring {name}')\n"
    )
    listed = {("automated_security_helper/x.py", "site", "Ignoring"): "its owner"}

    new, stale = _check(
        _with_library({"automated_security_helper/x.py": source}), listed
    )

    assert not new
    assert stale == sorted(listed)


def test_a_listed_site_matches_its_offender_and_no_other():
    """Listed, the site passes; a fragment two offenders hold is stale, since it
    no longer says which one it lists, and both are then new."""
    source = _HELPERS + (
        "\ndef site(name):\n"
        "    ASH_LOGGER.warning(f'Ignoring {_shown(name)}')\n"
        "    ASH_LOGGER.warning(f'Ignoring also {_shown(name)}')\n"
    )
    one = {("automated_security_helper/x.py", "site", "Ignoring also"): "its owner"}
    both = {("automated_security_helper/x.py", "site", "Ignoring"): "its owner"}
    sources = _with_library({"automated_security_helper/x.py": source})

    new, stale = _check(sources, one)
    assert len(new) == 1 and "Ignoring also" not in new[0][2] and not stale

    new, stale = _check(sources, both)
    assert len(new) == 2 and stale == sorted(both)


# -- every escaper of terminal_text is in a list ----------------------------------

#: terminal_text's names that show nothing: the predicates (two name escape_for
#: to compare an escape's text with it: the "written" and the "ascii" lookalike
#: readings of controls_shown), the marker, and as_written, which reads shown
#: text back.
_NO_ESCAPERS = frozenset(
    {
        "is_shown_as_escape",
        "_reads_as_written_escape",
        "_reads_as_ascii_escape",
        "ShownText",
        "as_written",
    }
)
#: Listed escapers that live outside terminal_text.
_ESCAPERS_ELSEWHERE = frozenset({"controls_escaped"})


def _unclassified(source: str) -> Tuple[Set[str], Set[str]]:
    """(terminal_text's names in no list, listed names it does not define), for
    its *source*.

    The fixpoint does not read terminal_text, and the lists name its escapers, so
    a new one in it was neither shown text nor a sink to the check: a site that
    logged ``f"m {shown_for_ci(v)}"`` passed. Each public function and class must
    be listed, and so must each name, public or private, that reaches an escaper
    or the maker: a function whose body names one, or a name the module assigns
    to one (an alias) or to a lambda that names one, followed through the
    module's own names to a fixpoint. The maker itself is the shown-text guard's
    (test_shown_text_is_shown_once.py)."""
    tree = ast.parse(source)
    defined: Dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    defined[target.id] = node.value
    public = {
        name
        for name, node in defined.items()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and not name.startswith("_")
    }
    reaching: Set[str] = set()
    targets = DOUBLING | NOT_DOUBLING | {"_as_shown"}
    changed = True
    while changed:
        changed = False
        for name, node in defined.items():
            if name in reaching or name == "_as_shown":
                continue
            if any(
                _name(inner) in targets | reaching
                for inner in ast.walk(node)
                if isinstance(inner, (ast.Name, ast.Attribute))
            ):
                reaching.add(name)
                changed = True
    listed = (DOUBLING | NOT_DOUBLING | _NO_ESCAPERS) - _ESCAPERS_ELSEWHERE
    return (public | reaching) - listed, listed - set(defined)


def test_every_public_name_of_terminal_text_is_listed():
    source = (_PACKAGE / "utils" / "terminal_text.py").read_text("utf-8")

    assert _unclassified(source) == (set(), set())


def test_a_new_escaper_of_terminal_text_must_be_listed():
    source = (_PACKAGE / "utils" / "terminal_text.py").read_text("utf-8")
    source += "\n\ndef shown_for_ci(text):\n    return shown_not_obeyed(text)\n"

    assert _unclassified(source) == ({"shown_for_ci"}, set())


def test_a_maker_of_shown_text_must_be_listed_whatever_its_name():
    """A function of terminal_text that calls the maker returns shown text: one
    named shown_in_latin1, or _shown_in_latin1, was no escaper to the walk."""
    source = (_PACKAGE / "utils" / "terminal_text.py").read_text("utf-8")
    source += (
        "\n\ndef shown_in_latin1(text):\n    return _as_shown(text)\n"
        "\n\ndef _shown_in_latin1(text):\n    return _as_shown(text)\n"
    )

    assert _unclassified(source) == ({"shown_in_latin1", "_shown_in_latin1"}, set())


@pytest.mark.parametrize(
    "added, unlisted",
    [
        pytest.param(
            "def _shown_for_ci(text):\n    return shown_not_obeyed(text)\n",
            "_shown_for_ci",
            id="private-composer",
        ),
        pytest.param("shown_for_ci = shown_not_obeyed\n", "shown_for_ci", id="alias"),
        pytest.param(
            "shown_for_ci = lambda text: shown_not_obeyed(text)\n",
            "shown_for_ci",
            id="lambda",
        ),
        pytest.param(
            "def _wrapped(text):\n    return _shown_twice(text)\n"
            "def _shown_twice(text):\n    return controls_shown(text)\n",
            {"_wrapped", "_shown_twice"},
            id="through-another",
        ),
    ],
)
def test_a_name_of_terminal_text_that_reaches_an_escaper_must_be_listed(
    added, unlisted
):
    """Its result is shown text the walk does not see, since it does not read
    terminal_text: a private composer, an alias or a lambda logged in a plain
    message passed."""
    source = (_PACKAGE / "utils" / "terminal_text.py").read_text("utf-8")
    source += "\n\n" + added
    expected = {unlisted} if isinstance(unlisted, str) else unlisted

    assert _unclassified(source) == (expected, set())


def test_the_shown_text_guards_escapers_are_listed_here():
    """test_shown_text_is_shown_once.py names the escapers that may make a
    ShownText; each one returns shown text, so this check must count it."""
    guard = Path(__file__).with_name("test_shown_text_is_shown_once.py")
    (escapers,) = [
        ast.literal_eval(node.value)
        for node in ast.parse(guard.read_text("utf-8")).body
        if isinstance(node, ast.Assign)
        and any(_name(target) == "_ESCAPERS" for target in node.targets)
    ]

    assert set(escapers) - (DOUBLING | NOT_DOUBLING) == set()


# -- a log call on a receiver whose name does not say "log" -------------------------

#: A logger bound to a name that does not say so, and a call on it: (module-level
#: code, the body of site(), whether site() offends).
_RECEIVER_CASES = {
    "adapter": (
        "",
        (
            "import logging\n"
            "    a = logging.LoggerAdapter(ASH_LOGGER, {})\n"
            "    a.warning(f'x {_shown(name)}')"
        ),
        True,
    ),
    "get-logger": (
        "",
        (
            "import logging\n"
            "    L = logging.getLogger('ash.x')\n"
            "    L.error(f'x {_shown(name)}')"
        ),
        True,
    ),
    "child": (
        "",
        "c = ASH_LOGGER.getChild('x')\n    c.info(f'x {_shown(name)}')",
        True,
    ),
    "not-a-logger": ("", "counter.info(f'x {_shown(name)}')", False),
    "import-alias": (
        "from automated_security_helper.utils.log import ASH_LOGGER as L\n",
        "L.warning(f'x {_shown(name)}')",
        True,
    ),
    "assigned-in-the-function": (
        "",
        "L = ASH_LOGGER\n    L.warning(f'x {_shown(name)}')",
        True,
    ),
    "assigned-in-the-module": (
        "L = ASH_LOGGER\n",
        "L.warning(f'x {_shown(name)}')",
        True,
    ),
    "walrus": (
        "",
        "if (L := ASH_LOGGER) is not None:\n        L.warning(f'x {_shown(name)}')",
        True,
    ),
    "tuple-target": (
        "",
        "L, count = ASH_LOGGER, 1\n    L.warning(f'x {_shown(name)}')",
        True,
    ),
    "child-chained": (
        "",
        "ASH_LOGGER.getChild('x').warning(f'x {_shown(name)}')",
        True,
    ),
    "walrus-receiver": (
        "",
        (
            "import logging\n"
            "    (L := logging.getLogger('ash')).warning(f'x {_shown(name)}')"
        ),
        True,
    ),
    "walrus-receiver-of-a-logger": (
        "",
        "(L := ASH_LOGGER).warning(f'x {_shown(name)}')",
        True,
    ),
    "maker-imported-as": (
        "from logging import getLogger as make\n",
        "make('ash.x').warning(f'x {_shown(name)}')",
        True,
    ),
    "assigned-not-a-logger": (
        "",
        "c = counter\n    c.info(f'x {_shown(name)}')",
        False,
    ),
    # A logger's log method bound to a name, or to a walrus, and called through it.
    "walrus-bound-method": (
        "",
        "(m := ASH_LOGGER.info)(f'x {_shown(name)}')",
        True,
    ),
    "walrus-bound-method-in-a-check": (
        "",
        "if (lg := ASH_LOGGER.warning):\n        lg(f'x {_shown(name)}')",
        True,
    ),
    "bound-method-assigned": (
        "",
        "lg = ASH_LOGGER.warning\n    lg(f'x {_shown(name)}')",
        True,
    ),
    "bound-method-rebound": (
        "",
        "lg = ASH_LOGGER.warning\n    say = lg\n    say(f'x {_shown(name)}')",
        True,
    ),
    "bound-method-in-the-module": (
        "say = ASH_LOGGER.error\n",
        "say(f'x {_shown(name)}')",
        True,
    ),
    "bound-method-tuple-element": (
        "",
        "lg, count = ASH_LOGGER.info, 1\n    lg(f'x {_shown(name)}')",
        True,
    ),
    "bound-method-of-a-bound-logger": (
        "",
        "L = ASH_LOGGER\n    lg = L.error\n    lg(f'x {_shown(name)}')",
        True,
    ),
    "bound-method-not-a-logger": (
        "",
        "m = counter.info\n    m(f'x {_shown(name)}')",
        False,
    ),
    "bound-other-method-of-a-logger": (
        "",
        "check = ASH_LOGGER.isEnabledFor\n    check(f'x {_shown(name)}')",
        False,
    ),
}


@pytest.mark.parametrize(
    "module, body, offends", _RECEIVER_CASES.values(), ids=list(_RECEIVER_CASES)
)
def test_a_logger_by_any_name_is_a_sink(module, body, offends):
    """The check took a log method for a sink only on a receiver whose name says
    "log", so an adapter `a` or a logger `L` passed shown text unseen: bound by a
    call that makes one, an import under another name, a plain assignment, a
    walrus or a tuple, or a logger's child called on directly."""
    source = _HELPERS + module + f"\ndef site(name):\n    {body}\n"
    new, stale = _check(_with_library({"automated_security_helper/x.py": source}), {})

    assert [s[:2] for s in new] == (
        [("automated_security_helper/x.py", "site")] if offends else []
    ), new


# -- the not-UTF-8 refusal is shown once, at its sinks -------------------------------

#: The refusal whose message holds its paths as they are, shown once at each sink.
_NOT_UTF8 = "WorkspacePathNotUtf8Error"


def _error_names(tree: ast.Module) -> Set[str]:
    """The refusal's name and each name *tree* binds to it: an import of it under
    another name, or an assignment of it or of such a name, to a fixpoint."""
    names = {_NOT_UTF8}
    assigned: List[Tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname and alias.name.rsplit(".", 1)[-1] == _NOT_UTF8:
                    names.add(alias.asname)
        if isinstance(node, ast.Assign):
            assigned += [
                (target.id, node.value)
                for target in node.targets
                if isinstance(target, ast.Name)
            ]
    changed = True
    while changed:
        changed = False
        for target, value in assigned:
            if target not in names and _name(value) in names:
                names.add(target)
                changed = True
    return names


def _names_the_error(node: Optional[ast.AST], names: Set[str]) -> bool:
    return node is not None and any(_name(inner) in names for inner in ast.walk(node))


def _shown_whole(use: ast.AST, parents: Dict[int, ast.AST], error: str) -> bool:
    """Whether *use*, a read of *error*, is ``shown_on_one_line(str(error))``
    or ``shown_on_one_line(error_text(error))``.

    error_text is str(error) for this error's own text (it has no
    ValidationError to describe), with the values the chain carries redacted,
    so it still shows the message whole, once.
    """
    text = parents.get(id(use))
    sink = parents.get(id(text)) if text is not None else None
    return (
        isinstance(text, ast.Call)
        and _name(text.func) in ("str", "error_text")
        and len(text.args) == 1
        and isinstance(sink, ast.Call)
        and _name(sink.func) == "shown_on_one_line"
        and sink.args == [text]
    )


def _not_utf8_offenders(source: str, path: str) -> List[str]:
    """Each place *source* raises the refusal with shown text, or handles it other
    than by showing it whole, once, with shown_on_one_line around str(error) or
    error_text(error).

    WorkspacePathNotUtf8Error's message holds its paths as they are, surrogate
    escapes included (core/exceptions.py): shown at the raise, each sink would show
    it again; written as it is by a new sink, it would print raw. Handlers are
    found by an except clause naming it and by an isinstance check of it, under
    its own name or one the module binds to it (an import under another name, an
    assignment). Not seen: a handler of a parent class (WorkspaceDefinitionError),
    which shows its message through its own sink; the error kept and passed
    elsewhere; a check by ``type(e) is`` or ``==``; a match case; the else branch
    of ``if not isinstance(...)``; a raise of a local that holds shown text; and an
    error built in one statement and raised in another.
    """
    tree = ast.parse(source)
    names = _error_names(tree)
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            if _name(node.exc.func) in names and any(
                isinstance(inner, ast.Call)
                and _name(inner.func) in (DOUBLING | NOT_DOUBLING)
                for inner in ast.walk(node.exc)
            ):
                found.append(f"{path}:{node.lineno}: raised with shown text")
        scopes = []
        if isinstance(node, ast.ExceptHandler) and node.name:
            if _names_the_error(node.type, names):
                scopes.append((node.name, node.body))
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Call)
            and _name(node.test.func) == "isinstance"
            and len(node.test.args) == 2
            and isinstance(node.test.args[0], ast.Name)
            and _names_the_error(node.test.args[1], names)
        ):
            scopes.append((node.test.args[0].id, node.body))
        for error, body in scopes:
            for statement in body:
                for use in ast.walk(statement):
                    if (
                        isinstance(use, ast.Name)
                        and use.id == error
                        and isinstance(use.ctx, ast.Load)
                        and not _shown_whole(use, parents, error)
                    ):
                        found.append(f"{path}:{use.lineno}: {error} not shown whole")
    return found


def test_the_not_utf8_refusal_is_raised_raw_and_shown_whole_where_handled():
    found = []
    for path, source in _package_sources().items():
        found += _not_utf8_offenders(source, path)

    assert found == []


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "try:\n    plan()\nexcept WorkspacePathNotUtf8Error as exc:\n"
            "    echo(str(exc))\n",
            id="handler-writes-it-as-it-is",
        ),
        pytest.param(
            "try:\n    plan()\nexcept (WorkspacePathNotUtf8Error, OSError) as exc:\n"
            "    log(f'refused: {exc}')\n",
            id="handler-of-a-tuple",
        ),
        pytest.param(
            "if isinstance(error, WorkspacePathNotUtf8Error):\n"
            "    response['error'] = str(error)\n",
            id="isinstance-branch",
        ),
        pytest.param(
            "raise WorkspacePathNotUtf8Error(shown_not_obeyed(f'x {path}'))\n",
            id="raised-shown",
        ),
        pytest.param(
            "from automated_security_helper.core.exceptions import (\n"
            "    WorkspacePathNotUtf8Error as NotUtf8,\n)\n"
            "try:\n    plan()\nexcept NotUtf8 as exc:\n    echo(str(exc))\n",
            id="handler-of-an-imported-alias",
        ),
        pytest.param(
            "import automated_security_helper.core.exceptions as errors\n"
            "NotUtf8 = errors.WorkspacePathNotUtf8Error\n"
            "if isinstance(error, NotUtf8):\n    response['error'] = str(error)\n",
            id="isinstance-of-an-assigned-alias",
        ),
        pytest.param(
            "from automated_security_helper.core.exceptions import (\n"
            "    WorkspacePathNotUtf8Error as NotUtf8,\n)\n"
            "raise NotUtf8(shown_not_obeyed(f'x {path}'))\n",
            id="raised-shown-under-an-alias",
        ),
        pytest.param(
            "if isinstance(error, WorkspacePathNotUtf8Error):\n"
            "    response['error'] = error_text(error)\n",
            id="error-text-without-the-one-line-pass",
        ),
    ],
)
def test_the_not_utf8_check_finds_each_way_past_the_one_pass(source):
    assert _not_utf8_offenders(source, "automated_security_helper/x.py")


def test_the_not_utf8_check_passes_the_one_pass_form():
    source = (
        "try:\n    plan()\nexcept WorkspacePathNotUtf8Error as exc:\n"
        "    echo(shown_on_one_line(str(exc)))\n"
        "if isinstance(error, WorkspacePathNotUtf8Error):\n"
        "    response['error'] = str(shown_on_one_line(str(error)))\n"
        "if isinstance(error, WorkspacePathNotUtf8Error):\n"
        "    response['error'] = str(shown_on_one_line(error_text(error)))\n"
        "raise WorkspacePathNotUtf8Error(f'The workspace file {path!r}')\n"
    )
    assert _not_utf8_offenders(source, "automated_security_helper/x.py") == []
