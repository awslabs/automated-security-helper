#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Find every environment variable ASH reads, and generate the reference page for them.

Usage:
    uv run python scripts/generate_env_var_reference.py           # rewrite the page
    uv run python scripts/generate_env_var_reference.py --check   # exit 1 with a diff if stale

Two consumers, one collector
----------------------------
:func:`read_env_names` is the interface other checks import (the docs doctest uses
it to refuse an ``ASH_*`` name no code reads). It returns ``(names, dynamic)``:
every variable name a read was found for, and every lookup site whose key could
not be resolved to a name. It is AST- and text-only and never imports ASH, so it
is cheap and safe to call from any test, and it reads the tree given to it (by
default the checkout this file is in), so a copy of a pull request's tree can be
measured with the same code.

:func:`generate` renders docs/content/reference/environment-variables.md from the
same reads, adding what only an import can supply: the default, help text and
CLI anchor of each option that declares an ``envvar``.

What counts as a read
---------------------
Python, every ``*.py`` under ``automated_security_helper/``:

* ``os.environ[KEY]``, ``os.environ.get(KEY, ...)``, ``.setdefault``, ``.pop``,
  ``KEY in os.environ`` and ``os.getenv(KEY, ...)``, also through ``from os
  import environ, getenv``;
* ``envvar=`` on any call (typer and click options).

A key that is not a string literal is resolved where that can be done without
running anything: a name bound to a literal in the same function or module, a
name imported from another package module, a ``for`` target over a literal
sequence, a function parameter (through the literal arguments its callers pass),
an attribute bound to a literal on some class, and a method whose every
``return`` is a literal. Each resolution is recorded as ``via`` so the page can
say how a name was found. A key that resolves to nothing -- a value read from a
config file, a name built with an f-string -- is recorded as a dynamic site, and
the page lists those sites. The literal set is therefore exact about what it
contains and makes no claim of completeness that the dynamic list does not
qualify.

Shell (the ``ash`` entry script, ``utils/*.sh``, and ``*.sh`` shipped inside the
package): an upper-case ``$NAME`` or ``${NAME}`` that none of those scripts
assigns, or any ``${NAME:-default}``-style expansion, which reads the environment
whether or not the script also assigns the name. Lower-case names are shell
locals by convention and are not considered. PowerShell (``utils/*.ps1``):
``$env:NAME`` outside an assignment, and ``[Environment]::GetEnvironmentVariable``.
Comments are stripped first, so a help comment naming a variable is not a read.

The Dockerfile is not a reader. Its ``ENV`` lines are recorded only for names that
something above reads, and shown as the value the container image sets.

Files are taken from ``git ls-files --cached --others --exclude-standard`` when
the tree is a git checkout, so ignored build copies (``assets/exceptions.py`` is
copied from ``core/exceptions.py`` at build time) are not double-counted, and from
the filesystem otherwise (an extracted archive has no ignored files to skip).
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (
    add_docs_root_argument,
    banner,
    code,
    generated_note,
    md_prose,
    prepare_environment,
    reference_dir,
    refuse_check_to_stdout,
    write_or_check,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "automated_security_helper"
GENERATOR = "scripts/generate_env_var_reference.py"
PAGE = "environment-variables.md"

#: Shell scripts the repository ships to users, besides ``*.sh`` inside the package.
SHELL_SCRIPT_GLOBS = ("ash", "utils/*.sh")
POWERSHELL_SCRIPT_GLOBS = ("utils/*.ps1",)
DOCKERFILE = "Dockerfile"

#: Marker for a variable whose reads carry no comment or docstring describing it.
PURPOSE_UNDOCUMENTED = "Purpose not documented in code."

_ENV_OBJECTS = {"os.environ", "environ", "os.environb", "environb"}
_GETENV = {"os.getenv", "getenv"}
_ENV_METHODS = {"get", "setdefault", "pop", "__contains__"}

#: Set by the shell itself rather than inherited, so reading one is not reading the
#: environment.
_SHELL_SPECIAL = {
    "BASH",
    "BASHPID",
    "BASH_LINENO",
    "BASH_REMATCH",
    "BASH_SOURCE",
    "BASH_VERSION",
    "EUID",
    "FUNCNAME",
    "HOSTTYPE",
    "IFS",
    "LINENO",
    "MACHTYPE",
    "OPTARG",
    "OPTIND",
    "OSTYPE",
    "PIPESTATUS",
    "PPID",
    "RANDOM",
    "REPLY",
    "SECONDS",
    "UID",
}

#: Tool directives, not prose; never quoted as a variable's purpose.
_PRAGMA = re.compile(
    r"^(noqa|nosec|nosemgrep|type:|pragma|pylint:|fmt:|mypy:|pyright:|isort:)",
    re.IGNORECASE,
)

_MAX_RESOLVE_DEPTH = 4
_COMMENT_LIMIT = 320


@dataclass(frozen=True)
class EnvRead:
    """One place an environment variable is read."""

    name: str
    path: str
    line: int
    language: str
    shape: str
    default: Optional[str] = None
    via: Optional[str] = None
    comment: Optional[str] = None
    #: The file the comment or docstring quoted as the purpose is in.
    comment_at: Optional[str] = None
    #: The function, ``Class.method`` or script function the read is in; "" when it
    #: is at module level or a script's top level.
    scope: str = ""
    #: The same, for where the quoted comment is.
    comment_scope: str = ""


@dataclass
class EnvScan:
    reads: list[EnvRead] = field(default_factory=list)
    #: ``path:line [shape] source`` per unresolved lookup: what read_env_names returns.
    dynamic: list[str] = field(default_factory=list)
    #: The same lookups as ``(path, scope, shape, source)``, for the page, which
    #: cites no line numbers.
    dynamic_sites: list[tuple[str, str, str, str]] = field(default_factory=list)
    image_env: dict[str, list[tuple[str, str, int]]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def _listed_files(repo_root: Path) -> Optional[list[str]]:
    if not (repo_root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted(p for p in result.stdout.decode().split("\0") if p)


def _files(repo_root: Path, patterns: Iterable[str]) -> list[Path]:
    """Repository files matching any glob in ``patterns``, sorted."""
    listed = _listed_files(repo_root)
    found: set[Path] = set()
    for pattern in patterns:
        if listed is None:
            found.update(
                p
                for p in repo_root.glob(pattern)
                if p.is_file() and "__pycache__" not in p.parts
            )
        else:
            regex = _glob_regex(pattern)
            found.update(repo_root / p for p in listed if regex.fullmatch(p))
    # A file deleted in the working tree is still listed by --cached.
    return sorted(p for p in found if p.is_file())


def _glob_regex(pattern: str) -> re.Pattern:
    """Translate a path glob where ``*`` stops at ``/`` and ``**/`` spans directories."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _first_sentences(text: str, limit: int = _COMMENT_LIMIT) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit]
    stop = max(cut.rfind(". "), cut.rfind("; "))
    if stop > limit // 3:
        return cut[: stop + 1]
    return cut.rsplit(" ", 1)[0] + " ..."


@dataclass
class _Module:
    name: str
    rel: str
    tree: ast.Module
    lines: list[str]
    comments: dict[int, str]
    parents: dict[int, ast.AST]
    constants: dict[str, tuple[object, int]]
    imports: dict[str, tuple[str, Optional[str]]]
    #: ``(first line, last line, qualified name)`` of every function and class.
    spans: list[tuple[int, int, str]] = field(default_factory=list)

    def scope_at(self, line: int) -> str:
        """The innermost function or class around ``line``, dotted; "" at module level."""
        inside = [span for span in self.spans if span[0] <= line <= span[1]]
        return max(inside, key=lambda span: span[0])[2] if inside else ""

    def parent(self, node: ast.AST) -> Optional[ast.AST]:
        return self.parents.get(id(node))

    def enclosing(self, node: ast.AST, kinds) -> Optional[ast.AST]:
        cur = self.parent(node)
        while cur is not None and not isinstance(cur, kinds):
            cur = self.parent(cur)
        return cur

    def statement(self, node: ast.AST) -> ast.AST:
        cur = node
        while cur is not None and not isinstance(cur, ast.stmt):
            cur = self.parent(cur)
        return cur or node

    def comment_for(self, line: int, stmt_line: int) -> Optional[tuple[str, int]]:
        """A trailing comment on ``line``, else the comment block directly above ``stmt_line``."""
        if self.comments.get(line) and self.lines[line - 1].lstrip()[:1] != "#":
            return self.comments[line], line
        block: list[str] = []
        cur = stmt_line - 1
        while cur >= 1 and self.lines[cur - 1].lstrip().startswith("#"):
            block.insert(0, self.comments.get(cur, ""))
            cur -= 1
        text = " ".join(t for t in block if t)
        if text:
            return text, cur + 1
        return None


_NOT_LITERAL = object()


def _literal(node: ast.AST) -> object:
    """A str or None constant, or a tuple of such (nested); ``_NOT_LITERAL`` otherwise."""
    if isinstance(node, ast.Constant) and (
        node.value is None or isinstance(node.value, str)
    ):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = []
        for elt in node.elts:
            value = _literal(elt)
            if value is _NOT_LITERAL:
                return _NOT_LITERAL
            items.append(value)
        return tuple(items)
    return _NOT_LITERAL


def _value_strings(node: ast.AST) -> Optional[object]:
    """A str literal, or a tuple of str literals for a literal list/tuple/set."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                items.append(elt.value)
            else:
                return None
        return tuple(items)
    return None


def _load_module(repo_root: Path, path: Path) -> Optional[_Module]:
    rel = path.relative_to(repo_root).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        return None
    parts = list(path.relative_to(repo_root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    name = ".".join(parts)

    comments: dict[int, str] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                body = tok.string.lstrip("#").lstrip(":").strip()
                comments[tok.start[0]] = "" if _PRAGMA.match(body) else body
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass

    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    constants: dict[str, tuple[object, int]] = {}
    imports: dict[str, tuple[str, Optional[str]]] = {}
    package = name if parts and path.name == "__init__.py" else ".".join(parts[:-1])
    for stmt in tree.body:
        targets: list[ast.AST] = []
        value = None
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        for target in targets:
            if isinstance(target, ast.Name):
                resolved = _literal(value)
                if resolved is not _NOT_LITERAL and resolved is not None:
                    constants[target.id] = (resolved, stmt.lineno)
        if isinstance(stmt, ast.ImportFrom):
            base = stmt.module or ""
            if stmt.level:
                anchor = package.split(".")
                anchor = (
                    anchor[: len(anchor) - (stmt.level - 1)]
                    if stmt.level > 1
                    else anchor
                )
                base = ".".join([*anchor, base] if base else anchor)
            for alias in stmt.names:
                imports[alias.asname or alias.name] = (base, alias.name)
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                imports[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0],
                    None,
                )
    spans: list[tuple[int, int, str]] = []

    def collect(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = f"{prefix}{child.name}"
                first = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                spans.append((first, child.end_lineno or child.lineno, qualified))
                collect(child, qualified + ".")
            else:
                collect(child, prefix)

    collect(tree, "")
    return _Module(
        name,
        rel,
        tree,
        text.splitlines(),
        comments,
        parents,
        constants,
        imports,
        spans,
    )


def _scope_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Nodes in ``scope``'s own namespace: nested functions and classes are not entered.

    Comprehensions are entered, since their targets are what a lookup inside them
    names.
    """
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _strings(value: object) -> Optional[list[str]]:
    """The names a constant holds: itself if a str, its items if a flat str sequence."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, tuple) and all(isinstance(v, str) for v in value):
        return list(value)
    return None


class _Resolver:
    """Resolves a lookup's key expression to the names it can hold."""

    def __init__(self, modules: dict[str, _Module]):
        self.modules = modules
        self._functions: dict[str, list[tuple[_Module, ast.AST]]] = {}
        self._classes: dict[str, list[tuple[_Module, ast.ClassDef]]] = {}
        self._calls: dict[str, list[tuple[_Module, ast.Call]]] = {}
        for mod in modules.values():
            for node in ast.walk(mod.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._functions.setdefault(node.name, []).append((mod, node))
                elif isinstance(node, ast.ClassDef):
                    self._classes.setdefault(node.name, []).append((mod, node))
                elif isinstance(node, ast.Call):
                    func = node.func
                    fname = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else None
                    )
                    if fname:
                        self._calls.setdefault(fname, []).append((mod, node))

    def resolve(
        self, mod: _Module, node: ast.AST, depth: int = 0
    ) -> tuple[list[tuple[str, Optional[str], Optional[tuple[str, int]]]], bool]:
        """Return ``([(name, via, definition_site)], complete)``.

        ``complete`` is False when some binding of the key could not be resolved,
        so the caller still records the site as dynamic.
        """
        if depth > _MAX_RESOLVE_DEPTH:
            return [], False
        value = _value_strings(node)
        if isinstance(value, str):
            return [(value, None, None)], True
        if isinstance(value, tuple):
            return [(v, None, None) for v in value], True

        if isinstance(node, ast.Name):
            return self._resolve_name(mod, node, node.id, depth)
        if isinstance(node, ast.Attribute):
            return self._resolve_attribute(mod, node, depth)
        if isinstance(node, ast.Call) and not node.args and not node.keywords:
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id in ("self", "cls")
            ):
                owner = mod.enclosing(node, (ast.ClassDef,))
                family = self._class_family(mod, owner)
                return self._resolve_returns(func.attr, family)
            if isinstance(func, ast.Name):
                return self._resolve_returns(func.id, [(mod, mod.tree)])
        return [], False

    def _resolve_name(self, mod: _Module, node: ast.AST, name: str, depth: int):
        func = mod.enclosing(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        while func is not None:
            if isinstance(func, ast.Lambda):
                func = mod.enclosing(
                    func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                )
                continue
            found, complete, bound = self._resolve_in_function(
                mod, func, node, name, depth
            )
            if bound:
                return found, complete
            func = mod.enclosing(
                func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            )
        constant = self.constant(mod, name)
        if constant is not None:
            value, label, site = constant
            values = _strings(value)
            if values is not None:
                return [(v, f"constant {label}", site) for v in values], True
        # A module-level loop or comprehension target.
        found, complete, bound = self._resolve_in_function(
            mod, mod.tree, node, name, depth
        )
        if bound:
            return found, complete
        return [], False

    def constant(self, mod: _Module, name: str):
        """``(value, name, (path, line))`` for a module constant visible as ``name``."""
        if name in mod.constants:
            value, line = mod.constants[name]
            return value, name, (mod.rel, line)
        if name in mod.imports:
            source, attr = mod.imports[name]
            target = self.modules.get(source)
            if attr is not None and target is not None and attr in target.constants:
                value, line = target.constants[attr]
                return value, attr, (target.rel, line)
        return None

    def _resolve_in_function(self, mod, func, use, name, depth):
        """Resolve ``name`` from bindings in ``func``'s own scope (or the module's).

        Returns ``(found, complete, bound)``; ``bound`` says whether this scope binds
        the name at all, so the caller knows whether to look further out.
        """
        args = getattr(func, "args", None)
        params = [a.arg for a in args.posonlyargs + args.args] if args else []
        kwonly = [a.arg for a in args.kwonlyargs] if args else []
        found: list = []
        complete = True
        bound = False

        for stmt in _scope_nodes(func):
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = (
                    stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name) and target.id == name:
                        bound = True
                        if stmt.value is None or isinstance(stmt, ast.AugAssign):
                            complete = False
                            continue
                        sub, ok = self.resolve(mod, stmt.value, depth + 1)
                        found += [(n, v or f"local {name}", d) for n, v, d in sub]
                        complete = complete and ok
            elif isinstance(stmt, (ast.For, ast.comprehension)):
                target = stmt.target
                if isinstance(target, ast.Name) and target.id == name:
                    bound = True
                    sub, ok = self.resolve(mod, stmt.iter, depth + 1)
                    found += [
                        (n, v or f"loop over {ast.unparse(stmt.iter)}", d)
                        for n, v, d in sub
                    ]
                    complete = complete and ok
                elif isinstance(target, ast.Tuple):
                    positions = [
                        i
                        for i, elt in enumerate(target.elts)
                        if isinstance(elt, ast.Name) and elt.id == name
                    ]
                    if not positions:
                        continue
                    bound = True
                    rows = None
                    site = None
                    label = ast.unparse(stmt.iter)
                    if isinstance(stmt.iter, ast.Name):
                        constant = self.constant(mod, stmt.iter.id)
                        if constant is not None:
                            rows, label, site = constant
                    else:
                        literal = _literal(stmt.iter)
                        rows = None if literal is _NOT_LITERAL else literal
                    index = positions[0]
                    picked = []
                    if isinstance(rows, tuple) and all(
                        isinstance(r, tuple) and len(r) > index for r in rows
                    ):
                        picked = [r[index] for r in rows]
                    if picked and all(isinstance(v, str) for v in picked):
                        found += [(v, f"loop over {label}", site) for v in picked]
                    else:
                        complete = False

        if args is not None and (name in params or name in kwonly):
            bound = True
            index = params.index(name) if name in params else None
            defaults = args.defaults
            if index is not None and defaults:
                offset = len(params) - len(defaults)
                if index >= offset:
                    sub, ok = self.resolve(mod, defaults[index - offset], depth + 1)
                    found += [
                        (n, v or f"default of parameter {name}", d) for n, v, d in sub
                    ]
            is_method = isinstance(mod.parent(func), ast.ClassDef)
            callers = self._callers(mod, func, is_method)
            if not callers:
                complete = False
            for caller_mod, call in callers:
                arg_node = None
                for kw in call.keywords:
                    if kw.arg == name:
                        arg_node = kw.value
                if arg_node is None and index is not None:
                    pos = index - (
                        1 if is_method and isinstance(call.func, ast.Attribute) else 0
                    )
                    if 0 <= pos < len(call.args) and not any(
                        isinstance(a, ast.Starred) for a in call.args[: pos + 1]
                    ):
                        arg_node = call.args[pos]
                if arg_node is None:
                    continue
                sub, ok = self.resolve(caller_mod, arg_node, depth + 1)
                via = f"argument {name} of {getattr(func, 'name', 'lambda')}() at {caller_mod.rel}:{call.lineno}"
                found += [(n, v or via, d) for n, v, d in sub]
                complete = complete and ok
        return found, complete and bool(found), bound

    def _resolve_attribute(self, mod: _Module, node: ast.Attribute, depth: int):
        base = node.value
        if isinstance(base, ast.Name) and base.id in mod.imports:
            source, attr = mod.imports[base.id]
            target_name = source if attr is None else f"{source}.{attr}"
            target = self.modules.get(target_name)
            if target is not None and node.attr in target.constants:
                value, line = target.constants[node.attr]
                values = _strings(value)
                if values is not None:
                    return [
                        (v, f"constant {node.attr}", (target.rel, line)) for v in values
                    ], True
        if isinstance(base, ast.Name) and base.id in ("self", "cls"):
            owner = mod.enclosing(node, (ast.ClassDef,))
            hits = []
            for cls_mod, cls in self._class_family(mod, owner):
                for stmt in cls.body:
                    target = value = None
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                        target, value = stmt.targets[0], stmt.value
                    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                        target, value = stmt.target, stmt.value
                    if isinstance(target, ast.Name) and target.id == node.attr:
                        resolved = _value_strings(value)
                        if isinstance(resolved, str):
                            hits.append(
                                (
                                    resolved,
                                    f"{cls.name}.{node.attr}",
                                    (cls_mod.rel, stmt.lineno),
                                )
                            )
            if hits:
                return hits, True
        return [], False

    def _class_family(self, mod: _Module, owner: Optional[ast.AST]):
        """``owner`` and every package class that subclasses it, by base-class name."""
        if not isinstance(owner, ast.ClassDef):
            return []
        family = [(mod, owner)]
        names = {owner.name}
        changed = True
        while changed:
            changed = False
            for cls_list in self._classes.values():
                for cls_mod, cls in cls_list:
                    if (cls_mod, cls) in family:
                        continue
                    bases = {
                        _attr_chain(
                            b.value if isinstance(b, ast.Subscript) else b
                        ).split(".")[-1]
                        for b in cls.bases
                    }
                    if bases & names:
                        family.append((cls_mod, cls))
                        names.add(cls.name)
                        changed = True
        return family

    def _callers(self, mod: _Module, func: ast.AST, is_method: bool):
        """Calls in the package that can reach ``func``.

        Deliberately narrow, because a name like ``get`` is called everywhere: a
        method is reached through ``self.`` or ``cls.`` in its own module, and a
        function through its bare name in its own module or in a module that
        imports it from there.
        """
        name = getattr(func, "name", None)
        if not name:
            return []
        out = []
        for caller_mod, call in self._calls.get(name, []):
            target = call.func
            if is_method:
                if (
                    caller_mod is mod
                    and isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in ("self", "cls")
                ):
                    out.append((caller_mod, call))
            elif isinstance(target, ast.Name):
                if caller_mod is mod or caller_mod.imports.get(name) == (
                    mod.name,
                    name,
                ):
                    out.append((caller_mod, call))
            elif isinstance(target, ast.Attribute) and isinstance(
                target.value, ast.Name
            ):
                imported = caller_mod.imports.get(target.value.id)
                if imported is not None:
                    source = (
                        imported[0]
                        if imported[1] is None
                        else f"{imported[0]}.{imported[1]}"
                    )
                    if source == mod.name:
                        out.append((caller_mod, call))
        return out

    def _resolve_returns(self, fname: str, scopes):
        """Literal return values of the functions named ``fname`` defined in ``scopes``."""
        found = []
        complete = True
        for scope_mod, scope in scopes:
            for func in getattr(scope, "body", []):
                if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if func.name != fname:
                    continue
                returns = [n for n in ast.walk(func) if isinstance(n, ast.Return)]
                if not returns:
                    # An abstract method that only raises names nothing and hides
                    # nothing; any other body without a return is unresolved.
                    if not any(isinstance(n, ast.Raise) for n in ast.walk(func)):
                        complete = False
                for ret in returns:
                    value = _value_strings(ret.value) if ret.value is not None else None
                    if isinstance(value, str):
                        found.append(
                            (
                                value,
                                f"return value of {fname}()",
                                (scope_mod.rel, ret.lineno),
                            )
                        )
                    else:
                        complete = False
        return found, complete and bool(found)


def _docstring_mention(
    mod: _Module, node: ast.AST, name: str
) -> Optional[tuple[str, int]]:
    """The sentence of the enclosing function's (or module's) docstring naming ``name``."""
    scopes = []
    func = mod.enclosing(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    while func is not None:
        scopes.append(func)
        func = mod.enclosing(
            func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        )
    scopes.append(mod.tree)
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")
    for scope in scopes:
        doc = ast.get_docstring(scope)
        if not doc or not pattern.search(doc):
            continue
        line = getattr(scope, "body", [None])[0]
        lineno = getattr(line, "lineno", 1) if line is not None else 1
        found = _mentioning_text(doc, pattern)
        if found:
            return found, lineno
    return None


#: A reStructuredText section title and its underline ("License and notice files"
#: over a row of dashes), which a docstring paragraph can open with.
_RST_TITLE = re.compile(
    r"^[^\n]*\n[ \t]*([-=~^\"'`#*+])\1{2,}[ \t]*(?:\n|$)", re.MULTILINE
)


def _mentioning_text(text: str, pattern: re.Pattern) -> Optional[str]:
    """The sentence of ``text`` that names the variable, or its paragraph if that is a fragment.

    A sentence under 60 characters is usually an item cut out of a list
    ("1. ``$ASH_MCP_WORKSPACE_ROOT`` 2."), so the whole paragraph is quoted instead.
    """
    for paragraph in re.split(r"\n\s*\n", text):
        if not pattern.search(paragraph):
            continue
        paragraph = _RST_TITLE.sub("", paragraph)
        flat = " ".join(paragraph.split())
        sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z`])", flat)
        for index, sentence in enumerate(sentences):
            if not pattern.search(sentence):
                continue
            if len(sentence) < 60:
                return _first_sentences(flat)
            # Quote from the start of the paragraph, which usually says what the
            # thing is, through the sentence naming the variable -- unless that
            # runs past the length limit, in which case the sentence alone.
            lead = " ".join(sentences[: index + 1])
            quoted = _first_sentences(lead)
            return quoted if pattern.search(quoted) else _first_sentences(sentence)
    return None


def _module_mention(mod: _Module, name: str, near: int) -> Optional[tuple[str, int]]:
    """A comment block or docstring anywhere in the module that names ``name``.

    The last resort before "not documented": the nearest such text to the read.
    """
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")
    candidates: list[tuple[int, str]] = []
    comment_candidates: list[tuple[int, str]] = []
    # Comment blocks: runs of consecutive comment-only lines.
    block: list[str] = []
    start = 0
    for number in range(1, len(mod.lines) + 2):
        text = mod.lines[number - 1] if number <= len(mod.lines) else ""
        if text.lstrip().startswith("#") and number in mod.comments:
            if not block:
                start = number
            block.append(mod.comments[number])
            continue
        if block:
            found = _mentioning_text(" ".join(b or "\n\n" for b in block), pattern)
            if found:
                comment_candidates.append((start, found))
            block = []
    for node in ast.walk(mod.tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            doc = ast.get_docstring(node)
            if doc and pattern.search(doc):
                found = _mentioning_text(doc, pattern)
                body = getattr(node, "body", [])
                if found and body:
                    candidates.append((body[0].lineno, found))
    # Comment blocks first: in this codebase a ``#:`` or block comment sits on the
    # thing it describes, while a docstring that names a variable is usually
    # discussing it in passing.
    pool = comment_candidates or candidates
    if not pool:
        return None
    line, text = min(pool, key=lambda c: (abs(c[0] - near), c[0]))
    return text, line


def _python_default(
    node: Optional[ast.AST], mod: _Module, resolver: _Resolver
) -> Optional[str]:
    """A read's default as a reader would set it.

    A str literal shows its value and a module constant the constant's value. A bare
    local or parameter name is omitted: ``setdefault(key, value)`` inside a helper
    says nothing about what any one variable defaults to, and pairing the name with
    a value from some other call site would be a guess. Any other expression is
    shown as written.
    """
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        if node.value is None:
            return None
        if isinstance(node.value, str):
            return node.value
    if isinstance(node, ast.Name):
        constant = resolver.constant(mod, node.id)
        if constant is not None and isinstance(constant[0], str):
            return constant[0]
        return None
    # The source as written, not ast.unparse(): unparse's spelling of an f-string
    # changed in Python 3.12, and this page is checked on 3.10 through 3.14.
    segment = ast.get_source_segment("\n".join(mod.lines), node)
    return " ".join(segment.split()) if segment else ast.unparse(node)


def _python_reads(repo_root: Path, scan: EnvScan) -> None:
    paths = list(_files(repo_root, [f"{PACKAGE}/**/*.py"]))
    modules: dict[str, _Module] = {}
    for path in paths:
        mod = _load_module(repo_root, path)
        if mod is not None:
            modules[mod.name] = mod
    resolver = _Resolver(modules)

    for mod in sorted(modules.values(), key=lambda m: m.rel):
        for node in ast.walk(mod.tree):
            lineno = getattr(node, "lineno", 0)
            sites: list[tuple[ast.AST, str, Optional[ast.AST]]] = []

            if (
                isinstance(node, ast.Subscript)
                and _attr_chain(node.value) in _ENV_OBJECTS
            ):
                if not isinstance(mod.parent(node), ast.Delete) and isinstance(
                    node.ctx, ast.Load
                ):
                    sites.append((node.slice, "subscript", None))
            if isinstance(node, ast.Compare):
                for op, comp in zip(node.ops, node.comparators):
                    if (
                        isinstance(op, (ast.In, ast.NotIn))
                        and _attr_chain(comp) in _ENV_OBJECTS
                    ):
                        sites.append((node.left, "presence check", None))
            if isinstance(node, ast.Call):
                chain = _attr_chain(node.func)
                if chain in _GETENV and node.args:
                    default = node.args[1] if len(node.args) > 1 else None
                    for kw in node.keywords:
                        if kw.arg == "default":
                            default = kw.value
                    sites.append((node.args[0], "getenv", default))
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in _ENV_METHODS
                    and _attr_chain(node.func.value) in _ENV_OBJECTS
                    and node.args
                ):
                    default = node.args[1] if len(node.args) > 1 else None
                    shape = f"environ.{node.func.attr}"
                    if node.func.attr == "__contains__":
                        shape = "presence check"
                    sites.append((node.args[0], shape, default))
                for kw in node.keywords:
                    if kw.arg != "envvar" or (
                        isinstance(kw.value, ast.Constant) and kw.value.value is None
                    ):
                        continue
                    if isinstance(kw.value, (ast.List, ast.Tuple)):
                        for element in kw.value.elts:
                            sites.append((element, "CLI option envvar", None))
                    else:
                        sites.append((kw.value, "CLI option envvar", None))

            for key, shape, default in sites:
                names, complete = resolver.resolve(mod, key)
                if not complete:
                    source = mod.lines[lineno - 1].strip() if lineno else ""
                    scan.dynamic.append(f"{mod.rel}:{lineno} [{shape}] {source}")
                    scan.dynamic_sites.append(
                        (mod.rel, mod.scope_at(lineno), shape, source)
                    )
                stmt = mod.statement(node)
                for name, via, definition in names:
                    if not name:
                        continue
                    comment = mod.comment_for(lineno, getattr(stmt, "lineno", lineno))
                    if comment is not None and not _describes(comment[0], name):
                        # A label for the code around the read ("# Project
                        # information") is not the variable's purpose, and no
                        # purpose is better than a wrong one.
                        comment = None
                    comment_at = mod.rel if comment else None
                    comment_scope = mod.scope_at(comment[1]) if comment else ""
                    if comment is None and definition is not None:
                        def_mod = next(
                            (m for m in modules.values() if m.rel == definition[0]),
                            None,
                        )
                        if def_mod is not None:
                            found = def_mod.comment_for(definition[1], definition[1])
                            if found and not _documents(def_mod.lines, found, name):
                                found = None
                            if found:
                                comment = found
                                comment_at = def_mod.rel
                                comment_scope = def_mod.scope_at(found[1])
                    if comment is None:
                        found = _docstring_mention(mod, node, name) or _module_mention(
                            mod, name, lineno
                        )
                        if found:
                            comment = found
                            comment_at = mod.rel
                            comment_scope = mod.scope_at(found[1])
                    scan.reads.append(
                        EnvRead(
                            name=name,
                            path=mod.rel,
                            line=lineno,
                            language="python",
                            shape=shape,
                            default=_python_default(default, mod, resolver),
                            via=(
                                f"{via} ({definition[0]}:{definition[1]})"
                                if via and definition
                                else via
                            ),
                            comment=_first_sentences(comment[0]) if comment else None,
                            comment_at=comment_at,
                            scope=mod.scope_at(lineno),
                            comment_scope=comment_scope,
                        )
                    )


# ---------------------------------------------------------------------------
# Shell, PowerShell, Dockerfile
# ---------------------------------------------------------------------------

_SH_COMMENT = re.compile(r"(^|\s)#.*$")
_SH_ASSIGN = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)\+?="
)
_SH_EXPORT_NAMES = re.compile(
    r"^\s*(?:export|local|readonly)\s+([A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s*$"
)
_SH_FOR = re.compile(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b")
_SH_READ = re.compile(r"\bread\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _strip_shell_comment(line: str) -> str:
    if line.lstrip().startswith("#!"):
        return ""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single and (i == 0 or line[i - 1] != "\\"):
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1].isspace():
                return line[:i]
    return line


def _shell_expansions(line: str) -> Iterator[tuple[str, Optional[str], Optional[str]]]:
    """Yield ``(name, operator, word)`` for each ``$NAME`` and ``${NAME...}`` in ``line``.

    Braces are matched with nesting, so ``${A:-"x:${B}"}`` yields A with the whole
    default word and then B.
    """
    i = 0
    while i < len(line):
        if line[i] != "$" or (i > 0 and line[i - 1] == "\\"):
            i += 1
            continue
        if line.startswith("${", i):
            depth, j = 0, i + 1
            while j < len(line):
                if line[j] == "{":
                    depth += 1
                elif line[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            inner = line[i + 2 : j]
            match = re.match(
                r"([A-Za-z_][A-Za-z0-9_]*)(:?[-=?+])?(.*)$", inner, re.DOTALL
            )
            if match:
                yield (
                    match.group(1),
                    match.group(2),
                    match.group(3) if match.group(2) else None,
                )
            yield from _shell_expansions(inner)
            i = j + 1
            continue
        match = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", line[i:])
        if match:
            yield match.group(1), None, None
            i += len(match.group(0))
            continue
        i += 1


def _shell_reads(repo_root: Path, scan: EnvScan) -> None:
    scripts = _files(repo_root, [*SHELL_SCRIPT_GLOBS, f"{PACKAGE}/**/*.sh"])
    parsed: list[tuple[str, list[str], list[str]]] = []
    assigned: set[str] = set()
    for path in scripts:
        rel = path.relative_to(repo_root).as_posix()
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
        code_lines = [_strip_shell_comment(line) for line in raw]
        for line in code_lines:
            for regex in (_SH_ASSIGN, _SH_FOR, _SH_READ):
                for match in regex.finditer(line):
                    assigned.add(match.group(1))
            names = _SH_EXPORT_NAMES.match(line)
            if names:
                assigned.update(names.group(1).split())
        parsed.append((rel, raw, code_lines))

    for rel, raw, code_lines in parsed:
        scopes = _script_scopes(code_lines, _SH_FUNCTION)
        # Names this script assigns unconditionally (at column 0) before a line.
        # A defaulted expansion of such a name reads the script's own value, not
        # the environment: `RESOLVED=x` then `${RESOLVED:-none}`.
        set_before: set[str] = set()
        for number, line in enumerate(code_lines, start=1):
            for name, operator, word in _shell_expansions(line):
                if not _ENV_NAME.match(name) or name in _SHELL_SPECIAL:
                    continue
                if name in assigned and not operator:
                    continue
                if operator and name in set_before:
                    continue
                default = None
                if operator and operator.lstrip(":") in ("-", "="):
                    default = word
                    if (
                        len(default) >= 2
                        and default[0] == default[-1]
                        and default[0] in "\"'"
                    ):
                        default = default[1:-1]
                comment = _shell_comment_above(raw, number)
                if comment is not None and not (
                    _describes(comment[0], name)
                    or re.match(
                        rf"^\s*(?:export\s+|readonly\s+|local\s+)?{re.escape(name)}=",
                        raw[number - 1],
                    )
                ):
                    # As for Python, and also taken when the line it heads assigns
                    # the variable itself.
                    comment = None
                scan.reads.append(
                    EnvRead(
                        name=name,
                        path=rel,
                        line=number,
                        language="shell",
                        shape=f"${{{name}{operator}...}}" if operator else f"${name}",
                        default=default,
                        comment=_first_sentences(comment[0]) if comment else None,
                        comment_at=rel if comment else None,
                        scope=scopes[number - 1],
                        comment_scope=scopes[comment[1] - 1] if comment else "",
                    )
                )
            top = re.match(
                r"^(?:export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)\+?=", line
            )
            if top:
                set_before.add(top.group(1))


#: A shell function definition: ``name() {`` or ``function name {``.
_SH_FUNCTION = re.compile(
    r"^(?P<indent>\s*)(?:function\s+(?P<a>[A-Za-z_][\w-]*)\s*(?:\(\s*\))?"
    r"|(?P<b>[A-Za-z_][\w-]*)\s*\(\s*\))\s*\{?\s*$"
)
#: A PowerShell function definition: ``function Verb-Noun {``.
_PS_FUNCTION = re.compile(
    r"^(?P<indent>\s*)function\s+(?P<a>[A-Za-z_][\w-]*)(?P<b>)\s*(?:\([^)]*\))?\s*\{?\s*$",
    re.IGNORECASE,
)


def _script_scopes(lines: list[str], definition: re.Pattern) -> list[str]:
    """The function each line of a shell or PowerShell script is in; "" at top level.

    A function starts at its definition line and ends at the first line that is
    only ``}`` at the definition's indentation, which is how the shipped scripts
    are written. Nested definitions are dotted, as Python scopes are.
    """
    stack: list[tuple[str, str]] = []
    scopes: list[str] = []
    for line in lines:
        match = definition.match(line)
        if match:
            stack.append((match.group("a") or match.group("b"), match.group("indent")))
            scopes.append(".".join(name for name, _ in stack))
            continue
        scopes.append(".".join(name for name, _ in stack))
        indent = line[: len(line) - len(line.lstrip())]
        if stack and line.strip() == "}" and indent == stack[-1][1]:
            stack.pop()
    return scopes


def _describes(text: str, name: str) -> bool:
    """Whether a comment next to a read can be quoted as the variable's purpose.

    It names the variable, or it is written as a sentence. What it must not be is
    a label for the code around it, which is how the wrong purposes looked:
    "Project information", "Resolve build target", "Check for npm cache
    directory", none of them a sentence and none naming the variable.
    """
    words = text.split()
    return name in text or (len(words) >= 4 and text.rstrip().endswith((".", "!", "?")))


def _documents(lines: list[str], comment: tuple[str, int], name: str) -> bool:
    """Whether a comment above the constant that holds ``name`` documents it.

    A ``#:`` comment documents the assignment under it, by the Sphinx convention
    this package follows; a plain one only as :func:`_describes` allows, because
    it may head a group of constants.
    """
    first = lines[comment[1] - 1].lstrip() if comment[1] - 1 < len(lines) else ""
    return first.startswith("#:") or _describes(comment[0], name)


def _shell_comment_above(raw: list[str], number: int) -> Optional[tuple[str, int]]:
    block: list[str] = []
    cur = number - 1
    while (
        cur >= 1
        and raw[cur - 1].lstrip().startswith("#")
        and not raw[cur - 1].lstrip().startswith("#!")
    ):
        block.insert(0, raw[cur - 1].lstrip().lstrip("#").strip())
        cur -= 1
    text = " ".join(b for b in block if b)
    return (text, cur + 1) if text else None


_PS_BLOCK_COMMENT = re.compile(r"<#.*?#>", re.DOTALL)
_PS_ENV = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)(\s*=(?!=))?", re.IGNORECASE)
_PS_GETENV = re.compile(
    r"\[(?:System\.)?Environment\]::GetEnvironmentVariable\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    re.IGNORECASE,
)


def _powershell_reads(repo_root: Path, scan: EnvScan) -> None:
    for path in _files(repo_root, POWERSHELL_SCRIPT_GLOBS):
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        # Blank block comments out line for line so reported line numbers still match.
        text = _PS_BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
        lines = [re.sub(r"(^|\s)#.*$", "", line) for line in text.splitlines()]
        scopes = _script_scopes(lines, _PS_FUNCTION)
        for number, stripped in enumerate(lines, start=1):
            for match in _PS_ENV.finditer(stripped):
                if match.group(2):
                    continue
                scan.reads.append(
                    EnvRead(
                        match.group(1),
                        rel,
                        number,
                        "powershell",
                        "$env:",
                        scope=scopes[number - 1],
                    )
                )
            for match in _PS_GETENV.finditer(stripped):
                scan.reads.append(
                    EnvRead(
                        match.group(1),
                        rel,
                        number,
                        "powershell",
                        "GetEnvironmentVariable",
                        scope=scopes[number - 1],
                    )
                )


_DOCKER_ENV = re.compile(r"^\s*ENV\s+(.*)$", re.IGNORECASE)
_DOCKER_FROM = re.compile(r"^\s*FROM\s+\S+(?:\s+AS\s+(\S+))?", re.IGNORECASE)


def _dockerfile_env(repo_root: Path) -> dict[str, list[tuple[str, str, int]]]:
    path = repo_root / DOCKERFILE
    found: dict[str, list[tuple[str, str, int]]] = {}
    if not path.is_file():
        return found
    stage = ""
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        frm = _DOCKER_FROM.match(line)
        if frm:
            stage = frm.group(1) or ""
            continue
        env = _DOCKER_ENV.match(line)
        if not env:
            continue
        body = env.group(1).strip()
        if "=" in body.split()[0]:
            for match in re.finditer(
                r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S*)', body
            ):
                found.setdefault(match.group(1), []).append(
                    (stage, match.group(2).strip('"'), number)
                )
        else:
            name, _, value = body.partition(" ")
            found.setdefault(name, []).append((stage, value.strip().strip('"'), number))
    return found


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def collect_env_reads(repo_root: Optional[Path] = None) -> EnvScan:
    """Every environment read in the tree at ``repo_root`` (default: this checkout)."""
    root = Path(repo_root or REPO_ROOT).resolve()
    scan = EnvScan()
    _python_reads(root, scan)
    _shell_reads(root, scan)
    _powershell_reads(root, scan)
    names = {r.name for r in scan.reads}
    scan.image_env = {k: v for k, v in _dockerfile_env(root).items() if k in names}
    scan.reads.sort(key=lambda r: (r.name, r.path, r.line, r.shape))
    scan.dynamic = sorted(set(scan.dynamic))
    scan.dynamic_sites = sorted(set(scan.dynamic_sites))
    return scan


def read_env_names(repo_root: Optional[Path] = None) -> tuple[set[str], list[str]]:
    """Return (names of environment variables ASH reads, unresolved lookup sites).

    The interface the docs doctest imports. The second element lists every lookup
    whose key could not be resolved statically, as ``path:line [shape] source``. A
    caller asserting that a name is NOT read must account for those sites rather
    than treat the first element as exhaustive.
    """
    scan = collect_env_reads(repo_root)
    return {r.name for r in scan.reads}, list(scan.dynamic)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


def _cli_envvars() -> dict[str, list[tuple[str, str, str, str]]]:
    """envvar name -> [(command label, option, anchor, default, help)] from the click tree."""
    from generate_cli_docs import (
        format_default,
        iter_commands,
        load_root_command,
        param_anchor,
    )

    found: dict[str, list] = {}
    for path, cmd, _ctx in iter_commands(load_root_command()):
        if not path:
            continue  # the root shares scan's options; scan's rows are enough
        for param in cmd.params:
            envvars = param.envvar
            if not envvars:
                continue
            for name in [envvars] if isinstance(envvars, str) else list(envvars):
                found.setdefault(name, []).append(
                    (
                        "ash " + " ".join(path),
                        param.opts[0] if param.opts else param.name,
                        param_anchor(path, param),
                        format_default(param),
                        " ".join((param.help or "").split()),
                    )
                )
    return found


def _scope_text(scope: str, language: str) -> str:
    if scope:
        return code(scope)
    return "module level" if language == "python" else "top level"


def _sites(reads: list[EnvRead]) -> str:
    """Each file a variable is read in, with the functions it is read in.

    No line numbers: a page that cited them went stale whenever any line above a
    read moved, which is nearly every change to a file that reads a variable.
    """
    by_path: dict[str, set[tuple[str, str]]] = {}
    for r in reads:
        by_path.setdefault(r.path, set()).add((r.scope, r.language))
    return "<br>".join(
        f"{code(p)} ("
        + ", ".join(_scope_text(s, lang) for s, lang in sorted(scopes))
        + ")"
        for p, scopes in sorted(by_path.items())
    )


def _default_entries(reads: list[EnvRead], cli: list, config: list) -> list[str]:
    """The entries of a variable's Default column: each read's default, else the
    defaults of the CLI options it sets, else those of the config keys it is the
    default of.

    When ``""`` is the only default the reads give, it counts as none if an option
    or config key gives one. ``os.environ.get(NAME, "")`` is how a read spells
    unset, and the option's default says what unset means: ASH_BIN_PATH's lookup
    cache keys on that ``""``, and unset, the variable means ``~/.ash/bin``, not an
    empty path. Beside a read that gives a value, ``""`` stays, as one of the
    spellings the code uses.
    """
    values = []
    for r in reads:
        if r.default is None:
            continue
        shown = r.default if r.default != "" else '""'
        if shown not in values:
            values.append(shown)
    if values == ['""'] and (cli or config):
        values = []
    entries = [code(v) for v in values]
    if not entries and cli:
        entries = sorted({c[3] for c in cli})
    if not entries and config:
        entries = sorted(
            {f"{value} (the default of {code(key)})" for key, _l, value in config}
        )
    return entries


def default_entries(
    repo_root: Optional[Path] = None, with_cli: bool = True
) -> dict[str, list[str]]:
    """Every variable's Default column entries, as the page renders them.

    The interface the docs checks use to compare a hand-written table's Default
    column with what the code gives. With ``with_cli`` the CLI options and config
    keys a variable is the default of are imported and read; without it only the
    reads themselves are.
    """
    scan = collect_env_reads(Path(repo_root or REPO_ROOT).resolve())
    cli = _cli_envvars() if with_cli else {}
    config = _config_env_sources() if with_cli else {}
    by_name: dict[str, list[EnvRead]] = {}
    for r in scan.reads:
        by_name.setdefault(r.name, []).append(r)
    for name in cli:
        by_name.setdefault(name, [])
    return {
        name: _default_entries(reads, cli.get(name, []), config.get(name, []))
        for name, reads in by_name.items()
    }


def _config_env_sources() -> dict[str, list[tuple[str, str, str]]]:
    """Variable -> [(config key, its page and anchor, its default)] it is the source of.

    A default such as ``global_settings.severity_threshold`` that the model reads
    from ``ASH_DEFAULT_SEVERITY_LEVEL`` is found by the configuration generator in
    the model source (``env_defaults``), for the AshConfig tree and every plugin's
    options. The default shown is the key's own with nothing set, which is what
    the variable falls back to: the read itself (a call into a resolver, for the
    severity level) need not say.
    """
    from _plugin_reference import discover
    from generate_config_reference import default_text, env_defaults, walk_config

    from automated_security_helper.config.ash_config import AshConfig

    found: dict[str, list[tuple[str, str, str]]] = {}
    sections, _missing = walk_config(AshConfig)
    for section in sections:
        for row in section.rows:
            for name in row["env_default"] or []:
                full = row["full"].replace("[]", "")
                found.setdefault(name, []).append(
                    (full, f"configuration.md#{full}", default_text(row["field"]))
                )
    for kind, page in (
        ("scanner", "scanners.md"),
        ("reporter", "reporters.md"),
        ("converter", "converters.md"),
    ):
        for plugin in discover(kind):
            model = plugin.options_cls
            if model is None:
                continue
            for field_name, names in env_defaults(model).items():
                info = model.model_fields.get(field_name)
                if info is None:
                    continue
                key = f"{kind}s.{plugin.name}.options.{info.alias or field_name}"
                for name in names:
                    found.setdefault(name, []).append(
                        (key, f"{page}#{key}", default_text(info))
                    )
    return {name: sorted(set(rows)) for name, rows in found.items()}


def _purpose(
    name: str, reads: list[EnvRead], cli: list, config: list | None = None
) -> tuple[str, bool]:
    if cli:
        parts = []
        for label, opt, anchor, _default, help_text in cli:
            link = f"[{code(label + ' ' + opt)}](cli.md#{anchor})"
            parts.append(
                f"Sets {link}." + (f" {md_prose(help_text)}" if help_text else "")
            )
        # One option's text is enough when several commands share the help text.
        unique_help = {c[4] for c in cli}
        if len(unique_help) == 1 and len(parts) > 1:
            links = ", ".join(
                f"[{code(c[0] + ' ' + c[1])}](cli.md#{c[2]})" for c in cli
            )
            text = next(iter(unique_help))
            return f"Sets {links}." + (f" {md_prose(text)}" if text else ""), True
        return "<br>".join(parts), True
    if config:
        # Taken from the model ahead of any comment: it says what the variable is
        # for in the terms a configuration file uses.
        keys = ", ".join(f"[{code(key)}]({link})" for key, link, _default in config)
        return f"Sets the default of {keys}.", True
    for r in reads:
        if r.comment:
            where = code(r.comment_at)
            if r.comment_scope:
                where += f", {code(r.comment_scope)}"
            return f"{md_prose(r.comment)} ({where})", True
    return PURPOSE_UNDOCUMENTED, False


def generate(
    repo_root: Optional[Path] = None, with_cli: bool = True
) -> tuple[str, dict]:
    root = Path(repo_root or REPO_ROOT).resolve()
    scan = collect_env_reads(root)
    cli = _cli_envvars() if with_cli else {}
    config_sources = _config_env_sources() if with_cli else {}

    by_name: dict[str, list[EnvRead]] = {}
    for r in scan.reads:
        by_name.setdefault(r.name, []).append(r)
    for name in cli:
        by_name.setdefault(name, [])

    stats = {
        "variables": len(by_name),
        "undocumented": [],
        "dynamic": len(scan.dynamic),
    }

    def table(names: list[str]) -> list[str]:
        rows = [
            "| Variable | Default | Container image | Read at | Purpose |",
            "|----------|---------|-----------------|---------|---------|",
        ]
        for name in names:
            reads = by_name[name]
            options = cli.get(name, [])
            config = config_sources.get(name, [])
            purpose, documented = _purpose(name, reads, options, config)
            if not documented:
                stats["undocumented"].append(name)
            default = "<br>".join(_default_entries(reads, options, config))
            image = "<br>".join(
                f"{code(value)} ({stage or 'all stages'})"
                for stage, value, _line in scan.image_env.get(name, [])
            )
            rows.append(
                f"| {code(name)} | {default} | {image} | {_sites(reads)} | {purpose} |"
            )
        return rows

    ash_names = sorted(n for n in by_name if n.startswith("ASH_"))
    other_names = sorted(n for n in by_name if not n.startswith("ASH_"))

    from_constants = _config_interpolation(root)

    lines = banner(GENERATOR, "an AST walk of the package and the shipped scripts")
    lines += [
        "# Environment variables",
        "",
        generated_note(GENERATOR, "the code that reads each variable"),
        "",
        (
            f"ASH reads {len(by_name)} environment variables: {len(ash_names)} of its own "
            f"(`ASH_` prefix) and {len(other_names)} set by other tools or the platform. "
            "The tables list every place each one is read. A variable that sets a CLI "
            "option links to that option; the option on the command line takes "
            "precedence over the variable."
        ),
        "",
        "Columns:",
        "",
        (
            "- Default: the value the code uses when the variable is unset, as written in "
            "the code, at each read that supplies one. Where none does, or the only one is "
            "an empty string, it is the default of the CLI option the variable sets, or of "
            "the configuration key it is the default of. Blank means none of these supplies "
            "one (the code checks whether the variable is set, or treats unset as empty)."
        ),
        (
            "- Container image: the value the ASH container image sets, from an `ENV` line "
            "in the `Dockerfile`, and the build stage that sets it."
        ),
        (
            "- Read at: the file of each read and the function, method or script "
            "function it is in, or module level or top level when it is in none. "
            "`ash` and `utils/` are the shell "
            "and PowerShell entry scripts; everything else is the Python package."
        ),
        (
            "- Purpose: the option's help text, or the code comment or docstring at the "
            f'read, quoted with the file and function it is in. "{PURPOSE_UNDOCUMENTED}" means the code '
            "around the read does not say."
        ),
        "",
        "## ASH variables",
        "",
        *table(ash_names),
        "",
        "## Variables from other tools and the platform",
        "",
        *table(other_names),
        "",
    ]
    if from_constants:
        prefix, allowlist, where = from_constants
        lines += [
            "## Variables a configuration file can read",
            "",
            "A value in a configuration file that begins with `${NAME}` or "
            "`${NAME:default}` has the reference replaced by that environment "
            "variable. Only names that start with "
            f"{code(prefix)} and these names are substituted: "
            + ", ".join(code(n) for n in allowlist)
            + ". Any other reference is left as written, with a warning. The prefix "
            f"and the list are defined in {code(where)}.",
            "",
        ]
    lines += [
        "## Lookups that could not be resolved",
        "",
        (
            "These reads take the variable name from a value the generator cannot "
            "resolve without running ASH: a name read from a configuration file, built "
            "at run time, or passed in from somewhere it cannot follow. A variable read "
            "only through one of these sites is not in the tables above."
        ),
        "",
    ]
    if scan.dynamic_sites:
        lines += [
            "```text",
            *(
                f"{path} ({scope or 'module level'}) [{shape}] {source}"
                for path, scope, shape, source in scan.dynamic_sites
            ),
            "```",
            "",
        ]
    else:
        lines += ["None.", ""]

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n", stats


def _config_interpolation(root: Path) -> Optional[tuple[str, list[str], str]]:
    rel = f"{PACKAGE}/core/constants.py"
    path = root / rel
    if not path.is_file():
        return None
    mod = _load_module(root, path)
    if mod is None:
        return None
    prefix = mod.constants.get("ASH_CONFIG_ENV_VAR_PREFIX")
    allow = mod.constants.get("ASH_CONFIG_ENV_VAR_ALLOWLIST")
    if not prefix or not allow or not isinstance(prefix[0], str):
        return None
    return prefix[0], list(allow[0]), rel


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
        "--repo-root",
        default=None,
        help="Code tree to scan for reads (default: the source tree of the "
        "automated_security_helper this interpreter imports, which is also where "
        "the CLI options are read from).",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    code_root = prepare_environment(Path(args.docs_root))
    output = Path(args.output) if args.output else reference_dir(args.docs_root) / PAGE
    content, stats = generate(Path(args.repo_root) if args.repo_root else code_root)
    summary = (
        f"{stats['variables']} variables, {len(stats['undocumented'])} with no purpose "
        f"in the code, {stats['dynamic']} unresolved lookup sites."
    )
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
