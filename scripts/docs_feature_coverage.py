#!/usr/bin/env python3
"""Which product features do the executed docs examples reach?

The docs examples job runs every runnable block of every docs page in a subprocess
(tests/integration/docs/docs_runner.py). With ``ASH_DOCS_COVERAGE_DIR`` set, coverage.py
measures the ``automated_security_helper`` code each of those subprocesses runs and
labels every line with the block that ran it (the context ``<page>::<fence line>``),
and the runner records, per page, every block it ran or saved. This script reads both
and answers, per feature, whether a passing executed example reached it.

Features are enumerated from code, never listed by hand:

* ``command:ash scan``: a command of the click tree (commands that share a callback are
  one feature, named by the longest visible path), measured in the callback's code;
* ``option:ash scan --scanners``: an option of such a command, which counts only when a
  block gives it on its command line and reaches the command's code;
* ``scanner:bandit``, ``reporter:sarif``, ``converter:archive``: a plugin the plugin
  modules register, measured in the work method the framework leaves to the plugin;
* ``config:global_settings.severity_threshold``: a row of the generated configuration
  reference, which counts when a block loads a saved configuration holding the key or
  gives it with ``--config-overrides``;
* ``mcp-tool:run_ash_scan``: a tool the MCP server registers, measured in its body.

Why options and keys are not plain code reach: an option's parameter and a config field
are read on every invocation, with their defaults, so reaching the code alone would mark
every option of every command the docs run as covered. The example's own text names what
it demonstrates; coverage proves that the block ran and reached the code that uses it.

``check`` fails (exit 1) on an uncovered feature missing from the shrink-only baseline
(scripts/docs_feature_coverage_baseline.txt) and on a baseline line that names no
feature; given the base branch's baseline it also fails on a line for a covered feature
and on a line the pull request added. It exits 2 when the measurement cannot be
trusted: nothing was measured, the data does not fit the docs tree, or the inventory
cannot be built the same everywhere.

Not measured: processes outside this interpreter's environment (a scanner's own tool,
``uvx``, a container), a sandboxed scanner's Python (the sandbox passes on an allowlist
of environment variables, and ``COVERAGE_PROCESS_START`` is not on it), and a process
killed by SIGKILL at a block's timeout. Plugins that share one work method cannot be
told apart by line coverage, so covering one covers each of them.
"""

from __future__ import annotations

import argparse
import ast
import functools
import importlib
import importlib.util
import inspect
import json
import os
import pkgutil
import re
import sys
import tempfile
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
#: The shrink-only baseline, beside the script the way scripts/ty_ceiling.txt sits
#: beside its check. CI allows exactly one docs-examples step to name a path under
#: tests/integration/docs, so the check cannot be handed a file from there.
DEFAULT_BASELINE = SCRIPTS_DIR / "docs_feature_coverage_baseline.txt"

PACKAGE = "automated_security_helper"
KINDS = ("command", "option", "scanner", "reporter", "converter", "config", "mcp-tool")
PLUGIN_KINDS = ("scanner", "reporter", "converter")
REPORT_JSON = "docs-feature-coverage.json"
REPORT_MD = "docs-feature-coverage.md"
BASELINE_OUT = "docs_feature_coverage_baseline.txt"
REPORT_SCHEMA = 1
#: How many ids per failing class the markdown lists before it counts the rest.
LISTED_IDS = 50

BASELINE_HEADER = """\
# Product features that no executed docs example reaches yet.
#
# This file may only shrink. scripts/docs_feature_coverage.py check fails on an
# uncovered feature that is not listed here and on a listed line that names no feature,
# and, in a pull request, on a line the base branch's file lacks and on a line for a
# feature an executed example now reaches: delete that line then.
#
# Never add a feature. A new command, option, plugin or configuration key ships with an
# executed docs example that reaches it. A feature that is renamed or removed leaves
# nothing to allow, so its line is deleted with it.
#
# One feature id per line, `<kind>:<name>`, in sorted order.
"""


class MeasurementError(Exception):
    """Any reason the measurement cannot be trusted: the run exits 2, not 0 or 1."""


class InventoryError(MeasurementError):
    """The feature inventory cannot be built the same way wherever the check runs."""


# --------------------------------------------------------------------------- #
# Loading the repository's other scripts
# --------------------------------------------------------------------------- #


def _load_script(name: str, filename: str):
    """A script of this directory, loaded by path (scripts/ is not a package).

    Registered in sys.modules before it runs, under the name the docs runner and
    verify_docs_freshness.py use for it, so one process holds one copy.
    """
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    if spec is None or spec.loader is None:
        raise MeasurementError(f"cannot load {SCRIPTS_DIR / filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def _checks():
    """scripts/docs_checks.py, the parser the docs checks and the runner share."""
    return _load_script("_ash_docs_checks", "docs_checks.py")


def _freshness():
    return _load_script(
        "_ash_verify_docs_freshness_for_coverage", "verify_docs_freshness.py"
    )


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Region:
    """The lines of one file that show a feature ran: ``path`` is repository-relative
    POSIX, from ``automated_security_helper/`` on, so data recorded in another checkout
    (a CI runner's) still matches."""

    path: str
    lines: frozenset[int]


@dataclass(frozen=True)
class Feature:
    id: str
    regions: tuple[Region, ...] = ()
    #: ``path:line`` of the code, for the report.
    location: str = ""
    note: str = ""
    #: For a command or an option: the paths of every command that runs the same
    #: callback (hidden aliases included), which an invocation may name.
    paths: tuple[tuple[str, ...], ...] = ()
    #: For an option: its canonical name, the first ``--`` spelling.
    canonical: str = ""

    @property
    def kind(self) -> str:
        return self.id.partition(":")[0]

    @property
    def name(self) -> str:
        return self.id.partition(":")[2]


@dataclass(frozen=True)
class Evaluation:
    covered: frozenset[str]
    presented: frozenset[str]
    denominators: Mapping[str, int]
    #: Feature id -> the pages whose executed blocks covered it.
    pages: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Regions: the code that shows a feature ran
# --------------------------------------------------------------------------- #


def _is_early_exit(statement: ast.stmt) -> bool:
    """A top-level ``if`` with no ``else`` (an ``elif`` is an ``else``) whose body ends
    in ``return`` or ``raise``."""
    return (
        isinstance(statement, ast.If)
        and not statement.orelse
        and isinstance(statement.body[-1], (ast.Return, ast.Raise))
    )


def _without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _find_function(
    tree: ast.AST, name: str, firstlineno: int
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != name:
            continue
        first = node.decorator_list[0].lineno if node.decorator_list else node.lineno
        if firstlineno in (node.lineno, first):
            return node
    raise InventoryError(
        f"no function {name!r} has its def or first decorator on line {firstlineno}"
    )


def _region_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[int]:
    """The statements past the function's last early exit, each as its full span.

    Importing a module runs its def lines, decorators and default values, and a
    docstring is not executed, so none of them shows the function ran. The statements
    up to a last early exit run on calls that do none of the function's work: the scan
    callback's ``ctx.invoked_subcommand`` exit runs before every subcommand, so a
    block that ran any other ``ash`` command would otherwise cover the scan. A
    statement is its whole span because coverage can record a continuation line. When
    nothing follows the last early exit the whole body is the region.
    """
    body = _without_docstring(node.body)
    exits = [index for index, statement in enumerate(body) if _is_early_exit(statement)]
    if exits and exits[-1] + 1 < len(body):
        body = body[exits[-1] + 1 :]
    lines = frozenset(
        line
        for statement in body
        for line in range(
            statement.lineno, (statement.end_lineno or statement.lineno) + 1
        )
    )
    if not lines:
        raise InventoryError(
            f"{node.name} (line {node.lineno}) has no statement to measure"
        )
    return lines


def region_lines(source: str, name: str, firstlineno: int) -> frozenset[int]:
    """The region of the function ``name`` whose def line, or first decorator's line, is
    ``firstlineno`` (a function's ``__code__.co_firstlineno``)."""
    return _region_of(_find_function(ast.parse(source), name, firstlineno))


def _raises_only_not_implemented(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A function that does nothing but raise NotImplementedError never runs."""
    body = _without_docstring(node.body)
    if len(body) != 1 or not isinstance(body[0], ast.Raise) or body[0].exc is None:
        return False
    exc = body[0].exc
    target = exc.func if isinstance(exc, ast.Call) else exc
    return isinstance(target, ast.Name) and target.id == "NotImplementedError"


def _calls_super_scan(node: ast.AST) -> bool:
    """Whether a function calls ``super().scan(...)``, the framework's template."""
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "scan"
        and isinstance(call.func.value, ast.Call)
        and isinstance(call.func.value.func, ast.Name)
        and call.func.value.func.id == "super"
        for call in ast.walk(node)
    )


def _package_path(path: str) -> str:
    """``automated_security_helper/...`` from the last such component of ``path``."""
    text = path.replace("\\", "/")
    index = text.rfind(f"{PACKAGE}/")
    while index > 0 and text[index - 1] != "/":
        index = text.rfind(f"{PACKAGE}/", 0, index)
    if index < 0:
        raise InventoryError(f"{path} is not inside the {PACKAGE} package")
    return text[index:]


@functools.lru_cache(maxsize=None)
def _parsed(path: str) -> tuple[str, ast.AST]:
    source = Path(path).read_text(encoding="utf-8")
    return source, ast.parse(source)


def _unwrapped(fn: Any):
    """The function under any wrappers (functools.wraps, lru_cache, Typer's)."""
    fn = inspect.unwrap(getattr(fn, "__func__", fn))
    if not hasattr(fn, "__code__"):
        raise InventoryError(
            f"{fn!r} is not a Python function, so it has no code to measure"
        )
    return fn


def _is_framework_code(fn: Any) -> bool:
    return str(getattr(fn, "__module__", "") or "").partition(".")[0] in (
        "typer",
        "click",
    )


def _function_info(fn: Any) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """(package-relative path, syntax node) of a function."""
    fn = _unwrapped(fn)
    if _is_framework_code(fn):
        raise InventoryError(
            f"{fn.__module__}.{fn.__name__} belongs to typer or click, not to {PACKAGE}"
        )
    filename = inspect.getsourcefile(fn)
    if filename is None:
        raise InventoryError(f"{fn.__qualname__} has no source file")
    _source, tree = _parsed(str(Path(filename).resolve()))
    node = _find_function(tree, fn.__name__, fn.__code__.co_firstlineno)
    return _package_path(Path(filename).resolve().as_posix()), node


def function_region(fn: Any) -> Region:
    path, node = _function_info(fn)
    return Region(path=path, lines=_region_of(node))


def code_feature(feature_id: str, fn: Any) -> Feature:
    """A feature shown by its function's region."""
    region = function_region(fn)
    return Feature(
        id=feature_id,
        regions=(region,),
        location=f"{region.path}:{_unwrapped(fn).__code__.co_firstlineno}",
    )


# --------------------------------------------------------------------------- #
# The inventory: commands and options
# --------------------------------------------------------------------------- #

_COMPLETION_OPTIONS = frozenset({"--install-completion", "--show-completion"})


def _canonical(names: Sequence[str]) -> str:
    """The first ``--`` spelling, else the first spelling."""
    return next((name for name in names if name.startswith("--")), names[0])


def _hidden(command: Any) -> bool:
    return bool(
        getattr(command, "hidden", False) or getattr(command, "deprecated", False)
    )


def _walk_commands(
    command: Any, path: tuple[str, ...]
) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, command
    subcommands = getattr(command, "commands", None) or {}
    for name in sorted(subcommands):
        yield from _walk_commands(subcommands[name], path + (name,))


def cli_features(root: Any) -> list[Feature]:
    """The commands and options of a click tree (``typer.main.get_command(app)``).

    Commands that run one callback are one feature: line coverage cannot tell them
    apart (bare ``ash`` is ``ash scan`` through the same function, and a hidden alias
    registers it again). The feature is named by the longest path that is neither
    hidden nor deprecated, and an invocation of any member path is evidence for it. A
    group with no callback runs no code of its own and is no feature; its subcommands
    are. The options are the parameters typer built, which are not ``click.Option``
    instances (typer builds its tree from its own vendored click), so they are read by
    ``param_type_name``.
    """
    groups: dict[Any, list[tuple[tuple[str, ...], Any]]] = defaultdict(list)
    for path, command in _walk_commands(root, ("ash",)):
        if command.callback is None:
            continue
        callback = _unwrapped(command.callback)
        if _is_framework_code(callback):
            raise InventoryError(
                f"'{' '.join(path)}' runs {callback.__module__}.{callback.__name__}, "
                f"which belongs to typer or click: nothing of {PACKAGE} could reach it"
            )
        groups[callback].append((path, command))

    features: list[Feature] = []
    for callback, members in groups.items():
        visible = [path for path, command in members if not _hidden(command)]
        if not visible:
            continue
        name = " ".join(min(visible, key=lambda path: (-len(path), path)))
        region = function_region(callback)
        paths = tuple(sorted(path for path, _ in members))
        location = f"{region.path}:{callback.__code__.co_firstlineno}"
        features.append(
            Feature(
                id=f"command:{name}",
                regions=(region,),
                location=location,
                paths=paths,
            )
        )
        options: dict[str, list[Region]] = {}
        for _path, command in members:
            for param in command.params:
                if getattr(param, "param_type_name", "") != "option" or param.hidden:
                    continue
                names = tuple(param.opts) + tuple(param.secondary_opts)
                if not names or _COMPLETION_OPTIONS & set(names):
                    continue
                extra = options.setdefault(_canonical(names), [])
                if param.callback is not None:
                    try:
                        found = function_region(param.callback)
                    except InventoryError:
                        continue  # typer's own or a lambda: no code of the package's
                    if found not in extra and found != region:
                        extra.append(found)
        for canonical, extra in options.items():
            features.append(
                Feature(
                    id=f"option:{name} {canonical}",
                    regions=(region, *extra),
                    location=location,
                    paths=paths,
                    canonical=canonical,
                )
            )
    if not any(feature.kind == "option" for feature in features):
        raise InventoryError(
            "the command tree yields no option at all, so it was read wrong "
            "(typer builds it from its own vendored click)"
        )
    return features


# --------------------------------------------------------------------------- #
# The inventory: plugins
# --------------------------------------------------------------------------- #


def _defined_below(cls: type, base: type, name: str) -> Any:
    """The most-derived definition of ``name`` in the classes below ``base``, or None."""
    for klass in cls.__mro__:
        if klass is base:
            return None
        if name in vars(klass):
            return vars(klass)[name]
    return None


def _work_method(cls: type, kind: str) -> Any:
    """The function that does a plugin's work, which the framework leaves to it.

    A scanner's work is its ``_execute_scan``, which ``ScannerPluginBase.scan`` (the
    template) calls. A scanner whose own ``scan`` does not call ``super().scan(...)``
    replaced the template, so its ``_execute_scan`` is a stub that never runs and the
    work is in that ``scan``. A reporter's is ``report``, a converter's ``convert``.
    """
    if kind == "scanner":
        from automated_security_helper.base.scanner_plugin import ScannerPluginBase

        scan = _defined_below(cls, ScannerPluginBase, "scan")
        if scan is not None and not _calls_super_scan(_function_info(scan)[1]):
            return scan
        method = _defined_below(cls, ScannerPluginBase, "_execute_scan")
    elif kind == "reporter":
        from automated_security_helper.base.reporter_plugin import ReporterPluginBase

        method = _defined_below(cls, ReporterPluginBase, "report")
    else:
        from automated_security_helper.base.converter_plugin import ConverterPluginBase

        method = _defined_below(cls, ConverterPluginBase, "convert")
    if method is None:
        raise InventoryError(
            f"{cls.__module__}.{cls.__name__} defines no work method of its own: "
            "it resolves to the framework's base class, which holds none of its code"
        )
    return method


def plugin_features(package: Any = None) -> list[Feature]:
    """The plugins the plugin modules register, each measured in its work method.

    The lists are the ones ASH's loader registers (``ASH_SCANNERS``, ``ASH_REPORTERS``
    and ``ASH_CONVERTERS`` of every module under the package), which docs_checks reads
    for the names the docs may give. The inventory must be the same wherever the check
    runs or the baseline would read stale, so a module that does not import, and a
    plugin group the builtin package recorded as not loaded, are errors.
    """
    if package is None:
        from automated_security_helper import plugin_modules as package

    failed: list[str] = []
    modules = []
    for info in pkgutil.walk_packages(
        package.__path__, package.__name__ + ".", onerror=failed.append
    ):
        try:
            modules.append(importlib.import_module(info.name))
        except Exception as exc:
            failed.append(f"{info.name} ({type(exc).__name__}: {exc})")
    if failed:
        raise InventoryError(
            "plugin modules that do not import, so the inventory would come out short: "
            + "; ".join(failed)
        )

    found: dict[type, str] = {}
    for module in modules:
        # A plugin group can fail only because of what was imported first; ASH retries
        # it once the first import has finished, and a real failure survives that.
        retry = getattr(module, "retry_failed_plugin_groups", None)
        if callable(retry):
            retry()
        errors = getattr(module, "ASH_PLUGIN_LOAD_ERRORS", None)
        if errors:
            raise InventoryError(
                f"{module.__name__} recorded plugin groups as not loaded: "
                + "; ".join(f"{key}: {value}" for key, value in sorted(errors.items()))
            )
        for kind in PLUGIN_KINDS:
            for plugin in getattr(module, f"ASH_{kind.upper()}S", None) or []:
                found.setdefault(plugin, kind)

    checks = _checks()
    built: dict[str, tuple[type, Feature]] = {}
    for plugin, kind in found.items():
        feature_id = f"{kind}:{checks._declared_plugin_name(plugin)}"
        method = _work_method(plugin, kind)
        path, node = _function_info(method)
        if _raises_only_not_implemented(node):
            raise InventoryError(
                f"{feature_id} is measured in {node.name} ({path}:{node.lineno}), which "
                "only raises NotImplementedError and so never runs"
            )
        if feature_id in built and built[feature_id][0] is not plugin:
            raise InventoryError(f"two plugin classes are named {feature_id}")
        region = Region(path=path, lines=_region_of(node))
        built[feature_id] = (
            plugin,
            Feature(
                id=feature_id,
                regions=(region,),
                location=f"{path}:{_unwrapped(method).__code__.co_firstlineno}",
            ),
        )

    by_region: dict[tuple[Region, ...], list[str]] = defaultdict(list)
    for feature_id, (_plugin, feature) in built.items():
        by_region[feature.regions].append(feature_id)
    features = []
    for feature_id, (_plugin, feature) in sorted(built.items()):
        others = sorted(set(by_region[feature.regions]) - {feature_id})
        note = f"shares its code with {', '.join(others)}" if others else ""
        features.append(
            Feature(
                id=feature.id,
                regions=feature.regions,
                location=feature.location,
                note=note,
            )
        )
    return features


# --------------------------------------------------------------------------- #
# The inventory: configuration rows and MCP tools
# --------------------------------------------------------------------------- #


@functools.lru_cache(maxsize=1)
def _config_walk() -> tuple[list[Any], Any]:
    generator = _load_script(
        "_ash_generate_config_reference", "generate_config_reference.py"
    )
    from automated_security_helper.config.ash_config import AshConfig

    sections, _missing = generator.walk_config(AshConfig)
    return sections, generator


def _model_location(model: type) -> str:
    try:
        filename = inspect.getsourcefile(model)
        line = inspect.getsourcelines(model)[1]
        return f"{_package_path(Path(filename).resolve().as_posix())}:{line}"
    except (InventoryError, OSError, TypeError):
        return ""


def config_features() -> list[Feature]:
    """One feature per row of the configuration reference, by its own walk of AshConfig.

    Section rows are features too: a document that sets ``a.b.c`` sets ``a`` and
    ``a.b``. The walk never descends into plugin classes, so the options of one
    plugin are documented on its own page and are not separate features here (the
    plugin is), and ``build.custom_scanners`` holds scanner objects whose fields are
    runtime state (``context.config`` is an AshConfig again), which it does not enter.
    """
    sections, _generator = _config_walk()
    features: dict[str, Feature] = {}
    for section in sections:
        location = _model_location(section.model)
        for row in section.rows:
            feature_id = f"config:{row['full']}"
            features.setdefault(feature_id, Feature(id=feature_id, location=location))
    return sorted(features.values(), key=lambda feature: feature.id)


def mcp_tool_features() -> list[Feature]:
    """The tools the MCP server registers, measured in their function bodies."""
    freshness = _freshness()
    server = Path(freshness.MCP_SERVER_PY)
    source = server.read_text(encoding="utf-8")
    tree = ast.parse(source)
    defs = {
        node.lineno: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    path = _package_path(server.resolve().as_posix())
    features = []
    for name, where in sorted(freshness.mcp_tool_names().items()):
        lineno = int(where.rpartition(":")[2])
        node = defs.get(lineno)
        if node is None:
            raise InventoryError(
                f"mcp tool {name} is not a function defined on line {lineno}"
            )
        features.append(
            Feature(
                id=f"mcp-tool:{name}",
                regions=(Region(path=path, lines=_region_of(node)),),
                location=f"{path}:{lineno}",
            )
        )
    return features


def inventory() -> list[Feature]:
    """Every feature, sorted by id, each id once, every kind present."""
    import typer

    from automated_security_helper.cli.main import app

    features = [
        *cli_features(typer.main.get_command(app)),
        *plugin_features(),
        *config_features(),
        *mcp_tool_features(),
    ]
    ids = [feature.id for feature in features]
    duplicated = sorted({i for i in ids if ids.count(i) > 1})
    if duplicated:
        raise InventoryError(f"features listed twice: {duplicated}")
    missing = sorted(set(KINDS) - {feature.kind for feature in features})
    if missing:
        raise InventoryError(f"the inventory holds no feature of kind {missing}")
    return sorted(features, key=lambda feature: feature.id)


def corpus_pages(docs_root: Path) -> list[Path]:
    """The markdown pages the docs examples test reads: the docs freshness corpus."""
    freshness = _freshness()
    if Path(docs_root).resolve() != Path(freshness.REPO_ROOT).resolve():
        freshness._use_trees(Path(docs_root))
    return [path for path in freshness.collect_md_files() if path.suffix == ".md"]


# --------------------------------------------------------------------------- #
# Configuration keys: what a document or an override sets
# --------------------------------------------------------------------------- #

#: A key as written: (spelling, whether its value is a list whose items continue it).
_Chain = tuple[tuple[str, bool], ...]


@functools.lru_cache(maxsize=1)
def _config_spellings() -> dict[str, dict[str, str]]:
    """Row prefix -> every spelling a key may be written with -> the row's alias.

    AshConfig sets ``populate_by_name``, so a key is written by its alias
    (``mcp-resource-management``) or its field name (``mcp_resource_management``); the
    feature id is always the row's own path, which uses the alias.
    """
    sections, _generator = _config_walk()
    spellings: dict[str, dict[str, str]] = defaultdict(dict)
    for section in sections:
        prefix = f"{section.path}[]" if section.is_list else section.path
        for row in section.rows:
            spellings[prefix][row["key"]] = row["key"]
            spellings[prefix][row["name"]] = row["key"]
    return dict(spellings)


def _written_chains(node: Any, chain: _Chain = ()) -> Iterator[_Chain]:
    """Every key a document writes, as the chain of keys down to it."""
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if not isinstance(key, str):
            continue
        yield chain + ((key, False),)
        if isinstance(value, dict):
            yield from _written_chains(value, chain + ((key, False),))
        elif isinstance(value, list):
            for item in value:
                yield from _written_chains(item, chain + ((key, True),))


def _rows_set_by(chain: _Chain) -> set[str]:
    """The rows a written key sets: it and every prefix of it. A key that matches no
    row, and what lies under it, sets nothing."""
    spellings = _config_spellings()
    prefix = ""
    rows: set[str] = set()
    for key, in_list in chain:
        alias = spellings.get(prefix, {}).get(key)
        if alias is None:
            break
        full = f"{prefix}.{alias}" if prefix else alias
        rows.add(f"config:{full}")
        prefix = full + ("[]" if in_list else "")
    return rows


def _rows_of_document(document: Any, at: _Chain = ()) -> set[str]:
    rows: set[str] = set()
    for chain in _written_chains(document):
        rows |= _rows_set_by(at + chain)
    return rows


def _rows_of_override(text: str) -> set[str]:
    """The row an ``--config-overrides`` value names: the text before ``=`` or ``+=``."""
    key = text.split("=", 1)[0]
    if "=" not in text:
        return set()
    key = key.removesuffix("+").strip()
    if not key:
        return set()
    return _rows_set_by(tuple((part, False) for part in key.split(".")))


def _ash_config_rows(block: Any, *, saved_only: bool) -> set[str]:
    """The rows an ASH configuration block sets, or none when it is not one.

    ``saved_only`` is the evidence rule: a block saved for a later block to load. The
    kinds are the ones docs_checks validates as ASH's own: ``ash``, ``ash-fragment``
    (written under its ``at=`` key) and ``pyproject`` (under ``[tool.ash]``);
    ``ash-invalid`` shows a refused document and never counts.
    """
    if block.family != "config":
        return set()
    if saved_only and (block.mode != "config" or not block.save_as):
        return set()
    document, error = _checks().parse_config_text(block.body, block.lang)
    if error is not None or not isinstance(document, dict):
        return set()
    kind = block.config_kind
    if kind == "ash":
        return _rows_of_document(document)
    if kind == "ash-fragment":
        at = str(block.marker.keys.get("at", "")) if block.marker else ""
        prefix = tuple((part, False) for part in at.split(".") if part)
        return _rows_of_document(document, prefix)
    if kind == "pyproject":
        tool = document.get("tool")
        section = tool.get("ash") if isinstance(tool, dict) else None
        return _rows_of_document(section)
    return set()


# --------------------------------------------------------------------------- #
# Reading a run: the runner's records and coverage.py's data
# --------------------------------------------------------------------------- #

_RECORD_FIELDS = ("line", "context", "session", "runs", "save_as", "expected", "ok")


@dataclass(frozen=True)
class _Recorded:
    page: str
    record: Mapping[str, Any]
    block: Any


def _counting_exits() -> frozenset[str]:
    """The exits a block may expect and still be evidence: success, scan errors,
    actionable findings. Every other expectation shows ASH refusing something or being
    stopped, and the code it names never ran its work. Read from the enum."""
    from automated_security_helper.core.enums import AshExitCode

    return frozenset(
        str(int(member))
        for member in (
            AshExitCode.SUCCESS,
            AshExitCode.SCAN_ERRORS,
            AshExitCode.ACTIONABLE_FINDINGS,
        )
    )


def _selected(page: Any) -> bool:
    """Whether the runner has a block to run or save on a page (the docs runner's
    ``session_blocks``): a runnable block, an output sample, or a saved block."""
    checks = _checks()
    samples = checks.output_samples(page)
    return any(
        block.closed
        and (
            checks.runner_runs(block)
            or id(block) in samples
            or (block.save_as and block.mode != "illustrative")
        )
        for block in page.blocks
    )


def _read_records(
    data: Path, docs_root: Path, pages: dict[Path, Any]
) -> list[_Recorded]:
    """The runner's per-page records, each block matched to the page's own block."""
    files = sorted((data / "blocks").glob("*.json"))
    if not files:
        raise MeasurementError(f"no block record under {data / 'blocks'}: nothing ran")
    checks = _checks()
    recorded: list[_Recorded] = []
    for file in files:
        try:
            content = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MeasurementError(f"{file} cannot be read: {exc}") from exc
        if (
            not isinstance(content, dict)
            or content.get("schema") != 1
            or not isinstance(content.get("page"), str)
            or not isinstance(content.get("blocks"), list)
        ):
            raise MeasurementError(f"{file} is not a schema 1 block record")
        rel = content["page"]
        path = Path(docs_root) / rel
        if not path.is_file():
            raise MeasurementError(
                f"{file} records page {rel}, which the docs tree {docs_root} lacks: "
                "the data comes from another tree"
            )
        key = path.resolve()
        if key not in pages:
            pages[key] = checks.parse_page(path, Path(docs_root))
        by_line = {block.fence_line: block for block in pages[key].blocks}
        for record in content["blocks"]:
            missing = [
                name
                for name in _RECORD_FIELDS
                if not isinstance(record, dict) or name not in record
            ]
            if missing:
                raise MeasurementError(f"{file} has a block record without {missing}")
            if (
                not isinstance(record["expected"], str)
                or not isinstance(record["runs"], bool)
                or not isinstance(record["ok"], bool)
            ):
                raise MeasurementError(
                    f"{file} has a block record with a field of the wrong type"
                )
            block = by_line.get(record["line"])
            if block is None:
                raise MeasurementError(
                    f"{rel} has no block fenced on line {record['line']}: the record "
                    "comes from another version of the page"
                )
            recorded.append(_Recorded(rel, record, block))
    return recorded


class _Coverage:
    """The coverage data of a run, combined into a file of its own.

    The data files are combined with ``keep=True`` into a temporary directory: coverage
    deletes what it combines by default, and the run's data is uploaded afterwards.
    """

    def __init__(self, data: Path):
        from coverage import CoverageData
        from coverage.data import combine_parallel_data
        from coverage.exceptions import CoverageException

        directory = Path(data) / "data"
        files = sorted(
            path
            for path in directory.glob(".coverage.*")
            if path.is_file() and not path.name.endswith(("-journal", "-wal", "-shm"))
        )
        if not files:
            raise MeasurementError(
                f"no coverage data file under {directory}: nothing was measured"
            )
        self.files = len(files)
        self._scratch = tempfile.TemporaryDirectory(prefix="docs-feature-coverage-")
        try:
            self._data = CoverageData(
                basename=os.path.join(self._scratch.name, ".coverage")
            )
            combine_parallel_data(
                self._data, data_paths=[str(path) for path in files], keep=True
            )
            self.contexts = frozenset(c for c in self._data.measured_contexts() if c)
            by_suffix: dict[str, list[str]] = defaultdict(list)
            for measured in self._data.measured_files():
                text = measured.replace("\\", "/")
                for match in re.finditer(rf"(?:^|(?<=/)){PACKAGE}/", text):
                    by_suffix[text[match.start() :]].append(measured)
            self._by_suffix = by_suffix
        except CoverageException as exc:
            self.close()
            raise MeasurementError(f"the coverage data cannot be read: {exc}") from exc
        except BaseException:
            self.close()
            raise
        self._lines: dict[str, dict[str, set[int]]] = {}

    def close(self) -> None:
        data = getattr(self, "_data", None)
        if data is not None:
            data.close()
        self._scratch.cleanup()

    def lines_by_context(self, path: str) -> dict[str, set[int]]:
        """The lines of the files matching ``path`` that each context ran."""
        if path not in self._lines:
            found: dict[str, set[int]] = defaultdict(set)
            for measured in self._by_suffix.get(path, ()):
                for line, contexts in self._data.contexts_by_lineno(measured).items():
                    for context in contexts:
                        found[context].add(line)
            self._lines[path] = found
        return self._lines[path]

    def reached(self, context: str, region: Region) -> bool:
        return bool(
            self.lines_by_context(region.path).get(context, set()) & region.lines
        )


class _Uses:
    """The ``ash`` command lines of blocks, read once per block."""

    def __init__(self, docs_root: Path):
        self.docs_root = Path(docs_root)
        self._cache: dict[tuple[str, int], list[Any]] = {}

    def of(self, block: Any) -> list[Any]:
        """(command path, option uses) for each invocation the block makes."""
        key = (str(block.path), block.fence_line)
        if key not in self._cache:
            checks = _checks()
            cli = checks.load_cli()
            invocations, _problems = checks.block_invocations(block, self.docs_root)
            self._cache[key] = [
                (invocation, *checks.invocation_usage(invocation.args, cli))
                for invocation in invocations
            ]
        return self._cache[key]

    def refuses_a_selection_of_dependencies(self, block: Any) -> bool:
        """A block that shows ``ash dependencies install --tool <unknown>`` refused.

        That refusal exits with ASH_EXIT_BAD_SELECTION, which is also the scan's
        actionable-findings code, so the exit alone cannot tell it from a scan that
        found something; the command can (docs_checks.shows_a_selection_refusal).
        """
        if not _checks().shows_a_selection_refusal(block):
            return False
        return any(
            inv.args[:1] == ["dependencies"] for inv, _path, _uses in self.of(block)
        )


def _option_keys(feature: Feature) -> tuple[tuple[tuple[str, ...], ...], str]:
    """(member command paths, canonical option name) of an option feature."""
    if feature.paths:
        return feature.paths, feature.canonical
    command, _, canonical = feature.name.rpartition(" ")
    return (tuple(command.split()),), canonical


_REGISTRY_KINDS = {"scanner": "scanner", "reporter": "reporter"}
_CONFIG_SECTIONS = {
    "scanners": "scanner",
    "reporters": "reporter",
    "converters": "converter",
}


def evaluate(
    features: Iterable[Feature], data: Path, docs_root: Path, corpus: Iterable[Path]
) -> Evaluation:
    """Which features a passing executed block of the run reached.

    ``data`` is the run's coverage directory: ``data/.coverage.*`` (coverage.py's data
    files) and ``blocks/*.json`` (the runner's records). Only a block the runner ran,
    that passed, and whose marker expects success, scan errors or findings is evidence,
    for every kind of feature (``_counting_exits``).
    """
    features = list(features)
    data, docs_root = Path(data), Path(docs_root)
    checks = _checks()
    pages: dict[Path, Any] = {}
    for path in corpus:
        pages[Path(path).resolve()] = checks.parse_page(Path(path), docs_root)
    recorded = _read_records(data, docs_root, pages)

    coverage = _Coverage(data)
    try:
        return _evaluate(features, recorded, coverage, docs_root, pages)
    finally:
        coverage.close()


def _evaluate(
    features: list[Feature],
    recorded: list[_Recorded],
    coverage: _Coverage,
    docs_root: Path,
    pages: dict[Path, Any],
) -> Evaluation:
    counting = _counting_exits()
    uses = _Uses(docs_root)
    run = [entry for entry in recorded if entry.record["runs"]]
    passed = [entry for entry in run if entry.record["ok"]]
    if not passed:
        raise MeasurementError(
            "no executed block passed: nothing shows a feature was reached"
        )
    if not any(entry.record["context"] in coverage.contexts for entry in passed):
        raise MeasurementError(
            "no passing block's context is in the coverage data: the collection is "
            "broken (the context never reached the measured processes)"
        )
    evidence = [
        entry
        for entry in passed
        if entry.record["expected"] in counting
        and not uses.refuses_a_selection_of_dependencies(entry.block)
    ]

    by_kind: dict[str, list[Feature]] = defaultdict(list)
    for feature in features:
        by_kind[feature.kind].append(feature)
    code_features = [f for f in features if f.kind not in ("option", "config")]
    option_index: dict[tuple[tuple[str, ...], str], list[Feature]] = defaultdict(list)
    for feature in by_kind["option"]:
        member_paths, canonical = _option_keys(feature)
        for path in member_paths:
            option_index[(path, canonical)].append(feature)
    config_ids = {feature.id for feature in by_kind["config"]}

    if config_ids:
        from automated_security_helper.config import resolve_config

        load_anchor = function_region(resolve_config.load_config_file)
        override_anchor = function_region(resolve_config.apply_config_overrides)

    covered: set[str] = set()
    covered_on: dict[str, set[str]] = defaultdict(set)

    def cover(feature_id: str, page: str) -> None:
        covered.add(feature_id)
        covered_on[feature_id].add(page)

    sessions: dict[tuple[str, int], list[_Recorded]] = defaultdict(list)
    for entry in recorded:
        sessions[(entry.page, entry.record["session"])].append(entry)

    for entry in evidence:
        context = entry.record["context"]
        for feature in code_features:
            if any(coverage.reached(context, region) for region in feature.regions):
                cover(feature.id, entry.page)
        if not (by_kind["option"] or config_ids):
            continue
        invoked = uses.of(entry.block)
        for _invocation, _path, option_uses in invoked:
            for use in option_uses:
                for feature in option_index.get(
                    (tuple(use.command), _canonical(use.names)), ()
                ):
                    if any(
                        coverage.reached(context, region) for region in feature.regions
                    ):
                        cover(feature.id, entry.page)
        if not config_ids:
            continue
        if coverage.reached(context, load_anchor):
            for earlier in sessions[(entry.page, entry.record["session"])]:
                if (
                    earlier.record["save_as"]
                    and earlier.record["ok"]
                    and earlier.record["line"] <= entry.record["line"]
                ):
                    for feature_id in _ash_config_rows(earlier.block, saved_only=True):
                        if feature_id in config_ids:
                            cover(feature_id, entry.page)
        if coverage.reached(context, override_anchor):
            for _invocation, _path, option_uses in invoked:
                for use in option_uses:
                    if "--config-overrides" in use.names and use.value:
                        for feature_id in _rows_of_override(use.value):
                            if feature_id in config_ids:
                                cover(feature_id, entry.page)

    known = {feature.id for feature in features}
    presented = _presented(features, option_index, config_ids, pages, uses) & known
    denominators = {
        "pages_recorded": len({entry.page for entry in recorded}),
        "pages_selected": sum(1 for page in pages.values() if _selected(page)),
        "blocks_run": len(run),
        "blocks_passed": len(passed),
        "data_files": coverage.files,
        "contexts": len(coverage.contexts),
    }
    return Evaluation(
        covered=frozenset(covered) & known,
        presented=frozenset(presented),
        denominators=denominators,
        pages={fid: tuple(sorted(found)) for fid, found in covered_on.items()},
    )


def _presented(
    features: list[Feature],
    option_index: dict[tuple[tuple[str, ...], str], list[Feature]],
    config_ids: set[str],
    pages: dict[Path, Any],
    uses: _Uses,
) -> set[str]:
    """Features any block of any corpus page shows, run or not (report only).

    A gap that is presented needs its example executed; one that is not needs
    documentation first.
    """
    checks = _checks()
    commands: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for feature in features:
        if feature.kind == "command":
            for path in feature.paths:
                commands[path].append(feature.id)
    shown: set[str] = set()
    for page in pages.values():
        for block in page.blocks:
            for _invocation, path, option_uses in uses.of(block):
                shown.update(commands.get(tuple(path), ()))
                for use in option_uses:
                    for feature in option_index.get(
                        (tuple(use.command), _canonical(use.names)), ()
                    ):
                        shown.add(feature.id)
                    kind = checks.REGISTRY_OPTIONS.get(
                        (tuple(use.command), use.names[0])
                    )
                    if kind in _REGISTRY_KINDS and use.value:
                        for name in use.value.split(","):
                            shown.add(f"{_REGISTRY_KINDS[kind]}:{name.strip().lower()}")
                    if "--config-overrides" in use.names and use.value:
                        shown |= _rows_of_override(use.value) & config_ids
            if config_ids:
                shown |= _ash_config_rows(block, saved_only=False) & config_ids
    for feature_id in list(shown):
        # A plugin's section in a configuration shows the plugin.
        section, _, name = feature_id.removeprefix("config:").partition(".")
        if (
            feature_id.startswith("config:")
            and section in _CONFIG_SECTIONS
            and name
            and "." not in name
        ):
            shown.add(f"{_CONFIG_SECTIONS[section]}:{name}")
    return shown


# --------------------------------------------------------------------------- #
# The baseline and the gate
# --------------------------------------------------------------------------- #


def read_baseline(path: Path) -> list[str]:
    """The feature ids of a baseline file: sorted, unique, each ``<kind>:<name>``.

    Anything else, or a file that cannot be read, is a measurement error: a baseline
    that does not mean what it says would pass or fail the gate for the wrong reason.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MeasurementError(f"the baseline {path} cannot be read: {exc}") from exc
    ids: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#") or not line.strip():
            continue
        kind, separator, name = line.partition(":")
        if (
            not separator
            or kind not in KINDS
            or not name
            or name != name.strip()
            or line != line.strip()
        ):
            raise MeasurementError(
                f"{path}:{number}: {line!r} is not a feature id (<kind>:<name>, kind one "
                f"of {', '.join(KINDS)}, no surrounding whitespace)"
            )
        ids.append(line)
    if ids != sorted(ids):
        raise MeasurementError(f"{path} is not in sorted order")
    if len(ids) != len(set(ids)):
        raise MeasurementError(f"{path} lists a feature twice")
    return ids


def gate_failures(
    *,
    feature_ids: Iterable[str],
    covered: Iterable[str],
    baseline: Iterable[str],
    base_baseline: Iterable[str] | None = None,
) -> dict[str, list[str]]:
    """The gate's four classes, each sorted.

    F1 an uncovered feature the baseline lacks (new, or its examples stopped reaching
    it); F2 a baseline line that names no feature (renamed or removed); F3 a baseline
    line for a covered feature (the ratchet: delete it); F4 a baseline line the base
    branch's baseline lacks (a pull request may not grow it). F3 and F4 apply only given
    the base branch's baseline: on a push, and on the pull request that adds the file,
    the CI runner can reach code the measurement the file was written from did not.
    """
    ids, covered, baseline = set(feature_ids), set(covered), set(baseline)
    failures = {
        "F1": sorted((ids - covered) - baseline),
        "F2": sorted(baseline - ids),
        "F3": [],
        "F4": [],
    }
    if base_baseline is not None:
        failures["F3"] = sorted(baseline & covered)
        failures["F4"] = sorted(baseline - set(base_baseline))
    return failures


_FAILURE_TITLES = {
    "F1": "uncovered features missing from the baseline (add an executed example that reaches each)",
    "F2": "baseline lines that name no feature (delete them)",
    "F3": "baseline lines for features an executed example now reaches (delete them)",
    "F4": "baseline lines the base branch's baseline lacks (a pull request may not add one)",
}


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #


def _figure(covered: int, total: int) -> tuple[str, float]:
    percent = round(100 * covered / total, 1) if total else 0.0
    return (
        f"{covered} of {total} features ({percent}%) reached by an executed docs example",
        percent,
    )


def _report(
    features: Sequence[Feature], evaluation: Evaluation, gate: dict[str, Any] | None
) -> dict[str, Any]:
    ordered = sorted(features, key=lambda feature: feature.id)
    totals: dict[str, dict[str, int]] = {}
    for feature in ordered:
        entry = totals.setdefault(feature.kind, {"covered": 0, "total": 0})
        entry["total"] += 1
        entry["covered"] += feature.id in evaluation.covered
    covered = sum(entry["covered"] for entry in totals.values())
    total = sum(entry["total"] for entry in totals.values())
    return {
        "schema": REPORT_SCHEMA,
        "totals": {kind: totals[kind] for kind in sorted(totals)},
        "overall": {
            "covered": covered,
            "total": total,
            "percent": _figure(covered, total)[1],
        },
        "denominators": dict(evaluation.denominators),
        "features": [
            {
                "id": feature.id,
                "kind": feature.kind,
                "covered": feature.id in evaluation.covered,
                "presented": feature.id in evaluation.presented,
                "pages": list(evaluation.pages.get(feature.id, ())),
                "location": feature.location,
                "note": feature.note,
            }
            for feature in ordered
        ],
        "gate": gate,
    }


def _listed(ids: Sequence[str]) -> list[str]:
    lines = [f"  - `{feature_id}`" for feature_id in ids[:LISTED_IDS]]
    if len(ids) > LISTED_IDS:
        lines.append(f"  - and {len(ids) - LISTED_IDS} more")
    return lines


def _markdown(report: dict[str, Any], evaluation: Evaluation) -> str:
    overall = report["overall"]
    lines = [
        "## Docs feature coverage",
        "",
        f"**{_figure(overall['covered'], overall['total'])[0]}**",
        "",
        "| kind | covered | total |",
        "|---|---|---|",
    ]
    lines += [
        f"| {kind} | {entry['covered']} | {entry['total']} |"
        for kind, entry in report["totals"].items()
    ]
    lines += ["", "What was read:", ""]
    lines += [f"- {name}: {value}" for name, value in report["denominators"].items()]
    gate = report["gate"]
    lines.append("")
    if gate is None:
        lines.append("No gate was applied (report only).")
    else:
        failing = {name: ids for name, ids in gate["failures"].items() if ids}
        lines.append("Gate: " + ("FAILED" if failing else "passed"))
        for name, ids in failing.items():
            lines += ["", f"{name}: {_FAILURE_TITLES[name]} ({len(ids)})", ""]
            lines += _listed(ids)
        warned = gate["warnings"].get("F3", [])
        if warned:
            warning = (
                "Warning, not a failure: no base branch baseline was given, so these "
                "baseline lines, for features an executed example reached, were not "
                f"checked against it. Delete them ({len(warned)}):"
            )
            lines += ["", warning, ""]
            lines += _listed(warned)
    unexecuted = len(evaluation.presented - evaluation.covered)
    presented = (
        f"Features presented in the docs but not reached by an executed example: {unexecuted}. "
        "An uncovered feature that is presented needs its example executed; one that "
        "is not needs documentation first."
    )
    lines += ["", presented, ""]
    return "\n".join(lines)


def _baseline_text(uncovered: Iterable[str]) -> str:
    return BASELINE_HEADER + "".join(
        f"{feature_id}\n" for feature_id in sorted(uncovered)
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _measure(
    *,
    data: Path,
    docs_root: Path,
    features: list[Feature] | None,
    corpus: list[Path] | None,
) -> tuple[list[Feature], Evaluation]:
    features = list(inventory() if features is None else features)
    corpus = list(corpus_pages(docs_root) if corpus is None else corpus)
    return features, evaluate(features, data, docs_root, corpus)


def _fail(error: MeasurementError) -> int:
    print(f"docs feature coverage: measurement error: {error}", file=sys.stderr)
    return 2


def run_check(
    *,
    data: Path,
    baseline: Path | None = None,
    base_baseline: Path | None = None,
    docs_root: Path,
    out: Path,
    summary: Path | None = None,
    features: list[Feature] | None = None,
    corpus: list[Path] | None = None,
) -> int:
    """Read a run, apply the gate, write the report. 0 pass, 1 gate failure, 2 error.

    ``features`` and ``corpus`` replace the inventory and the docs corpus: the tests
    plant a feature through them.
    """
    try:
        listed = read_baseline(DEFAULT_BASELINE if baseline is None else baseline)
        base = None if base_baseline is None else read_baseline(base_baseline)
        features, evaluation = _measure(
            data=data, docs_root=docs_root, features=features, corpus=corpus
        )
    except MeasurementError as error:
        return _fail(error)
    failures = gate_failures(
        feature_ids=[feature.id for feature in features],
        covered=evaluation.covered,
        baseline=listed,
        base_baseline=base,
    )
    code = 1 if any(failures.values()) else 0
    gate = {
        "exit_code": code,
        "failures": failures,
        "warnings": {
            "F3": sorted(set(listed) & evaluation.covered) if base is None else [],
        },
    }
    report = _report(features, evaluation, gate)
    markdown = _markdown(report, evaluation)
    out = Path(out)
    _write(out / REPORT_JSON, json.dumps(report, indent=2) + "\n")
    _write(out / REPORT_MD, markdown)
    uncovered = [f.id for f in features if f.id not in evaluation.covered]
    _write(out / BASELINE_OUT, _baseline_text(uncovered))
    if summary is not None:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(("\n" if handle.tell() else "") + markdown)
    print(markdown)
    return code


def run_report(
    *,
    data: Path,
    docs_root: Path,
    out: Path,
    features: list[Feature] | None = None,
    corpus: list[Path] | None = None,
) -> int:
    """The same outputs as ``check`` with no gate: 0, or 2 on a measurement error."""
    try:
        features, evaluation = _measure(
            data=data, docs_root=docs_root, features=features, corpus=corpus
        )
    except MeasurementError as error:
        return _fail(error)
    report = _report(features, evaluation, None)
    markdown = _markdown(report, evaluation)
    out = Path(out)
    _write(out / REPORT_JSON, json.dumps(report, indent=2) + "\n")
    _write(out / REPORT_MD, markdown)
    _write(
        out / BASELINE_OUT,
        _baseline_text(f.id for f in features if f.id not in evaluation.covered),
    )
    print(markdown)
    return 0


def run_write_baseline(
    *,
    data: Path,
    baseline: Path,
    docs_root: Path,
    features: list[Feature] | None = None,
    corpus: list[Path] | None = None,
) -> int:
    """Write the baseline this run needs: every uncovered feature. 0, or 2 and no file."""
    try:
        features, evaluation = _measure(
            data=data, docs_root=docs_root, features=features, corpus=corpus
        )
    except MeasurementError as error:
        return _fail(error)
    _write(
        Path(baseline),
        _baseline_text(f.id for f in features if f.id not in evaluation.covered),
    )
    return 0


# --------------------------------------------------------------------------- #
# The command line
# --------------------------------------------------------------------------- #


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, text in (
        ("report", "write the report, applying no gate"),
        ("check", "write the report and apply the gate"),
        ("write-baseline", "write the baseline file this run needs"),
    ):
        command = sub.add_parser(name, help=text, description=text)
        command.add_argument(
            "--data", required=True, type=Path, help="the run's coverage directory"
        )
        command.add_argument(
            "--docs-root",
            type=Path,
            default=REPO_ROOT,
            help="the docs tree (default: this repository)",
        )
        if name != "write-baseline":
            command.add_argument(
                "--out",
                type=Path,
                default=Path("docs-feature-coverage-report"),
                help="where the report is written",
            )
        if name != "report":
            command.add_argument(
                "--baseline",
                type=Path,
                default=None,
                help="the baseline file (default: scripts/docs_feature_coverage_baseline.txt)",
            )
        if name == "check":
            command.add_argument(
                "--base-baseline",
                type=Path,
                default=None,
                help="the base branch's baseline; with it F3 and F4 apply",
            )
            command.add_argument(
                "--summary",
                type=Path,
                default=None,
                help="a file to append the markdown to",
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    """0 pass, 1 gate failure, 2 measurement or input error, and 2 for any exception
    nothing expected (Python's own exit for one is 1, the gate-failure code)."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "check":
            return run_check(
                data=args.data,
                baseline=args.baseline,
                base_baseline=args.base_baseline,
                docs_root=args.docs_root,
                out=args.out,
                summary=args.summary,
            )
        if args.command == "report":
            return run_report(data=args.data, docs_root=args.docs_root, out=args.out)
        return run_write_baseline(
            data=args.data,
            baseline=DEFAULT_BASELINE if args.baseline is None else args.baseline,
            docs_root=args.docs_root,
        )
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
