# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Settle tracer: recording cells for the delivered-config family.

MEASUREMENT, NOT SUITE. These cells record what happens on the paths of five
failing tests of ``tests/unit/cli/mcp/test_delivered_config_links.py`` and assert
only their own controls: the scenario was built, and the recorder captured rows.
They pass whatever they see. They must not be folded into the suite permanently;
once the two questions below are settled, delete the module.

The swallow site. Four tests expect a refused repository config to refuse the
scan, and the refusal vanishes instead (the scan answers with the default config,
or ends without exit 3). The containment arm of ``resolve_config._resolve_config``
(``except ConfigFileRefused``) is gated on ``discovered_label is not None``. The
cells record, for each scenario, what the gate sees: ``discovered_label``, the
``config_path`` and ``source_dir`` the resolution was entered with, the refusal's
type, the ``repository_file`` judge's answers, and whether the containment arm ran.

  * q1-not-a-config      twin of test_a_linked_file_that_is_not_a_config_is_not_quoted
  * q1-bad-expiry        twin of test_a_validators_own_message_is_reported_by_its_type
  * q1-unknown-key       twin of test_a_key_the_schema_does_not_have_is_not_named
  * q1-scan-itself       twin of test_the_scan_itself_refuses_it_without_reading_it

Each of them drives two variants over one delivered tree. ``scan`` goes through the
real ``_run_scan_async`` and stops once ``resolve_config`` has answered (as the
originals' ``_scan_resolution`` does), so no tool is started. ``named`` calls
``resolve_config`` directly with the delivered file passed as ``config_path``, which
shows whether naming the file changes the gate.

The log emission. ``ASHConfigSourceError`` propagates for a delivered config
that does not parse, yet ``caplog`` holds no "Failed to load" record. The cells
record the emission path rather than the exception path: the logger's state, every
call of its level methods (with the calling line), ``Logger.filter``,
``Logger.handle`` and ``callHandlers``, a recording handler on ``ASH_LOGGER`` and
one on the root logger, ``caplog``'s records, and probes at the three statements of
``_resolve_config`` that could log or raise for a load failure. A control record is
emitted after the scenario to show whether the plumbing delivers anything at all.

  * q2-yaml-parse           twin of test_the_log_line_for_it_does_not_quote_it_either
  * q2-read-failure-control the same plumbing with an injected OSError, the one
                            failure whose "Failed to load configuration file" call
                            site is known to log

How the probes work. ``_resolve_config``'s local ``discovered_label`` cannot be read
from outside, and a source edit is not allowed, so the module parses
``resolve_config.py`` from disk, inserts ``__settle_probe__(site, locals())`` before
named statements of that one function (found by their text, not by line number),
compiles the result and swaps the live function's ``__code__`` for the cell. Both
the swap and the injected global are undone by ``monkeypatch``. The probe swallows
its own errors, so it cannot change the run. When a statement cannot be found, or
the compile fails, the ``probe_install`` row says so and the wrapper-level rows
(entry arguments, ``discover_config_source``, ``permit``, ``repository_file``,
``read_config_bytes``, the logger calls) still record. Rejected: ``sys.settrace``
(fights coverage and debuggers; ``sys.monitoring`` needs 3.12 and the project
supports 3.10), editing the source, and syrupy snapshots.

Rows are JSON lines. Each cell publishes them four ways, any of which survives a
passing run: ``print`` (visible with ``-s`` or ``-rP``), the testsuite's
``<properties>`` in the junit file (through ``record_testsuite_property``, the
one property element pytest's default ``junit_family``, xunit2, admits; a
testcase's ``<properties>``, which the ``record_property`` fixture writes and
warns about, is not in that schema), the terminal reporter (the
console log), and ``settle-trace-<cell>.jsonl`` under the test's ``tmp_path`` and
under ``$ASH_SETTLE_TRACE_DIR`` when that is set to an existing directory. Every
line starts ``SETTLE-TRACE <cell> `` so a log can be filtered with one pattern.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import errno
import hashlib
import itertools
import json
import logging
import os
import platform
import shutil
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.integration

SESSION = "client-1"

#: The host files the delivered tree links to; the texts and canaries are those of
#: tests/unit/cli/mcp/test_delivered_config_links.py.
CANARY = "canary-text-5c1e9d2b"
NOT_A_CONFIG = f"{CANARY} on the first line\nsecond line\n"
YAML_CANARY = "canary-yaml-77aa31"
NOT_YAML = f"key: [unclosed {YAML_CANARY}\n"
EXPIRY_CANARY = "canary-zz-41f7"
BAD_EXPIRY = (
    "project_name: linked\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
    f"      expiration: '{EXPIRY_CANARY}'\n"
)
KEY_CANARY = "canary-key-9d1e"
UNKNOWN_KEY = (
    f"project_name: linked\nglobal_settings:\n  {KEY_CANARY}: 1\n"
    "  severity_threshold: NOT-A-SEVERITY\n"
)
LINK_OUT = f"# {CANARY}\nproject_name: linked\n"

CONTROL_TEXT = "settle-trace control record: ASH_LOGGER.error after the scenario"
_UNSET = object()


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
    )

    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "host": host, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture(autouse=True)
def _mcp_cells_pins(monkeypatch: pytest.MonkeyPatch):
    """The two pins tests/unit/cli/mcp/conftest.py gives every MCP cell."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import config_sources

    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: "fedcba9876543210")
    monkeypatch.setattr(config_sources, "_LIVE_SCAN_COPIES", set())


@pytest.fixture
def host_set_aside(_server, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The operator sets the host directory aside, so a scan may reach it."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    return _server["host"]


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


class _Rows:
    """A thread-safe list of recorded rows; ``phase`` and ``variant`` ride on each."""

    def __init__(self, cell: str) -> None:
        self.cell = cell
        self.phase = "scenario"
        self.variant = "-"
        self._lock = threading.Lock()
        self._rows: List[Dict[str, Any]] = []
        self._started = time.monotonic()

    def add(self, kind: str, **fields: Any) -> None:
        row: Dict[str, Any] = {"kind": kind}
        row.update(fields)
        with self._lock:
            row["n"] = len(self._rows) + 1
            row["t"] = round(time.monotonic() - self._started, 4)
            row["thread"] = threading.current_thread().name
            row["phase"] = self.phase
            row["variant"] = self.variant
            self._rows.append(row)

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._rows)

    def lines(self) -> List[str]:
        lines = []
        for row in self.snapshot():
            try:
                lines.append(
                    json.dumps(row, sort_keys=True, default=_plain, ensure_ascii=True)
                )
            except (TypeError, ValueError):
                lines.append(_brief(row, 2000))
        return lines


def _text(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return f"<unprintable {type(value).__name__}>"


def _brief(value: Any, limit: int = 200) -> str:
    text = value if isinstance(value, str) else _text(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _plain(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(_brief(item) for item in value)
    return _brief(value)


def _p(value: Any) -> Optional[str]:
    """A path-like value as short text; None stays None."""
    if value is None:
        return None
    try:
        return _brief(os.fspath(value), 400)
    except TypeError:
        return _brief(value, 400)


def _safe(read: Callable[[], Any]) -> Any:
    try:
        return read()
    except Exception as exc:
        return f"<error {type(exc).__name__}: {_brief(_text(exc), 120)}>"


def _quietly(action: Callable[[], Any]) -> None:
    """Run a recording step; a recorder must never change the run it watches."""
    try:
        action()
    except Exception:
        return


def _exc_fields(exc: BaseException) -> Dict[str, Any]:
    return {
        "exc_type": type(exc).__name__,
        "exc_mro": [cls.__name__ for cls in type(exc).__mro__][:8],
        "exc_message": _brief(_text(exc), 300),
        "exc_cause": None if exc.__cause__ is None else type(exc.__cause__).__name__,
        "exc_context": (
            None if exc.__context__ is None else type(exc.__context__).__name__
        ),
    }


def _kwargs_summary(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for key, value in kwargs.items():
        if value is None or isinstance(value, (bool, int, float)):
            summary[str(key)] = value
        elif isinstance(value, (str, os.PathLike)):
            summary[str(key)] = _p(value)
        elif callable(value):
            summary[str(key)] = "<callable>"
        elif isinstance(value, (list, tuple, set, frozenset, dict)):
            summary[str(key)] = f"<{type(value).__name__} len={len(value)}>"
        else:
            summary[str(key)] = f"<{type(value).__name__}>"
    return summary


def _config_summary(config: Any) -> Dict[str, Any]:
    """What an answered resolution holds; ``loaded_from`` None is a default config."""
    if config is None:
        return {"result_type": "NoneType"}
    return {
        "result_type": type(config).__name__,
        "project_name": _safe(lambda: config.project_name),
        "loaded_from": _safe(lambda: _p(getattr(config, "_loaded_from", None))),
        "resolution_warnings": _safe(
            lambda: [
                _brief(item, 160)
                for item in list(getattr(config, "_resolution_warnings", []) or [])[:3]
            ]
        ),
    }


def _entry_summary(entry: Any) -> Dict[str, Any]:
    if entry is None:
        return {"entry": None}
    as_dict = _safe(entry.to_dict)
    return {
        "entry_status": _safe(lambda: _brief(getattr(entry, "status", None))),
        "entry_error_message": _safe(
            lambda: _brief(getattr(entry, "error_message", None))
        ),
        "entry_dict_keys": sorted(as_dict)[:24] if isinstance(as_dict, dict) else None,
    }


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------


def _write_rows(directory: Path, cell: str, lines: List[str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"settle-trace-{cell}.jsonl"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _publish(
    request: pytest.FixtureRequest,
    rows: _Rows,
    directory: Path,
) -> None:
    """Put the rows where a passing run still shows them. Never raises."""
    lines = rows.lines()
    cell = rows.cell

    def to_stdout() -> None:
        print(f"SETTLE-TRACE BEGIN {cell} ({len(lines)} rows)")
        for line in lines:
            print(f"SETTLE-TRACE {cell} {line}")
        print(f"SETTLE-TRACE END {cell}")

    def to_junit() -> None:
        # The testsuite's <properties>, the one place the default junit_family
        # (xunit2) admits a property: a testcase's <properties> breaks that
        # schema, which is what the record_property fixture warns about, and
        # appending to the node's user_properties wrote the same element
        # without the warning. The property names carry the cell, so the rows
        # stay attributable without a per-testcase element. Requested here,
        # not as a parameter, so a cell that never publishes asks for nothing.
        # On a pytest-xdist worker the fixture is a no-op (pytest builds the
        # junit writer on the controller only; pytest issue 7767), so under
        # xdist the rows reach the junit file from no worker; the files and
        # terminal channels below carry them there, and junit is one of four.
        record = request.getfixturevalue("record_testsuite_property")
        for index, line in enumerate(lines, 1):
            record(f"settle-trace.{cell}.{index:03d}", line)

    def to_files() -> None:
        _write_rows(directory, cell, lines)
        extra = os.environ.get("ASH_SETTLE_TRACE_DIR")
        if extra and Path(extra).is_dir():
            _write_rows(Path(extra), cell, lines)

    def to_terminal() -> None:
        reporter = request.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is None:
            return
        reporter.write_sep("-", f"settle-trace {cell} ({len(lines)} rows)")
        for line in lines:
            reporter.write_line(f"SETTLE-TRACE {cell} {line}")

    for step in (to_stdout, to_junit, to_files, to_terminal):
        _quietly(step)


def _meta_row(rows: _Rows, request: pytest.FixtureRequest) -> None:
    from automated_security_helper.config import resolve_config as rc

    source_file = Path(rc.__file__)
    rows.add(
        "meta",
        node=request.node.nodeid,
        python=sys.version.split()[0],
        implementation=platform.python_implementation(),
        platform=platform.platform(),
        pytest=pytest.__version__,
        tracer_installed=sys.gettrace() is not None,
        resolve_config_file=_p(source_file),
        resolve_config_sha16=_safe(
            lambda: hashlib.sha256(source_file.read_bytes()).hexdigest()[:16]
        ),
    )


# ---------------------------------------------------------------------------
# The delivered tree
# ---------------------------------------------------------------------------


def _linked_tree(server: Dict[str, Path], text: str) -> Path:
    """A delivered tree whose ``.ash/.ash.yaml`` links to a host file holding ``text``."""
    from tests.utils.delivered_trees import clone, write

    host_file = write(server["host"] / "ash.yaml", text)
    return clone(
        server["tmp"], {"app.py": "x = 1\n"}, {".ash/.ash.yaml": host_file}, SESSION
    )


def _scenario_row(rows: _Rows, server: Dict[str, Path], source: Path) -> bool:
    """Record the tree and the session gate; True when the scenario was built."""
    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        config_base_gate,
    )

    link = source / ".ash" / ".ash.yaml"
    host_file = server["host"] / "ash.yaml"
    built = link.is_symlink() and host_file.is_file()
    rows.add(
        "scenario",
        source=_p(source),
        link=_p(link),
        link_is_symlink=link.is_symlink(),
        link_target=_safe(lambda: _p(os.readlink(link))),
        host_file=_p(host_file),
        host_file_is_file=host_file.is_file(),
        allowed_config_roots=os.environ.get("ASH_MCP_ALLOWED_CONFIG_ROOTS"),
        workspace_root=os.environ.get("ASH_MCP_WORKSPACE_ROOT"),
        caller_is_remote=_safe(lambda: caller_is_remote(SESSION)),
        gate_permits_host_file=_safe(
            lambda: config_base_gate(SESSION)(host_file.resolve())
        ),
    )
    return built


# ---------------------------------------------------------------------------
# The statement probes inside resolve_config._resolve_config
# ---------------------------------------------------------------------------

_PROBE_GLOBAL = "__settle_probe__"
_WATCHED = (
    "config_path",
    "source_dir",
    "confinement_source_dir",
    "confinement_dir",
    "discovered_label",
)
_PROBED: Dict[str, Tuple[types.CodeType, List[Tuple[str, int]]]] = {}


def _src(node: Optional[ast.AST]) -> str:
    try:
        return "" if node is None else ast.unparse(node)
    except Exception:
        return ""


def _handler_of(parent: ast.AST, exception_text: str) -> bool:
    return isinstance(parent, ast.ExceptHandler) and exception_text in _src(parent.type)


def _first_of(parent: ast.AST, statement: ast.AST) -> bool:
    body = getattr(parent, "body", None)
    return isinstance(body, list) and bool(body) and body[0] is statement


def _assigns_discovered_label(statement: ast.AST) -> bool:
    return (
        isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "discovered_label"
            for target in statement.targets
        )
        and "discovery.selected" in _src(statement.value)
    )


#: (label, placement, matcher(statement, parent)). Statements are found by their
#: text, cheapest test first, so a renamed statement shows up as a missing label in
#: the ``probe_install`` row instead of a wrong line number.
_SITES: Tuple[Tuple[str, str, Callable[[ast.AST, ast.AST], bool]], ...] = (
    (
        "discovery_selected",
        "after",
        lambda s, p: _assigns_discovered_label(s),
    ),
    (
        "refusal_arm",
        "before",
        lambda s, p: _first_of(p, s) and _handler_of(p, "ConfigFileRefused"),
    ),
    (
        "gate",
        "before",
        lambda s, p: (
            isinstance(s, ast.If)
            and _handler_of(p, "ConfigFileRefused")
            and "discovered_label" in _src(s.test)
        ),
    ),
    (
        "containment_arm",
        "before",
        lambda s, p: (
            isinstance(p, ast.If)
            and _first_of(p, s)
            and "discovered_label" in _src(p.test)
            and "after_overrides" in _src(p.test)
        ),
    ),
    (
        "reraise",
        "before",
        lambda s, p: (
            isinstance(s, ast.Raise)
            and s.exc is None
            and _handler_of(p, "ConfigFileRefused")
        ),
    ),
    (
        "parse_or_os_handler",
        "before",
        lambda s, p: _first_of(p, s) and _handler_of(p, "yaml.YAMLError"),
    ),
    (
        "failed_to_load_site",
        "before",
        lambda s, p: (
            isinstance(s, ast.Expr) and "Failed to load configuration file" in _src(s)
        ),
    ),
    (
        "unparsed_raise",
        "before",
        lambda s, p: (
            isinstance(s, ast.Raise)
            and s.exc is not None
            and "ASHConfigSourceError(unparsed)" in _src(s.exc)
        ),
    ),
)


def _probe_statement(label: str, anchor: ast.AST) -> ast.stmt:
    probe = ast.parse(f"{_PROBE_GLOBAL}({label!r}, locals())").body[0]
    for node in ast.walk(probe):
        ast.copy_location(node, anchor)
    return probe


def _inject_probes(function: ast.FunctionDef) -> List[Tuple[str, int]]:
    """Insert the probe calls into ``function``; the (label, line) pairs found."""
    found: List[Tuple[str, int]] = []
    for parent in ast.walk(function):
        for field in ("body", "orelse", "finalbody"):
            statements = getattr(parent, field, None)
            if not isinstance(statements, list) or not statements:
                continue
            if not isinstance(statements[0], ast.stmt):
                continue
            rebuilt: List[ast.stmt] = []
            for statement in statements:
                ahead: List[ast.stmt] = []
                behind: List[ast.stmt] = []
                for label, placement, matcher in _SITES:
                    try:
                        hit = matcher(statement, parent)
                    except Exception:
                        hit = False
                    if not hit:
                        continue
                    found.append((label, statement.lineno))
                    probe = _probe_statement(label, statement)
                    (ahead if placement == "before" else behind).append(probe)
                rebuilt.extend(ahead)
                rebuilt.append(statement)
                rebuilt.extend(behind)
            statements[:] = rebuilt
    return found


def _probed_code(module: Any) -> Tuple[types.CodeType, List[Tuple[str, int]]]:
    """``_resolve_config``'s code with the probe calls compiled in, from the file."""
    path = Path(module.__file__)
    key = str(path)
    if key in _PROBED:
        return _PROBED[key]
    tree = ast.parse(path.read_bytes(), filename=key)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_resolve_config"
    )
    first_line = min([function.lineno, *[d.lineno for d in function.decorator_list]])
    found = _inject_probes(function)
    ast.fix_missing_locations(tree)
    compiled = compile(tree, key, "exec", dont_inherit=True)
    code = next(
        const
        for const in compiled.co_consts
        if isinstance(const, types.CodeType)
        and const.co_name == "_resolve_config"
        and const.co_firstlineno == first_line
    )
    _PROBED[key] = (code, found)
    return _PROBED[key]


def _site_fields(site: str, v: Dict[str, Any]) -> Dict[str, Any]:
    """What a probe reads from the locals of ``_resolve_config`` at ``site``."""
    label = v.get("discovered_label")
    refusal = v.get("refusal")
    fields: Dict[str, Any] = {
        "discovered_label": None if label is None else _brief(label),
        "discovered_label_is_none": label is None,
        "config_path": _p(v.get("config_path")),
        "config_path_is_none": v.get("config_path") is None,
        "source_dir": _p(v.get("source_dir")),
        "confinement_source_dir": _p(v.get("confinement_source_dir")),
        "confinement_dir": _p(v.get("confinement_dir")),
        "no_discovery": v.get("no_discovery"),
        "fallback_to_default": v.get("fallback_to_default"),
        "permit_base_given": v.get("permit_base") is not None,
        "repository_file_given": v.get("repository_file") is not None,
        "unbound": [name for name in _WATCHED if name not in v],
    }
    if site in ("refusal_arm", "gate", "containment_arm", "reraise"):
        fields["refusal_type"] = type(refusal).__name__
        fields["refusal_after_overrides"] = getattr(refusal, "after_overrides", None)
    if site == "refusal_arm":
        fields["refusal_message"] = _brief(_text(refusal), 300)
    if site == "gate":
        fields["refused_files"] = _safe(
            lambda: [_p(path) for path in v.get("refused_files", [])][:8]
        )
        fields["refused_names"] = _safe(
            lambda: {
                (_p(path) or ""): [_p(name) for name in names][:4]
                for path, names in dict(v.get("refused_names") or {}).items()
            }
        )
        fields["clause_discovered_label_is_not_none"] = label is not None
        fields["clause_not_after_overrides"] = not getattr(
            refusal, "after_overrides", True
        )
        fields["clause_repository_file_given"] = v.get("repository_file") is not None
    if site in ("parse_or_os_handler", "failed_to_load_site"):
        error = v.get("e")
        fields["handled_type"] = type(error).__name__
        fields["handled_is_os_error"] = isinstance(error, OSError)
        fields["handled_message"] = _brief(_text(error), 200)
    if site == "unparsed_raise":
        fields["unparsed"] = _brief(v.get("unparsed"))
    return fields


def _make_probe(
    rows: _Rows, calls: threading.local
) -> Callable[[str, Dict[str, Any]], None]:
    def probe(site: str, local_vars: Dict[str, Any]) -> None:
        try:
            rows.add(
                "site",
                site=site,
                call=getattr(calls, "n", None),
                **_site_fields(site, local_vars),
            )
        except Exception as exc:
            problem = _brief(f"{type(exc).__name__}: {_text(exc)}")
            _quietly(lambda: rows.add("site_error", site=site, error=problem))

    return probe


# ---------------------------------------------------------------------------
# Wrapper-level recorders for the resolution
# ---------------------------------------------------------------------------


def _recording_permit(
    permit: Optional[Callable[[Path], bool]], rows: _Rows
) -> Optional[Callable[[Path], bool]]:
    if permit is None:
        return None

    def recording(path: Path) -> bool:
        try:
            allowed = permit(path)
        except BaseException as exc:
            rows.add("permit", path=_p(path), outcome="raised", **_exc_fields(exc))
            raise
        rows.add("permit", path=_p(path), allowed=bool(allowed))
        return allowed

    return recording


def _recording_judge(
    judge: Callable[[Path, Path], bool], rows: _Rows, number: int
) -> Callable[[Path, Path], bool]:
    def recording(real: Path, named: Path) -> bool:
        try:
            answer = judge(real, named)
        except BaseException as exc:
            rows.add(
                "repository_file",
                call=number,
                real=_p(real),
                named=_p(named),
                outcome="raised",
                **_exc_fields(exc),
            )
            raise
        rows.add(
            "repository_file",
            call=number,
            real=_p(real),
            named=_p(named),
            result=bool(answer),
        )
        return answer

    return recording


def _install_recorders(
    monkeypatch: pytest.MonkeyPatch, rows: _Rows, calls: threading.local
) -> None:
    """Probe ``_resolve_config`` and wrap what it calls. Undone by ``monkeypatch``."""
    from automated_security_helper.config import config_sources
    from automated_security_helper.config import resolve_config as rc

    real_resolve = rc._resolve_config
    real_discover = rc.discover_config_source
    real_read = config_sources.read_config_bytes
    numbers = itertools.count(1)

    # The probes go onto the original function object, before the module name is
    # rebound to the wrapper below.
    install: Dict[str, Any] = {"installed": False}
    try:
        code, found = _probed_code(rc)
        if code.co_freevars != real_resolve.__code__.co_freevars:
            raise ValueError("the compiled function's free variables differ")
        monkeypatch.setitem(vars(rc), _PROBE_GLOBAL, _make_probe(rows, calls))
        monkeypatch.setattr(real_resolve, "__code__", code)
        labels = sorted({label for label, _line in found})
        install.update(
            installed=True,
            sites=[f"{label}@{line}" for label, line in found],
            missing=sorted({site[0] for site in _SITES} - set(labels)),
        )
    except Exception as exc:
        install["error"] = _brief(f"{type(exc).__name__}: {_text(exc)}", 300)
    rows.add("probe_install", **install)

    def resolve_entry(*args: Any, **kwargs: Any) -> Any:
        number = next(numbers)
        previous = getattr(calls, "n", None)
        calls.n = number
        config_path = args[0] if args else kwargs.get("config_path")
        source_dir = args[1] if len(args) > 1 else kwargs.get("source_dir")
        permit_base = args[4] if len(args) > 4 else kwargs.get("permit_base")
        judge = kwargs.get("repository_file")
        rows.add(
            "resolve_entry",
            call=number,
            config_path_is_none=config_path is None,
            config_path=_p(config_path),
            source_dir=_p(source_dir),
            fallback_to_default=args[2] if len(args) > 2 else None,
            no_discovery=kwargs.get("no_discovery"),
            permit_base_given=permit_base is not None,
            repository_file_given=judge is not None,
            overlay_given=kwargs.get("overlay") is not None,
        )
        if judge is not None:
            kwargs["repository_file"] = _recording_judge(judge, rows, number)
        try:
            result = real_resolve(*args, **kwargs)
        except BaseException as exc:
            calls.n = previous
            rows.add("resolve_exit", call=number, outcome="raised", **_exc_fields(exc))
            raise
        calls.n = previous
        rows.add(
            "resolve_exit", call=number, outcome="returned", **_config_summary(result)
        )
        return result

    def discover(*args: Any, **kwargs: Any) -> Any:
        search_dir = args[0] if args else kwargs.get("search_dir")
        permit = args[1] if len(args) > 1 else kwargs.get("permit")
        note = {
            "call": getattr(calls, "n", None),
            "search_dir": _p(search_dir),
            "permit_given": permit is not None,
        }
        try:
            discovery = real_discover(
                search_dir, permit=_recording_permit(permit, rows)
            )
        except BaseException as exc:
            rows.add("discover", outcome="raised", **note, **_exc_fields(exc))
            raise
        selected = getattr(discovery, "selected", None)
        rows.add(
            "discover",
            outcome="returned",
            selected_path=None if selected is None else _p(selected.path),
            selected_kind=None if selected is None else _text(selected.kind),
            selected_label=None if selected is None else _safe(lambda: selected.label),
            ignored=_safe(lambda: [_p(s.path) for s in discovery.ignored][:6]),
            notes=_safe(lambda: len(discovery.notes)),
            **note,
        )
        return discovery

    def read(path: Any, *args: Any, **kwargs: Any) -> Any:
        _quietly(lambda: rows.add("read", path=_p(os.path.realpath(path))))
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(rc, "_resolve_config", resolve_entry)
    monkeypatch.setattr(rc, "discover_config_source", discover)
    monkeypatch.setattr(config_sources, "read_config_bytes", read)


# ---------------------------------------------------------------------------
# Logger recorders
# ---------------------------------------------------------------------------

_LEVELLED = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "exception": logging.ERROR,
}
_ALL_METHODS = (*_LEVELLED, "verbose", "trace")
_LOUD_METHODS = ("warning", "error", "critical", "exception")


def _record_fields(record: Any) -> Dict[str, Any]:
    return {
        "logger_name": getattr(record, "name", None),
        "level_name": getattr(record, "levelname", None),
        "message": _brief(_safe(record.getMessage), 160),
        "where": (
            f"{os.path.basename(getattr(record, 'pathname', ''))}"
            f":{getattr(record, 'lineno', '')}:{getattr(record, 'funcName', '')}"
        ),
    }


class _RecordingHandler(logging.Handler):
    """Takes every record it is given and records it; emits nothing."""

    def __init__(self, label: str, rows: _Rows) -> None:
        super().__init__(level=logging.NOTSET)
        self.label = label
        self.rows = rows

    def emit(self, record: logging.LogRecord) -> None:
        _quietly(
            lambda: self.rows.add(
                "handler_took", at=self.label, **_record_fields(record)
            )
        )


def _handler_chain(logger: logging.Logger) -> List[Dict[str, Any]]:
    """The loggers and handlers a record of ``logger`` would walk, as callHandlers does."""
    from automated_security_helper.utils import log as ash_log

    scope_attr = getattr(ash_log, "_RUN_SCOPE_ATTR", None)
    chain: List[Dict[str, Any]] = []
    current: Optional[logging.Logger] = logger
    while current is not None and len(chain) < 6:
        chain.append(
            {
                "logger": current.name or "root",
                "propagate": current.propagate,
                "handlers": [
                    {
                        "type": type(handler).__name__,
                        "level": handler.level,
                        "scope": (
                            _brief(getattr(handler, scope_attr, None))
                            if scope_attr
                            else None
                        ),
                    }
                    for handler in list(current.handlers)
                ],
            }
        )
        current = current.parent if current.propagate else None
    return chain


def _logger_state(logger: logging.Logger, caplog: Any) -> Dict[str, Any]:
    from automated_security_helper.utils import log as ash_log

    root = logging.getLogger()
    return {
        "logger": logger.name,
        "logger_class": type(logger).__name__,
        "own_level": logger.level,
        "effective_level": logger.getEffectiveLevel(),
        "enabled_for_error": logger.isEnabledFor(logging.ERROR),
        "propagate": logger.propagate,
        "disabled": logger.disabled,
        "manager_disable": logging.root.manager.disable,
        "filters": [type(item).__name__ for item in logger.filters],
        "chain": _safe(lambda: _handler_chain(logger)),
        "delivers_error": _safe(lambda: ash_log.delivers(logger, logging.ERROR)),
        "root_handlers": [type(item).__name__ for item in root.handlers],
        "caplog_handler_on_logger": caplog.handler in logger.handlers,
        "caplog_handler_on_root": caplog.handler in root.handlers,
        "caplog_handler_level": caplog.handler.level,
    }


class _LoggerProbe:
    """Instance-level wrappers on one logger's level methods, filter, handle and walk.

    Set as instance attributes by ``install`` and removed by ``remove``, so the class
    and every other logger stay as they are. Each wrapper records and then calls the
    original. Use it through ``_probing``.
    """

    def __init__(
        self,
        logger: logging.Logger,
        rows: _Rows,
        methods: Tuple[str, ...] = _ALL_METHODS,
        internals: bool = True,
    ) -> None:
        self.logger = logger
        self.rows = rows
        self.methods = methods
        self.internals = internals
        self._saved: Dict[str, Any] = {}

    def install(self) -> None:
        names = list(self.methods)
        if self.internals:
            names.extend(["filter", "handle", "callHandlers"])
        for name in names:
            original = getattr(self.logger, name, None)
            if not callable(original):
                continue
            self._saved[name] = vars(self.logger).get(name, _UNSET)
            setattr(self.logger, name, self._wrapper(name, original))

    def remove(self) -> None:
        for name, saved in self._saved.items():
            if saved is _UNSET:
                vars(self.logger).pop(name, None)
            else:
                setattr(self.logger, name, saved)
        self._saved.clear()

    def _wrapper(self, name: str, original: Callable[..., Any]) -> Callable[..., Any]:
        rows, logger = self.rows, self.logger
        level = _LEVELLED.get(name)

        def level_method(*args: Any, **kwargs: Any) -> Any:
            def note() -> None:
                # note <- _quietly <- level_method <- the code that logged.
                frame = sys._getframe(3)
                rows.add(
                    "logcall",
                    method=name,
                    caller=(
                        f"{os.path.basename(frame.f_code.co_filename)}"
                        f":{frame.f_lineno}:{frame.f_code.co_name}"
                    ),
                    message=_brief(args[0] if args else None, 160),
                    enabled=None if level is None else logger.isEnabledFor(level),
                )

            _quietly(note)
            return original(*args, **kwargs)

        def filter_method(record: Any, *args: Any, **kwargs: Any) -> Any:
            result = original(record, *args, **kwargs)
            _quietly(
                lambda: rows.add(
                    "logger_filter", kept=bool(result), **_record_fields(record)
                )
            )
            return result

        def handle_method(record: Any, *args: Any, **kwargs: Any) -> Any:
            _quietly(
                lambda: rows.add(
                    "logger_handle", disabled=logger.disabled, **_record_fields(record)
                )
            )
            return original(record, *args, **kwargs)

        def walk_method(record: Any, *args: Any, **kwargs: Any) -> Any:
            _quietly(
                lambda: rows.add(
                    "logger_call_handlers",
                    chain=_safe(lambda: _handler_chain(logger)),
                    **_record_fields(record),
                )
            )
            return original(record, *args, **kwargs)

        if name == "filter":
            return filter_method
        if name == "handle":
            return handle_method
        if name == "callHandlers":
            return walk_method
        return level_method


@contextlib.contextmanager
def _probing(
    logger: logging.Logger,
    rows: _Rows,
    methods: Tuple[str, ...] = _ALL_METHODS,
    internals: bool = True,
):
    probe = _LoggerProbe(logger, rows, methods, internals)
    probe.install()
    try:
        yield probe
    finally:
        probe.remove()


# ---------------------------------------------------------------------------
# The swallow-site cases: the refusal that vanishes
# ---------------------------------------------------------------------------


def _guarded(rows: _Rows, variant: str, run: Callable[[], None]) -> None:
    rows.variant = variant
    try:
        run()
    except SystemExit as exc:
        rows.add("variant_system_exit", code=_brief(exc.code))
    except Exception as exc:
        rows.add("variant_error", **_exc_fields(exc))


def _scan_variant(rows: _Rows, source: Path, reraise_refusals: bool) -> None:
    """Start the real MCP scan; stop once ``resolve_config`` has answered.

    With ``reraise_refusals`` a refusal is raised on, so the scan's own handling of
    it (exit 3, the entry's message) is what the entry row shows; an answer still
    stops the scan, because going on would start real tools.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> Any:
        rows.add("scan_resolve_call", call_kwargs=_kwargs_summary(kwargs))
        try:
            answer = real(*args, **kwargs)
        except Exception as exc:
            rows.add("scan_resolve_outcome", outcome="raised", **_exc_fields(exc))
            if reraise_refusals:
                raise
            raise _StopAfterResolution from None
        rows.add("scan_resolve_outcome", outcome="returned", **_config_summary(answer))
        raise _StopAfterResolution

    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    try:
        with (
            patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
            patch.object(orchestrator, "resolve_config", recording),
            patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(source),
                    output_dir=str(output),
                    severity_threshold="MEDIUM",
                    session_id=SESSION,
                )
            )
    finally:
        _quietly(
            lambda: rows.add("scan_entry", **_entry_summary(registry.get_scan(scan_id)))
        )


def _named_variant(rows: _Rows, source: Path) -> None:
    """Resolve with the delivered file passed as ``config_path``, as a named config."""
    from automated_security_helper.cli.mcp.profile_registry import (
        resolve_session_trusted_config_path,
        session_client_rules,
    )
    from automated_security_helper.cli.mcp.sandbox import (
        caller_is_remote,
        config_base_gate,
    )
    from automated_security_helper.config import resolve_config as rc

    kwargs: Dict[str, Any] = {
        "config_path": source / ".ash" / ".ash.yaml",
        "source_dir": source,
        "permit_base": config_base_gate(SESSION),
        "untrusted_config": True,
        "trusted_config_path": resolve_session_trusted_config_path(SESSION),
        "client_config_policy": session_client_rules(SESSION),
        "remote_client": caller_is_remote(SESSION),
    }
    rows.add("named_resolve_call", call_kwargs=_kwargs_summary(kwargs))
    try:
        answer = rc.resolve_config(**kwargs)
    except Exception as exc:
        rows.add("named_resolve_outcome", outcome="raised", **_exc_fields(exc))
    else:
        rows.add("named_resolve_outcome", outcome="returned", **_config_summary(answer))


def _q1_summary(rows: _Rows, host_file: Path) -> Dict[str, Any]:
    data = rows.snapshot()

    def pick(kind: str, **match: Any) -> List[Dict[str, Any]]:
        return [
            row
            for row in data
            if row["kind"] == kind and all(row.get(k) == v for k, v in match.items())
        ]

    summary: Dict[str, Any] = {}
    for variant in ("scan", "named"):
        gate = pick("site", site="gate", variant=variant)
        summary[variant] = {
            "entered_with_config_path_none": [
                row.get("config_path_is_none")
                for row in pick("resolve_entry", variant=variant)
            ],
            "discovered_labels_at_gate": [row.get("discovered_label") for row in gate],
            "gate_clauses": [
                [
                    row.get("clause_discovered_label_is_not_none"),
                    row.get("clause_not_after_overrides"),
                    row.get("clause_repository_file_given"),
                ]
                for row in gate
            ],
            "refusal_types": [
                row.get("refusal_type")
                for row in pick("site", site="refusal_arm", variant=variant)
            ],
            "judge_results": [
                row.get("result") for row in pick("repository_file", variant=variant)
            ],
            "containment_arm_ran": len(
                pick("site", site="containment_arm", variant=variant)
            ),
            "reraised_by_the_arm": len(pick("site", site="reraise", variant=variant)),
            "discover_outcomes": [
                row.get("outcome") for row in pick("discover", variant=variant)
            ],
            "permit_answers": [
                row.get("allowed") for row in pick("permit", variant=variant)
            ],
            "resolve_exit": [
                [row.get("outcome"), row.get("exc_type"), row.get("loaded_from")]
                for row in pick("resolve_exit", variant=variant)
            ],
        }
    reads = {row.get("path") for row in pick("read")}
    summary["host_file_was_read"] = _p(os.path.realpath(host_file)) in reads
    return summary


def _measure_a_refused_delivery(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    server: Dict[str, Path],
    *,
    cell: str,
    text: str,
    reraise_refusals: bool,
) -> None:
    from automated_security_helper.utils.log import ASH_LOGGER

    rows = _Rows(cell)
    controls: Dict[str, bool] = {"scenario_constructed": False}
    calls = threading.local()
    try:
        _meta_row(rows, request)
        source = _linked_tree(server, text)
        controls["scenario_constructed"] = _scenario_row(rows, server, source)
        _install_recorders(monkeypatch, rows, calls)
        with _probing(ASH_LOGGER, rows, methods=_LOUD_METHODS, internals=False):
            _guarded(
                rows, "scan", lambda: _scan_variant(rows, source, reraise_refusals)
            )
            _guarded(rows, "named", lambda: _named_variant(rows, source))
        rows.variant = "-"
        rows.add("summary", **_q1_summary(rows, server["host"] / "ash.yaml"))
    except Exception as exc:
        rows.add("cell_error", **_exc_fields(exc))
    finally:
        controls["recorder_captured_rows"] = any(
            row["kind"] != "meta" for row in rows.snapshot()
        )
        rows.add("controls", **controls)
        _publish(request, rows, server["tmp"])
    assert controls["scenario_constructed"], "the delivered tree was not constructed"
    assert controls["recorder_captured_rows"], "the recorder captured no row"


@pytest.mark.usefixtures("host_set_aside")
def test_settle_q1_not_a_config(_server, monkeypatch, request) -> None:
    """Twin of test_a_linked_file_that_is_not_a_config_is_not_quoted."""
    _measure_a_refused_delivery(
        request,
        monkeypatch,
        _server,
        cell="q1-not-a-config",
        text=NOT_A_CONFIG,
        reraise_refusals=False,
    )


@pytest.mark.usefixtures("host_set_aside")
def test_settle_q1_bad_expiry(_server, monkeypatch, request) -> None:
    """Twin of test_a_validators_own_message_is_reported_by_its_type."""
    _measure_a_refused_delivery(
        request,
        monkeypatch,
        _server,
        cell="q1-bad-expiry",
        text=BAD_EXPIRY,
        reraise_refusals=False,
    )


@pytest.mark.usefixtures("host_set_aside")
def test_settle_q1_unknown_key(_server, monkeypatch, request) -> None:
    """Twin of test_a_key_the_schema_does_not_have_is_not_named."""
    _measure_a_refused_delivery(
        request,
        monkeypatch,
        _server,
        cell="q1-unknown-key",
        text=UNKNOWN_KEY,
        reraise_refusals=False,
    )


def test_settle_q1_scan_itself(_server, monkeypatch, request) -> None:
    """Twin of test_the_scan_itself_refuses_it_without_reading_it.

    No ``host_set_aside``, as in the original. A refusal is raised on, so the
    scan's own handling shows in the entry row; an answer stops the scan.
    """
    _measure_a_refused_delivery(
        request,
        monkeypatch,
        _server,
        cell="q1-scan-itself",
        text=LINK_OUT,
        reraise_refusals=True,
    )


# ---------------------------------------------------------------------------
# The log-emission cases: the log record that does not arrive
# ---------------------------------------------------------------------------


def _injected_read_failure(*args: Any, **kwargs: Any) -> Any:
    raise OSError(errno.EIO, "settle-trace injected read failure")


def _resolve_directly(rows: _Rows, source: Path) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    rows.add("direct_resolve_call", source_dir=_p(source))
    try:
        answer = resolve_config(source_dir=source)
    except Exception as exc:
        rows.add(
            "direct_resolve_outcome",
            outcome="raised",
            is_config_source_error=isinstance(exc, ASHConfigSourceError),
            **_exc_fields(exc),
        )
    else:
        rows.add(
            "direct_resolve_outcome", outcome="returned", **_config_summary(answer)
        )


def _caplog_row(rows: _Rows, caplog: Any, moment: str) -> None:
    records = list(caplog.records)
    rows.add(
        "caplog",
        moment=moment,
        count=len(records),
        failed_to_load=sum("Failed to load" in _text(r.getMessage()) for r in records),
        records=[
            f"{r.name}|{r.levelname}|{_brief(_safe(r.getMessage), 100)}"
            for r in records[:8]
        ],
    )


def _q2_summary(rows: _Rows) -> Dict[str, Any]:
    data = rows.snapshot()
    summary: Dict[str, Any] = {}
    for phase in ("scenario", "control"):
        here = [row for row in data if row.get("phase") == phase]

        def count(kind: str, **match: Any) -> int:
            return sum(
                1
                for row in here
                if row["kind"] == kind
                and all(row.get(k) == v for k, v in match.items())
            )

        calls = [row for row in here if row["kind"] == "logcall"]
        summary[phase] = {
            "logcalls_by_method": {
                name: sum(1 for row in calls if row.get("method") == name)
                for name in sorted({row.get("method") for row in calls})
            },
            "error_level_calls": sum(
                1 for row in calls if row.get("method") in ("error", "exception")
            ),
            "failed_to_load_calls": sum(
                1 for row in calls if "Failed to load" in _text(row.get("message"))
            ),
            "logger_filter_kept": count("logger_filter", kept=True),
            "logger_filter_dropped": count("logger_filter", kept=False),
            "logger_handle_reached": count("logger_handle"),
            "call_handlers_reached": count("logger_call_handlers"),
            "ash_logger_handler_took": count("handler_took", at="ash_logger"),
            "root_logger_handler_took": count("handler_took", at="root_logger"),
            "site_parse_or_os_handler": count("site", site="parse_or_os_handler"),
            "site_failed_to_load_site": count("site", site="failed_to_load_site"),
            "site_unparsed_raise": count("site", site="unparsed_raise"),
        }
    carried = [row for row in data if row["kind"] == "caplog"]
    summary["caplog_after_scenario"] = [
        [row.get("count"), row.get("failed_to_load")]
        for row in carried
        if row.get("moment") == "after_scenario"
    ]
    summary["caplog_after_control"] = [
        [row.get("count"), row.get("failed_to_load")]
        for row in carried
        if row.get("moment") == "after_control"
    ]
    return summary


def _measure_log_emission(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    caplog: Any,
    server: Dict[str, Path],
    *,
    cell: str,
    inject_read_failure: bool,
) -> None:
    from automated_security_helper.utils.log import ASH_LOGGER

    rows = _Rows(cell)
    controls: Dict[str, bool] = {"scenario_constructed": False}
    calls = threading.local()
    try:
        _meta_row(rows, request)
        source = _linked_tree(server, NOT_YAML)
        controls["scenario_constructed"] = _scenario_row(rows, server, source)
        if inject_read_failure:
            from automated_security_helper.config import resolve_config as rc

            monkeypatch.setattr(rc, "load_config_file_for_run", _injected_read_failure)
        _install_recorders(monkeypatch, rows, calls)
        ash_handler = _RecordingHandler("ash_logger", rows)
        root_handler = _RecordingHandler("root_logger", rows)
        root = logging.getLogger()
        ASH_LOGGER.addHandler(ash_handler)
        root.addHandler(root_handler)
        try:
            with _probing(ASH_LOGGER, rows):
                rows.add(
                    "logger_state",
                    moment="before_at_level",
                    **_logger_state(ASH_LOGGER, caplog),
                )
                with caplog.at_level(logging.ERROR, logger=ASH_LOGGER.name):
                    rows.add(
                        "logger_state",
                        moment="inside_at_level",
                        **_logger_state(ASH_LOGGER, caplog),
                    )
                    _resolve_directly(rows, source)
                    rows.add(
                        "logger_state",
                        moment="after_scenario",
                        **_logger_state(ASH_LOGGER, caplog),
                    )
                    _caplog_row(rows, caplog, "after_scenario")
                    rows.phase = "control"
                    ASH_LOGGER.error(CONTROL_TEXT)
                    _caplog_row(rows, caplog, "after_control")
                rows.phase = "after"
        finally:
            ASH_LOGGER.removeHandler(ash_handler)
            root.removeHandler(root_handler)
        rows.add("summary", **_q2_summary(rows))
    except Exception as exc:
        rows.add("cell_error", **_exc_fields(exc))
    finally:
        controls["recorder_captured_rows"] = any(
            row["kind"] != "meta" for row in rows.snapshot()
        )
        rows.add("controls", **controls)
        _publish(request, rows, server["tmp"])
    assert controls["scenario_constructed"], "the delivered tree was not constructed"
    assert controls["recorder_captured_rows"], "the recorder captured no row"


@pytest.mark.usefixtures("host_set_aside")
def test_settle_q2_yaml_parse_emission(_server, monkeypatch, caplog, request) -> None:
    """Twin of test_the_log_line_for_it_does_not_quote_it_either."""
    _measure_log_emission(
        request,
        monkeypatch,
        caplog,
        _server,
        cell="q2-yaml-parse",
        inject_read_failure=False,
    )


@pytest.mark.usefixtures("host_set_aside")
def test_settle_q2_read_failure_control(_server, monkeypatch, caplog, request) -> None:
    """The same plumbing with an injected OSError: the call site known to log."""
    _measure_log_emission(
        request,
        monkeypatch,
        caplog,
        _server,
        cell="q2-read-failure-control",
        inject_read_failure=True,
    )
