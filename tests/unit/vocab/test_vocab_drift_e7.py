"""Drift gate for the small serialized vocabularies (enum unit E7).

Every vocabulary here has one home (an enum), and the code that was cured
carries members, not the spelling. This module fails when a spelling comes
back. It has two modes, because a vocabulary's spellings are not all equally
distinctive:

* STRONG: the vocabulary's spellings are distinctive (``"unverifiable"``,
  ``"run_completed"``), so an ``ast`` walk of the cured files flags any string
  constant equal to a member value. Docstrings are skipped (comments never
  reach the AST), and so is the body of the enum's own class.
* POSITIVE: the spellings are short common words (``"input"``, ``"tool"``,
  ``"fail"``, ``"global"``) or numbers, where a scan of every constant drowns
  in unrelated uses. Those vocabularies pin the known former copy sites
  instead: a list of ``(file, forbidden fragment)`` pairs, each a spelling of
  the OLD shape at a site this unit cured.

A gate that scans nothing reads as clean, so the module carries a planted
positive control for each mode: a stray spelling in a fixture that the scanner
must flag, and a scan whose file count is asserted.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, List, Sequence, Set, Tuple

import pytest

from automated_security_helper.core.enums import AshExitCode, ThresholdSource
from automated_security_helper.express.runtime import ExpressOp
from automated_security_helper.models.vocab import FailureKind
from automated_security_helper.utils.content_databases import StalenessPolicy
from automated_security_helper.utils.inner_run_outcome import InnerRunRecordType
from automated_security_helper.utils.pre_installed_tool import ToolInstallStatus

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

pytestmark = pytest.mark.unit


def _docstring_nodes(tree: ast.AST) -> Set[int]:
    skipped: Set[int] = set()
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
                skipped.add(id(body[0].value))
    return skipped


def stray_spellings(
    source: str, values: Set[str], skip_classes: Iterable[str] = ()
) -> List[Tuple[int, str]]:
    """The ``(line, value)`` of every string constant in *source* equal to one of
    *values*, outside docstrings and outside the bodies of *skip_classes*."""
    tree = ast.parse(source)
    docstrings = _docstring_nodes(tree)
    skipped_classes = set(skip_classes)
    found: List[Tuple[int, str]] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.ClassDef) and node.name in skipped_classes:
            return
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in values
            and id(node) not in docstrings
        ):
            found.append((node.lineno, node.value))
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return found


#: STRONG mode: (enum class, scope, allowlist of (path, reason)). The scope is
#: the files this unit cured; it grows as later units land.
STRONG = [
    (
        ToolInstallStatus,
        [
            "utils/pre_installed_tool.py",
            "base/uv_tool_mixin.py",
            "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        ],
        [],
    ),
    (
        InnerRunRecordType,
        ["utils/inner_run_outcome.py"],
        [],
    ),
]


def _values(enum_class) -> Set[str]:
    return {member.value for member in enum_class}


@pytest.mark.parametrize(
    "enum_class,scope,allowlist", STRONG, ids=[row[0].__name__ for row in STRONG]
)
def test_strong_vocabularies_have_no_stray_spellings(enum_class, scope, allowlist):
    allowed = {path for path, _reason in allowlist}
    scanned = 0
    stray = {}
    for relative in scope:
        if relative in allowed:
            continue
        found = stray_spellings(
            (PACKAGE / relative).read_text(encoding="utf-8"),
            _values(enum_class),
            skip_classes={enum_class.__name__},
        )
        scanned += 1
        if found:
            stray[relative] = found
    assert scanned == len(scope) - len(allowed), "a scope file was not scanned"
    assert not stray, f"{enum_class.__name__} spelled by hand: {stray}"


def test_the_strong_scanner_flags_a_planted_stray_spelling(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        '"""A docstring that says "unverifiable" is skipped."""\n'
        "class ToolInstallStatus:\n"
        '    HERE = "unverifiable"\n'
        "def verdict():\n"
        '    return "unverifiable"\n',
        encoding="utf-8",
    )
    found = stray_spellings(
        planted.read_text(encoding="utf-8"),
        _values(ToolInstallStatus),
        skip_classes={"ToolInstallStatus"},
    )
    assert found == [(5, "unverifiable")]


#: POSITIVE mode: (path, forbidden fragment, what it was). Each pair is a site
#: this unit cured; the fragment is the shape the old code had there.
POSITIVE: Sequence[Tuple[str, str, str]] = [
    # A6 FailureKind
    ("models/asharp_model.py", 'Literal["input", "tool"]', "kind field Literal"),
    ("base/converter_plugin.py", 'Literal["input", "tool"]', "kind parameter"),
    ("base/converter_plugin.py", 'kind == "input"', "kind compare"),
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        'Literal["input", "tool"]',
        "_failure_kind return type",
    ),
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        'kind="input"',
        "record_failed_input kind",
    ),
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        '== "tool"',
        "_failure_kind compare",
    ),
    (
        "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        'kind="input"',
        "record_failed_input kind",
    ),
    # A7 ThresholdSource
    (
        "core/scanner_statistics_calculator.py",
        'scanner_threshold_def = "',
        "source assigned as text",
    ),
    ("core/scanner_statistics_calculator.py", '"unavailable",', "source as text"),
    # A13 StalenessPolicy
    ("utils/content_databases.py", "STALENESS_FAIL", "retired constant"),
    ("utils/content_databases.py", "STALENESS_WARN", "retired constant"),
    ("utils/content_databases.py", "STALENESS_POLICIES", "retired constant"),
    ("utils/content_db_staleness.py", "STALENESS_FAIL", "retired constant"),
    ("utils/content_db_staleness.py", "STALENESS_WARN", "retired constant"),
    ("utils/content_db_staleness.py", "STALENESS_POLICIES", "retired constant"),
    ("config/staleness_trust.py", "STALENESS_FAIL", "retired constant"),
    ("utils/offline_cache_check.py", "STALENESS_FAIL", "retired constant"),
    # A14 ExpressOp
    ("express/client.py", '"op": "', "writer literal"),
    ("express/daemon.py", 'op == "', "reader compare"),
    ("express/daemon.py", 'op != "', "reader compare"),
    ("express/daemon.py", '.get("op") == "', "reader compare"),
    ("express/daemon.py", '.get("op") != "', "reader compare"),
    ("cli/express.py", '"op": "', "writer literal"),
    # A16 InnerRunRecordType
    ("utils/inner_run_outcome.py", "_CHECKPOINT =", "retired constants"),
    # A17 AshExitCode: bare integers handed to the exit machinery
    ("cli/plugin.py", "typer.Exit(1)", "bare exit code"),
    ("cli/plugin.py", "typer.Exit(3)", "bare exit code"),
    ("cli/diff.py", "typer.Exit(1)", "bare exit code"),
    ("cli/express.py", "typer.Exit(1)", "bare exit code"),
    ("cli/report.py", "typer.Exit(1)", "bare exit code"),
    ("cli/report.py", "typer.Exit(3)", "bare exit code"),
    ("cli/config.py", "typer.Exit(1)", "bare exit code"),
    ("cli/config.py", "typer.Exit(0)", "bare exit code"),
    ("cli/config.py", "typer.Exit(3)", "bare exit code"),
    ("cli/main.py", "typer.Exit(1)", "bare exit code"),
    ("cli/dependency_check.py", "typer.Exit(3)", "bare exit code"),
    ("cli/dependency_check.py", "typer.Exit(1)", "bare exit code"),
    ("cli/mcp/__init__.py", "typer.Exit(1)", "bare exit code"),
    ("cli/mcp/__init__.py", "typer.Exit(3)", "bare exit code"),
    ("cli/merge.py", "typer.Exit(1)", "bare exit code"),
    ("cli/merge.py", "typer.Exit(3)", "bare exit code"),
    ("cli/scan.py", "typer.Exit(1)", "bare exit code"),
    ("cli/scan.py", "typer.Exit(3)", "bare exit code"),
    ("cli/scan.py", "typer.Exit(0)", "bare exit code"),
    ("cli/inspect/inspect_findings_app.py", "typer.Exit(1)", "bare exit code"),
    ("interactions/run_ash_scan.py", "sys.exit(1)", "bare exit code"),
    ("interactions/run_ash_scan.py", "sys.exit(3)", "bare exit code"),
    ("interactions/run_ash_scan.py", "sys.exit(0)", "bare exit code"),
    ("core/constants.py", "ASH_EXIT_USAGE_ERROR = 5", "number spelled twice"),
]


def positive_hits(root: Path, pairs: Sequence[Tuple[str, str, str]]):
    return [
        (path, fragment, what)
        for path, fragment, what in pairs
        if fragment in (root / path).read_text(encoding="utf-8")
    ]


def test_the_cured_sites_stay_cured():
    hits = positive_hits(PACKAGE, POSITIVE)
    assert not hits, f"a cured site spells its vocabulary by hand again: {hits}"


#: Callees that end the process or the command with the integer they are given.
_EXIT_CALLEES = {"Exit", "SystemExit", "exit", "_exit"}


def _callee(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_int_literal(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    )


def int_literal_exits(source: str) -> List[Tuple[int, str]]:
    """``(line, spelling)`` of each integer literal handed to an exit.

    The AST shape of the ``typer.Exit(1)`` fragments above, so ``Exit(code=1)``,
    ``raise SystemExit(2)``, ``sys.exit(0)`` and a subclass of ``typer.Exit`` that
    calls ``super().__init__(1)`` are caught however they are spelled. A member
    (``AshExitCode.X``), a name or an attribute is not flagged.
    """
    tree = ast.parse(source)
    found: List[Tuple[int, str]] = []
    exit_classes = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            (isinstance(b, ast.Name) and b.id in _EXIT_CALLEES)
            or (isinstance(b, ast.Attribute) and b.attr in _EXIT_CALLEES)
            for b in node.bases
        )
    }
    in_exit_class: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in exit_classes:
            in_exit_class.update(id(child) for child in ast.walk(node))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _callee(node)
        if name in _EXIT_CALLEES:
            args = list(node.args[:1]) + [
                k.value for k in node.keywords if k.arg in {"code", "exit_code"}
            ]
            for arg in args:
                if _is_int_literal(arg):
                    found.append((node.lineno, f"{name}({arg.value})"))
        elif (
            name == "__init__"
            and id(node) in in_exit_class
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Call)
            and _callee(node.func.value) == "super"
            and any(_is_int_literal(a) for a in node.args[:1])
        ):
            found.append((node.lineno, f"super().__init__({node.args[0].value})"))
    return sorted(found)


#: Integer exits that stay literal on purpose, by file: ``ash plugin``'s own usage
#: refusal is 2, a command-specific code with no ``AshExitCode`` member (the one
#: member that is 2, ``ACTIONABLE_FINDINGS``, would misname it).
ALLOWED_INT_EXITS = {"cli/plugin.py": {"Exit(2)"}}


#: The files the exit-code cure touched: every ``bare exit code`` row above.
EXIT_SCOPE = sorted(
    {path for path, _frag, what in POSITIVE if what == "bare exit code"}
)


@pytest.mark.parametrize("relative", EXIT_SCOPE)
def test_no_cured_file_hands_an_integer_literal_to_an_exit(relative):
    source = (PACKAGE / relative).read_text(encoding="utf-8")
    allowed = ALLOWED_INT_EXITS.get(relative, set())
    assert [s for s in int_literal_exits(source) if s[1] not in allowed] == []


@pytest.mark.parametrize(
    "source",
    [
        "raise typer.Exit(1)\n",
        "raise typer.Exit(code=1)\n",
        "raise Exit(3)\n",
        "raise SystemExit(2)\n",
        "sys.exit(0)\n",
        "sys.exit(code=4)\n",
        "class Done(typer.Exit):\n    def __init__(self):\n        super().__init__(1)\n",
    ],
)
def test_the_int_exit_scan_flags_a_planted_spelling(source):
    assert int_literal_exits(source), source


@pytest.mark.parametrize(
    "source",
    [
        "raise typer.Exit(AshExitCode.SCAN_ERRORS)\n",
        "raise typer.Exit(code=AshExitCode.OK)\n",
        "sys.exit(code)\n",
        "raise SystemExit(int(code))\n",
        "class Plain:\n    def __init__(self):\n        super().__init__(1)\n",
        "raise typer.Exit()\n",
    ],
)
def test_the_int_exit_scan_leaves_members_and_other_calls_alone(source):
    assert int_literal_exits(source) == []


def test_the_exit_scope_is_not_empty():
    assert len(EXIT_SCOPE) >= 10, EXIT_SCOPE


def test_the_positive_pins_find_a_planted_fragment(tmp_path):
    (tmp_path / "planted.py").write_text(
        'def go():\n    raise typer.Exit(1)\n    return {"op": "scan"}\n',
        encoding="utf-8",
    )
    pairs = [
        ("planted.py", "typer.Exit(1)", "planted exit"),
        ("planted.py", '"op": "', "planted op"),
        ("planted.py", "never present", "negative control"),
    ]
    assert [row[2] for row in positive_hits(tmp_path, pairs)] == [
        "planted exit",
        "planted op",
    ]


def test_every_positive_pin_names_a_file_that_exists():
    for path, _fragment, _what in POSITIVE:
        assert (PACKAGE / path).is_file(), path


def test_the_ash_exit_code_table_is_derived_not_respelled():
    from automated_security_helper.core.constants import (
        ASH_EXIT_CODES,
        ASH_EXIT_INTERRUPTED,
        ASH_EXIT_TERMINATED,
        ASH_EXIT_USAGE_ERROR,
    )
    from automated_security_helper.models.workspace import WorkspaceExitCode

    assert ASH_EXIT_USAGE_ERROR == AshExitCode.USAGE_ERROR
    assert ASH_EXIT_INTERRUPTED == AshExitCode.INTERRUPTED
    assert ASH_EXIT_TERMINATED == AshExitCode.TERMINATED
    assert WorkspaceExitCode.USAGE_ERROR == AshExitCode.USAGE_ERROR
    assert set(ASH_EXIT_CODES) == {
        AshExitCode.SUCCESS.value,
        AshExitCode.SCAN_ERRORS.value,
        AshExitCode.ACTIONABLE_FINDINGS.value,
        AshExitCode.INVALID_CONFIG.value,
        AshExitCode.WORKSPACE_ERROR.value,
        AshExitCode.USAGE_ERROR.value,
    }
    # The numbers the CLI reference and CI gates read.
    assert {m.name: m.value for m in AshExitCode} == {
        "SUCCESS": 0,
        "SCAN_ERRORS": 1,
        "ACTIONABLE_FINDINGS": 2,
        "INVALID_CONFIG": 3,
        "WORKSPACE_ERROR": 4,
        "USAGE_ERROR": 5,
        "INTERRUPTED": 130,
        "TERMINATED": 143,
    }


def test_the_config_staleness_literals_accept_exactly_the_policy_members():
    # The config models validate strictly and the loader writes YAML with
    # safe_dump, which cannot represent an enum member, so these two fields stay
    # Literals. The accepted set is pinned to the enum here instead.
    import typing

    from automated_security_helper.config.ash_config import (
        AshConfig,
        ContentDbStalenessOverride,
    )

    for model, field in (
        (AshConfig, "content_db_staleness"),
        (ContentDbStalenessOverride, "policy"),
    ):
        annotation = model.model_fields[field].annotation
        assert set(typing.get_args(annotation)) == _values(StalenessPolicy), field
    assert AshConfig(project_name="x").content_db_staleness == (
        StalenessPolicy.FAIL.value
    )


def test_the_threshold_source_the_calculator_resolves_is_a_member():
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results = AshAggregatedResults()
    _threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
        results, "bandit"
    )
    assert isinstance(source, ThresholdSource)


def test_the_wire_spellings_are_exactly_the_old_ones():
    assert _values(FailureKind) == {"input", "tool"}
    assert _values(ThresholdSource) == {"global", "config", "unavailable"}
    assert _values(StalenessPolicy) == {"fail", "warn"}
    assert _values(ExpressOp) == {"scan", "status", "stop", "go", "signal"}
    assert _values(ToolInstallStatus) == {"satisfied", "unsatisfied", "unverifiable"}
    assert _values(InnerRunRecordType) == {
        "run_completed",
        "report_path_refused",
        "reports_written",
    }
