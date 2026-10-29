# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ASH ships about its MCP tools says what the tools do.

Why this file exists
--------------------
Two texts tell an agent how to drive the MCP server and ship with ASH: the tool
reference generated into the agent plugins (scripts/generate_mcp_tool_reference.py
renders it from the registry and TOOL_NOTES), and the GenAI steering guide, which
is in the wheel and is what ``ash get-genai-guide`` writes out. Both can drift
from the server with no test reading them. The statements each test pins:

* cancel_scan stops a scan, rather than marking it cancelled and leaving it
  running.
* ``is_complete`` is true for every ending, a cancelled scan included, so no text
  may say to poll ``status`` instead. A failed or cancelled scan has no results
  of its own: ``results_available`` says which scans do, and the files in the
  output directory of one that does not are the previous scan's.
* run_ash_scan's ``severity_threshold`` is not ignored: it makes the config's
  threshold stricter for that scan, never looser.
* ``actionable_only`` lists the unsuppressed findings rather than adding an empty
  ``findings`` list, in a ``filter_level="full"`` response, and the SARIF it
  is built from is not returned.
* ``actionable_only`` keeps the unsuppressed findings at or above the severity
  threshold the scan was judged by, the set that makes a scan exit 2, so no
  troubleshooting page may say "findings below it are still listed".

The tool reference is prose, so it is read for those statements. The guide's MCP
examples are code an agent copies, so they are run: against stand-in progress
responses for each way a scan ends (the server's side of that contract is
tests/unit/cli/mcp/test_is_complete_tracks_the_scan.py), and against the real
get_scan_results tool reading a results file written the way ASH writes one.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV

REPO = Path(__file__).resolve().parents[4]
TOOL_REFERENCE = (
    REPO
    / "ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md"
)
GUIDE = REPO / "docs/content/docs/genai-steering-guide.md"
#: The MCP server guide: the docs-site page that lists the error categories.
MCP_SERVER_GUIDE = REPO / "docs/content/docs/mcp-server-guide.md"
#: The plugins' troubleshooting page, copied into every plugin backend from here.
TROUBLESHOOTING = (
    REPO
    / "ash-agent-plugins/agentic-coding/transpiler/_base/references/troubleshooting.md"
)

#: Statements of the old behavior. None may appear in a shipped text.
STALE = {
    "is_complete stays false for a cancelled scan": r"stays `?False`? for cancell?ed",
    "do not rely on is_complete": r"(rely on|polling on) `?is_complete`? alone",
    "is_complete does not flip": r"`?is_complete`? does not flip",
    "cancel does not stop the scan": r"(does not|doesn't|cannot) stop",
    "severity_threshold is ignored": (
        r"severity_threshold[^\n]*\bignored\b|\bignored\b[^\n]*severity_threshold"
    ),
    # Without actionable_only a response has no findings list at all.
    "actionable_only=False shows every finding": (
        r"actionable_only=False`? to see|set it to `?false`? to see"
    ),
    # actionable_only leaves out the findings below the severity threshold.
    "findings below the threshold are listed": r"below (it|the threshold)[^\n.]*\blisted",
}


# ---------------------------------------------------------------------------
# The tool reference
# ---------------------------------------------------------------------------


def _section(text: str, tool: str) -> str:
    match = re.search(
        rf"^## {re.escape(tool)}\n(.*?)(?=^## )", text, re.DOTALL | re.MULTILINE
    )
    assert match, f"the tool reference has no section for {tool}"
    return match.group(1)


def _row(section: str, parameter: str) -> str:
    rows = [
        line for line in section.splitlines() if line.startswith(f"| `{parameter}`")
    ]
    assert rows, f"no `{parameter}` row"
    return rows[0]


@pytest.mark.parametrize(
    "path", [TOOL_REFERENCE, GUIDE, TROUBLESHOOTING], ids=lambda p: p.name
)
def test_no_shipped_text_states_the_old_behavior(path):
    text = path.read_text(encoding="utf-8")
    stale = {
        claim: pattern
        for claim, pattern in STALE.items()
        if re.search(pattern, text, re.IGNORECASE)
    }
    assert not stale, f"{path.name} still says: {sorted(stale)}"


def test_the_mcp_guide_lists_every_error_category():
    """docs/content/docs/mcp-server-guide.md says 'The following error
    categories are used': every category a response can carry is in that
    list, so a client reading the guide can branch on each one it may get."""
    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
    )

    if not MCP_SERVER_GUIDE.exists():
        pytest.skip(
            "docs/content/docs/mcp-server-guide.md is not in this tree: the "
            "docs site's pages are repository files, not wheel files, so a "
            "run from an installed package has nothing to read"
        )
    text = MCP_SERVER_GUIDE.read_text(encoding="utf-8")
    # The categories must be in THAT list, not merely somewhere on the page:
    # a category named only by an example elsewhere kept this green when its
    # list line was dropped.
    marker = "The following error categories are used"
    assert marker in text, MCP_SERVER_GUIDE.name
    listing_lines = []
    for line in text.split(marker, 1)[1].splitlines()[1:]:
        if line.lstrip().startswith("#"):
            break
        listing_lines.append(line)
    listing = "\n".join(listing_lines)
    missing = [c.value for c in ErrorCategory if f"`{c.value}`" not in listing]
    assert missing == [], missing


def test_the_tool_reference_says_cancel_scan_stops_the_scan():
    section = _section(TOOL_REFERENCE.read_text(encoding="utf-8"), "cancel_scan")
    assert "is stopped" in section and "no reports" in section, section


def test_the_tool_reference_says_is_complete_ends_every_scan():
    text = TOOL_REFERENCE.read_text(encoding="utf-8")
    progress = _section(text, "get_scan_progress")
    assert "`is_complete` is `true` once the scan has ended" in progress, progress
    assert "`results_available`" in progress, progress
    assert "until `is_complete` is `true`" in _section(text, "run_ash_scan")


def test_the_tool_reference_says_severity_threshold_tightens_the_config():
    row = _row(
        _section(TOOL_REFERENCE.read_text(encoding="utf-8"), "run_ash_scan"),
        "severity_threshold",
    )
    assert "stricter" in row and "never looser" in row, row
    assert "severity_threshold" in inspect.signature(mcp_server.run_ash_scan).parameters


def test_the_tool_reference_says_actionable_only_lists_the_findings():
    row = _row(
        _section(TOOL_REFERENCE.read_text(encoding="utf-8"), "get_scan_results"),
        "actionable_only",
    )
    assert "add `findings`" in row and "`full`" in row, row


def test_the_tool_reference_says_actionable_only_keeps_what_fails_the_scan():
    """Unsuppressed and at or above the threshold, as for exit 2."""
    row = _row(
        _section(TOOL_REFERENCE.read_text(encoding="utf-8"), "get_scan_results"),
        "actionable_only",
    )
    assert "unsuppressed" in row and "at or above the severity threshold" in row, row
    assert "exit code 2" in row, row


# ---------------------------------------------------------------------------
# The steering guide's MCP examples, run
# ---------------------------------------------------------------------------

TOOLS = (
    "run_ash_scan",
    "get_scan_progress",
    "get_scan_results",
    "get_scan_summary",
    "get_scan_result_paths",
    "list_active_scans",
    "cancel_scan",
)
_CALLS_A_TOOL = re.compile(r"\b(" + "|".join(TOOLS) + r")\(")


@dataclass
class Example:
    heading: str
    code: str

    def __str__(self) -> str:
        return self.heading


def _mcp_examples() -> List[Example]:
    """The guide's python blocks that call an MCP tool, each under its heading.

    The block under a "WRONG" heading shows what not to do and is left out.
    """
    examples: List[Example] = []
    heading = ""
    block: List[str] = []
    in_block = False
    for line in GUIDE.read_text(encoding="utf-8").splitlines():
        if in_block:
            if line.startswith("```"):
                in_block = False
                code = "\n".join(block)
                if _CALLS_A_TOOL.search(code) and "WRONG" not in heading:
                    examples.append(Example(heading, code))
            else:
                block.append(line)
        elif line.startswith("```python"):
            in_block, block = True, []
        elif line.startswith("#"):
            heading = line.lstrip("#").strip()
    return examples


EXAMPLES = _mcp_examples()
POLLING = [e for e in EXAMPLES if "get_scan_progress(" in e.code]
READING = [e for e in EXAMPLES if e not in POLLING]


def test_the_guide_has_the_examples_this_file_runs():
    """A parser that found nothing would make every test below pass vacuously."""
    headings = [example.heading for example in EXAMPLES]
    assert len(POLLING) == 2, headings
    assert any(h.startswith("Pattern 1") for h in headings), headings
    assert any(h.startswith("Pattern 2") for h in headings), headings


def test_the_guide_says_cancel_scan_stops_the_scan():
    lines = [
        line
        for line in GUIDE.read_text(encoding="utf-8").splitlines()
        if line.startswith("- `cancel_scan`")
    ]
    assert lines and "stop" in lines[0], lines


def _keyword_values(name: str) -> List[Any]:
    """Every literal passed as keyword ``name`` in the guide's MCP examples."""
    flags = ast.PyCF_ONLY_AST | ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
    values = []
    for example in EXAMPLES:
        tree = compile(example.code, example.heading, "exec", flags=flags)
        values += [
            keyword.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for keyword in node.keywords
            if keyword.arg == name and isinstance(keyword.value, ast.Constant)
        ]
    return values


def test_every_example_severity_threshold_tightens_the_default():
    """The guide says severity_threshold makes the threshold stricter, never looser.

    Its example passed "HIGH", which is looser than the default MEDIUM, so the
    server kept MEDIUM (severity_ladder.stricter_of): the example tightened
    nothing while its comment said it did.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.severity_ladder import stricter_of

    default = AshConfig().global_settings.severity_threshold
    values = _keyword_values("severity_threshold")
    assert values, "no example passes severity_threshold"
    looser = [v for v in values if v == default or stricter_of(v, default) != v]
    assert not looser, (
        f"{looser} would not make the default {default} stricter, so the server "
        f"ignores it"
    )


def test_the_guide_lists_the_thresholds_the_config_accepts():
    """It listed INFO, which is a severity and not a threshold; ALL was missing."""
    from automated_security_helper.utils.severity_ladder import SEVERITY_THRESHOLDS

    listed = [
        match.group(1)
        for match in re.finditer(
            r"severity_threshold: \w+\s+#\s*([A-Z, ]+)",
            GUIDE.read_text(encoding="utf-8"),
        )
    ]
    assert listed, "the guide's sample config lists no thresholds"
    for names in listed:
        assert {n.strip() for n in names.split(",")} == set(SEVERITY_THRESHOLDS), names


class _Response(dict):
    """A tool's response, usable with and without ``await``: the guide does both."""

    def __await__(self):
        if False:  # pragma: no cover - makes this a generator
            yield
        return self


def _checked(name: str, args: tuple, kwargs: Dict[str, Any]) -> None:
    """Refuse an argument the real tool does not take, as the server would."""
    real = getattr(mcp_server, name)
    parameters = [
        p for p in inspect.signature(real).parameters.values() if p.name != "ctx"
    ]
    inspect.Signature(parameters).bind(*args, **kwargs)


def _real_results(**kwargs: Any) -> Dict[str, Any]:
    """The real get_scan_results tool, on its own loop: an example may hold this one."""
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    with ThreadPoolExecutor(1) as pool:
        return pool.submit(
            asyncio.run, mcp_server.get_scan_results(ctx, **kwargs)
        ).result()


#: How each ending reads in get_scan_progress, by the server's contract.
ENDINGS: Dict[str, Dict[str, Any]] = {
    "completed": {"status": "completed", "results_available": True},
    "incomplete": {"status": "incomplete", "results_available": True},
    "failed": {
        "status": "failed",
        "results_available": False,
        "error_message": "ASH exited with code 1",
        "output_holds_previous_results": True,
    },
    "cancelled": {
        "status": "cancelled",
        "results_available": False,
        "error_message": None,
        "output_holds_previous_results": True,
    },
}

#: Findings in the results file: two actionable, one suppressed, and one HIGH
#: finding below its scanner's own threshold (SEMGREP_THRESHOLD), which the
#: guide's critical/high examples select by severity and must not list.
FINDINGS = [
    ("bandit", "B602", "error", "HIGH", "src/app.py", 12, False),
    (
        "detect-secrets",
        "SECRET-AWS-ACCESS-KEY",
        "error",
        "CRITICAL",
        "config/settings.ini",
        3,
        False,
    ),
    ("bandit", "B101", "note", "LOW", "tests/test_app.py", 4, True),
    ("semgrep", "SEMGREP-HIGH", "error", "HIGH", "src/web.py", 9, False),
]
#: semgrep's own threshold in the scan's config. The global one is the default.
SEMGREP_THRESHOLD = "CRITICAL"


@pytest.fixture
def project(tmp_path, monkeypatch) -> Path:
    """A scanned project with results ASH wrote, and the guide's relative paths in it."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    root = tmp_path / "project"
    output = root / ".ash" / "ash_output"
    output.mkdir(parents=True)
    config = AshConfig.model_validate(
        {
            "project_name": "project",
            "scanners": {
                "semgrep": {
                    "enabled": True,
                    "options": {"severity_threshold": SEMGREP_THRESHOLD},
                }
            },
        }
    )
    document = json.loads(
        AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    )
    results = []
    for scanner, rule, level, severity, path, line, suppressed in FINDINGS:
        result: Dict[str, Any] = {
            "ruleId": rule,
            "level": level,
            "kind": "fail",
            "message": {"text": f"{rule} finding"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": line},
                    }
                }
            ],
            "properties": {"scanner_name": scanner, "issue_severity": severity},
        }
        if suppressed:
            result["suppressions"] = [{"kind": "external", "justification": "test"}]
        results.append(result)
    document["sarif"]["runs"][0]["results"] = results
    document["metadata"]["summary_stats"]["actionable"] = 2
    document["metadata"]["summary_stats"]["total"] = 4
    document["scanner_results"] = {
        "bandit": {"status": "FAILED", "finding_count": 2},
        "detect-secrets": {"status": "FAILED", "finding_count": 1},
        "semgrep": {"status": "PASSED", "finding_count": 1},
    }
    (output / "ash_aggregated_results.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    monkeypatch.chdir(root)
    # The polling examples wait between polls.
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    return root


class _Server:
    """The tools the guide calls: arguments checked, calls recorded."""

    def __init__(self, project: Path, ending: str = "completed") -> None:
        self.project = project
        self.ending = ending
        self.calls: List[str] = []

    def namespace(self) -> Dict[str, Any]:
        namespace: Dict[str, Any] = {"__name__": "guide_example"}
        for name in TOOLS:
            namespace[name] = self._tool(name)
        return namespace

    def _tool(self, name: str) -> Callable[..., _Response]:
        def call(*args: Any, **kwargs: Any) -> _Response:
            _checked(name, args, kwargs)
            self.calls.append(name)
            return _Response(getattr(self, name)(**kwargs))

        return call

    def run_ash_scan(self, **_kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "scan_id": "scan-1",
            "status": "running",
            "directory_path": str(self.project),
        }

    def get_scan_progress(self, **_kwargs: Any) -> Dict[str, Any]:
        polls = self.calls.count("get_scan_progress")
        assert polls < 20, f"the example kept polling a {self.ending} scan"
        base = {
            "scan_id": "scan-1",
            "directory_path": str(self.project),
            "output_directory": str(self.project / ".ash" / "ash_output"),
        }
        if polls == 1:
            return {**base, "status": "running", "is_complete": False}
        return {**base, "is_complete": True, **ENDINGS[self.ending]}

    def get_scan_results(self, **kwargs: Any) -> Dict[str, Any]:
        return _real_results(**kwargs)

    def get_scan_summary(self, **_kwargs: Any) -> Dict[str, Any]:
        return {"success": True}

    def get_scan_result_paths(self, **_kwargs: Any) -> Dict[str, Any]:
        return {"success": True}

    def list_active_scans(self, **_kwargs: Any) -> Dict[str, Any]:
        return {"success": True, "active_scans": []}

    def cancel_scan(self, **_kwargs: Any) -> Dict[str, Any]:
        return {"success": True, "status": "cancelled"}


def _run(example: Example, server: _Server) -> Dict[str, Any]:
    """Run an example as an agent would, and any function it defines that takes a source_dir."""
    namespace = server.namespace()
    code = compile(
        example.code,
        f"<{GUIDE.name}: {example.heading}>",
        "exec",
        flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
    )
    outcome = eval(code, namespace)  # noqa: S307 -- the guide's own example code
    if inspect.iscoroutine(outcome):
        asyncio.run(outcome)
    for value in list(namespace.values()):
        if inspect.isfunction(value) and list(inspect.signature(value).parameters) == [
            "source_dir"
        ]:
            namespace["returned"] = value(source_dir=str(server.project))
    return namespace


@pytest.mark.parametrize("ending", ENDINGS)
@pytest.mark.parametrize("example", POLLING, ids=str)
def test_a_polling_example_reads_results_only_for_a_scan_that_has_them(
    example, ending, project
):
    """It stops at every ending, and reads results for completed and incomplete only.

    Reading them for a failed or cancelled scan returns the previous scan's
    findings as this scan's; skipping them for an incomplete one drops findings
    the scan did produce.
    """
    server = _Server(project, ending)

    _run(example, server)

    read = "get_scan_results" in server.calls
    expected = ENDINGS[ending]["results_available"]
    assert read == expected, (
        f"the example {'read' if read else 'did not read'} results for the "
        f"{ending} scan: {server.calls}"
    )


@pytest.mark.parametrize("example", READING, ids=str)
def test_a_results_example_runs_against_the_real_tool(example, project, capsys):
    """Its arguments are the tool's, and the response has what it reads.

    Pattern 1 gates on actionable critical and high findings, of which the
    results file has two, so it exits 1. Pattern 2 lists them, and neither the
    suppressed one nor the HIGH one below semgrep's own CRITICAL threshold.
    """
    server = _Server(project)
    exit_code = None
    try:
        _run(example, server)
    except SystemExit as stopped:
        exit_code = stopped.code

    assert "get_scan_results" in server.calls, server.calls
    output = capsys.readouterr().out
    if example.heading.startswith("Pattern 1"):
        assert exit_code == 1, (exit_code, output)
    if example.heading.startswith("Pattern 2"):
        assert "B602" in output and "SECRET-AWS-ACCESS-KEY" in output, output
        assert "B101" not in output, output
        assert "SEMGREP-HIGH" not in output, output
