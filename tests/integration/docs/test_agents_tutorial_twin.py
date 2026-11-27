# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""getting-started/agents.md's tutorial, with the agent's tools called directly.

The page has a coding agent start ``ash mcp`` and work through a small project: scan it,
read the results, explain a finding, draft a suppression, fix a finding and compare two
scans. The agent itself, its MCP client configuration and the server's transport are
the boundary of this twin; nothing here starts an MCP server or an agent.

What the agent calls is ASH, and the twin runs that. The scans are ``ash scan fs
--only-scanners bandit --offline``, which is the scan ``run_ash_scan`` runs narrowed to
the one scanner that has findings in this project (the page: "three findings, all from
bandit"). The tools that read the results, ``explain_finding``,
``suggest_suppression`` and ``diff_scan_results``, are called through the functions
the MCP tools wrap
(``mcp_explain_finding``, ``mcp_suggest_suppression``, ``mcp_diff_scan_results``), on
the results of those scans. The project, the suppression config, the validate step and
the fix are the page's own blocks, read from the page.

The twin holds the page's outputs to what ASH does:

- step 5's table of the three findings (rule, severity, line) is the scan's findings;
- step 7's finding id, description and severity rationale are the ones
  ``explain_finding`` returns for B602;
- step 8's suggested entry has the fields the page shows, with the expiration 90 days
  from today, and the config the page writes is accepted by ``ash config validate``
  and refused (exit 3) once ``reason`` is misspelled;
- with that config, the scan has one actionable finding left (B602), and after step 9's
  fix none, exit 0;
- step 9's table of what ``diff_scan_results`` returns: B602 resolved, B603 new at LOW,
  no severity change, and B324 in none of the lists because it is still found, marked
  suppressed with the reason.

The suppression the page writes expires on 2027-06-30. After that date a scan reports
B324 again and this test fails, which is the page's own date going stale.

Like the local tutorial's twin, it fails, and does not skip, when bandit is missing.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


jt = _load("_ash_journey_twin", Path(__file__).resolve().parent / "journey_twin.py")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="the docs job has no Windows runner and the windows-latest legs "
        "install no scanner tools, so bandit is MISSING there and every scan of "
        "the twin exits 1 (test_docs_runner_can_fail.py skips the same way)",
    ),
]

PAGE = "docs/content/getting-started/agents.md"


def _cells(row: list[str]) -> list[str]:
    return [cell.replace("`", "").strip() for cell in row]


def _table(page, first_header: str) -> list[list[str]]:
    table = next((t for t in page.tables if t.header[0] == first_header), None)
    assert table is not None, f"{page.rel} has no table headed {first_header!r}"
    return [_cells(cells) for _line, cells in table.rows]


def _prose(page) -> str:
    """The page's prose with each run of white space as one space."""
    return " ".join(" ".join(text for _line, text in page.prose).split())


def _the_page_says(page, pattern: str) -> str:
    found = re.search(pattern, _prose(page))
    assert found, f"{page.rel} no longer says {pattern!r}"
    return found.group(1)


def test_the_agents_tutorial_holds_with_bandit_offline(tmp_path, request):
    jt.require_bandit()
    root = jt.docs_root(request.config)
    page = jt.parse_page(PAGE, root)

    project = jt.only_block(jt.blocks_under(page, r"2\."), "git init", lang="bash")
    suppression = [
        b for b in jt.blocks_under(page, r"8\.") if b.lang == "bash"
    ]  # .ashrc.yaml, validate, the typo, its removal
    fix = jt.only_block(
        jt.blocks_under(page, r"9\."), "subprocess.call(command)\n", lang="bash"
    )
    assert fix.body.startswith("cat > app.py"), "step 9 no longer rewrites app.py"

    twin = jt.Twin("the agents tutorial")
    twin.run(project.body)
    twin.run(
        jt.BANDIT_SCAN,
        code=2,
        prints=("Exiting due to 2 actionable findings",),
    )
    twin.run(jt.capture_scan("scan1"))
    for block in suppression:
        accepted = block.body.strip() == "ash config validate"
        twin.run(
            block.body,
            code=jt.block_exit(block),
            prints=("Configuration is valid! A scan accepts it.",) if accepted else (),
        )
    twin.run(
        jt.BANDIT_SCAN,
        code=2,
        prints=("Exiting due to 1 actionable findings",),
    )
    twin.run(jt.capture_scan("scan2"))
    twin.run(fix.body)
    twin.run(jt.BANDIT_SCAN, code=0, absent=("Exiting due to",))
    twin.run(jt.capture_scan("scan3"))
    session = twin.execute(tmp_path, root)

    # Step 5: the findings the agent reports.
    first = jt.findings(session, "scan1")
    shown = {(r[0], r[1], int(r[2])) for r in _table(page, "Rule")}
    scanned = {(f["rule_id"], f["severity"].upper(), f["line_start"]) for f in first}
    assert scanned == shown, f"the scan found {scanned}; step 5 shows {shown}"
    assert {f["scanner"] for f in first} == {"bandit"}

    # Step 7: explain_finding on B602.
    from automated_security_helper.cli.mcp_tools import (
        mcp_diff_scan_results,
        mcp_explain_finding,
        mcp_suggest_suppression,
    )

    before_dir = jt.captured(session, "scan1/ash_aggregated_results.json").parent
    b602 = next(f for f in first if f["rule_id"] == "B602")
    assert b602["id"] == _the_page_says(page, r"`?(bandit-B602-[0-9a-f]+)`?")
    explained = mcp_explain_finding(b602["id"], results_path=str(before_dir))
    assert explained["success"], explained
    wording = _the_page_says(page, r'scanner\'s description, "([^"]+)"')
    assert wording in explained["finding"]["description"]
    assert "above MEDIUM threshold" in explained["finding"]["severity_rationale"]

    # Step 8: the entry suggest_suppression returns, and the date it defaults to.
    b324 = next(f for f in first if f["rule_id"] == "B324")
    sample = next(
        b for b in jt.blocks_under(page, r"8\.") if "client_supplied" in b.body
    )
    entry = yaml.safe_load(sample.body)
    reason = entry["reason"]
    suggested = mcp_suggest_suppression(
        b324["id"],
        results_path=str(before_dir / "ash_aggregated_results.json"),
        justification=reason,
    )
    assert suggested["success"], suggested
    got = dict(suggested["json"])
    assert got.pop("expires") == (date.today() + timedelta(days=90)).isoformat()
    entry.pop("expires")
    assert got == entry

    # Steps 8 and 9: after the config, B324 is suppressed with that reason; after the
    # fix, nothing actionable is left.
    second = jt.findings(session, "scan2")
    suppressed = [f for f in second if f["rule_id"] == "B324"]
    assert [f["is_suppressed"] for f in suppressed] == [True]
    assert reason in suppressed[0]["suppression_justification"]
    third = jt.findings(session, "scan3")
    assert [f for f in third if f["rule_id"] == "B324" and not f["is_suppressed"]] == []
    assert [
        f
        for f in third
        if not f["is_suppressed"] and f["severity"].upper() not in {"LOW", "INFO"}
    ] == []

    # Step 9: diff_scan_results.
    after_dir = jt.captured(session, "scan3/ash_aggregated_results.json").parent
    diff = mcp_diff_scan_results(
        str(before_dir / "ash_aggregated_results.json"),
        str(after_dir / "ash_aggregated_results.json"),
    )
    shown_diff = {r[0]: r[1] for r in _table(page, "List")}
    assert [f["rule_id"] for f in diff["resolved"]] == ["B602"]
    assert shown_diff["resolved"].startswith("B602")
    assert [(f["rule_id"], f["severity"].upper()) for f in diff["new"]] == [
        ("B603", "LOW")
    ]
    assert shown_diff["new"].startswith("B603, LOW")
    assert diff["severity_changed"] == []
    assert shown_diff["severity_changed"].startswith("Empty")
