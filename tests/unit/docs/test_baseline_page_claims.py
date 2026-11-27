# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the docs say ``--baseline`` does, held to the sentence and to the code.

``ash scan --baseline`` changes what the exit code counts, so the pages a reader uses to
learn the gate have to say so and say what it costs. This module pins those sentences the
way test_page_claims.py pins the rest of the gate pages: ``assert_on_page`` checks that
the sentence is still on its page, and the test then probes the code that makes it true.
A test goes red when either half moves.

The pages and what each pins:

- how-to/set-the-gate.md#baseline: the gate counts only findings the baseline lacks, what
  a baseline never hides, the matching tradeoff, the modes it supports, and that it can be
  combined with ``--changed-files-only``.
- reference/exit-codes.md: the exit 5 refusals of ``--baseline``, one probe per refused
  combination and per refused baseline file.
- how-to/ci/github-actions.md#baseline: the semantics sentences (SARIF-only filtering,
  one hard link, project and directory scope, the environment variable, the unsupported
  modes, the matching tradeoff) and the reusable workflows' SARIF upload skip, which
  getting-started/ci.md and how-to/export-reports.md repeat.
- how-to/scale-large-repos.md and the personas pages: the sentences that route a
  changed-files, reviewer, developer or SDLC reader to ``--baseline``.

The Security Hub sentence of the GitHub Actions page is pinned in
test_baseline_security_hub_page_claim.py, whose fixtures are autouse.

Nothing here starts a scanner. Probes run the gate over saved results the way
tests/unit/interactions/test_scan_baseline_narrows_every_report.py does, call the
baseline functions, load the workflow files, and invoke the CLI on arguments it refuses
before it scans.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.utils.scan_baseline import ScanBaseline, apply_baseline
from tests.unit.docs.test_page_claims import _code_root, assert_on_page
from tests.unit.interactions.test_scan_baseline_narrows_every_report import (
    baseline as baseline_of,
    finding,
    report_exit_code,
    results,
)

pytestmark = pytest.mark.unit

SET_THE_GATE = "how-to/set-the-gate.md"
EXIT_CODES = "reference/exit-codes.md"
GITHUB_ACTIONS = "how-to/ci/github-actions.md"
CI_TUTORIAL = "getting-started/ci.md"
EXPORT_REPORTS = "how-to/export-reports.md"
SCALE_LARGE_REPOS = "how-to/scale-large-repos.md"
SECURITY_REVIEWER = "personas/security-reviewer.md"
DEVELOPER = "personas/developer.md"
SDLC_AIDLC = "personas/sdlc-aidlc.md"

SCAN_WORKFLOW = "run-ash-security-scan.yml"
UPLOAD_WORKFLOW = "upload-ash-sarif.yml"
FILTERED_NOTICE = (
    "SARIF upload skipped because the scan results were filtered by a baseline."
)
UNREADABLE_NOTICE = "SARIF upload skipped because the scan results could not be read to rule out a baseline."

# The matching tradeoff, said on set-the-gate.md and on github-actions.md.
ABSORPTION = (
    "For findings without usable fingerprints, if one old finding is fixed and another "
    "appears with the same scanner, rule, file, package, message and severity, the new "
    "finding can be treated as the old one"
)


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #


def _gate_exit_code(tmp_path: Path, monkeypatch, current: List[Dict[str, Any]], old):
    """The exit code of a report-phase scan of ``current`` against a baseline of ``old``."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ExecutionPhase, ExportFormat

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir(parents=True)
    saved_baseline = results(*old)
    saved_baseline.ash_config = get_default_config()
    scan = results(*current)
    scan.ash_config = saved_baseline.ash_config
    saved = tmp_path / "saved.json"
    saved.write_text(scan.model_dump_json(by_alias=True))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(saved_baseline.model_dump_json(by_alias=True))
    return report_exit_code(
        source_dir=source,
        output_dir=tmp_path / "out",
        existing_results=str(saved),
        baseline=str(baseline_path),
        phases=[ExecutionPhase.REPORT],
        output_formats=[ExportFormat.SARIF],
        show_summary=False,
        progress=False,
        quiet=True,
        fail_on_incomplete_scanners=False,
    )


def _probe_the_gate_counts_only_new_findings(tmp_path, monkeypatch) -> None:
    """Every finding in the baseline passes, and one new finding fails."""
    every_finding_is_in_the_baseline = _gate_exit_code(
        tmp_path / "matched",
        monkeypatch,
        current=[finding(20, "old", "HIGH")],
        old=[finding(10, "old", "HIGH")],
    )
    one_finding_is_new = _gate_exit_code(
        tmp_path / "new",
        monkeypatch,
        current=[finding(20, "old", "HIGH"), finding(10, "new", "HIGH")],
        old=[finding(10, "old", "HIGH")],
    )
    assert (every_finding_is_in_the_baseline, one_finding_is_new) == (0, 2)


def _probe_a_worse_finding_stays() -> None:
    """The control matches; a rise in severity, a lapsed suppression and a baseline
    scanner that did not complete each keep the finding."""
    control = results(finding(10, "old", "HIGH"))
    assert apply_baseline(control, baseline_of(finding(10, "old", "HIGH"))).matched == 1
    assert control.sarif.runs[0].results == []

    rose = results(finding(10, severity="HIGH", fingerprint="f"))
    outcome = apply_baseline(
        rose, baseline_of(finding(10, severity="LOW", fingerprint="f"))
    )
    assert (outcome.matched, len(rose.sarif.runs[0].results)) == (0, 1)

    was_suppressed = finding(10, severity="HIGH")
    was_suppressed["suppressions"] = [{"kind": "external", "state": "accepted"}]
    lapsed = results(finding(10, severity="HIGH"))
    outcome = apply_baseline(lapsed, baseline_of(was_suppressed))
    assert (outcome.matched, len(lapsed.sarif.runs[0].results)) == (0, 1)

    incomplete = results(finding(10, severity="HIGH"))
    incomplete.scanner_results.clear()
    incomplete.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status="MISSING", excluded=False
    )
    current = results(finding(10, severity="HIGH"))
    outcome = apply_baseline(
        current,
        ScanBaseline("abc", incomplete, tuple(incomplete.to_flat_vulnerabilities())),
    )
    assert (outcome.matched, len(current.sarif.runs[0].results)) == (0, 1)


def _probe_findings_outside_sarif_still_count(tmp_path) -> None:
    """A finding in ``additional_reports`` is not filtered and the gate counts it."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _gating_actionable_count,
    )

    current = results(finding(10, severity="HIGH"))
    current.ash_config = get_default_config()
    current.additional_reports = {
        "plugin": {
            "source": {
                "scanner_name": "plugin",
                "status": "PASSED",
                "raw_results": {"findings": [{"rule": "P"}]},
                "severity_counts": {"high": 1},
            }
        }
    }
    opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
    assert _gating_actionable_count(current, opts, False) == 2
    apply_baseline(current, baseline_of(finding(10, severity="HIGH")))
    assert _gating_actionable_count(current, opts, False) == 1


def _probe_the_matching_tradeoff() -> None:
    """A new finding the same as a fixed one is left out; a new message is not."""
    absorbed = results(finding(20))
    outcome = apply_baseline(absorbed, baseline_of(finding(10)))
    assert absorbed.sarif.runs[0].results == []
    assert outcome.matched_without_lines == 1

    different = results(finding(20), finding(10, "new", "HIGH"))
    apply_baseline(different, baseline_of(finding(10)))
    assert [row.message.root.text for row in different.sarif.runs[0].results] == ["new"]


def _scan(tmp_path: Path, *arguments: str, env: Dict[str, str] | None = None):
    source = tmp_path / "source"
    source.mkdir(parents=True, exist_ok=True)
    return CliRunner().invoke(app, ["scan", "fs", str(source), *arguments], env=env)


def _scan_without_a_subject(tmp_path: Path, *arguments: str):
    """``_scan`` without a subject, the deprecated form that still takes
    ``--workspace``. ``ash scan fs`` has no workspace option and
    ``ash scan workspace`` no ``--baseline``, so the scan's own refusal of
    ``--baseline`` with a workspace is reached only without a subject."""
    source = tmp_path / "source"
    source.mkdir(parents=True, exist_ok=True)
    return CliRunner().invoke(app, ["scan", "--source-dir", str(source), *arguments])


#: Each way ``--baseline`` is refused on the command line, before any scan starts.
REFUSED_COMBINATIONS = [
    ["--use-existing"],
    ["--express"],
    ["--mode", "container"],
    ["--mode", "nix"],
    ["--workspace", "workspace.yaml"],
    ["--shard-index", "0"],
    ["--shard-count", "2"],
    ["--phases", "convert"],
]


def _probe_the_refused_combinations(tmp_path: Path) -> None:
    missing = str(tmp_path / "baseline.json")
    for index, arguments in enumerate(REFUSED_COMBINATIONS):
        scan = _scan_without_a_subject if "--workspace" in arguments else _scan
        response = scan(
            tmp_path / f"refused-{index}", "--baseline", missing, *arguments
        )
        assert response.exit_code == 5, (arguments, response.output)
        assert "--baseline" in response.output, (arguments, response.output)


def _probe_local_and_precommit_reach_the_baseline(tmp_path: Path) -> None:
    """Those two modes read the baseline, so the missing file is the refusal."""
    missing = str(tmp_path / "baseline.json")
    for mode in ("local", "precommit"):
        response = _scan(tmp_path / mode, "--mode", mode, "--baseline", missing)
        assert response.exit_code == 5, (mode, response.output)
        assert "Error reading --baseline" in response.output, (mode, response.output)
        assert "not supported" not in response.output, (mode, response.output)


def _probe_a_baseline_a_scan_saved_can_be_read(tmp_path: Path) -> None:
    from automated_security_helper.utils.scan_baseline import read_baseline

    source = tmp_path / "source"
    source.mkdir(parents=True)
    saved = tmp_path / "ash_aggregated_results.json"
    saved.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    read = read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")
    assert read.sha256


def _workflow(name: str) -> dict:
    path = _code_root() / ".github" / "workflows" / name
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(document: dict) -> Iterator[dict]:
    for job in document["jobs"].values():
        yield from job.get("steps", [])


def _step(document: dict, **expected: str) -> dict:
    found = [
        step
        for step in _steps(document)
        if all(
            str(step.get(key, "")).startswith(value) for key, value in expected.items()
        )
    ]
    assert len(found) == 1, (expected, len(found))
    return found[0]


def _probe_the_workflows_skip_the_upload() -> None:
    """Both workflows read the results' ``baseline`` marker and gate the upload on it."""
    scan = _workflow(SCAN_WORKFLOW)
    check = _step(scan, id="baseline_check")
    assert FILTERED_NOTICE in check["run"]
    assert UNREADABLE_NOTICE in check["run"]
    upload = _step(scan, uses="github/codeql-action/upload-sarif@")
    assert "needs.ash.outputs.baseline == 'false'" in upload["if"]
    assert "github.event_name == 'pull_request'" in upload["if"]

    sarif = _workflow(UPLOAD_WORKFLOW)
    check = _step(sarif, id="baseline_check")
    assert FILTERED_NOTICE in check["with"]["script"]
    assert UNREADABLE_NOTICE in check["with"]["script"]
    upload = _step(sarif, uses="github/codeql-action/upload-sarif@")
    assert upload["if"] == "steps.baseline_check.outputs.baseline == 'false'"

    # The marker both read is in the results file only after a baseline filtered it.
    filtered = results(finding(10))
    apply_baseline(filtered, baseline_of(finding(10)))
    assert "baseline" in json.loads(filtered.model_dump_json(by_alias=True))["metadata"]
    assert filtered.baseline_filtered
    unfiltered = results(finding(10))
    assert (
        "baseline"
        not in json.loads(unfiltered.model_dump_json(by_alias=True))["metadata"]
    )
    assert not unfiltered.baseline_filtered


def _probe_a_changed_files_scan_can_use_a_baseline(tmp_path, monkeypatch) -> None:
    """Both options in one scan leave the new finding in the changed file."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import ExecutionPhase, ExportFormat
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )
    from automated_security_helper.utils import get_scan_set

    class Logger:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(
        get_scan_set, "git_repository_root", lambda *args, **kwargs: source
    )
    monkeypatch.setattr(get_scan_set, "get_changed_files", lambda **kwargs: ["src.py"])
    old = results(finding(10, "old", "HIGH"))
    old.ash_config = get_default_config()
    current = results(finding(20, "old", "HIGH"), finding(10, "new", "HIGH"))
    current.ash_config = old.ash_config
    saved = tmp_path / "saved.json"
    saved.write_text(current.model_dump_json(by_alias=True))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    opts = ScanOptions(
        source_dir=source,
        output_dir=tmp_path / "out",
        existing_results=str(saved),
        baseline=str(baseline_path),
        changed_files_only=True,
        phases=[ExecutionPhase.REPORT],
        output_formats=[ExportFormat.SARIF],
        show_summary=False,
        progress=False,
        fail_on_incomplete_scanners=False,
    )
    result, _ = _run_local_mode(opts, Logger())
    assert [row.message.root.text for row in result.sarif.runs[0].results] == ["new"]
    assert result.metadata.changed_files_only is True
    assert result.metadata.baseline["matched_without_lines"] == 1


# --------------------------------------------------------------------------- #
# how-to/set-the-gate.md
# --------------------------------------------------------------------------- #


def test_the_gate_page_says_a_baseline_leaves_only_new_findings_to_the_gate(
    tmp_path, monkeypatch
):
    assert_on_page(
        SET_THE_GATE,
        "`--baseline PATH`, or `ASH_BASELINE`, changes what the gate counts and leaves "
        "its order alone.",
    )
    assert_on_page(
        SET_THE_GATE,
        "Row 6 and `--min-severity` then see only the findings the baseline lacks: a "
        "scan whose findings are all in the baseline exits 0, and a new finding at or "
        "above its threshold exits 2.",
    )
    _probe_the_gate_counts_only_new_findings(tmp_path, monkeypatch)


def test_the_gate_page_says_findings_outside_sarif_still_count(tmp_path):
    assert_on_page(
        SET_THE_GATE,
        "Findings a scanner reports outside SARIF are not filtered, so they still count.",
    )
    _probe_findings_outside_sarif_still_count(tmp_path)


def test_the_gate_page_says_a_baseline_does_not_hide_a_worse_finding():
    assert_on_page(
        SET_THE_GATE,
        "A finding stays in the scan when its severity rose above its baseline entry, "
        "when the baseline suppressed it and the scan does not, or when its scanner did "
        "not complete in the baseline's scan.",
    )
    _probe_a_worse_finding_stays()


def test_the_gate_page_states_the_matching_tradeoff():
    assert_on_page(
        SET_THE_GATE,
        f"{ABSORPTION}, and the gate does not count it. A new finding with a different "
        "message is not matched.",
    )
    _probe_the_matching_tradeoff()


def test_the_gate_page_names_the_modes_a_baseline_works_in(tmp_path):
    assert_on_page(
        SET_THE_GATE,
        "`--baseline` works with `--mode local` and `--mode precommit` only; it exits 5 "
        "with `--use-existing`, `--express`, container or Nix mode, a workspace, "
        "shards, or `--phases` that leave out both scan and report",
    )
    _probe_the_refused_combinations(tmp_path / "refused")
    _probe_local_and_precommit_reach_the_baseline(tmp_path / "reached")


def test_the_gate_page_says_a_baseline_combines_with_changed_files_only(
    tmp_path, monkeypatch
):
    assert_on_page(SET_THE_GATE, "It can be combined with `--changed-files-only`.")
    _probe_a_changed_files_scan_can_use_a_baseline(tmp_path, monkeypatch)


# --------------------------------------------------------------------------- #
# reference/exit-codes.md
# --------------------------------------------------------------------------- #


def test_the_exit_codes_page_lists_the_baseline_option_refusals(tmp_path):
    assert_on_page(
        EXIT_CODES,
        "A usage error from `--baseline` (or `ASH_BASELINE`), which Set the gate explains. "
        "The option is refused with `--use-existing`, `--express`, `--mode container`, "
        "`--mode nix`, `--workspace`, `--shard-index` or `--shard-count`, and a "
        "`--phases` list that has neither scan nor report.",
    )
    _probe_the_refused_combinations(tmp_path)


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {"shard": {"index": 0, "count": 2}},
        {"changed_files_only": True},
        {"baseline": {}},
    ],
    ids=["not-json", "shard", "changed-files-only", "earlier-baseline"],
)
def test_the_exit_codes_page_lists_the_baseline_files_refused_as_results(
    tmp_path, metadata
):
    assert_on_page(
        EXIT_CODES,
        "is not the results of a full scan (results of a workspace aggregate, a shard, "
        "`--changed-files-only`, or an earlier `--baseline` are not)",
    )
    source = tmp_path / "source"
    source.mkdir()
    baseline = tmp_path / "baseline.json"
    data = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    if metadata is not None:
        data["metadata"].update(metadata)
    baseline.write_text("not json" if metadata is None else json.dumps(data))
    response = _scan(tmp_path, "--mode", "local", "--baseline", str(baseline))
    assert response.exit_code == 5, response.output
    assert "Error reading --baseline" in response.output


def test_the_exit_codes_page_lists_a_workspace_aggregate_as_refused():
    from automated_security_helper.utils.scan_results_file import (
        ScanResultsRefused,
        parse_full_scan_results,
    )

    assert_on_page(EXIT_CODES, "results of a workspace aggregate, a shard,")
    data = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    data["workspace"] = {
        "workspace_file": "/repo/app.code-workspace",
        "workspace_root": "/repo",
        "exit_code": 0,
    }
    with pytest.raises(ScanResultsRefused, match="per-project"):
        parse_full_scan_results(json.dumps(data).encode("utf-8"))


def test_the_exit_codes_page_lists_a_baseline_inside_the_scan_as_refused(tmp_path):
    assert_on_page(
        EXIT_CODES,
        "The baseline file is refused when it is inside the source or output directory,",
    )
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    inside_source = source / "baseline.json"
    inside_source.write_text(json.dumps({"metadata": {}, "sarif": {"runs": []}}))
    response = _scan(tmp_path, "--mode", "local", "--baseline", str(inside_source))
    assert response.exit_code == 5, response.output
    assert "inside the scanned tree" in response.output

    inside_output = output / "baseline.json"
    inside_output.write_text("{}")
    response = _scan(
        tmp_path,
        "--mode",
        "local",
        "--output-dir",
        str(output),
        "--baseline",
        str(inside_output),
    )
    assert response.exit_code == 5, response.output
    assert "inside the output directory" in response.output


def test_the_exit_codes_page_lists_a_baseline_with_two_links_as_refused(tmp_path):
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        read_baseline,
    )

    assert_on_page(EXIT_CODES, "is not a regular file with exactly one hard link,")
    source = tmp_path / "source"
    source.mkdir()
    inside = source / "baseline.json"
    inside.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    outside = tmp_path / "baseline.json"
    try:
        os.link(inside, outside)
    except OSError:
        pytest.skip("hard links are unavailable")
    with pytest.raises(BaselineRefused, match="hard link"):
        read_baseline(outside, source_dir=source, output_dir=tmp_path / "out")


def test_the_exit_codes_page_lists_a_baseline_of_another_project_or_directory(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        check_baseline_scope,
        read_baseline,
    )

    assert_on_page(
        EXIT_CODES,
        "or belongs to a different project or scan directory.",
    )
    source = tmp_path / "source"
    source.mkdir()
    other = AshAggregatedResults()
    other.metadata.project_name = "not-the-project"
    baseline = tmp_path / "baseline.json"
    baseline.write_text(other.model_dump_json(by_alias=True))
    monkeypatch.setattr(
        "automated_security_helper.utils.staged_files.staged_files_for_source",
        lambda _: [],
    )
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "precommit",
            "--staged",
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5, response.output
    assert "different project" in response.output

    elsewhere = AshAggregatedResults()
    elsewhere.metadata.scan_source = "one"
    saved = tmp_path / "elsewhere.json"
    saved.write_text(elsewhere.model_dump_json(by_alias=True))
    read = read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")
    with pytest.raises(BaselineRefused, match="different directory"):
        check_baseline_scope(
            read, project_name=elsewhere.metadata.project_name, scan_source="two"
        )


# --------------------------------------------------------------------------- #
# how-to/ci/github-actions.md#baseline
# --------------------------------------------------------------------------- #


def test_the_actions_page_says_a_baseline_filters_sarif_and_not_other_reports(
    tmp_path,
):
    assert_on_page(
        GITHUB_ACTIONS,
        "removes matched SARIF findings from the shared results used by reports, the "
        "summary, and the exit code. Additional (non-SARIF) report findings are not "
        "filtered.",
    )
    _probe_findings_outside_sarif_still_count(tmp_path)
    kept = results(finding(10))
    kept.additional_reports = {"other": [{"id": "other", "title": "kept"}]}
    apply_baseline(kept, baseline_of(finding(10)))
    assert kept.sarif.runs[0].results == []
    assert kept.additional_reports["other"][0]["title"] == "kept"


def test_the_actions_page_says_a_baseline_is_one_regular_file_with_one_link(tmp_path):
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        read_baseline,
    )

    assert_on_page(
        GITHUB_ACTIONS, "It must be a regular file with exactly one hard link."
    )
    source = tmp_path / "source"
    source.mkdir()
    saved = tmp_path / "saved" / "ash_aggregated_results.json"
    saved.parent.mkdir()
    saved.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    assert read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")
    linked = tmp_path / "linked.json"
    try:
        os.link(saved, linked)
    except OSError:
        pytest.skip("hard links are unavailable")
    with pytest.raises(BaselineRefused, match="hard link"):
        read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")


def test_the_actions_page_says_a_baseline_must_match_project_and_directory(tmp_path):
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        check_baseline_scope,
        read_baseline,
    )

    assert_on_page(
        GITHUB_ACTIONS,
        "ASH refuses different project names and different recorded relative scan "
        "directories.",
    )
    source = tmp_path / "source"
    source.mkdir()
    results_file = AshAggregatedResults()
    results_file.metadata.scan_source = "one"
    saved = tmp_path / "baseline.json"
    saved.write_text(results_file.model_dump_json(by_alias=True))
    read = read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")
    project = results_file.metadata.project_name
    with pytest.raises(BaselineRefused, match="different project"):
        check_baseline_scope(read, project_name="different", scan_source="one")
    with pytest.raises(BaselineRefused, match="different directory"):
        check_baseline_scope(read, project_name=project, scan_source="two")
    assert check_baseline_scope(read, project_name=project, scan_source="one") == []


def test_the_actions_page_says_the_environment_variable_supplies_the_option(tmp_path):
    assert_on_page(GITHUB_ACTIONS, "`ASH_BASELINE` supplies the same option.")
    missing = str(tmp_path / "baseline.json")
    response = _scan(tmp_path, "--mode", "local", env={"ASH_BASELINE": missing})
    assert response.exit_code == 5, response.output
    assert "Error reading --baseline" in response.output


def test_the_actions_page_lists_the_modes_a_baseline_refuses(tmp_path):
    assert_on_page(
        GITHUB_ACTIONS,
        "`--baseline` is not supported with container or Nix mode, workspace or sharded "
        "scans, or explicit `--express`.",
    )
    assert_on_page(
        GITHUB_ACTIONS, "`--baseline` cannot be combined with `--use-existing`."
    )
    _probe_the_refused_combinations(tmp_path)


def test_the_actions_page_states_the_matching_tradeoff():
    assert_on_page(
        GITHUB_ACTIONS,
        "if one old finding is fixed and another appears with the same scanner, rule, "
        "file, package, message and severity, the new finding can be treated as the old "
        "one.",
    )
    _probe_the_matching_tradeoff()


def test_the_actions_page_says_the_reusable_workflows_skip_a_filtered_upload():
    assert_on_page(
        GITHUB_ACTIONS,
        "Both `run-ash-security-scan.yml`, in its pull request upload, and "
        "`upload-ash-sarif.yml` read `ash_aggregated_results.json` before the upload step. "
        "When its `metadata` records a baseline (`--baseline` in `ash-args`), they skip "
        f"the SARIF upload and print the notice `{FILTERED_NOTICE}`",
    )
    assert_on_page(
        GITHUB_ACTIONS,
        "When the file cannot be read to rule a baseline out, they skip the upload and "
        f"print `{UNREADABLE_NOTICE}` Nothing is uploaded, so code scanning keeps its "
        "earlier analysis.",
    )
    _probe_the_workflows_skip_the_upload()


def test_the_actions_page_points_the_gate_page_for_the_tradeoff():
    assert_on_page(
        GITHUB_ACTIONS,
        "Set the gate states the same tradeoff for every CI system.",
    )
    assert_on_page(SET_THE_GATE, "Matching has a tradeoff that comes with the option.")


# --------------------------------------------------------------------------- #
# The pages that repeat the upload skip
# --------------------------------------------------------------------------- #


def test_the_ci_tutorial_says_the_sarif_job_skips_a_filtered_upload():
    assert_on_page(
        CI_TUTORIAL,
        "The job also skips the upload, with a notice in its log, when the downloaded "
        "results record a baseline (a scan run with `--baseline` in `ash-args`) or "
        "cannot be read to rule one out.",
    )
    _probe_the_workflows_skip_the_upload()


def test_the_export_page_says_not_to_upload_the_sarif_of_a_baseline_scan():
    assert_on_page(
        EXPORT_REPORTS,
        "Do not upload the SARIF of a scan run with `--baseline`: it holds only the "
        "findings the baseline lacks, and GitHub replaces earlier results for the same "
        "tool and category with whatever an upload carries. The reusable workflows skip "
        "that upload and print a notice",
    )
    _probe_the_workflows_skip_the_upload()


# --------------------------------------------------------------------------- #
# how-to/scale-large-repos.md and the personas pages
# --------------------------------------------------------------------------- #


def test_the_scale_page_routes_a_changed_files_reader_to_the_baseline(
    tmp_path, monkeypatch
):
    assert_on_page(
        SCALE_LARGE_REPOS,
        "`--changed-files-only` drops the findings in files the change did not touch, "
        "and `--baseline` drops the findings a saved full scan already holds, in any "
        "file. A scan can use both, and the findings that remain are the new ones in "
        "the changed files.",
    )
    _probe_a_changed_files_scan_can_use_a_baseline(tmp_path, monkeypatch)


def test_the_reviewer_page_names_the_baseline_as_a_way_to_judge_a_pull_request():
    assert_on_page(
        SECURITY_REVIEWER,
        "`--baseline` drops the findings a saved full scan of `main` already holds, so "
        "the gate fails only on a finding the baseline did not have. A finding whose "
        "severity rose, or whose suppression ended, stays in the scan",
    )
    assert_on_page(
        SECURITY_REVIEWER, "Three options sharpen what a pull request is judged on:"
    )
    _probe_a_worse_finding_stays()


def test_the_developer_page_names_the_baseline_for_local_and_precommit_scans(tmp_path):
    assert_on_page(
        DEVELOPER,
        "`--baseline PATH`, in local and precommit mode, leaves out the findings a saved "
        "full scan of the default branch already holds, so a local scan fails only on "
        "what your change added, as CI does when it gates against the same baseline",
    )
    _probe_local_and_precommit_reach_the_baseline(tmp_path / "reached")
    _probe_the_refused_combinations(tmp_path / "refused")


def test_the_sdlc_page_names_the_merge_scan_as_the_source_of_a_baseline(tmp_path):
    assert_on_page(
        SDLC_AIDLC,
        "whose saved `ash_aggregated_results.json` can serve as the `--baseline` of "
        "later local and precommit scans",
    )
    _probe_a_baseline_a_scan_saved_can_be_read(tmp_path / "saved")
    _probe_local_and_precommit_reach_the_baseline(tmp_path / "reached")
