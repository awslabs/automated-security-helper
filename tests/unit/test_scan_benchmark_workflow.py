# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan-time benchmark workflow, .github/workflows/ash-scan-benchmark.yml.

WHY THIS EXISTS
---------------
The workflow runs a pull request's own code on a GitHub-hosted runner, from a fork too,
and it is meant to be informational: it must never be able to block a merge, and it must
never hold more than a read-only token. Both properties rest on lines a later edit could
change without any run failing, so they are checked here, on the file:

* it starts on pull_request (filtered to the product's paths), on a nightly schedule and
  on workflow_dispatch; never on pull_request_target or workflow_run;
* its job carries ``continue-on-error``, and the required-checks job of
  ash-unified-ci.yml does not name it;
* its token is ``contents: read`` (and ``actions: read`` for the trend artifact), nothing
  asks for a write scope or an OIDC token, and it reads no secret;
* every action is pinned to a commit that another workflow in the repository already
  uses, and no checkout keeps credentials;
* no ``${{ }}`` expression is pasted into a script, so an event value cannot become
  shell text;
* every trigger times three builds with five runs each: the tip, the previous commit
  (HEAD~1) and the previous release (the highest vX.Y.Z tag that is an ancestor of
  HEAD), resolved from a full-history checkout the way ash-upgrade-paths.yml resolves its
  starting points, and the step summary and the nightly trend carry all three.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "ash-scan-benchmark.yml"
SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _doc() -> dict:
    return yaml.safe_load(_text())


def _triggers(doc: dict) -> dict:
    # PyYAML reads the bare key ``on`` as the boolean True.
    return doc.get("on", doc.get(True))


def _job() -> dict:
    return _doc()["jobs"]["benchmark"]


def _steps() -> list[dict]:
    return _job()["steps"]


def _step(name: str) -> dict:
    return next(s for s in _steps() if s["name"] == name)


def test_it_starts_on_pull_request_schedule_and_dispatch_only():
    triggers = _triggers(_doc())
    assert set(triggers) == {"pull_request", "schedule", "workflow_dispatch"}
    assert len(triggers["schedule"]) == 1
    assert triggers["schedule"][0]["cron"].count(" ") == 4


def test_the_pull_request_filter_names_the_product_and_its_own_files():
    paths = _triggers(_doc())["pull_request"]["paths"]
    assert paths[:2] == ["automated_security_helper/**", "pyproject.toml"]
    assert set(paths[2:]) == {
        ".github/workflows/ash-scan-benchmark.yml",
        "scripts/measure_precommit_cost.py",
    }


def test_it_never_uses_a_trigger_that_runs_fork_code_with_a_write_token():
    text = _text()
    assert "pull_request_target" not in text
    assert "workflow_run" not in text


def test_the_job_can_never_block_a_merge():
    assert _job()["continue-on-error"] is True
    unified = (WORKFLOWS / "ash-unified-ci.yml").read_text(encoding="utf-8")
    assert "ash-scan-benchmark" not in unified
    assert "Scan-time benchmark" not in unified


def test_the_token_is_read_only_and_nothing_widens_it():
    doc = _doc()
    assert doc["permissions"] == {"contents": "read"}
    assert _job()["permissions"] == {"contents": "read", "actions": "read"}
    text = _text()
    assert not re.search(r":\s*write\b", text)
    assert "id-token" not in text
    assert "secrets." not in text
    assert "pull-requests" not in text
    assert "gh pr comment" not in text


def test_every_action_is_pinned_to_a_commit_already_used_elsewhere():
    others = "\n".join(
        p.read_text(encoding="utf-8")
        for p in WORKFLOWS.glob("*.yml")
        if p.name != WORKFLOW.name
    )
    uses = [s["uses"] for s in _steps() if "uses" in s]
    assert uses, "the job uses no action at all"
    for ref in uses:
        assert SHA_PIN.match(ref), ref
        assert ref in others, f"{ref} is not pinned anywhere else in the repository"


def test_no_checkout_keeps_credentials():
    checkouts = [
        s for s in _steps() if s.get("uses", "").startswith("actions/checkout@")
    ]
    assert len(checkouts) == 1
    for step in checkouts:
        assert step["with"]["persist-credentials"] is False


def test_setup_uv_does_not_cache():
    step = next(
        s for s in _steps() if s.get("uses", "").startswith("astral-sh/setup-uv@")
    )
    assert step["with"] == {"enable-cache": False}


def test_no_expression_is_pasted_into_a_script():
    for step in _steps():
        if "run" in step:
            assert "${{" not in step["run"], step["name"]


def test_every_script_runs_in_bash_with_strict_flags():
    assert _doc()["defaults"]["run"]["shell"] == "bash"
    for step in _steps():
        if "run" in step:
            assert "set -euo pipefail" in step["run"], step["name"]


def test_the_checkout_takes_full_history_and_tags_like_the_upgrade_job():
    """The old trees come from the local clone, so the clone needs its history."""
    step = next(
        s for s in _steps() if s.get("uses", "").startswith("actions/checkout@")
    )
    assert step["with"]["fetch-depth"] == 0
    upgrade = (WORKFLOWS / "ash-upgrade-paths.yml").read_text(encoding="utf-8")
    assert "fetch-depth: 0" in upgrade


def test_the_baselines_resolve_the_way_the_upgrade_job_resolves_its_starting_points():
    run = _step("Resolve the previous commit and the previous release")["run"]
    upgrade = (WORKFLOWS / "ash-upgrade-paths.yml").read_text(encoding="utf-8")
    # The previous commit: HEAD~1, as the upgrade job's from-prev-commit arm.
    assert "git rev-parse --verify HEAD~1" in run
    assert "git rev-parse --verify HEAD~1" in upgrade
    # The previous release: the highest vX.Y.Z tag, selected as the upgrade job selects
    # its tags (a version sort filtered to the release shape), not the nearest tag by
    # distance. It does not keep the upgrade job's ancestor-of-HEAD filter, which on
    # main skips the latest releases (they are cut on a line main does not contain).
    for fragment in (
        "git tag --sort=-v:refname",
        "grep -E '^v[0-9]+\\.[0-9]+\\.[0-9]+$'",
        "sed -n '1p'",
    ):
        assert fragment in run, fragment
    assert "git tag --sort=-v:refname" in upgrade
    assert "merge-base --is-ancestor" not in run
    assert "git describe" not in run.replace("`git describe", "")


def test_the_old_trees_are_local_worktrees_and_nothing_is_fetched():
    for name in ("Install the previous commit", "Install the previous release"):
        run = _step(name)["run"]
        assert "git worktree add --detach" in run, name
        assert "git fetch" not in run, name
        assert "git clone" not in run, name


def test_all_three_builds_are_timed_together_on_every_trigger_five_runs_each():
    step = _step("Time the tip against the previous commit and the previous release")
    assert "if" not in step
    run = step["run"]
    assert "scripts/measure_precommit_cost.py bench" in run
    assert "--ash" in run and "--commit" in run
    assert re.search(r"--baseline prev-release\b", run)
    assert re.search(r"--baseline prev-commit\b", run)
    assert run.count("--baseline ") == 2
    assert re.search(r"--repeats 5\b", run)
    assert '--summary "$GITHUB_STEP_SUMMARY"' in run
    assert "--json" in run


def test_the_trend_arguments_are_added_on_the_schedule_only():
    run = _step("Time the tip against the previous commit and the previous release")[
        "run"
    ]
    assert "--trend-in" in run and "--trend-out" in run
    assert '"$EVENT_NAME" = schedule' in run
    assert run.index('"$EVENT_NAME" = schedule') < run.index("--trend-out")


def test_the_trend_is_fetched_and_uploaded_on_the_schedule_only():
    assert "schedule" in _step("Fetch the previous trend")["if"]
    assert "schedule" in _step("Upload the trend")["if"]
    assert _step("Upload the trend")["with"]["name"] == "scan-benchmark-trend"


def test_the_record_uploads_even_when_a_step_failed_but_not_when_cancelled():
    step = _step("Upload the benchmark record")
    assert "!cancelled()" in step["if"]
    assert step["with"]["if-no-files-found"] == "ignore"


def test_the_workflow_states_why_it_is_not_a_gate():
    text = _text()
    assert "informational" in text.lower()
    assert "#1099" in text
