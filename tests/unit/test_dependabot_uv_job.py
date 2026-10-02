# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The self-run uv Dependabot job and the script that publishes its pull requests.

Why this file exists
--------------------
Version updates for the root uv project moved out of GitHub-hosted Dependabot and into
``.github/workflows/ash-uv-dependency-updates.yml``, because GitHub drops
``versioning-strategy`` from uv jobs (dependabot-core#16112) and the fallback raises a floor
on every release. That leaves the configuration in two places: the job definition the
workflow runs, ``.github/dependabot-uv-job.yml``, and the root uv entry in
``.github/dependabot.yml``, which still governs security updates and which a reader will look
at first. The first half of this file holds them together. A group added to one and not the
other would change which pull request an update lands in depending on who opened it.

The second half covers ``.github/scripts/dependabot_uv_prs.py``: what it refuses to publish,
and how it maps proposals onto already-open pull requests. That mapping decides whether a run
opens a duplicate, leaves a stale pull request open, or closes a live one, and it is pure
logic, so it is tested here rather than against the API.

What it does not cover
----------------------
Whether the updater honours the strategy. That was measured by running the pinned image
through the CLI against this repository, which is recorded in the workflow's header comment,
and it cannot be re-measured without network access and Docker.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
JOB_FILE = REPO_ROOT / ".github" / "dependabot-uv-job.yml"
DEPENDABOT_YML = REPO_ROOT / ".github" / "dependabot.yml"
SCRIPT = REPO_ROOT / ".github" / "scripts" / "dependabot_uv_prs.py"


def _load_script() -> Any:
    spec = importlib.util.spec_from_file_location("dependabot_uv_prs", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


prs = _load_script()

BASE = "a" * 40


@pytest.fixture(scope="module")
def job() -> dict[str, Any]:
    return yaml.safe_load(JOB_FILE.read_text())["job"]


@pytest.fixture(scope="module")
def hosted_entry() -> dict[str, Any]:
    updates = yaml.safe_load(DEPENDABOT_YML.read_text())["updates"]
    [entry] = [
        u for u in updates if u["package-ecosystem"] == "uv" and u["directory"] == "/"
    ]
    return entry


# -- the job definition against .github/dependabot.yml ----------------------------------


def test_job_sets_the_strategy_the_hosted_job_loses(job: dict[str, Any]) -> None:
    assert job["requirements-update-strategy"] == "bump_versions_if_necessary"
    assert job["package-manager"] == "uv"
    assert job["source"]["directory"] == "/"
    assert not job.get("lockfile-only")


def test_hosted_entry_opens_no_version_updates(hosted_entry: dict[str, Any]) -> None:
    # Anything above zero and both would open every update, one raising the floor.
    assert hosted_entry["open-pull-requests-limit"] == 0


def test_groups_match_in_order(
    job: dict[str, Any], hosted_entry: dict[str, Any]
) -> None:
    # Whole rule mappings, so an exclude-patterns or dependency-type added on one side only
    # fails here too.
    hosted = list(hosted_entry["groups"].items())
    ours = [(g["name"], g["rules"]) for g in job["dependency-groups"]]
    assert len(hosted) >= 4
    assert ours == hosted
    assert all("applies-to" not in g for g in job["dependency-groups"])


def test_ignores_match(job: dict[str, Any], hosted_entry: dict[str, Any]) -> None:
    hosted = [
        (i["dependency-name"], i.get("update-types")) for i in hosted_entry["ignore"]
    ]
    ours = [
        (i["dependency-name"], i.get("update-types")) for i in job["ignore-conditions"]
    ]
    assert ours == hosted


def test_cooldown_and_prefix_match(
    job: dict[str, Any], hosted_entry: dict[str, Any]
) -> None:
    assert job["cooldown"] == hosted_entry["cooldown"]
    assert (
        job["commit-message-options"]["prefix"]
        == hosted_entry["commit-message"]["prefix"]
    )


def test_label_matches(hosted_entry: dict[str, Any]) -> None:
    assert hosted_entry["labels"] == [prs.LABEL]


# -- extract -------------------------------------------------------------------------------


def _dep(
    name: str, old: str, new: str, req: str, new_req: str | None = None
) -> dict[str, Any]:
    return {
        "name": name,
        "previous-version": old,
        "version": new,
        "previous-requirements": [
            {"requirement": req, "file": "pyproject.toml", "groups": []}
        ],
        "requirements": [
            {"requirement": new_req or req, "file": "pyproject.toml", "groups": []}
        ],
    }


def _file(name: str, content: str = "x", directory: str = "/") -> dict[str, Any]:
    return {
        "name": name,
        "directory": directory,
        "content": content,
        "content_encoding": "utf-8",
        "deleted": False,
        "operation": "update",
        "support_file": False,
        "type": "file",
    }


def _pr_event(
    group: str | None, files: list[dict[str, Any]], deps: list[dict[str, Any]]
) -> dict:
    data: dict[str, Any] = {
        "base-commit-sha": "a" * 40,
        "dependencies": deps,
        "updated-dependency-files": files,
        "pr-title": f"build: bump the {group} group",
        "pr-body": "body",
        "commit-message": "build: bump",
    }
    if group:
        data["dependency-group"] = {"name": group}
    return {"type": "create_pull_request", "expect": {"data": data}}


def _output(*events: dict[str, Any]) -> dict[str, Any]:
    done = {
        "type": "mark_as_processed",
        "expect": {"data": {"base-commit-sha": "a" * 40}},
    }
    return {"input": {"job": {}}, "output": [*events, done]}


def test_extract_accepts_a_lockfile_only_group() -> None:
    event = _pr_event(
        "engine-minor",
        [_file("uv.lock")],
        [_dep("boto3", "1.43.100", "1.43.104", ">=1.43.100,<1.44")],
    )
    [proposal] = prs.extract(_output(event), BASE)
    assert proposal.group == "engine-minor"
    assert set(proposal.files) == {"uv.lock"}
    assert proposal.branch.startswith("dependabot-uv/engine-minor/")


@pytest.mark.parametrize(
    "bad",
    [
        _file(".github/workflows/x.yml"),
        _file("pyproject.toml", directory="/ash-agent-plugins"),
        {**_file("uv.lock"), "deleted": True},
        {**_file("uv.lock"), "operation": "delete"},
    ],
)
def test_extract_refuses_anything_but_root_manifests(bad: dict[str, Any]) -> None:
    event = _pr_event(
        "engine-minor", [_file("uv.lock"), bad], [_dep("x", "1", "2", ">=1")]
    )
    with pytest.raises(prs.OutputError):
        prs.extract(_output(event), BASE)


def test_extract_fails_on_an_updater_error() -> None:
    # Otherwise publish would read a crashed run as "every group is up to date" and close
    # every open pull request.
    error = {
        "type": "record_update_job_error",
        "expect": {"data": {"error-type": "unknown_error"}},
    }
    with pytest.raises(prs.OutputError, match="error"):
        prs.extract(_output(error), BASE)


def test_extract_fails_on_an_unfinished_run() -> None:
    with pytest.raises(prs.OutputError, match="processed"):
        prs.extract(
            {"output": [{"type": "update_dependency_list", "expect": {"data": {}}}]},
            BASE,
        )


def test_extract_names_an_ungrouped_update_after_its_dependency() -> None:
    event = _pr_event(
        None, [_file("uv.lock")], [_dep("moto[server]", "5.2.3", "5.3.0", ">=5.2.3,<6")]
    )
    [proposal] = prs.extract(_output(event), BASE)
    assert proposal.group == "moto-server"


def test_fingerprint_ignores_dependency_order_and_tracks_versions() -> None:
    a = _dep("a", "1", "2", ">=1")
    b = _dep("b", "1", "2", ">=1")
    one = prs.extract(_output(_pr_event("g", [_file("uv.lock")], [a, b])), BASE)[0]
    two = prs.extract(_output(_pr_event("g", [_file("uv.lock")], [b, a])), BASE)[0]
    three = prs.extract(
        _output(_pr_event("g", [_file("uv.lock")], [a, _dep("b", "1", "3", ">=1")])),
        BASE,
    )[0]
    assert one.branch == two.branch
    assert one.branch != three.branch


def test_proposals_survive_the_artifact_round_trip() -> None:
    event = _pr_event(
        "g",
        [_file("uv.lock", "lock"), _file("pyproject.toml", "py")],
        [_dep("a", "1", "2", ">=1")],
    )
    proposals = prs.extract(_output(event), BASE)
    assert prs.from_json(prs.to_json(proposals)) == proposals


# -- sanitize ------------------------------------------------------------------------------


def test_sanitize_routes_links_through_the_redirector_and_breaks_mentions() -> None:
    text = "Fixes https://github.com/o/r/issues/1 by @someone, see `@decorator` and a@b.com"
    out = prs.sanitize(text)
    assert "https://redirect.github.com/o/r/issues/1" in out
    assert "@someone" not in out
    assert "@" + prs.ZERO_WIDTH_SPACE + "someone" in out
    assert "`@decorator`" in out
    assert "a@b.com" in out


# -- plan ----------------------------------------------------------------------------------


def _proposal(group: str, version: str = "2") -> Any:
    event = _pr_event(group, [_file("uv.lock")], [_dep("a", "1", version, ">=1")])
    return prs.extract(_output(event), BASE)[0]


def _open(number: int, branch: str, mergeable: bool | None = True) -> dict[str, Any]:
    return {"number": number, "branch": branch, "mergeable": mergeable}


def test_plan_opens_a_new_group() -> None:
    p = _proposal("engine-minor")
    result = prs.plan([p], [])
    assert result.create == [(p, p.branch)]
    assert result.keep == [] and result.close == []


def test_plan_keeps_an_identical_open_pull_request() -> None:
    p = _proposal("engine-minor")
    result = prs.plan([p], [_open(5, p.branch, mergeable=None)])
    assert result.keep == [(p, 5)]
    assert result.create == [] and result.close == []


def test_plan_supersedes_an_older_proposal_for_the_same_group() -> None:
    old, new = _proposal("engine-minor", "2"), _proposal("engine-minor", "3")
    result = prs.plan([new], [_open(5, old.branch)])
    assert result.create == [(new, new.branch)]
    assert result.close == [(5, old.branch, "superseded")]


def test_plan_reopens_a_conflicting_pull_request_on_a_fresh_branch() -> None:
    p = _proposal("engine-minor")
    result = prs.plan([p], [_open(5, p.branch, mergeable=False)])
    [(created, branch)] = result.create
    assert created == p and branch == f"{p.branch}-{p.base_sha[:8]}"
    assert result.close == [(5, p.branch, "conflicts with main")]


def test_plan_closes_a_group_the_updater_no_longer_proposes() -> None:
    gone = _proposal("scanner-minor")
    kept = _proposal("engine-minor")
    result = prs.plan([kept], [_open(5, gone.branch), _open(6, kept.branch)])
    assert result.keep == [(kept, 6)]
    assert result.close == [(5, gone.branch, "up to date")]


def test_plan_does_not_confuse_groups_sharing_a_prefix() -> None:
    # engine-minor must not claim engine-major-upgrade's pull request.
    minor = _proposal("engine-minor")
    major = _proposal("engine-major-upgrade")
    result = prs.plan([minor], [_open(7, major.branch)])
    assert result.create == [(minor, minor.branch)]
    assert result.close == [(7, major.branch, "up to date")]


def test_plan_keeps_a_reopened_pull_request_after_main_moves() -> None:
    # Run 1 reopened a conflicting pull request on <branch>-<old base>. Run 2, with main
    # moved on and the same versions, must keep that one rather than open a third.
    p = _proposal("engine-minor")
    reopened = f"{p.branch}-bbbbbbbb"
    result = prs.plan([p], [_open(6, reopened)])
    assert result.keep == [(p, 6)]
    assert result.create == [] and result.close == []


def test_extract_refuses_a_proposal_on_another_base() -> None:
    # publish builds on the proposal's base commit, so a foreign base would carry its tree.
    event = _pr_event("g", [_file("uv.lock")], [_dep("a", "1", "2", ">=1")])
    event["expect"]["data"]["base-commit-sha"] = "c" * 40
    with pytest.raises(prs.OutputError, match="pinned"):
        prs.extract(_output(event), BASE)
    with pytest.raises(prs.OutputError, match="processed"):
        prs.extract(_output(), "d" * 40)


# -- the API wrapper -----------------------------------------------------------------------


class _FakeGitHub(prs.GitHub):
    """Records calls, answers from a script, and raises ApiError where told to."""

    def __init__(self, fail: dict[tuple[str, str], int] | None = None) -> None:
        super().__init__("o/r", "t")
        self.calls: list[tuple[str, str, Any]] = []
        self.fail = fail or {}

    def call(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path, body))
        status = self.fail.get((method, path.split("?")[0]))
        if status:
            raise prs.ApiError(status, f"{method} {path} -> HTTP {status}")
        if path.startswith("/git/commits/"):
            return {"tree": {"sha": "t0"}}
        if path == "/pulls" and method == "POST":
            return {"number": 42}
        return {"sha": "s"}


def test_open_pr_moves_a_branch_left_behind_by_a_closed_pull_request() -> None:
    p = _proposal("engine-minor")
    gh = _FakeGitHub(fail={("POST", "/git/refs"): 422})
    assert gh.open_pr(p, p.branch, "main") == 42
    [patch] = [c for c in gh.calls if c[0] == "PATCH"]
    assert patch[1] == f"/git/refs/heads/{p.branch}"
    assert patch[2]["force"] is True
    commit = next(c for c in gh.calls if c[1] == "/git/commits")
    assert commit[2]["parents"] == [BASE]


def test_open_pr_does_not_swallow_other_ref_errors() -> None:
    p = _proposal("engine-minor")
    gh = _FakeGitHub(fail={("POST", "/git/refs"): 403})
    with pytest.raises(prs.ApiError):
        gh.open_pr(p, p.branch, "main")


def test_close_pr_tolerates_an_already_deleted_branch() -> None:
    gh = _FakeGitHub(fail={("DELETE", "/git/refs/heads/dependabot-uv/g/x"): 422})
    gh.close_pr(5, "dependabot-uv/g/x", "closing")
    assert ("PATCH", "/pulls/5", {"state": "closed"}) in gh.calls


def test_publish_closes_superseded_pull_requests_even_when_a_create_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = _proposal("engine-minor", "3")
    old = _proposal("engine-minor", "2")
    stale = _proposal("scanner-minor")
    proposals = tmp_path / "p.json"
    proposals.write_text(prs.json.dumps(prs.to_json([new])))

    instances: list[_FakeGitHub] = []

    class Fake(_FakeGitHub):
        def __init__(self, *_: Any) -> None:
            super().__init__(fail={("POST", "/pulls"): 500})
            instances.append(self)

        def open_prs(self) -> list[dict[str, Any]]:
            return [_open(5, old.branch), _open(6, stale.branch)]

    monkeypatch.setattr(prs, "GitHub", Fake)
    monkeypatch.setenv("GH_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    assert prs.main(["publish", str(proposals), "--expect-base", BASE]) == 1
    [gh] = instances
    closed = [c[1] for c in gh.calls if c[0] == "PATCH" and c[1].startswith("/pulls/")]
    assert closed == ["/pulls/5", "/pulls/6"]


def test_publish_without_a_token_fails_and_names_the_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    proposals = tmp_path / "p.json"
    proposals.write_text(prs.json.dumps(prs.to_json([_proposal("g")])))
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert prs.main(["publish", str(proposals), "--expect-base", BASE]) == 1
    out = capsys.readouterr().out
    assert (
        "DEPENDABOT_UV_APP_CLIENT_ID" in out and "DEPENDABOT_UV_APP_PRIVATE_KEY" in out
    )


def test_publish_refuses_proposals_on_another_base(tmp_path: Path) -> None:
    proposals = tmp_path / "p.json"
    proposals.write_text(prs.json.dumps(prs.to_json([_proposal("g")])))
    assert prs.main(["publish", str(proposals), "--expect-base", "e" * 40]) == 1


def test_job_subcommand_pins_the_commit(tmp_path: Path) -> None:
    dest = tmp_path / "job.yml"
    assert prs.main(["job", str(JOB_FILE), str(dest), "--commit", BASE]) == 0
    pinned = yaml.safe_load(dest.read_text())["job"]
    assert pinned["source"]["commit"] == BASE
    assert {**pinned, "source": {}} == {
        **yaml.safe_load(JOB_FILE.read_text())["job"],
        "source": {},
    }
