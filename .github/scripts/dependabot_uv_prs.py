#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Turn a dependabot CLI run into pull requests for the root uv project.

WHY THIS EXISTS
---------------
GitHub-hosted Dependabot drops `versioning-strategy` from every uv job it builds
(dependabot-core#16112), so for this project it raises a floor in pyproject.toml on every
release. .github/workflows/ash-uv-dependency-updates.yml runs the same updater through the
dependabot CLI with .github/dependabot-uv-job.yml, which does carry the strategy. The CLI
only computes updates. It writes what it would have sent to GitHub's Dependabot service
into a YAML file and opens nothing. This script is the part of that service the workflow
needs: it reads the file and opens, refreshes or closes pull requests.

It runs in two jobs, as two subcommands, so the job that holds write credentials never
runs the updater:

  extract  In the job that ran the updater, with a read-only token. Validates the CLI
           output and writes the pull requests it describes to a JSON file, which is
           passed to the next job as an artifact.
  publish  In a job that runs no third-party code. Reads that JSON and talks to the REST
           API with a GitHub App installation token. The token comes from an App rather
           than GITHUB_TOKEN because a pull request opened with GITHUB_TOKEN starts no
           `pull_request` workflows, and the ruleset on main requires three checks that
           only `pull_request` runs report.

WHAT extract REFUSES
--------------------
Any error event from the updater, so a failed or partial run fails the workflow rather
than looking like "nothing to update". And any file outside pyproject.toml and uv.lock at
the repository root: the publish job writes whatever bytes it is given, and it should not
be possible for a dependency update to write anywhere else, .github/ above all. And any
proposal not computed against the commit the job was pinned to (`job` writes that commit
into the job file). publish builds each commit on the proposal's base commit, so an
arbitrary base would bring that commit's whole tree along, and the updater container,
which runs dependency build code, is where the proposals come from.

HOW publish MAPS UPDATES TO PULL REQUESTS
-----------------------------------------
The CLI is not told which pull requests are already open, so every run proposes the full
set of updates each group needs against the current main. Each proposal gets a branch
named for its group and a hash of the dependency versions it moves to, under
`dependabot-uv/`. Then, per group:

  * a pull request on that exact branch already open, and mergeable: left alone;
  * open but conflicting with main: closed, and the update reopened on a branch that also
    carries the base commit, so nothing is ever force-pushed;
  * other open pull requests for the same group: closed as superseded, branch deleted;
  * a group with an open pull request and no proposal this run: closed, because the
    updater found nothing left to do for it. That inference is safe only because extract
    fails on any updater error, so a missing proposal cannot be a crashed one.

Commits are made through the Git data API on top of the base commit the updater worked
from, so they are signed by GitHub as the App and no credential is written to disk.

KNOWN LIMITATIONS
-----------------
Dependabot's `@dependabot` comment commands do not exist here: nothing reads them. To
stop an update, close the pull request and it will be proposed again on the next run if
it still applies; add an `ignore` to both files to stop it for good.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BRANCH_PREFIX = "dependabot-uv/"
ALLOWED_FILES = frozenset({"pyproject.toml", "uv.lock"})
ERROR_EVENTS = frozenset({"record_update_job_error", "record_update_job_unknown_error"})
LABEL = "dependencies"
# GitHub rejects a pull request body over 65536 characters.
MAX_BODY = 65000
ZERO_WIDTH_SPACE = chr(0x200B)
FOOTER = (
    "\n\n---\n"
    "Opened by `.github/workflows/ash-uv-dependency-updates.yml`, which runs Dependabot with "
    "`.github/dependabot-uv-job.yml` because GitHub-hosted Dependabot drops "
    "`versioning-strategy` for uv (dependabot/dependabot-core#16112). `@dependabot` commands "
    "do nothing here. Close this pull request to drop the update until the next run."
)


class OutputError(Exception):
    """The CLI output is not something publish may act on."""


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Proposal:
    group: str
    base_sha: str
    title: str
    body: str
    commit_message: str
    files: dict[str, str]
    dependencies: list[dict[str, Any]]

    @property
    def fingerprint(self) -> str:
        moved = sorted(
            (
                d["name"],
                d["version"],
                tuple(r["requirement"] for r in d.get("requirements") or []),
            )
            for d in self.dependencies
        )
        return hashlib.sha256(json.dumps(moved).encode()).hexdigest()[:10]

    @property
    def branch(self) -> str:
        return f"{BRANCH_PREFIX}{self.group}/{self.fingerprint}"


def group_key(name: str) -> str:
    """Branch-safe form of a group name, or of a dependency name for an ungrouped update."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "update"


def extract(output: dict[str, Any], expected_base: str) -> list[Proposal]:
    """Validate CLI output and return the pull requests it proposes.

    expected_base is the commit the job file pinned. Every proposal must have been computed
    against it, because publish uses a proposal's base commit as the parent and base tree of
    the commit it makes: a different one would carry that commit's whole tree into the pull
    request, not just pyproject.toml and uv.lock.
    """
    events = output.get("output")
    if not isinstance(events, list):
        raise OutputError("CLI output has no `output` list; the updater did not run")
    errors = [e for e in events if e.get("type") in ERROR_EVENTS]
    if errors:
        details = "; ".join(json.dumps(e.get("expect", {}).get("data")) for e in errors)
        raise OutputError(f"updater reported {len(errors)} error(s): {details}")
    processed = [e for e in events if e.get("type") == "mark_as_processed"]
    if not processed:
        raise OutputError(
            "updater never marked the job processed; the run did not finish"
        )
    for event in processed:
        sha = (event.get("expect", {}).get("data") or {}).get("base-commit-sha")
        if sha != expected_base:
            raise OutputError(
                f"updater processed {sha}, not the pinned {expected_base}"
            )

    proposals = []
    for event in events:
        if event.get("type") != "create_pull_request":
            continue
        data = event["expect"]["data"]
        files = {}
        for f in data["updated-dependency-files"]:
            if f.get("directory") != "/" or f.get("name") not in ALLOWED_FILES:
                raise OutputError(
                    f"refusing to write {f.get('directory')}{f.get('name')}"
                )
            if (
                f.get("deleted")
                or f.get("operation") != "update"
                or f.get("type") != "file"
            ):
                raise OutputError(f"refusing a non-update change to {f['name']}")
            if f.get("content_encoding", "utf-8") != "utf-8":
                raise OutputError(
                    f"unexpected encoding for {f['name']}: {f['content_encoding']}"
                )
            files[f["name"]] = f["content"]
        if not files:
            raise OutputError(f"pull request {data.get('pr-title')!r} changes no files")
        if data.get("base-commit-sha") != expected_base:
            raise OutputError(
                f"pull request {data.get('pr-title')!r} is based on "
                f"{data.get('base-commit-sha')}, not the pinned {expected_base}"
            )
        deps = data["dependencies"]
        group = (data.get("dependency-group") or {}).get("name") or deps[0]["name"]
        proposals.append(
            Proposal(
                group=group_key(group),
                base_sha=data["base-commit-sha"],
                title=data["pr-title"],
                body=data.get("pr-body") or "",
                commit_message=data.get("commit-message") or data["pr-title"],
                files=files,
                dependencies=deps,
            )
        )
    groups = [p.group for p in proposals]
    if len(groups) != len(set(groups)):
        raise OutputError(f"two proposals for one group: {groups}")
    return proposals


def sanitize(text: str) -> str:
    """Stop release notes copied into the body from notifying anyone upstream.

    Hosted Dependabot links through redirect.github.com so upstream issues do not collect a
    backlink from every pull request that quotes them; the CLI emits plain github.com links.
    A bare @name would also notify that user, so a zero-width space breaks it.
    """
    text = text.replace("https://github.com/", "https://redirect.github.com/")
    text = re.sub(r"(?<![\w/`\[@.])@(?=[A-Za-z0-9])", "@" + ZERO_WIDTH_SPACE, text)
    return text


@dataclass
class Plan:
    keep: list[tuple[Proposal, int]] = field(default_factory=list)
    create: list[tuple[Proposal, str]] = field(default_factory=list)
    close: list[tuple[int, str, str]] = field(default_factory=list)


def plan(proposals: list[Proposal], open_prs: list[dict[str, Any]]) -> Plan:
    """Decide what to do. open_prs: our open pull requests as {number, branch, mergeable}."""
    result = Plan()
    by_group: dict[str, list[dict[str, Any]]] = {}
    for pr in open_prs:
        rest = pr["branch"][len(BRANCH_PREFIX) :]
        by_group.setdefault(rest.split("/", 1)[0], []).append(pr)

    for proposal in proposals:
        current = by_group.pop(proposal.group, [])
        # Same versions: the plain branch, or one reopened on a later base after a conflict.
        same = [
            pr
            for pr in current
            if pr["branch"] == proposal.branch
            or pr["branch"].startswith(proposal.branch + "-")
        ]
        keeper = next((pr for pr in same if pr["mergeable"] is not False), None)
        if keeper is not None:
            result.keep.append((proposal, keeper["number"]))
        elif same:
            rebased = f"{proposal.branch}-{proposal.base_sha[:8]}"
            result.create.append((proposal, rebased))
        else:
            result.create.append((proposal, proposal.branch))
        for pr in current:
            if keeper is not None and pr["number"] == keeper["number"]:
                continue
            reason = "conflicts with main" if pr in same else "superseded"
            result.close.append((pr["number"], pr["branch"], reason))

    for prs in by_group.values():
        for pr in prs:
            result.close.append((pr["number"], pr["branch"], "up to date"))
    return result


class GitHub:
    def __init__(
        self, repo: str, token: str, api: str = "https://api.github.com"
    ) -> None:
        # The token goes in a header on every request, so only ever to an https endpoint.
        if not api.startswith("https://"):
            raise ValueError(f"refusing a non-https API URL: {api}")
        self.repo, self.token, self.api = repo, token, api.rstrip("/")

    def call(self, method: str, path: str, body: Any = None) -> Any:
        url = f"{self.api}/repos/{self.repo}{path}"
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data, timeout=60) as resp:  # nosec B310 - https enforced in __init__
                raw = resp.read()
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")[:500]
            raise ApiError(
                err.code, f"{method} {path} -> HTTP {err.code}: {detail}"
            ) from None
        return json.loads(raw) if raw else None

    def open_prs(self) -> list[dict[str, Any]]:
        found, page = [], 1
        while True:
            batch = self.call("GET", f"/pulls?state=open&per_page=100&page={page}")
            for pr in batch:
                head = pr["head"]
                if (
                    head["ref"].startswith(BRANCH_PREFIX)
                    and (head.get("repo") or {}).get("full_name") == self.repo
                ):
                    detail = self.call("GET", f"/pulls/{pr['number']}")
                    found.append(
                        {
                            "number": pr["number"],
                            "branch": head["ref"],
                            "mergeable": detail["mergeable"],
                        }
                    )
            if len(batch) < 100:
                return found
            page += 1

    def open_pr(self, proposal: Proposal, branch: str, base: str) -> int:
        base_tree = self.call("GET", f"/git/commits/{proposal.base_sha}")["tree"]["sha"]
        entries = []
        for name, content in sorted(proposal.files.items()):
            blob = self.call(
                "POST",
                "/git/blobs",
                {
                    "content": base64.b64encode(content.encode()).decode(),
                    "encoding": "base64",
                },
            )
            entries.append(
                {"path": name, "mode": "100644", "type": "blob", "sha": blob["sha"]}
            )
        tree = self.call(
            "POST", "/git/trees", {"base_tree": base_tree, "tree": entries}
        )
        commit = self.call(
            "POST",
            "/git/commits",
            {
                "message": sanitize(proposal.commit_message),
                "tree": tree["sha"],
                "parents": [proposal.base_sha],
            },
        )
        self.set_branch(branch, commit["sha"])
        body = sanitize(proposal.body)[: MAX_BODY - len(FOOTER)] + FOOTER
        pr = self.call(
            "POST",
            "/pulls",
            {"title": proposal.title, "head": branch, "base": base, "body": body},
        )
        self.call("POST", f"/issues/{pr['number']}/labels", {"labels": [LABEL]})
        return pr["number"]

    def set_branch(self, branch: str, sha: str) -> None:
        """Point a branch under BRANCH_PREFIX at sha, creating it if needed.

        The branch can already exist with no open pull request: someone closed one by hand,
        which keeps its branch, and the next run proposes the same versions again. plan()
        only creates on a branch no open pull request uses, so moving it loses nothing.
        """
        if not branch.startswith(BRANCH_PREFIX):
            raise ValueError(
                f"refusing to move {branch}, which is not under {BRANCH_PREFIX}"
            )
        try:
            self.call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})
        except ApiError as err:
            if err.status != 422:
                raise
            self.call("PATCH", f"/git/refs/heads/{branch}", {"sha": sha, "force": True})

    def close_pr(self, number: int, branch: str, comment: str) -> None:
        self.call("POST", f"/issues/{number}/comments", {"body": comment})
        self.call("PATCH", f"/pulls/{number}", {"state": "closed"})
        try:
            self.call("DELETE", f"/git/refs/heads/{branch}")
        except ApiError as err:
            # Already deleted, by hand or by delete_branch_on_merge.
            if err.status not in (404, 422):
                raise


def describe(proposals: list[Proposal]) -> str:
    lines = [f"{len(proposals)} pull request(s) proposed by the updater.", ""]
    for p in proposals:
        lines.append(f"- `{p.branch}`: {p.title} ({', '.join(sorted(p.files))})")
        for d in p.dependencies:
            old = [r["requirement"] for r in d.get("previous-requirements") or []]
            new = [r["requirement"] for r in d.get("requirements") or []]
            moved = (
                "requirement unchanged" if old == new else f"requirement {old} -> {new}"
            )
            lines.append(
                f"  - {d['name']} {d.get('previous-version')} -> {d['version']}, {moved}"
            )
    return "\n".join(lines)


def to_json(proposals: list[Proposal]) -> list[dict[str, Any]]:
    return [p.__dict__ for p in proposals]


def from_json(items: list[dict[str, Any]]) -> list[Proposal]:
    return [Proposal(**item) for item in items]


def cmd_extract(args: argparse.Namespace) -> int:
    import yaml  # only the extract job has PyYAML; publish runs on the bare runner python

    proposals = extract(yaml.safe_load(Path(args.output).read_text()), args.expect_base)
    Path(args.dest).write_text(json.dumps(to_json(proposals)))
    print(describe(proposals))
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    proposals = from_json(json.loads(Path(args.proposals).read_text()))
    print(describe(proposals))
    # Checked again here so that this job does not rest on the artifact's say-so.
    for proposal in proposals:
        if proposal.base_sha != args.expect_base:
            raise OutputError(
                f"{proposal.branch} is based on {proposal.base_sha}, not {args.expect_base}"
            )
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print(
            "::error::No GitHub App token, so no pull request can be opened. Set the "
            "DEPENDABOT_UV_APP_CLIENT_ID variable and DEPENDABOT_UV_APP_PRIVATE_KEY secret."
        )
        return 1
    gh = GitHub(
        os.environ["GITHUB_REPOSITORY"],
        token,
        os.environ.get("GITHUB_API_URL") or "https://api.github.com",
    )
    decided = plan(proposals, gh.open_prs())
    for proposal, number in decided.keep:
        print(f"keep #{number} for {proposal.group}: already open with these versions")
    # One failure must not stop the rest, or a single bad create would leave every
    # superseded pull request open. Failures are reported together and fail the run.
    failures = []
    opened: dict[str, int] = {}
    for proposal, branch in decided.create:
        try:
            opened[proposal.group] = gh.open_pr(proposal, branch, args.base)
        except ApiError as err:
            failures.append(f"open {branch}: {err}")
            continue
        print(f"opened #{opened[proposal.group]} on {branch}")
    for number, branch, reason in decided.close:
        group = branch[len(BRANCH_PREFIX) :].split("/", 1)[0]
        if reason == "up to date":
            comment = "The updater proposed nothing for this group on the latest run, so it is no longer needed."
        elif group in opened:
            comment = f"Superseded by #{opened[group]} ({reason})."
        else:
            comment = f"Closed: {reason}."
        try:
            gh.close_pr(number, branch, comment)
        except ApiError as err:
            failures.append(f"close #{number}: {err}")
            continue
        print(f"closed #{number} ({reason})")
    for failure in failures:
        print(f"::error::{failure}")
    return 1 if failures else 0


def cmd_job(args: argparse.Namespace) -> int:
    """Copy the job file with source.commit set.

    The CLI's --commit flag is read only when it builds a job from flags; with -f it is
    ignored, so the commit has to be in the file for the run to be pinned to it.
    """
    import yaml

    job = yaml.safe_load(Path(args.job).read_text())
    job["job"]["source"]["commit"] = args.commit
    Path(args.dest).write_text(yaml.safe_dump(job, sort_keys=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser(
        "extract", help="validate dependabot CLI output and write proposals"
    )
    ex.add_argument("output", help="YAML written by `dependabot update -o`")
    ex.add_argument("dest", help="JSON file to write the proposals to")
    ex.add_argument("--expect-base", required=True, help="commit the job was pinned to")
    ex.set_defaults(func=cmd_extract)
    pub = sub.add_parser("publish", help="open, keep or close pull requests")
    pub.add_argument("proposals", help="JSON written by extract")
    pub.add_argument("--base", default="main")
    pub.add_argument(
        "--expect-base", required=True, help="commit the job was pinned to"
    )
    pub.set_defaults(func=cmd_publish)
    jb = sub.add_parser("job", help="copy the job file pinned to one commit")
    jb.add_argument("job", help="the committed job file")
    jb.add_argument("dest", help="where to write the pinned copy")
    jb.add_argument("--commit", required=True)
    jb.set_defaults(func=cmd_job)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OutputError as err:
        print(f"::error::{err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
