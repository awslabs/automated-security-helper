# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every Actions cache under .github/ is saved from a push to the default branch only.

Why this file exists
--------------------
A cache saved from a pull request is scoped to that pull request's ref, so no other
pull request can restore it. Each open pull request therefore kept its own copy of
each cache, and on 2026-10-06 that put the repository at 10.84 GB against GitHub's
10 GB cache quota and evicting: npm 2.54 GB over 36 entries, the weekly OpenGrep
binary 1.95 GB over 42, and the unpruned uv cache 3.62 GB over 43. A pull request
falls back to its base branch's entries, so saving from main is what every pull
request reads anyway.

So the shape is restore everywhere, save from main. Two spellings save from every
ref without a `uses: actions/cache/save` line to notice in review: the combined
`actions/cache`, whose post-job step saves, and setup-node's `cache:` input. Both
are refused here.

What it does not cover
----------------------
setup-uv's built-in cache is gated by its own `save-cache` input, and the uv sites
that save are allowlisted one by one in .github/scripts/assert-publish-surfaces.py.
This file checks the actions/cache family and setup-node only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIR = REPO_ROOT / ".github"
SCAN_WORKFLOW = GITHUB_DIR / "workflows" / "run-ash-security-scan.yml"

_MAIN_REFS = (
    "github.ref == 'refs/heads/main'",
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
)


def _steps() -> Iterator[tuple[str, dict[str, Any]]]:
    files = sorted(GITHUB_DIR.rglob("*.yml")) + sorted(GITHUB_DIR.rglob("*.yaml"))
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rel = str(path.relative_to(REPO_ROOT))
        for job in (data.get("jobs") or {}).values():
            for step in (job or {}).get("steps") or []:
                yield rel, step
        for step in (data.get("runs") or {}).get("steps") or []:
            yield rel, step


def _action(step: dict[str, Any]) -> str:
    return str(step.get("uses", "")).split("@", 1)[0]


def test_every_cache_save_requires_a_push_to_the_default_branch():
    saves = [(rel, s) for rel, s in _steps() if _action(s) == "actions/cache/save"]
    # Positive control: grype (two sites), the base image, npm (three) and OpenGrep
    # (two). A scan that found none would pass the loop below without checking anything.
    assert len(saves) >= 8, f"only {len(saves)} actions/cache/save step(s) found"

    bad = []
    for rel, step in saves:
        condition = " ".join(str(step.get("if", "")).split())
        if (
            "github.event_name == 'push'" not in condition
            or not any(ref in condition for ref in _MAIN_REFS)
            or "||" in condition
        ):
            bad.append(f"  {rel}: {step.get('name')!r} saves under if: {condition!r}")
    assert not bad, (
        "these cache saves can run outside a push to the default branch, which writes "
        "a per-ref copy no other pull request can read:\n" + "\n".join(bad)
    )


def test_no_step_uses_a_cache_that_saves_from_every_ref():
    bad = []
    for rel, step in _steps():
        action = _action(step)
        if action == "actions/cache":
            bad.append(f"  {rel}: {step.get('name')!r} uses the combined actions/cache")
        if action == "actions/setup-node" and (step.get("with") or {}).get("cache"):
            bad.append(f"  {rel}: setup-node `cache:` saves from every ref")
    assert not bad, (
        "use actions/cache/restore plus an actions/cache/save gated on a push to the "
        "default branch instead:\n" + "\n".join(bad)
    )


def test_the_reusable_scan_workflow_asks_callers_for_nothing_new():
    """The OpenGrep save must not cost an external caller a permission.

    A called workflow's declared permissions are validated against the caller's grant
    when the run starts, so adding one here breaks every caller that does not grant
    it (measured in #713). Cache steps need none; this pins the set.
    """
    data = yaml.safe_load(SCAN_WORKFLOW.read_text(encoding="utf-8"))
    assert data["permissions"] == {
        "contents": "read",
        "checks": "write",
        "pull-requests": "write",
    }
    for job in data["jobs"].values():
        assert "permissions" not in job, job.get("name")


def _jobs_steps() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    files = sorted(GITHUB_DIR.rglob("*.yml")) + sorted(GITHUB_DIR.rglob("*.yaml"))
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rel = str(path.relative_to(REPO_ROOT))
        for job in (data.get("jobs") or {}).values():
            yield rel, (job or {}).get("steps") or []
        steps = (data.get("runs") or {}).get("steps")
        if steps:
            yield rel, steps


def test_every_cache_restore_reports_its_hit_rate():
    """Each restore writes one `cache <name>: hit|partial|miss` summary line.

    The line is how a cache's effectiveness is watched over time, so a restore
    without one is a cache nobody can tell is working. Lookup-only probes restore
    nothing and are exempt.
    """
    restores = 0
    bad = []
    for rel, steps in _jobs_steps():
        reported = {
            str((s.get("env") or {}).get("CACHE_HIT", ""))
            for s in steps
            if str(s.get("name", "")).startswith("Cache report:")
        }
        for step in steps:
            if _action(step) != "actions/cache/restore":
                continue
            if str((step.get("with") or {}).get("lookup-only", "")).lower() == "true":
                continue
            restores += 1
            sid = step.get("id")
            want = f"${{{{ steps.{sid}.outputs.cache-hit }}}}"
            if not sid or want not in reported:
                bad.append(f"  {rel}: {step.get('name')!r} (id {sid!r})")
    assert restores >= 8, f"only {restores} restore step(s) found"
    assert not bad, "these cache restores write no hit-rate line:\n" + "\n".join(bad)


def test_the_pip_cache_never_includes_locally_built_wheels():
    """pip's wheels/ directory is where ASH's own wheel would land; it must not ship."""
    found = 0
    for rel, step in _steps():
        if not _action(step).startswith("actions/cache"):
            continue
        key = str((step.get("with") or {}).get("key", ""))
        if not key.startswith("pip-"):
            continue
        found += 1
        paths = [p.strip() for p in str(step["with"]["path"]).splitlines() if p.strip()]
        assert paths and all(p.endswith(("/http", "/http-v2")) for p in paths), (
            f"{rel}: {step.get('name')!r} caches {paths}; only pip's http "
            "directories may be cached"
        )
    assert found >= 2, "the pip cache restore and save were not found"
