# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CI uploads of ASH output carry only ``reports/`` and ``ash_aggregated_results.json``.

Why this file exists
--------------------
ASH's output directory also holds ``scanners/`` and ``converted/``: each tool's raw
output as the tool wrote it, and the converted copies of the scanned files. Those are
not masked, so a secret a scanner found is in them in full. ASH's own scan workflow,
its run-scan-test action and the CI examples in the docs uploaded the whole output
directory as a build artifact, which put that raw output in every artifact a reader of
the run can download. They now upload ``reports/`` and ``ash_aggregated_results.json``
only, which is everything the reporting job, the SARIF upload and a reader need.

What this asserts
-----------------
Every artifact upload that names an ASH output location, in .github/ and in the docs
(GitHub ``actions/upload-artifact`` ``path:``, GitLab ``artifacts: paths:``, CodeBuild
``artifacts: files:``, Jenkins ``archiveArtifacts``, CircleCI ``store_artifacts``),
names ``reports`` (or something inside it) or ``ash_aggregated_results.json``. The
scan finds at least the uploads this change touched, so it cannot pass by finding none.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

SOURCES = [
    *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
    *sorted((REPO_ROOT / ".github" / "actions").glob("*/action.yml")),
    *sorted((REPO_ROOT / "docs" / "content").rglob("*.md")),
    *sorted((REPO_ROOT / "docs" / "content").rglob("*.template")),
    *sorted((REPO_ROOT / "docs" / "content" / "tutorials" / "CI").rglob("*.yml")),
    *sorted((REPO_ROOT / "docs" / "content" / "tutorials" / "CI").rglob("Jenkinsfile")),
    REPO_ROOT / "README.md",
]

# What names ASH's output: its default directories, the workflow input and the
# tutorials' variable for it.
_ASH_OUTPUT = re.compile(r"ash_output|\.ash/merged|ASH_OUTPUT|inputs\.output-dir")
# reports/ (or something inside it) and the results file, at the top of the output
# directory or, for a workspace scan, as exactly projects/*/reports and
# projects/*/ash_aggregated_results.json.
_ALLOWED = re.compile(
    r"^(?:(?!/projects/).)*?/(?:reports(?:/.*)?|ash_aggregated_results\.json)/?$"
    r"|/projects/\*/(?:reports(?:/.*)?|ash_aggregated_results\.json)/?$"
)
# Raw tool output and converted files, at any depth.
_RAW = re.compile(r"(?:^|/)(?:scanners|converted)(?:/|$)")


def _allowed(value: str) -> bool:
    target = _normalized(value)
    return bool(_ALLOWED.search(target)) and not _RAW.search(target)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _strip(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    return value.strip("'\"").rstrip(",").strip()


def _block_items(lines: list[str], start: int, key: str) -> list[str]:
    """The values of ``key:`` (inline, ``|`` block or ``-`` list) in the mapping at ``start``."""
    base = _indent(lines[start])
    values = []
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        if _indent(line) <= base or line.strip().startswith("```"):
            break
        match = re.match(rf"\s*{re.escape(key)}:\s*(.*)$", line)
        if not match:
            continue
        inline = match.group(1).strip()
        if inline and inline not in ("|", "|-", ">", ">-"):
            values.append(_strip(inline))
            continue
        own = _indent(line)
        for nxt in lines[i + 1 :]:
            if not nxt.strip():
                continue
            if _indent(nxt) <= own:
                break
            values.append(_strip(nxt.strip().lstrip("- ")))
        break
    return values


def _github_step_paths(lines: list[str], at: int) -> list[str]:
    """``path:`` of the upload-artifact step whose ``uses:`` line is at ``at``."""
    uses = lines[at]
    step_indent = _indent(uses) - (2 if uses.strip().startswith("uses:") else 0)
    out = []
    for i in range(at + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        if line.strip().startswith("```") or (
            _indent(line) <= step_indent and line.strip().startswith("- ")
        ):
            break
        if re.match(r"\s*with:\s*$", line):
            out += _block_items(lines, i, "path")
    return out


def _uploads(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    found: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        text = line.strip()
        if "actions/upload-artifact@" in text and "uses:" in text:
            found += [(i + 1, v) for v in _github_step_paths(lines, i)]
        elif re.match(r"(?:-\s*)?artifacts:\s*$", text):
            found += [(i + 1, v) for v in _block_items(lines, i, "paths")]
            found += [(i + 1, v) for v in _block_items(lines, i, "files")]
        elif re.match(r"-\s*store_artifacts:\s*$", text):
            found += [(i + 1, v) for v in _block_items(lines, i, "path")]
        if "archiveArtifacts" in text:
            window = " ".join(lines[i : i + 3])
            match = re.search(r"artifacts:\s*(['\"])(.*?)\1", window)
            if match:
                found += [(i + 1, _strip(v)) for v in match.group(2).split(",")]
    return found


def _ash_output_uploads() -> list[tuple[str, int, str]]:
    return [
        (str(path.relative_to(REPO_ROOT)), line, value)
        for path in SOURCES
        if path.is_file()
        for line, value in _uploads(path)
        if _ASH_OUTPUT.search(value)
    ]


def _normalized(value: str) -> str:
    """The upload target with its trailing glob removed."""
    return re.sub(r"/\*\*(?:/\*)?$|/\*$", "", value.strip())


def test_every_upload_of_ash_output_names_only_reports_or_the_results_file():
    uploads = _ash_output_uploads()
    wide = [
        f"{where}:{line}: {value}"
        for where, line, value in uploads
        if not _allowed(value)
    ]
    assert not wide, (
        "these uploads carry ASH's whole output directory, scanners/ and converted/ "
        "with each tool's raw, unmasked output included; upload reports/ and "
        "ash_aggregated_results.json instead:\n" + "\n".join(wide)
    )


def test_the_scan_finds_the_uploads_it_is_about():
    where = {w for w, _, _ in _ash_output_uploads()}
    for expected in (
        ".github/workflows/run-ash-security-scan.yml",
        ".github/actions/run-scan-test/action.yml",
        "docs/content/docs/advanced-usage.md.template",
        "docs/content/tutorials/running-ash-in-ci.md.template",
        "docs/content/docs/plugins/community/trivy-plugin.md",
        "docs/content/tutorials/CI/GitLabCI/.gitlab-ci.yml",
        "docs/content/tutorials/CI/Jenkins/Jenkinsfile",
        "docs/content/tutorials/CI/GitHubActions/.github/workflows/run-ash-scan.yml",
    ):
        assert expected in where, f"found no upload of ASH output in {expected}"


def test_the_allowed_forms():
    for ok in (
        ".ash/ash_output/reports",
        ".ash/ash_output/reports/",
        ".ash/ash_output/reports/**/*",
        ".ash/ash_output/reports/ash.sarif",
        ".ash/ash_output/ash_aggregated_results.json",
        "${{ inputs.output-dir }}/reports",
        "${{ inputs.output-dir }}/projects/*/reports",
        "${{ inputs.output-dir }}/projects/*/ash_aggregated_results.json",
        ".ash/ash_output/projects/*/reports/**/*",
    ):
        assert _allowed(ok), ok
    for wide in (
        ".ash/ash_output",
        ".ash/ash_output/",
        ".ash/ash_output/**/*",
        "${{ inputs.output-dir }}",
        ".ash/ash_output/scanners",
        ".ash/ash_output/converted",
        ".ash/merged",
        "${{ inputs.output-dir }}/projects",
        "${{ inputs.output-dir }}/projects/*",
        "${{ inputs.output-dir }}/projects/**",
        "${{ inputs.output-dir }}/projects/web/reports",
        "${{ inputs.output-dir }}/projects/*/scanners",
        "${{ inputs.output-dir }}/projects/*/converted",
        "${{ inputs.output-dir }}/projects/*/scanners/reports",
        "${{ inputs.output-dir }}/scanners/bandit/reports",
        "${{ inputs.output-dir }}/projects/*/reports/../scanners",
    ):
        assert not _allowed(wide), wide


def test_the_scan_workflow_uploads_the_per_project_copies_too():
    workflow = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
    values = {value for _, value in _uploads(workflow)}
    for expected in (
        "${{ inputs.output-dir }}/reports",
        "${{ inputs.output-dir }}/ash_aggregated_results.json",
        "${{ inputs.output-dir }}/projects/*/reports",
        "${{ inputs.output-dir }}/projects/*/ash_aggregated_results.json",
    ):
        assert expected in values, (expected, sorted(values))
