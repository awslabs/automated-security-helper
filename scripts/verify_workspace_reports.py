# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove a real workspace scan produces the reports the RFC's table promises.

Run with: python scripts/verify_workspace_reports.py

Why this exists
---------------
``tests/unit/workspace/test_workspace_reporting.py`` and
``test_merged_reporter_content.py`` assert the same behaviours as this script, and
they are not a substitute for it. Every one of them builds its model in Python.
What none of them exercises is the path an operator actually takes: a real
workspace file on disk, real scanners, the real report phase inside each project's
own orchestrator, and then the workspace-level report step reading back the file
the aggregator streamed.

Three classes of failure live only on that path.

* A reporter that works against a hand-built model and fails against the
  aggregator's output. The unified file is assembled by hand rather than by
  ``json.dump`` of one object, precisely so peak memory stays bounded -- so
  "reporters can read what the aggregator writes" is a property of two pieces of
  code agreeing, not of either one alone.
* The plugin registry resolving a different reporter set than a test injects. A
  default run resolves 15 reporters; the four under ``ash_aws_plugins`` are
  registered only when an operator names that module. A test that injects all 19
  cannot notice that the other four never appear in a real run's manifest.
* A workspace-level artefact written to the wrong place, or a per-project one
  clobbered. Both are properties of the output *tree*, and a test asserting on a
  returned string cannot see either.

What the fixture is shaped to catch
-----------------------------------
Two projects, generated at runtime outside the repository:

* ``api`` -- threshold LOW, no ``project_name`` in its config, so its display label
  falls back to its key. That is the common case and it is the one that used to
  produce ``Project: ASH`` in every per-project report.
* ``web`` -- threshold LOW, and its config *does* declare ``project_name: web-app``.
  So its label differs from its key, which is what makes the label-versus-key
  rendering testable at all: with both projects labelled after their keys, a
  renderer that printed the key everywhere would pass.

Each project holds a different vulnerable file, tripping a different bandit rule.
That is deliberate and it is the same reasoning as
``verify_multi_project_attribution.py``: with identical files, "the csv row for
``api`` exists" would be satisfied by a reporter that credited every finding to
whichever project it happened to read first. Different marker rules make the
ground truth the source on disk rather than anything in the payload, so nothing in
the pipeline can move both sides of a comparison together.

Deliberate choices
------------------
* Only bandit runs. This gate is about reporters, not scanners, and every
  additional scanner adds runtime and a new upstream release that can turn the
  branch red without a source change.
* Assertions are structural, never on finding counts. Bandit's per-rule severities
  move between releases, and a count assertion turns an upstream release into a
  failure. What cannot move is that a project's own row exists, carries its own
  label, and agrees with the verdict recorded for it.
* The scan runs as a subprocess with ``cwd`` set to the repository, not to the
  workspace. Workspace mode's whole premise is that the working directory is not
  the scan target, and running from inside the workspace would hide any path bug
  that depends on that difference.
* The workspace is built under a temporary directory obtained from ``tempfile``
  rather than a hardcoded path. ASH self-scans this repository, and a literal
  temp path in committed source is an actionable finding here.

Failure modes and known limitations
-----------------------------------
* This does not exercise the four ``ash_aws_plugins`` reporters. They need
  credentials and they publish side effects, so a gate cannot run them. Their
  declared behaviour is asserted in
  ``tests/unit/workspace/test_workspace_reporting.py::TestTheManifestIsExhaustive``
  against the full nineteen, which is the strongest check available without a
  live account.
* An ``UNSUPPORTED`` reporter is not exercised either: none ships in that state.
  The refusal path is proven in unit tests with a declared-unsupported double.
* The scan needs bandit installed and takes tens of seconds. It is not part of the
  unit suite for that reason.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess  # nosec B404 -- the gate runs ASH as a child process to produce the reports it checks
import sys
import tempfile
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILENAME = "ash_aggregated_results.json"
REPORTS_DIR_NAME = "reports"
MANIFEST_FILENAME = "workspace-reports.json"
WORKSPACE_FILENAME = "fixture.code-workspace"

#: The scanner this gate runs. One, on purpose: see "Deliberate choices".
SCANNER = "bandit"

CONFIG_TEMPLATE = """project_name: {name}
global_settings:
  severity_threshold: {threshold}
"""


@dataclass(frozen=True)
class FixtureProject:
    key: str
    #: What lands in the project's own ``project_name``. When it equals the key,
    #: the label falls back to the key -- the common case.
    declared_name: str
    #: What the reports should call it.
    expected_label: str
    #: Python that trips exactly one bandit rule no other project trips.
    source: str


FIXTURE_PROJECTS = (
    FixtureProject(
        key="api",
        declared_name="api",
        expected_label="api",
        # B602: subprocess with shell=True.
        source='import subprocess\nsubprocess.call("ls -la", shell=True)\n',
    ),
    FixtureProject(
        key="web",
        declared_name="web-app",
        # Label differs from key, so the report has to show both.
        expected_label="web-app (web)",
        # B403/B301: pickle import and load.
        source='import pickle\npickle.loads(b"payload")\n',
    ),
)

#: Reporters whose workspace-level artefact must exist after a default run, keyed
#: by the filename the report phase gives them. Derived from the RFC's table
#: rather than from the code, so a ruling silently flipped in code fails here.
EXPECTED_MERGED_ARTIFACTS = {
    "csv": "ash.csv",
    "flat-json": "ash.flat.json",
    "html": "ash.html",
    "junitxml": "ash.junit.xml",
    "markdown": "ash.summary.md",
    "ocsf": "ash.ocsf.json",
    "sarif": "ash.sarif",
    "text": "ash.summary.txt",
    "unused-suppressions": "ash.unused-suppressions.json",
}

#: Reporters that must produce NO workspace-level artefact, and whose per-project
#: files must exist instead.
EXPECTED_PER_PROJECT_ARTIFACTS = {
    "cyclonedx": "ash.cdx.json",
    "github-ghas": "ash.ghas.sarif",
    "gitlab-cyclonedx": "ash.gl-dependency-scanning-report.cdx.json",
    "gitlab-sast": "ash.gl-sast-report.json",
}


class GateFailure(AssertionError):
    """One asserted property did not hold."""


def build_workspace(root: Path) -> Path:
    """Write the fixture projects and the workspace definition. Returns the file."""
    for project in FIXTURE_PROJECTS:
        source_dir = root / project.key / "src"
        source_dir.mkdir(parents=True, exist_ok=True)
        (source_dir / "marker.py").write_text(project.source, encoding="utf-8")

        config_dir = root / project.key / ".ash"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "ash.yaml").write_text(
            CONFIG_TEMPLATE.format(name=project.declared_name, threshold="LOW"),
            encoding="utf-8",
        )

    definition = root / WORKSPACE_FILENAME
    definition.write_text(
        json.dumps(
            {"folders": [{"path": project.key} for project in FIXTURE_PROJECTS]},
            indent=2,
        ),
        encoding="utf-8",
    )
    return definition


def run_scan(definition: Path, output_dir: Path, timeout: float):
    """Run one workspace scan with the default phases, from the repository root.

    ``cwd=REPO_ROOT`` rather than the workspace, and passed to the child rather
    than set with ``os.chdir``: this project deliberately removed process-wide cwd
    dependence, and workspace mode's premise is that the working directory is not
    the scan target.
    """
    command = [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--workspace",
        str(definition),
        "--output-dir",
        str(output_dir),
        "--scanners",
        SCANNER,
        "--no-progress",
        "--simple",
    ]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    return subprocess.run(  # nosec B603 -- list args, no shell, argv[0] is sys.executable
        command,
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise GateFailure(f"expected file does not exist: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def check_manifest(output_dir: Path) -> List[str]:
    """Every reporter accounted for, with the behaviour the RFC's table states."""
    problems: List[str] = []
    manifest = _read_json(output_dir / REPORTS_DIR_NAME / MANIFEST_FILENAME)
    reporters: Dict[str, Any] = manifest["reporters"]

    expected_projects = [project.key for project in FIXTURE_PROJECTS]
    if manifest["projects"] != expected_projects:
        problems.append(
            f"manifest projects {manifest['projects']} do not match the fixture "
            f"{expected_projects} -- order matters, because it is the operator's "
            f"stated order and two runs of one workspace must be comparable"
        )

    for name, filename in EXPECTED_MERGED_ARTIFACTS.items():
        entry = reporters.get(name)
        if entry is None:
            problems.append(f"{name}: absent from the manifest entirely")
            continue
        if entry["workspace_artifact"] != f"{REPORTS_DIR_NAME}/{filename}":
            problems.append(
                f"{name}: manifest says workspace_artifact="
                f"{entry['workspace_artifact']!r}, expected {filename!r}"
            )
        if not (output_dir / REPORTS_DIR_NAME / filename).is_file():
            problems.append(f"{name}: {filename} is named in the manifest but missing")

    for name, filename in EXPECTED_PER_PROJECT_ARTIFACTS.items():
        entry = reporters.get(name)
        if entry is None:
            problems.append(f"{name}: absent from the manifest entirely")
            continue
        if entry["behaviour"] != "per-project":
            problems.append(
                f"{name}: behaviour is {entry['behaviour']!r}, expected per-project"
            )
        if entry["workspace_artifact"] is not None:
            problems.append(
                f"{name}: produced a workspace artefact "
                f"({entry['workspace_artifact']}) but is ruled per-project"
            )
        if (output_dir / REPORTS_DIR_NAME / filename).exists():
            problems.append(
                f"{name}: {filename} exists at workspace level but is ruled per-project"
            )
        if entry["missing_per_project_artifacts"]:
            problems.append(
                f"{name}: no artefact for project(s) "
                f"{entry['missing_per_project_artifacts']}"
            )
        # The count is asserted before the paths, and that ordering is the point.
        # An empty pointer list satisfies "every pointer exists" vacuously, and a
        # mutation that routed per-project reporters down a different branch --
        # leaving the list empty while every other assertion here still held --
        # passed this gate until this check existed. A gate that cannot fail is
        # worth less than no gate, because it is believed.
        pointers = entry["per_project_artifacts"]
        if len(pointers) != len(FIXTURE_PROJECTS):
            problems.append(
                f"{name}: manifest lists {len(pointers)} per-project artefact(s), "
                f"expected one per project ({len(FIXTURE_PROJECTS)})"
            )
        if [pointer["project"] for pointer in pointers] != [
            project.key for project in FIXTURE_PROJECTS
        ]:
            problems.append(
                f"{name}: per-project pointers name "
                f"{[pointer['project'] for pointer in pointers]}, expected "
                f"{[project.key for project in FIXTURE_PROJECTS]}"
            )
        for pointer in pointers:
            if not (output_dir / pointer["path"]).is_file():
                problems.append(
                    f"{name}: manifest points at {pointer['path']}, which does not exist"
                )
        if entry.get("error"):
            problems.append(
                f"{name}: recorded an error rather than a clean per-project "
                f"ruling: {entry['error']}"
            )

    scoped = reporters.get("unused-suppressions")
    if scoped is not None and scoped["covers_projects"]:
        problems.append(
            "unused-suppressions is marked as covering projects; it is "
            "workspace-scoped and a consumer must not read it as a merge"
        )
    return problems


def check_merged_content(output_dir: Path) -> List[str]:
    """Each merged artefact names every project, in its own format's place."""
    problems: List[str] = []
    reports = output_dir / REPORTS_DIR_NAME
    keys = {project.key for project in FIXTURE_PROJECTS}

    rows = list(csv.reader(StringIO((reports / "ash.csv").read_text(encoding="utf-8"))))
    if not rows or rows[0][0] != "workspace_project":
        problems.append(
            f"csv: first column is {rows[0][0]!r}, expected workspace_project"
        )
    else:
        index = rows[0].index("workspace_project")
        present = {row[index] for row in rows[1:] if row}
        if present != keys:
            problems.append(
                f"csv: projects in rows are {sorted(present)}, expected {sorted(keys)}"
            )

    flat = _read_json(reports / "ash.flat.json")
    attributed = {finding.get("workspace_project") for finding in flat["findings"]}
    if attributed != keys:
        problems.append(f"flat-json: finding projects are {sorted(attributed)}")
    if [p["project"] for p in flat.get("workspace", {}).get("projects", [])] != [
        project.key for project in FIXTURE_PROJECTS
    ]:
        problems.append(
            "flat-json: workspace block does not list the projects in order"
        )

    sarif = _read_json(reports / "ash.sarif")
    if len(sarif["runs"]) != len(FIXTURE_PROJECTS):
        problems.append(
            f"sarif: {len(sarif['runs'])} run(s), expected {len(FIXTURE_PROJECTS)}"
        )
    roots = set()
    for run in sarif["runs"]:
        bases = run.get("originalUriBaseIds") or {}
        if len(bases) != 1:
            problems.append(
                f"sarif: a run declares {len(bases)} base id(s), expected 1"
            )
        roots.update(entry["uri"] for entry in bases.values())
    if len(roots) != len(FIXTURE_PROJECTS):
        problems.append(f"sarif: runs share a root; roots were {sorted(roots)}")

    from defusedxml import ElementTree

    suites = {
        suite.get("name")
        for suite in ElementTree.fromstring(
            (reports / "ash.junit.xml").read_text(encoding="utf-8")
        ).iter("testsuite")
    }
    for key in keys:
        if not any(name and name.startswith(f"{key}/") for name in suites):
            problems.append(
                f"junitxml: no testsuite named {key}/<scanner>; got {sorted(suites)}"
            )

    ocsf = _read_json(reports / "ash.ocsf.json")
    labelled = {
        label.split(":", 1)[1]
        for finding in ocsf
        for label in (finding["metadata"].get("labels") or [])
        if label.startswith("workspace_project:")
    }
    if labelled != keys:
        problems.append(f"ocsf: labelled projects are {sorted(labelled)}")

    scoped = _read_json(reports / "ash.unused-suppressions.json")
    if scoped.get("scope") != "workspace":
        problems.append(f"unused-suppressions: scope is {scoped.get('scope')!r}")

    return problems


def check_labels(output_dir: Path) -> List[str]:
    """A project whose declared name differs from its key shows both.

    The reason this is a separate check: ``metadata.project_name`` was the literal
    string "ASH" for every project before Phase 2b, so a renderer that printed a
    constant satisfied every "the project appears" assertion.
    """
    problems: List[str] = []
    reports = output_dir / REPORTS_DIR_NAME
    markdown = (reports / "ash.summary.md").read_text(encoding="utf-8")
    text = (reports / "ash.summary.txt").read_text(encoding="utf-8")
    html = (reports / "ash.html").read_text(encoding="utf-8")

    if "## Projects" not in markdown:
        problems.append("markdown: no '## Projects' section")
    if "PROJECTS" not in text:
        problems.append("text: no PROJECTS section")
    if 'id="workspace-projects"' not in html:
        problems.append("html: no workspace-projects section")

    for project in FIXTURE_PROJECTS:
        if f"| {project.expected_label} |" not in markdown:
            problems.append(f"markdown: no row labelled {project.expected_label!r}")
        if project.expected_label not in text:
            problems.append(f"text: no row labelled {project.expected_label!r}")
        if f"<td>{project.expected_label}</td>" not in html:
            problems.append(f"html: no cell labelled {project.expected_label!r}")

    return problems


def check_per_project_identity(output_dir: Path) -> List[str]:
    """Each project's own results name that project, not a shared constant."""
    problems: List[str] = []
    seen = {}
    for project in FIXTURE_PROJECTS:
        results = _read_json(output_dir / "projects" / project.key / RESULTS_FILENAME)
        metadata = results.get("metadata") or {}
        seen[project.key] = metadata.get("project_name")
        if metadata.get("project_name") != project.declared_name:
            problems.append(
                f"{project.key}: per-project metadata.project_name is "
                f"{metadata.get('project_name')!r}, expected {project.declared_name!r}"
            )
        if metadata.get("workspace_project") != project.key:
            problems.append(
                f"{project.key}: per-project metadata.workspace_project is "
                f"{metadata.get('workspace_project')!r}"
            )
    if len(set(seen.values())) != len(seen):
        problems.append(
            f"two projects share a project_name: {seen} -- per-project artefacts "
            f"published to a shared destination would be indistinguishable"
        )
    return problems


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--timeout",
        type=float,
        default=900.0,
        help="Seconds to allow the scan (default: 900)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Leave the generated workspace and output on disk for inspection",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    scratch = Path(tempfile.mkdtemp(prefix="ash-workspace-reports-gate-"))
    try:
        workspace_root = scratch / "workspace"
        workspace_root.mkdir(parents=True, exist_ok=True)
        output_dir = scratch / "output"

        definition = build_workspace(workspace_root)
        print(f"workspace: {definition}")
        print(f"output:    {output_dir}")

        completed = run_scan(definition, output_dir, args.timeout)
        print(f"exit code: {completed.returncode}")

        problems: List[str] = []
        # Exit 2 is the expected outcome: both fixture projects carry findings
        # above their own LOW threshold. Anything else means the scan itself did
        # not do what this gate assumes, so the report assertions below would be
        # measuring the wrong run.
        if completed.returncode != 2:
            problems.append(
                f"expected exit code 2 (actionable findings), got "
                f"{completed.returncode}\nstdout:\n{completed.stdout[-4000:]}"
                f"\nstderr:\n{completed.stderr[-4000:]}"
            )
        else:
            for check in (
                check_manifest,
                check_merged_content,
                check_labels,
                check_per_project_identity,
            ):
                problems.extend(check(output_dir))

        if problems:
            print("\nFAILED:")
            for problem in problems:
                print(f"  - {problem}")
            return 1

        print(
            f"\nPASSED: {len(EXPECTED_MERGED_ARTIFACTS)} merged artefact(s), "
            f"{len(EXPECTED_PER_PROJECT_ARTIFACTS)} per-project ruling(s), "
            f"and {len(FIXTURE_PROJECTS)} project identities verified on disk."
        )
        return 0
    finally:
        if args.keep:
            print(f"\nkept: {scratch}")
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
