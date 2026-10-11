# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A job downloads another job's artifact by the ID that job handed over.

Why this exists
---------------
Every artifact one job hands to another carries ``-attempt-${{ github.run_attempt }}``
in its name, because upload-artifact names are immutable within a run and "Re-run all
jobs" would otherwise fail the upload (ash-package.yml's build job says why). The
consumers recomputed that name from their own run_attempt. After "Re-run failed jobs",
a producer that passed in attempt 1 does not run again, so its artifact keeps the
``-attempt-1`` name while the re-run consumer asks for ``-attempt-2``. Release Assets
run 37993713568 attempt 2 failed exactly so, "Artifact not found for name:
ash-package-<sha>-attempt-2", with every package job green. A download by a fixed name
that a job in the same workflow uploads fails the other way round: the producer, re-run,
cannot upload that name again.

So a download of an artifact produced in the same run takes the producer's
``artifact-id`` output, through ``needs`` and, across a reusable workflow, its
``workflow_call`` outputs, the way ash-tag-on-merge.yml already downloads the release
assets. This reads every workflow and composite action and refuses:

* a download whose name, pattern or artifact-ids is built from ``github.run_attempt``;
* a download by ``name:`` of an artifact a job in the same workflow uploads;
* an ``artifact-ids`` that is not one ``${{ needs.<job>.outputs.<name> }}`` of a job
  in the step's ``needs``;
* an ``artifact-ids`` with no earlier step in the job holding that same expression to
  a number. download-artifact reads an empty ``artifact-ids`` as no filter and
  downloads every artifact of the run, each into its own subdirectory.

tests/unit/test_release_workflow_references.py checks that each ``needs`` output read
here is one the producer declares.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

from tests.utils.helpers import github_yaml_files

REPO = Path(__file__).resolve().parents[2]

DOWNLOAD = "actions/download-artifact@"
UPLOAD = "actions/upload-artifact@"
RUN_ATTEMPT = re.compile(r"\$\{\{[^}]*\bgithub\.run_attempt\b[^}]*\}\}")
NEEDS_OUTPUT = re.compile(
    r"^\$\{\{\s*needs\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}$"
)
NUMBER_CHECK = "^[0-9]+$"


def _steps(doc: dict) -> Iterator[tuple[str, dict, list]]:
    """(job id, job, steps) for each job, and ("", {}, steps) for a composite action."""
    for job_id, job in (doc.get("jobs") or {}).items():
        if isinstance(job, dict):
            yield job_id, job, job.get("steps") or []
    runs = doc.get("runs")
    if isinstance(runs, dict):
        yield "", {}, runs.get("steps") or []


def _uses(step: Any, prefix: str) -> bool:
    return isinstance(step, dict) and str(step.get("uses", "")).startswith(prefix)


def _needs(job: dict) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def violations(doc: dict) -> list[str]:
    """What is wrong with each artifact download in one workflow or action."""
    uploaded = {
        str(step["with"]["name"])
        for _, _, steps in _steps(doc)
        for step in steps
        if _uses(step, UPLOAD) and (step.get("with") or {}).get("name")
    }
    found: list[str] = []
    for job_id, job, steps in _steps(doc):
        for index, step in enumerate(steps):
            if not _uses(step, DOWNLOAD):
                continue
            where = f"{job_id or 'action'}: {step.get('name') or step['uses']}"
            inputs = {k: str(v) for k, v in (step.get("with") or {}).items()}
            for key in ("name", "pattern", "artifact-ids"):
                if RUN_ATTEMPT.search(inputs.get(key, "")):
                    found.append(
                        f"{where}: {key} is built from github.run_attempt, which a "
                        "job re-run in a later attempt recomputes; take the "
                        "producer's artifact-id through needs instead"
                    )
            name = inputs.get("name")
            if name and name in uploaded and not RUN_ATTEMPT.search(name):
                found.append(
                    f"{where}: downloads {name!r} by name, and a job in this workflow "
                    "uploads it; a re-run producer cannot upload that name again, so "
                    "hand over the artifact-id instead"
                )
            ids = inputs.get("artifact-ids")
            if ids is None:
                continue
            match = NEEDS_OUTPUT.match(ids.strip())
            if not match:
                found.append(
                    f"{where}: artifact-ids {ids!r} is not one "
                    "${{ needs.<job>.outputs.<name> }}"
                )
                continue
            if match.group(1) not in _needs(job):
                found.append(f"{where}: {match.group(1)!r} is not in this job's needs")
            checked = any(
                ids.strip()
                in [str(v).strip() for v in (prior.get("env") or {}).values()]
                and NUMBER_CHECK in str(prior.get("run", ""))
                for prior in steps[:index]
                if isinstance(prior, dict)
            )
            if not checked:
                found.append(
                    f"{where}: no earlier step holds {ids.strip()} to a number, and "
                    "download-artifact reads an empty artifact-ids as every artifact "
                    "of the run"
                )
    return found


def _documents() -> list[tuple[str, dict]]:
    docs = []
    for path in github_yaml_files(REPO):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict):
            docs.append((path.relative_to(REPO).as_posix(), doc))
    return docs


def _downloads(doc: dict) -> list[dict]:
    return [s for _, _, steps in _steps(doc) for s in steps if _uses(s, DOWNLOAD)]


def test_the_walk_reads_every_download():
    docs = dict(_documents())
    total = sum(len(_downloads(doc)) for doc in docs.values())
    # The release's assemble job alone downloads eight; the package workflow four.
    assert total >= 14, total
    assemble = docs[".github/workflows/ash-release-assets.yml"]["jobs"]["assemble"]
    assert len([s for s in assemble["steps"] if _uses(s, DOWNLOAD)]) == 8


def test_every_download_takes_the_producers_id():
    found = [f"{rel}: {v}" for rel, doc in _documents() for v in violations(doc)]
    assert not found, "\n".join(found)


GOOD = """
jobs:
  build:
    outputs:
      artifact-id: ${{ steps.upload.outputs.artifact-id }}
    steps:
      - id: upload
        uses: actions/upload-artifact@sha
        with:
          name: wheel-${{ github.sha }}-attempt-${{ github.run_attempt }}
  use:
    needs: build
    steps:
      - name: Check the wheel artifact ID
        env:
          ARTIFACT_ID: ${{ needs.build.outputs.artifact-id }}
        run: |
          [[ "$ARTIFACT_ID" =~ ^[0-9]+$ ]] || exit 1
      - uses: actions/download-artifact@sha
        with:
          artifact-ids: ${{ needs.build.outputs.artifact-id }}
          path: dist
"""


def _plant(old: str, new: str) -> dict:
    assert old in GOOD, old
    return yaml.safe_load(GOOD.replace(old, new))


def test_the_good_shape_passes():
    assert violations(yaml.safe_load(GOOD)) == []


def test_a_download_of_another_workflows_artifact_by_name_passes():
    # upload-ash-sarif.yml reads the artifact its caller's scan job uploaded.
    doc = yaml.safe_load(
        "jobs:\n  upload:\n    steps:\n"
        "      - uses: actions/download-artifact@sha\n"
        "        with:\n          name: ash_output\n"
    )
    assert violations(doc) == []


@pytest.mark.parametrize(
    "old, new, needle",
    [
        (
            "artifact-ids: ${{ needs.build.outputs.artifact-id }}\n          path",
            "name: wheel-${{ github.sha }}-attempt-${{ github.run_attempt }}\n          path",
            "built from github.run_attempt",
        ),
        (
            "artifact-ids: ${{ needs.build.outputs.artifact-id }}\n          path",
            "pattern: wheel-*-attempt-${{ github.run_attempt }}\n          path",
            "built from github.run_attempt",
        ),
        (
            "name: wheel-${{ github.sha }}-attempt-${{ github.run_attempt }}",
            "name: wheel",
            "",
        ),
        (
            "artifact-ids: ${{ needs.build.outputs.artifact-id }}\n          path",
            "artifact-ids: ${{ steps.find.outputs.id }}\n          path",
            "is not one",
        ),
        ("    needs: build\n", "    needs: []\n", "is not in this job's needs"),
        ("^[0-9]+$", "^[0-9]*$", "to a number"),
        (
            "ARTIFACT_ID: ${{ needs.build.outputs.artifact-id }}",
            "ARTIFACT_ID: ${{ needs.build.outputs.other }}",
            "to a number",
        ),
    ],
    ids=[
        "name-from-run-attempt",
        "pattern-from-run-attempt",
        "renamed-upload-is-not-a-violation-alone",
        "id-not-from-needs",
        "producer-not-needed",
        "check-allows-empty",
        "check-holds-another-output",
    ],
)
def test_each_planted_defect_is_reported(old, new, needle):
    found = violations(_plant(old, new))
    if needle:
        assert any(needle in f for f in found), found
    else:
        assert found == [], found


def test_a_download_by_the_name_a_sibling_job_uploads_is_reported():
    doc = _plant(
        "name: wheel-${{ github.sha }}-attempt-${{ github.run_attempt }}", "name: wheel"
    )
    step = doc["jobs"]["use"]["steps"][1]
    step["with"] = {"name": "wheel", "path": "dist"}
    found = violations(doc)
    assert any("a re-run producer cannot upload that name again" in f for f in found)


def test_a_composite_action_download_from_run_attempt_is_reported():
    doc = yaml.safe_load(
        "runs:\n  using: composite\n  steps:\n"
        "    - uses: actions/download-artifact@sha\n"
        "      with:\n"
        "        name: x-${{ github.run_attempt }}\n"
    )
    assert any("built from github.run_attempt" in f for f in violations(doc))


needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="bash on Windows runners is the WSL stub; the steps run under Git Bash or Linux",
)


def _id_checks() -> list[tuple[str, dict]]:
    """Every step that holds a download's artifact-ids to a number, by where it is."""
    checks = []
    for rel, doc in _documents():
        for job_id, _, steps in _steps(doc):
            for index, step in enumerate(steps):
                if not _uses(step, DOWNLOAD):
                    continue
                ids = str((step.get("with") or {}).get("artifact-ids", "")).strip()
                if not ids:
                    continue
                for prior in steps[:index]:
                    env = {
                        k: str(v).strip() for k, v in (prior.get("env") or {}).items()
                    }
                    if ids in env.values() and NUMBER_CHECK in str(
                        prior.get("run", "")
                    ):
                        key = f"{rel}::{job_id}::{prior['name']}"
                        if key not in {k for k, _ in checks}:
                            checks.append((key, prior))
    return checks


def _run(script: str, env: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    script_file = tmp_path / "step.sh"
    script_file.write_text(script, encoding="utf-8")
    bash = shutil.which("bash")
    assert bash
    # The shell Actions runs a `shell: bash` step with on a hosted runner.
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", str(script_file)],
        env={"PATH": os.environ["PATH"], **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_every_id_check_is_found():
    keys = [key for key, _ in _id_checks()]
    # assemble's one check covers its eight downloads; ash-package.yml has four
    # downloading jobs, the VS Code e2e job one, and the release job one.
    assert len(keys) >= 7, keys


@needs_bash
@pytest.mark.parametrize(
    "key, step", [pytest.param(k, s, id=k) for k, s in _id_checks()]
)
def test_each_id_check_passes_numbers_and_refuses_anything_else(key, step, tmp_path):
    env = dict.fromkeys(step["env"], "4242424242")
    proc = _run(step["run"], env, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for name in step["env"]:
        for bad in ("", "ash-package-abc-attempt-1"):
            proc = _run(step["run"], {**env, name: bad}, tmp_path)
            assert proc.returncode != 0, (key, name, bad)
            assert "not an artifact ID" in proc.stdout, proc.stdout
