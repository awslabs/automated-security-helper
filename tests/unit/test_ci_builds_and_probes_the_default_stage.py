# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CI builds the image's default stage and checks who can write to it.

``ash build-image`` and ``ash --mode container`` build the ``non-root`` stage when no
``--build-target`` is given, and that is the image an operator runs. The scan legs in
``ash-unified-ci.yml`` build ``ci`` (with an explicit ``--build-target ci``). The
steps only ``non-root`` has -- its user's home, the grype cache handed to that user,
ASH_BIN_PATH handed back to root, its closing sweep of anything left writable by
every user -- are checked as Dockerfile text by
tests/unit/test_dockerfile_directory_permissions.py, and in a built image by one
job: it builds that stage with no target, as an operator does, and runs the image
permissions probe (tests/snapshot/container/runtime/test_container_image_permissions.py)
against the ``automated-security-helper:non-root`` tag it produces. It runs on pull
requests too, and the required-checks census (test_required_checks_census.py) holds
it to the gate.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
PROBE = "tests/snapshot/container/runtime/test_container_image_permissions.py"
DEFAULT_TAG = "automated-security-helper:non-root"


def _jobs() -> Dict[str, Dict[str, Any]]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _words(step: Dict[str, Any]) -> List[str]:
    """The run script's words; a script shlex cannot split matches nothing."""
    try:
        return shlex.split(step.get("run") or "", comments=True)
    except ValueError:
        return []


def _build_target(words: List[str]) -> str | None:
    for index, word in enumerate(words):
        if word == "--build-target":
            return words[index + 1]
        if word.startswith("--build-target="):
            return word.partition("=")[2]
    return None


def _builds_the_default_stage(step: Dict[str, Any]) -> bool:
    words = _words(step)
    return "build-image" in words and _build_target(words) in (None, "non-root")


def _probes_the_default_tag(step: Dict[str, Any]) -> bool:
    env = step.get("env") or {}
    return PROBE in _words(step) and env.get("ASH_IMAGE_NAME") == DEFAULT_TAG


def _default_stage_jobs() -> List[Tuple[str, Dict[str, Any], int, int]]:
    found = []
    for name, job in _jobs().items():
        steps = job.get("steps") or []
        builds = [i for i, step in enumerate(steps) if _builds_the_default_stage(step)]
        probes = [i for i, step in enumerate(steps) if _probes_the_default_tag(step)]
        if builds and probes:
            found.append((name, job, builds[0], probes[-1]))
    return found


def test_a_job_builds_the_default_stage_and_probes_it():
    found = _default_stage_jobs()

    assert len(found) == 1, [name for name, *_ in found]
    _name, job, build, probe = found[0]
    assert build < probe
    probe_step = job["steps"][probe]
    assert "--run-container-snapshots" in _words(probe_step)
    assert (probe_step.get("env") or {}).get("OCI_RUNNER") == "docker"


def test_it_runs_on_pull_requests_and_answers_to_the_gate():
    [(name, job, _build, _probe)] = _default_stage_jobs()

    assert "if" not in job, "a job-level condition would skip it on some events"
    assert name in _jobs()["required-checks"]["needs"]


RUN_SCAN_TEST = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"


def test_the_scan_legs_probe_the_ci_stage_too():
    """run-scan-test builds ``ci`` for the scan legs; its runtime-snapshot step runs
    the same permissions probe against it, with the flag that enables it."""
    steps = yaml.safe_load(RUN_SCAN_TEST.read_text(encoding="utf-8"))["runs"]["steps"]
    probing = [step for step in steps if PROBE in _words(step)]

    assert len(probing) == 1, [step.get("name") for step in probing]
    assert "--run-container-snapshots" in _words(probing[0])


def test_a_ci_build_is_not_mistaken_for_the_default_stage():
    """Control for the matcher: the scan legs' explicit ci builds do not count."""
    assert not _builds_the_default_stage(
        {"run": "ash build-image --build-target ci --no-run"}
    )
    assert not _builds_the_default_stage({"run": "ash build-image --build-target=ci"})
    assert _builds_the_default_stage({"run": "ash build-image --no-run"})
