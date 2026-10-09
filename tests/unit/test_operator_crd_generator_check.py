# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Kubernetes operator's committed CRDs match what its generator emits from AshConfig.

Why this exists
---------------
deploy/kubernetes-operator/generated/ holds the operator's CRDs and the schema
translation report, generated from ``AshConfig.model_json_schema()``. Only the
operator workflow's crd-drift job compared them with the generator, and that job
runs in its own environment, outside the root unit suite. A merge from main that
changed AshConfig (#757 added the ``sandbox`` section) therefore passed every local
check and failed crd-drift in CI: config-schema-translation.json, crd-ashmcpservers.yaml
and crd-ashscans.yaml all differed.

This runs the same ``python -m ash_operator.generate_manifests --check`` from the
operator directory, in the root environment, where ASH is importable, so the
generator reads the live model (the crd-drift job installs ASH for the same
reason). The generator needs only PyYAML and ASH, both root dependencies, so
nothing is skipped. The fix when it fails is the command the failure prints, run
from deploy/kubernetes-operator.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - runs this repository's own generator
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OPERATOR = REPO / "deploy" / "kubernetes-operator"
GENERATED = OPERATOR / "generated"


def _check(out: Path | None = None) -> subprocess.CompletedProcess:
    argv = [sys.executable, "-m", "ash_operator.generate_manifests", "--check"]
    if out is not None:
        argv += ["--out", str(out)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(OPERATOR)
    return subprocess.run(  # nosec B603 - this interpreter, a module from this checkout
        argv,
        cwd=OPERATOR,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
    )


def test_the_committed_crds_match_the_generator() -> None:
    result = _check()
    assert result.returncode == 0, (
        "deploy/kubernetes-operator/generated/ is stale against AshConfig. From "
        "deploy/kubernetes-operator run `PYTHONPATH=. python -m "
        "ash_operator.generate_manifests` and commit the result.\n"
        + result.stdout
        + result.stderr
    )
    assert "match byte for byte" in result.stdout, result.stdout


def test_a_drifted_copy_fails_the_check(tmp_path: Path) -> None:
    """Control: the same invocation reports a committed file that differs."""
    copy = tmp_path / "generated"
    shutil.copytree(GENERATED, copy)
    target = copy / "crd-ashscans.yaml"
    target.write_bytes(target.read_bytes() + b"# drift\n")
    result = _check(copy)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "crd-ashscans.yaml: differs" in result.stderr, result.stderr
