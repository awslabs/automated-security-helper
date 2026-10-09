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
nothing is skipped.

The output must not depend on the platform it is generated on. This suite runs on
Windows, and two of ASH's defaults (opengrep's and semgrep's ``enabled``) are
computed from ``platform.system()`` when ASH is imported. The CRD's schema digest
used to hash them, so a Windows ``--check`` failed against the committed files and
a Windows regeneration would have broken every other platform.
test_the_render_is_the_same_on_every_platform holds that.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - runs this repository's own generator
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
OPERATOR = REPO / "deploy" / "kubernetes-operator"
GENERATED = OPERATOR / "generated"

REMEDY = (
    "From deploy/kubernetes-operator, with that directory and the repository root on "
    "PYTHONPATH, run `python -m ash_operator.generate_manifests` and commit the "
    "result. The output is the same on every platform."
)

# Run in a fresh interpreter so the patched platform.system() is in place before ASH
# is imported, which is when the platform-dependent defaults are computed.
RENDER_AS = """
import json, platform, sys
platform.system = lambda: sys.argv[1]
from ash_operator.generate_manifests import render_all
json.dump(render_all(), sys.stdout, sort_keys=True)
"""

# Which schema source the generator would use, and which ASH it would import. The
# generator falls back to the committed AshConfig.json, silently, when ASH does not
# import, and from the operator directory a different installed ASH could shadow
# this checkout's.
PREFLIGHT = """
import json
import automated_security_helper
from ash_operator.crd_schema import ash_config_json_schema
_schema, source = ash_config_json_schema()
print(json.dumps({"source": source, "ash": automated_security_helper.__file__}))
"""


def _env() -> dict[str, str]:
    env = dict(os.environ)
    parts = [str(OPERATOR), str(REPO)]
    if env.get("PYTHONPATH"):
        parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _python(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - this interpreter, code from this checkout
        [sys.executable, *args],
        cwd=OPERATOR,
        env=_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
    )


def _check(out: Path | None = None) -> subprocess.CompletedProcess:
    args = ["-m", "ash_operator.generate_manifests", "--check"]
    if out is not None:
        args += ["--out", str(out)]
    return _python(*args)


def _problem_lines(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if line.startswith("  ")]


def test_the_child_reads_this_checkouts_model() -> None:
    result = _python("-c", PREFLIGHT)
    assert result.returncode == 0, result.stdout + result.stderr
    found = json.loads(result.stdout)
    assert found["source"] == "model", found
    assert Path(found["ash"]).resolve().is_relative_to(REPO.resolve()), found


def test_the_committed_crds_match_the_generator() -> None:
    result = _check()
    assert result.returncode == 0, (
        f"deploy/kubernetes-operator/generated/ is stale against AshConfig. {REMEDY}\n"
        + result.stdout
        + result.stderr
    )
    assert "match byte for byte" in result.stdout, result.stdout


@pytest.mark.parametrize("system", ["Windows", "Darwin"])
def test_the_render_is_the_same_on_every_platform(system: str) -> None:
    linux = _python("-c", RENDER_AS, "Linux")
    other = _python("-c", RENDER_AS, system)
    assert linux.returncode == 0, linux.stderr
    assert other.returncode == 0, other.stderr
    rendered_linux = json.loads(linux.stdout)
    rendered_other = json.loads(other.stdout)
    assert rendered_linux, "the generator rendered nothing"
    differing = sorted(
        name
        for name in rendered_linux.keys() | rendered_other.keys()
        if rendered_linux.get(name) != rendered_other.get(name)
    )
    assert differing == [], (
        f"the generator writes different bytes with platform.system() == {system!r}: "
        f"{differing}"
    )


def test_a_drifted_copy_fails_the_check(tmp_path: Path) -> None:
    """Control: an untouched copy passes, and one planted drift is the one problem."""
    copy = tmp_path / "generated"
    shutil.copytree(GENERATED, copy)
    clean = _check(copy)
    assert clean.returncode == 0, clean.stdout + clean.stderr

    target = copy / "crd-ashscans.yaml"
    target.write_bytes(target.read_bytes() + b"# drift\n")
    drifted = _check(copy)
    assert drifted.returncode == 1, drifted.stdout + drifted.stderr
    problems = _problem_lines(drifted.stderr)
    assert len(problems) == 1, problems
    assert problems[0].startswith("  crd-ashscans.yaml: differs"), problems
