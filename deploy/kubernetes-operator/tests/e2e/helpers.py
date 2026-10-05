"""Shared helpers for the end-to-end test.

A module rather than importing from ``conftest.py``: a conftest is a plugin, and
importing one by path gives two module objects with two copies of the constants the
moment anything changes the collection root.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from ash_operator import constants

# Both overridable so concurrent runs on one host -- or a CI runner and a developer
# -- never share a cluster or an image tag. The images are only ever loaded into
# kind (`kind load docker-image`); nothing in this harness pushes them anywhere.
CLUSTER_NAME = os.environ.get("ASH_OPERATOR_E2E_CLUSTER", "ash-operator-e2e")
IMAGE_TAG = os.environ.get("ASH_OPERATOR_E2E_IMAGE_TAG", "local")
NAMESPACE = "ash-system"
ASH_IMAGE = f"ash-e2e:{IMAGE_TAG}"
# An ASH whose ScanPhase does not stamp candidate_scanners, for the provenance
# negative control. See tests/e2e/Dockerfile.ash-nostamp.
ASH_IMAGE_NOSTAMP = f"ash-e2e-nostamp:{IMAGE_TAG}"
OPERATOR_IMAGE = f"ash-operator:{IMAGE_TAG}"
GROUP = constants.GROUP
TERMINAL = frozenset(constants.TERMINAL_PHASES)

E2E_DIR = Path(__file__).resolve().parent
OPERATOR_DIR = E2E_DIR.parents[1]
REPO_ROOT = OPERATOR_DIR.parents[1]


# Root-level files the ASH wheel build reads. "Dockerfile" is the one that is easy to
# miss: pyproject.toml force-includes automated_security_helper/assets/Dockerfile,
# which is gitignored and which hatch_build.py generates from the root Dockerfile
# during the build. Without the root file in the context, `pip install .` fails with
# "Forced include not found ... assets/Dockerfile".
ASH_SOURCE_FILES = (
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "hatch_build.py",
    "Dockerfile",
)
# What hatch_build.py writes into automated_security_helper/assets/, all gitignored.
# Never copied: a copy left in a developer's checkout by an earlier build would stand
# in for the one this build has to generate, which is how a context missing the root
# Dockerfile built locally and failed on every clean CI checkout.
ASH_GENERATED_ASSETS = frozenset(
    {"Dockerfile", "ASH_INSTALLED_REVISION", "tool_downloads.py", "exceptions.py"}
)


def stage_ash_source(dest: Path, repo_root: Path = REPO_ROOT) -> None:
    """Copy what an ASH wheel build needs from ``repo_root`` into ``dest``.

    Only that, rather than the whole checkout, which would drag in .git, other work
    in progress and any venv sitting in it. Every listed file is required: a context
    that silently lacks one builds an image from something other than the checkout.
    """
    dest.mkdir(parents=True, exist_ok=True)
    missing = [name for name in ASH_SOURCE_FILES if not (repo_root / name).is_file()]
    if missing:
        raise FileNotFoundError(f"the ASH build context needs {missing} from {repo_root}")
    for name in ASH_SOURCE_FILES:
        shutil.copy(repo_root / name, dest / name)

    package = repo_root / "automated_security_helper"
    assets = package / "assets"
    generic = shutil.ignore_patterns("__pycache__", "*.pyc")

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set(generic(directory, names))
        if Path(directory) == assets:
            ignored |= ASH_GENERATED_ASSETS & set(names)
        return ignored

    shutil.copytree(package, dest / "automated_security_helper", ignore=ignore)


def context() -> str:
    return f"kind-{CLUSTER_NAME}"


def run(
    argv: list[str],
    *,
    check: bool = True,
    timeout: int = 600,
    stdin: str | None = None,
) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(argv)}", flush=True)
    result = subprocess.run(
        argv, check=False, capture_output=True, text=True, timeout=timeout, input=stdin
    )
    if result.returncode != 0:
        print(result.stdout[-4000:], flush=True)
        print(result.stderr[-4000:], flush=True)
    if check and result.returncode != 0:
        raise AssertionError(
            f"{argv[0]} exited {result.returncode}\n"
            f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
        )
    return result


def kubectl(
    *args: str, check: bool = True, timeout: int = 300, stdin: str | None = None
) -> subprocess.CompletedProcess:
    return run(
        ["kubectl", "--context", context(), *args],
        check=check,
        timeout=timeout,
        stdin=stdin,
    )


def kubectl_json(*args: str) -> dict:
    return json.loads(kubectl(*args, "-o", "json").stdout)


def kubectl_apply_stdin(body: str) -> None:
    kubectl("apply", "-f", "-", stdin=body)


def wait_for(predicate, *, timeout: int, interval: float = 3.0, what: str = "condition"):
    """Poll *predicate* until truthy, then return its value.

    Returns the value rather than True so a caller can assert on the object it waited
    for without fetching it again, and so the failure message carries the last state
    observed instead of only "timed out".
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}; last saw {last!r}")


def operator_logs(tail: int = 200) -> str:
    result = kubectl(
        "-n", NAMESPACE, "logs", "deployment/ash-operator", f"--tail={tail}", check=False
    )
    return result.stdout + result.stderr
