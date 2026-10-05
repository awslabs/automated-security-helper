"""Shared helpers for the end-to-end test.

A module rather than importing from ``conftest.py``: a conftest is a plugin, and
importing one by path gives two module objects with two copies of the constants the
moment anything changes the collection root.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

CLUSTER_NAME = os.environ.get("ASH_OPERATOR_E2E_CLUSTER", "ash-operator-e2e")
NAMESPACE = "ash-system"
ASH_IMAGE = "ash-e2e:local"
# An ASH whose ScanPhase does not stamp candidate_scanners, for the provenance
# negative control. See tests/e2e/Dockerfile.ash-nostamp.
ASH_IMAGE_NOSTAMP = "ash-e2e-nostamp:local"
OPERATOR_IMAGE = "ash-operator:local"
GROUP = "ash.awslabs.github.io"
TERMINAL = frozenset({"Succeeded", "Failed", "Refused"})

E2E_DIR = Path(__file__).resolve().parent
OPERATOR_DIR = E2E_DIR.parents[1]
REPO_ROOT = OPERATOR_DIR.parents[1]


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
