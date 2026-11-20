"""The repository-wide e2e contract, applied to the operator.

Every v4 channel scans the same three cases from ``tests/e2e/fixtures/cases.json`` at
the repository root and hands the result to ``scripts/e2e/assert_outcome.py``. This
module is how the operator does the same, without a copy of either:

- :func:`case_spec` turns a case into an ``AshScan`` spec. The case's scanners become
  ``spec.scanners`` and its ``args`` become ``spec.extraScanArguments``.
- A case's ``env`` has no direct equivalent, because an ``AshScan`` has no field for
  the scan pods' environment. :data:`ENV_EQUIVALENTS` maps each variable the cases set
  to what produces the same ASH behavior through the CR, and :func:`case_spec` refuses
  a variable or value it does not know. A case that grows a new variable fails here
  until someone works out its equivalent, rather than being scanned without it.
- :func:`read_merged_output` copies the merged report off the results volume, from a
  pod that mounts the run's claim, and :func:`judge` runs the shared
  ``assert_outcome.py`` on it with the exit code ``ashx merge`` returned.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

from ash_operator.constants import RESULTS_MOUNT
from tests.e2e.helpers import (
    ASH_IMAGE,
    NAMESPACE,
    REPO_ROOT,
    kubectl,
    kubectl_apply_stdin,
)

SHARED_FIXTURES = REPO_ROOT / "tests" / "e2e" / "fixtures"
CASES_FILE = SHARED_FIXTURES / "cases.json"
ASSERT_OUTCOME = REPO_ROOT / "scripts" / "e2e" / "assert_outcome.py"

# The merged report's place under a run's results prefix. scan_controller.py passes
# `--merge-output <prefix>/merged` to the collector.
MERGED_SUBDIR = "merged"

# Each environment variable the cases set, and the CR-side equivalent of each value.
#
# ASH_OFFLINE=YES: `ashx scan --offline` sets ASH_OFFLINE=YES in-process before any
# scanner is built (interactions/run_ash_scan.py, _run_local_mode), so the flag and the
# variable are the same switch.
#
# OPENGREP_RULES_CACHE_DIR="": ASH reads the variable with os.environ.get(..., ""), so
# an empty value and an unset one are the same input. The e2e ASH image does not set
# it, which test_the_ash_image_sets_no_rule_cache_dir checks, so the scan pods run with
# it unset.
ENV_EQUIVALENTS: dict[str, dict[str, list[str]]] = {
    "ASH_OFFLINE": {"YES": ["--offline"]},
    "OPENGREP_RULES_CACHE_DIR": {"": []},
}


def load_cases(path: Path = CASES_FILE) -> dict[str, dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document["cases"]
    assert set(cases) >= {"findings", "clean", "incomplete"}, sorted(cases)
    return cases


def env_as_arguments(env: dict[str, str]) -> list[str]:
    """The scan arguments that stand in for *env*, or an AssertionError naming the gap."""
    arguments: list[str] = []
    for name, value in sorted(env.items()):
        known = ENV_EQUIVALENTS.get(name)
        if known is None or value not in known:
            raise AssertionError(
                f"the case sets {name}={value!r}, and an AshScan cannot set a scan pod's "
                f"environment. Add its equivalent to ENV_EQUIVALENTS in {__file__} "
                f"(an ASH flag or config override that has the same effect), or the "
                f"operator would scan this case without it."
            )
        arguments += known[value]
    return arguments


def case_spec(case: dict[str, Any]) -> dict[str, Any]:
    """The parts of an AshScan spec that come from the case.

    One shard: the incomplete case selects two scanners, and with one per shard the
    shard holding only opengrep would complete nothing, which ``ashx merge`` refuses
    outright instead of reporting exit 1. The fan-out has its own tests.
    """
    args = list(case.get("args") or [])
    assert all(isinstance(a, str) for a in args), args
    return {
        "shardCount": 1,
        "scanners": list(case["scanners"]),
        "extraScanArguments": args + env_as_arguments(dict(case.get("env") or {})),
    }


READER_POD = textwrap.dedent(
    """
    apiVersion: v1
    kind: Pod
    metadata:
      name: {name}
      namespace: {namespace}
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      serviceAccountName: ash-scan
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: ash-results
          persistentVolumeClaim:
            claimName: {claim}
            readOnly: true
      containers:
        - name: reader
          image: {image}
          imagePullPolicy: Never
          command: ["sleep", "1800"]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: ash-results
              mountPath: {mount}
              readOnly: true
    """
)


def read_merged_output(scan_name: str, status: dict[str, Any], dest: Path) -> Path:
    """Copy the run's merged report directory to *dest* and return it.

    Read from a pod mounting the run's own claim at the path the collector wrote to,
    so the files judged are the ones ``ashx merge`` produced, not a summary of them.
    """
    prefix = status["resultsPrefix"]
    assert prefix.startswith(RESULTS_MOUNT + "/"), prefix
    pod = f"read-{scan_name}"[:63]
    kubectl("-n", NAMESPACE, "delete", "pod", pod, "--ignore-not-found", "--wait=true")
    kubectl_apply_stdin(
        READER_POD.format(
            name=pod,
            namespace=NAMESPACE,
            claim=status["resultsClaimName"],
            image=ASH_IMAGE,
            mount=RESULTS_MOUNT,
        )
    )
    try:
        kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=180s")
        listing = kubectl(
            "-n", NAMESPACE, "exec", pod, "--", "find", f"{prefix}/{MERGED_SUBDIR}", "-type", "f"
        ).stdout
        print(f"=== {scan_name} merged output ===\n{listing}")
        if dest.exists():
            raise AssertionError(f"{dest} already exists; refusing to judge a stale copy")
        dest.parent.mkdir(parents=True, exist_ok=True)
        kubectl("-n", NAMESPACE, "cp", f"{pod}:{prefix}/{MERGED_SUBDIR}", str(dest), timeout=300)
    finally:
        # Waited for, because a pod object naming the claim keeps it from being deleted
        # (pvc-protection), and the lifecycle test uninstalls right after reading.
        kubectl(
            "-n",
            NAMESPACE,
            "delete",
            "pod",
            pod,
            "--ignore-not-found",
            "--grace-period=1",
            "--wait=true",
        )
    assert dest.is_dir(), f"kubectl cp produced no directory at {dest}"
    return dest


def judge(
    case: str | None, output_dir: Path, rc: int, *expectation: str
) -> subprocess.CompletedProcess[str]:
    """Run the shared verdict on *output_dir*, as every other channel does.

    With a *case*, the expectations are the case's. With ``case=None`` they are the
    explicit ``assert_outcome.py`` flags in *expectation*, for an output this tree's
    case does not describe, such as one an older operator produced.
    """
    selector = ["--case", case, "--cases", str(CASES_FILE)] if case else list(expectation)
    assert selector, "give a case or explicit expectations"
    result = subprocess.run(
        [
            sys.executable,
            str(ASSERT_OUTCOME),
            *selector,
            "--output-dir",
            str(output_dir),
            "--rc",
            str(rc),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    print(f"$ assert_outcome {' '.join(selector)} --rc {rc} --output-dir {output_dir}")
    print(result.stdout + result.stderr)
    return result
