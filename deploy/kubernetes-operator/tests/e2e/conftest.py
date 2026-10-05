"""kind cluster lifecycle for the end-to-end test.

Skipped unless ``ASH_OPERATOR_E2E=1``, because it builds two images and creates a
cluster. The skip is loud rather than silent: a suite reporting "all passed" while
never having stood a cluster up is the same shape as a gate that proves nothing, so
:func:`pytest_report_header` prints which mode the run is in.

The cluster is deleted in a fixture finaliser, unconditionally and idempotently. A
kind cluster left running is a container that outlives the session that made it.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from tests.e2e.helpers import (
    ASH_IMAGE,
    ASH_IMAGE_NOSTAMP,
    CLUSTER_NAME,
    IMAGE_TAG,
    NAMESPACE,
    OPERATOR_DIR,
    OPERATOR_IMAGE,
    kubectl,
    kubectl_apply_stdin,
    run,
    stage_ash_source,
)

E2E_ENABLED = os.environ.get("ASH_OPERATOR_E2E") == "1"
E2E_DIR = Path(__file__).resolve().parent


def pytest_report_header(config):
    if E2E_ENABLED:
        return f"ash-operator e2e: ENABLED against kind cluster {CLUSTER_NAME!r}"
    return (
        "ash-operator e2e: DISABLED (set ASH_OPERATOR_E2E=1). Nothing under tests/e2e "
        "ran, so a green result here says nothing about the cluster path."
    )


@pytest.fixture(scope="session", autouse=True)
def require_tooling():
    if not E2E_ENABLED:
        pytest.skip("ASH_OPERATOR_E2E is not 1")
    missing = [tool for tool in ("kind", "kubectl", "docker") if shutil.which(tool) is None]
    if missing:
        pytest.fail(
            f"the e2e was enabled but {missing} are not on PATH. Failing rather than "
            f"skipping: an enabled e2e that quietly does nothing is worse than one "
            f"that refuses to start."
        )
    run(["docker", "info"], timeout=120)


@pytest.fixture(scope="session")
def ash_image(require_tooling) -> str:
    """Build the minimal ASH image from the checkout under test.

    From *this* worktree rather than a published artefact, so the image's ASH is the
    same code the unit suite measured.
    """
    with tempfile.TemporaryDirectory(prefix="ash-e2e-ctx-") as ctx:
        context_dir = Path(ctx)
        shutil.copy(E2E_DIR / "Dockerfile.ash", context_dir / "Dockerfile")
        stage_ash_source(context_dir / "ash-source")
        run(
            [
                "docker",
                "build",
                "-t",
                ASH_IMAGE,
                "-f",
                str(context_dir / "Dockerfile"),
                str(context_dir),
            ],
            timeout=2400,
        )
    return ASH_IMAGE


@pytest.fixture(scope="session")
def ash_image_nostamp(ash_image) -> str:
    """Build the provenance negative-control image, FROM the normal one."""
    # Dockerfile.ash-nostamp names the ash-e2e repository itself and takes only the
    # tag, so a renamed ASH_IMAGE must fail here rather than build FROM a stale image.
    assert ash_image == f"ash-e2e:{IMAGE_TAG}", ash_image
    run(
        [
            "docker",
            "build",
            "-t",
            ASH_IMAGE_NOSTAMP,
            "--build-arg",
            f"BASE_TAG={IMAGE_TAG}",
            "-f",
            str(E2E_DIR / "Dockerfile.ash-nostamp"),
            str(E2E_DIR),
        ],
        timeout=600,
    )
    return ASH_IMAGE_NOSTAMP


@pytest.fixture(scope="session")
def operator_image(require_tooling) -> str:
    run(
        [
            "docker",
            "build",
            "-t",
            OPERATOR_IMAGE,
            "-f",
            str(OPERATOR_DIR / "Dockerfile"),
            str(OPERATOR_DIR),
        ],
        timeout=1200,
    )
    return OPERATOR_IMAGE


@pytest.fixture(scope="session")
def cluster(require_tooling, ash_image, ash_image_nostamp, operator_image):
    existing = run(["kind", "get", "clusters"], check=False).stdout.split()
    if CLUSTER_NAME in existing:
        # A leftover from an interrupted run. Deleted rather than reused: a cluster in
        # an unknown state produces failures that look like the operator's.
        run(["kind", "delete", "cluster", "--name", CLUSTER_NAME], timeout=300)
    run(["kind", "create", "cluster", "--name", CLUSTER_NAME, "--wait", "180s"], timeout=1200)
    try:
        for image in (ash_image, ash_image_nostamp, operator_image):
            run(["kind", "load", "docker-image", image, "--name", CLUSTER_NAME], timeout=1200)
        yield CLUSTER_NAME
    finally:
        run(["kind", "delete", "cluster", "--name", CLUSTER_NAME], check=False, timeout=300)


@pytest.fixture(scope="session")
def installed(cluster):
    """CRDs, RBAC and the operator, in that order."""
    generated = OPERATOR_DIR / "generated"
    crds = sorted(generated.glob("crd-*.yaml"))
    assert crds, (
        f"no generated CRDs under {generated}. Run "
        f"`python -m ash_operator.generate_manifests` first -- installing nothing and "
        f"then passing would prove nothing."
    )
    for crd in crds:
        kubectl("apply", "-f", str(crd))
    for crd in crds:
        plural = crd.stem.removeprefix("crd-")
        kubectl(
            "wait",
            "--for=condition=Established",
            f"crd/{plural}.ash.awslabs.github.io",
            "--timeout=90s",
        )
    # The namespace lives in operator.yaml, and rbac.yaml's objects are in it, so the
    # namespace has to exist first -- but the Deployment must not, or its ReplicaSet
    # fails to create a pod with "serviceaccount ash-operator not found" and spends a
    # restart backoff before the SA arrives.
    shipped = (OPERATOR_DIR / "manifests" / "operator.yaml").read_text()
    # The shipped manifest names `ash-operator:local`. A run with its own image tag
    # substitutes it here, and asserts that it did: an apply that silently kept the
    # shipped name would run whatever image last carried that tag on the node.
    shipped_image = "image: ash-operator:local"
    assert shipped.count(shipped_image) == 1, "operator.yaml no longer names one image"
    kubectl_apply_stdin(shipped.replace(shipped_image, f"image: {OPERATOR_IMAGE}"))
    kubectl("apply", "-f", str(OPERATOR_DIR / "manifests" / "rbac.yaml"))
    kubectl("-n", NAMESPACE, "rollout", "restart", "deployment/ash-operator", check=False)
    kubectl(
        "-n",
        NAMESPACE,
        "wait",
        "--for=condition=Available",
        "deployment/ash-operator",
        "--timeout=300s",
    )
    yield
