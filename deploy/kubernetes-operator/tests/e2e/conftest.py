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
    OPERATOR_DIR,
    OPERATOR_IMAGE,
    run,
    stage_ash_locks,
    stage_ash_source,
)
from tests.e2e.lifecycle import install_operator

E2E_ENABLED = os.environ.get("ASH_OPERATOR_E2E") == "1"
E2E_DIR = Path(__file__).resolve().parent

# The node image the kind cluster boots, pinned by digest rather than left to kind's
# built-in default: that default is a tag nothing in this tree records, and
# .github/scripts/assert-images-pinned.py requires every kind cluster to name a digest.
# This is kind v0.33.0's own default (its release notes list it), so pinning it changes
# nothing about the cluster. Bump it together with KIND_VERSION in
# .github/workflows/ash-kubernetes-operator.yml: kind does not promise that a node image
# built for one release works with another, and since v0.32.0 `kind load` needs a kind at
# least as new as the image. Kubernetes 1.37 here is also the minor KUBECTL_VERSION in that
# workflow targets, and kubectl is supported within one minor of the API server.
KIND_NODE_IMAGE = (
    "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)


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
    missing = [tool for tool in ("kind", "kubectl", "docker", "uv") if shutil.which(tool) is None]
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
        stage_ash_locks(context_dir / "locks")
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
    create = ["kind", "create", "cluster", "--name", CLUSTER_NAME, "--image", KIND_NODE_IMAGE]
    run([*create, "--wait", "180s"], timeout=1200)
    try:
        for image in (ash_image, ash_image_nostamp, operator_image):
            run(["kind", "load", "docker-image", image, "--name", CLUSTER_NAME], timeout=1200)
        yield CLUSTER_NAME
    finally:
        run(["kind", "delete", "cluster", "--name", CLUSTER_NAME], check=False, timeout=300)


@pytest.fixture(scope="session")
def installed(cluster):
    """CRDs, RBAC and the operator, as README.md installs them."""
    generated = OPERATOR_DIR / "generated"
    assert sorted(generated.glob("crd-*.yaml")), (
        f"no generated CRDs under {generated}. Run "
        f"`python -m ash_operator.generate_manifests` first -- installing nothing and "
        f"then passing would prove nothing."
    )
    install_operator(OPERATOR_DIR, OPERATOR_IMAGE)
    yield


# The lifecycle module uninstalls the operator and reinstalls it from N-1, so it has
# to run after every module that relies on the session's fresh install. The EKS
# applier module installs the operator the way the EKS stack does, CRDs and cluster
# RBAC included, so it needs the cluster the lifecycle module's last uninstall leaves:
# none of the operator's objects at all. Ordered here rather than by file name, which
# a rename would silently change; every other module keeps its collected order.
LIFECYCLE_MODULE = "test_e2e_lifecycle.py"
EKS_APPLIER_MODULE = "test_e2e_eks_applier.py"
RUN_LAST = (LIFECYCLE_MODULE, EKS_APPLIER_MODULE)


def pytest_collection_modifyitems(session, config, items):
    items.sort(
        key=lambda item: RUN_LAST.index(item.path.name) + 1 if item.path.name in RUN_LAST else 0
    )
