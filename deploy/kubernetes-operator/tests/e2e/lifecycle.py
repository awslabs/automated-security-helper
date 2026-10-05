"""Install, uninstall and N-1 helpers for the lifecycle e2e.

Install follows README.md's two commands, uninstall the reverse two, so the e2e tests
what an adopter runs. N-1 is the operator as it was before the most recent change to
the code it ships, built from ``git archive`` so nothing is written into the checkout.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tests.e2e.helpers import (
    CLUSTER_NAME,
    GROUP,
    IMAGE_TAG,
    NAMESPACE,
    OPERATOR_DIR,
    REPO_ROOT,
    kubectl,
    kubectl_apply_stdin,
    kubectl_json,
    run,
    wait_for,
)

OPERATOR_REL = OPERATOR_DIR.relative_to(REPO_ROOT).as_posix()
# What the operator image and its install consist of. A commit that touches none of
# these changes nothing an adopter runs, so it cannot be the change an upgrade crosses.
SHIPPED_PATHS = (f"{OPERATOR_REL}/ash_operator", f"{OPERATOR_REL}/generated")
PREVIOUS_OPERATOR_IMAGE = f"ash-operator-prev:{IMAGE_TAG}"
SHIPPED_IMAGE_LINE = "image: ash-operator:local"
CRD_PLURALS = ("ashscans", "ashmcpservers")
OWNER_KINDS = frozenset({"AshScan", "AshMcpServer"})
# Everything a scan or an MCP server creates, and therefore everything uninstall has
# to leave behind none of.
OWNED_RESOURCES = "jobs,pods,configmaps,persistentvolumeclaims,deployments,services"
CLUSTER_SCOPED_RBAC = (
    "clusterrole/ash-operator-crd-reader",
    "clusterrolebinding/ash-operator-crd-reader",
)


def crd_files(operator_dir: Path) -> list[Path]:
    files = [operator_dir / "generated" / f"crd-{plural}.yaml" for plural in CRD_PLURALS]
    missing = [str(f) for f in files if not f.is_file()]
    assert not missing, f"no CRD files at {missing}"
    return files


def install_operator(operator_dir: Path, image: str) -> None:
    """README.md's install: the CRDs, then manifests/ with the image substituted."""
    for crd in crd_files(operator_dir):
        kubectl("apply", "-f", str(crd))
    for plural in CRD_PLURALS:
        kubectl("wait", "--for=condition=Established", f"crd/{plural}.{GROUP}", "--timeout=90s")
    # The namespace lives in operator.yaml, and rbac.yaml's objects are in it, so the
    # namespace has to exist first -- but the Deployment must not, or its ReplicaSet
    # fails to create a pod with "serviceaccount ash-operator not found" and spends a
    # restart backoff before the SA arrives.
    shipped = (operator_dir / "manifests" / "operator.yaml").read_text()
    # The shipped manifest names `ash-operator:local`. A run with its own image tag
    # substitutes it here, and asserts that it did: an apply that silently kept the
    # shipped name would run whatever image last carried that tag on the node.
    assert shipped.count(SHIPPED_IMAGE_LINE) == 1, "operator.yaml no longer names one image"
    kubectl_apply_stdin(shipped.replace(SHIPPED_IMAGE_LINE, f"image: {image}"))
    kubectl("apply", "-f", str(operator_dir / "manifests" / "rbac.yaml"))
    kubectl("-n", NAMESPACE, "rollout", "restart", "deployment/ash-operator", check=False)
    kubectl("-n", NAMESPACE, "rollout", "status", "deployment/ash-operator", "--timeout=300s")
    kubectl(
        "-n",
        NAMESPACE,
        "wait",
        "--for=condition=Available",
        "deployment/ash-operator",
        "--timeout=300s",
    )


def operator_pods() -> list[dict[str, Any]]:
    listing = kubectl_json(
        "-n", NAMESPACE, "get", "pods", "-l", "app.kubernetes.io/name=ash-operator"
    )
    return [p for p in listing["items"] if not p["metadata"].get("deletionTimestamp")]


def owned_leftovers() -> list[str]:
    """Every object in the namespace that a scan or an MCP server created.

    Matched two ways, by owner reference and by the operator's labels, because a shard
    pod is owned by its Job and not by the AshScan, and an object that lost its owner
    reference would otherwise be invisible to the check.
    """
    listing = kubectl_json("-n", NAMESPACE, "get", OWNED_RESOURCES)
    found = []
    for item in listing.get("items", []):
        meta = item["metadata"]
        owners = {ref.get("kind") for ref in meta.get("ownerReferences") or []}
        labels = set(meta.get("labels") or {})
        ours = {f"{GROUP}/scan-uid", f"{GROUP}/mcp-name"} & labels
        if owners & OWNER_KINDS or ours:
            found.append(f"{item['kind']}/{meta['name']}")
    return sorted(found)


def exists(*args: str) -> bool:
    result = kubectl("get", *args, check=False)
    if result.returncode == 0:
        return True
    assert "NotFound" in result.stderr or "not found" in result.stderr, result.stderr
    return False


def uninstall_crds(operator_dir: Path) -> None:
    """The first uninstall command: the CRDs, which deletes every AshScan and AshMcpServer."""
    argv = ["delete", "--wait=true", "--timeout=300s"]
    for crd in crd_files(operator_dir):
        argv += ["-f", str(crd)]
    kubectl(*argv, timeout=360)


def uninstall_manifests(operator_dir: Path) -> None:
    """The second: manifests/, which is the namespace, the RBAC and the Deployment."""
    kubectl(
        "delete",
        "--wait=true",
        "--timeout=600s",
        "-f",
        str(operator_dir / "manifests"),
        timeout=660,
    )


def wait_no_leftovers(timeout: int = 300) -> None:
    wait_for(
        lambda: not owned_leftovers() or None,
        timeout=timeout,
        what="the garbage collector to remove every object a scan or MCP server owned",
    )


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def previous_ref() -> tuple[str, str]:
    """(sha, why) for N-1.

    ``ASH_OPERATOR_E2E_PREV_REF`` names it outright. Otherwise it is the first parent
    of the newest first-parent commit that changed the shipped code, which on a
    mainline is the tree before the last merge that changed the operator. Either way
    the shipped code must differ from HEAD's, or the upgrade crosses nothing.
    """
    override = os.environ.get("ASH_OPERATOR_E2E_PREV_REF")
    if override:
        sha = git("rev-parse", "--verify", f"{override}^{{commit}}")
        why = f"ASH_OPERATOR_E2E_PREV_REF={override}"
    else:
        changed = git("log", "-1", "--first-parent", "--format=%H", "HEAD", "--", *SHIPPED_PATHS)
        assert changed, (
            f"no commit in this clone changed {SHIPPED_PATHS}. The checkout is probably "
            f"shallow; the workflow fetches full history for this reason."
        )
        try:
            sha = git("rev-parse", "--verify", f"{changed}^1^{{commit}}")
        except subprocess.CalledProcessError as err:
            raise AssertionError(
                f"{changed} changed the operator but its parent is not in this clone; "
                f"fetch full history"
            ) from err
        why = f"first parent of {changed[:12]}, the newest change to the shipped operator"
    diff = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "diff", "--quiet", sha, "HEAD", "--", *SHIPPED_PATHS],
        check=False,
    )
    assert diff.returncode == 1, (
        f"N-1 {sha[:12]} ({why}) ships the same operator code as HEAD, so an upgrade "
        f"from it crosses no change"
    )
    return sha, why


ASH_CLI_LINE = re.compile(r'^ASH_CLI = "([^"]+)"$', re.MULTILINE)


def build_previous_operator(dest: Path) -> dict[str, Any]:
    """Export N-1's operator tree into *dest*, build its image and load it into kind.

    N-1's own Dockerfile is used with one change: its FROM line is replaced by HEAD's,
    which is digest-pinned. An older Dockerfile may name a bare tag, and building one
    would pull whatever that tag points at today. The replacement is refused unless
    both lines name the same base image, so it cannot hide a base change.
    """
    sha, why = previous_ref()
    present = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{sha}:{OPERATOR_REL}/Dockerfile"],
        check=False,
    )
    assert present.returncode == 0, (
        f"N-1 {sha[:12]} ({why}) has no operator to install. That is the commit before "
        f"the operator existed; name an N-1 with ASH_OPERATOR_E2E_PREV_REF."
    )
    archive = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", "--format=tar", sha, OPERATOR_REL],
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="ash-op-prev-") as scratch:
        tarball = Path(scratch) / "prev.tar"
        tarball.write_bytes(archive)
        run(["tar", "-xf", str(tarball), "-C", str(dest)])
    tree = dest / OPERATOR_REL

    dockerfile = tree / "Dockerfile"
    lines = dockerfile.read_text().splitlines()
    from_lines = [i for i, line in enumerate(lines) if line.startswith("FROM ")]
    head_from = [
        line
        for line in (OPERATOR_DIR / "Dockerfile").read_text().splitlines()
        if line.startswith("FROM ")
    ]
    assert len(from_lines) == 1 and len(head_from) == 1, (from_lines, head_from)
    old_base = lines[from_lines[0]].split()[1].split("@")[0]
    new_base = head_from[0].split()[1].split("@")[0]
    assert old_base == new_base, (
        f"N-1 builds FROM {old_base} and HEAD FROM {new_base}; repinning N-1 onto HEAD's "
        f"digest would change its base image, so this needs a deliberate decision"
    )
    lines[from_lines[0]] = head_from[0]
    dockerfile.write_text("\n".join(lines) + "\n")

    run(
        ["docker", "build", "-t", PREVIOUS_OPERATOR_IMAGE, "-f", str(dockerfile), str(tree)],
        timeout=1200,
    )
    run(
        ["kind", "load", "docker-image", PREVIOUS_OPERATOR_IMAGE, "--name", CLUSTER_NAME],
        timeout=1200,
    )
    constants = (tree / "ash_operator" / "constants.py").read_text()
    match = ASH_CLI_LINE.search(constants)
    assert match, "N-1's constants.py names no ASH_CLI"
    print(f"=== N-1 operator: {sha} ({why}), ASH_CLI={match.group(1)!r} ===")
    return {
        "sha": sha,
        "why": why,
        "dir": tree,
        "image": PREVIOUS_OPERATOR_IMAGE,
        "cli": match.group(1),
    }


def remove_image(image: str) -> None:
    if shutil.which("docker"):
        run(["docker", "image", "rm", "-f", image], check=False)
