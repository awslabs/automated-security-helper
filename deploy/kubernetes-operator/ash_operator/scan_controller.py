"""The AshScan reconciler.

What Kubernetes does not give this design, and therefore what lives here: a merge
trigger. Both CDK backends get one from a pipeline engine -- CodePipeline's
``runOrder + 1`` holds the merge until every shard action finishes, which is what
makes that action the gate. ``completionMode: Indexed`` supplies
``JOB_COMPLETION_INDEX`` per pod and nothing else; there is no "after all
completions" primitive. So this controller watches the shard Job to a terminal
state and creates the collector itself.

The collector is created after a **terminal** state, not after ``Complete``. A
shard Job that Failed still gets a collector, because the collector's index walk
is what turns a missing shard into a named refusal. Skipping it on failure would
leave the run with no verdict at all and nothing in ``.status`` saying which index
was missing -- which is worse than a refusal, because a human then has to go and
find out.
"""

from __future__ import annotations

import logging
from typing import Any

import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException

from ash_operator import manifests
from ash_operator.attempts import run_prefix
from ash_operator.constants import (
    GROUP,
    LABEL_ROLE,
    LABEL_SCAN_UID,
    MAX_SHARD_COUNT,
    RESULTS_MOUNT,
    ROLE_COLLECT,
    ROLE_SHARD,
    SCAN_PLURAL,
    VERSION,
)
from ash_operator.contract import ContractError, validate_shard_selection
from ash_operator.results import parse_collector_summary, status_from_summary

LOG = logging.getLogger("ash_operator.scan")

MERGE_OUTPUT_SUBDIR = "merged"


def _apis() -> tuple[kubernetes.client.BatchV1Api, kubernetes.client.CoreV1Api]:
    return kubernetes.client.BatchV1Api(), kubernetes.client.CoreV1Api()


def _create_ignoring_conflict(create, body: dict[str, Any], what: str) -> None:
    """Create *body*, treating 409 as success.

    A reconciler is called more than once for the same state, and a create that
    already happened is not an error. Catching only 409 rather than every
    ApiException matters: a 403 from a too-narrow RBAC rule would otherwise look
    like "already exists" and the run would wait forever for a Job nobody made.
    """
    try:
        create(body)
        LOG.info("created %s %s", what, body["metadata"]["name"])
    except ApiException as err:
        if err.status != 409:
            raise
        LOG.debug("%s %s already exists", what, body["metadata"]["name"])


def _validate(spec: dict[str, Any]) -> int:
    shard_count = spec.get("shardCount")
    if shard_count is None:
        raise kopf.PermanentError("spec.shardCount is required")
    shard_count = int(shard_count)
    try:
        validate_shard_selection(0, shard_count)
    except ContractError as err:
        raise kopf.PermanentError(str(err)) from err
    if not spec.get("image"):
        raise kopf.PermanentError(
            "spec.image is required. ASH publishes no container image to any public "
            "registry and will not, so there is no default to fall back to -- every "
            "deployment builds its own."
        )
    if not spec.get("source"):
        raise kopf.PermanentError(
            "spec.source is required: it is the volume carrying the tree to scan."
        )
    if shard_count > MAX_SHARD_COUNT:
        raise kopf.PermanentError(f"spec.shardCount {shard_count} exceeds {MAX_SHARD_COUNT}.")
    return shard_count


@kopf.on.create(GROUP, VERSION, SCAN_PLURAL)
@kopf.on.resume(GROUP, VERSION, SCAN_PLURAL)
def reconcile_scan(spec, meta, status, patch, body, **_):
    """Create the results claim, the run ConfigMap and the indexed shard Job."""
    shard_count = _validate(dict(spec))
    scan = {"metadata": dict(meta)}
    batch, core = _apis()
    namespace = meta["namespace"]

    if (status or {}).get("phase") in ("Succeeded", "Failed", "Refused"):
        # Terminal. Re-running would need a new CR: the results prefix is keyed on
        # this CR's UID, and republishing into it would put two runs' attempts
        # under one index.
        return

    ash_config = dict(spec).get("config") or None
    configmap = manifests.build_run_configmap(scan=scan, ash_config=ash_config)
    pvc = manifests.build_results_pvc(scan=scan, spec=dict(spec))
    claim_name = (dict(spec).get("results") or {}).get("claimName") or (
        pvc["metadata"]["name"] if pvc else None
    )
    if claim_name is None:  # pragma: no cover - build_results_pvc covers both arms
        raise kopf.PermanentError("could not determine a results claim name")

    if pvc is not None:
        _create_ignoring_conflict(
            lambda b: core.create_namespaced_persistent_volume_claim(namespace, b),
            pvc,
            "PersistentVolumeClaim",
        )
    _create_ignoring_conflict(
        lambda b: core.create_namespaced_config_map(namespace, b), configmap, "ConfigMap"
    )

    prefix = run_prefix(RESULTS_MOUNT, meta["uid"])
    shard_job = manifests.build_shard_job(
        scan=scan,
        spec=dict(spec),
        configmap_name=configmap["metadata"]["name"],
        has_config=ash_config is not None,
        results_prefix=prefix,
        results_claim_name=claim_name,
    )
    _create_ignoring_conflict(lambda b: batch.create_namespaced_job(namespace, b), shard_job, "Job")

    patch.status["phase"] = "Scanning"
    patch.status["shardCount"] = shard_count
    patch.status["resultsPrefix"] = prefix
    patch.status["configMapName"] = configmap["metadata"]["name"]
    patch.status["resultsClaimName"] = claim_name
    patch.status["shardJobName"] = shard_job["metadata"]["name"]
    kopf.info(
        body,
        reason="ShardsDispatched",
        message=(
            f"dispatched {shard_count} shard(s) as one Indexed Job; the collector "
            f"runs once every shard reaches a terminal state"
        ),
    )


@kopf.on.event("batch", "v1", "jobs", labels={LABEL_ROLE: ROLE_SHARD})
def on_shard_job_progress(event, meta, status, namespace, **_):
    """Create the collector once the shard Job is terminal.

    An ``on.event`` handler rather than ``on.field`` or ``on.update``, and that is an
    RBAC decision as much as a design one. Stateful handlers make kopf store
    per-handler progress and a diffbase *on the watched object*, so an ``on.field``
    handler here required ``patch`` on ``batch/jobs`` -- measured: the operator
    otherwise logs ``jobs.batch "…-shard" is forbidden: … cannot patch resource
    "jobs"`` and throttles forever while the scan sits in Scanning. Event handlers
    are stateless, so the Role needs no write verb on Jobs at all and nothing
    annotates objects the operator does not own.

    The cost is that this fires on every watch event for a matching Job, including
    the initial listing and repeats after a restart. Both branches below are
    idempotent: the collector is created once (409 is treated as success) and the
    status patch is by-field.
    """
    if event.get("type") == "DELETED":
        return
    scan_uid = (meta.get("labels") or {}).get(LABEL_SCAN_UID)
    if not scan_uid:
        return
    succeeded = int((status or {}).get("succeeded") or 0)
    failed = int((status or {}).get("failed") or 0)
    conditions = {c.get("type"): c.get("status") for c in ((status or {}).get("conditions") or [])}
    terminal = conditions.get("Complete") == "True" or conditions.get("Failed") == "True"
    if not terminal:
        return

    scan = _find_scan_by_uid(namespace, scan_uid)
    if scan is None:
        LOG.info("shard Job %s has no AshScan with uid %s", meta["name"], scan_uid)
        return
    scan_status = scan.get("status") or {}
    if scan_status.get("collectJobName"):
        return

    spec = scan.get("spec") or {}
    prefix = scan_status.get("resultsPrefix") or run_prefix(RESULTS_MOUNT, scan["metadata"]["uid"])
    claim_name = scan_status.get("resultsClaimName")
    configmap_name = scan_status.get("configMapName")
    if not (claim_name and configmap_name):
        LOG.warning(
            "AshScan %s is missing resultsClaimName/configMapName in status; the "
            "collector cannot be built without them",
            scan["metadata"]["name"],
        )
        return

    batch, _core = _apis()
    collect_job = manifests.build_collect_job(
        scan={"metadata": dict(scan["metadata"])},
        spec=dict(spec),
        configmap_name=configmap_name,
        has_config=bool(spec.get("config")),
        results_prefix=prefix,
        results_claim_name=claim_name,
        merge_output=f"{prefix}/{MERGE_OUTPUT_SUBDIR}",
    )
    _create_ignoring_conflict(
        lambda b: batch.create_namespaced_job(namespace, b), collect_job, "Job"
    )
    _patch_scan_status(
        namespace,
        scan["metadata"]["name"],
        {
            "phase": "Merging",
            "collectJobName": collect_job["metadata"]["name"],
            "shardJobSucceeded": succeeded,
            "shardJobFailed": failed,
        },
    )


@kopf.on.event("batch", "v1", "jobs", labels={LABEL_ROLE: ROLE_COLLECT})
def on_collect_job_progress(event, meta, status, namespace, **_):
    """Read the collector's verdict out of its pod and write ``.status``.

    Stateless for the same reason as the shard handler above -- see its docstring.
    """
    if event.get("type") == "DELETED":
        return
    scan_uid = (meta.get("labels") or {}).get(LABEL_SCAN_UID)
    if not scan_uid:
        return
    conditions = {c.get("type"): c.get("status") for c in ((status or {}).get("conditions") or [])}
    if conditions.get("Complete") != "True" and conditions.get("Failed") != "True":
        return

    scan = _find_scan_by_uid(namespace, scan_uid)
    if scan is None:
        return
    shard_count = int((scan.get("spec") or {}).get("shardCount") or 0)

    message = _collector_termination_message(namespace, meta["name"])
    summary = parse_collector_summary(message)
    new_status = status_from_summary(summary, expected_shard_count=shard_count)
    new_status["shardPods"] = _shard_pod_states(namespace, scan_uid)
    _patch_scan_status(namespace, scan["metadata"]["name"], new_status)
    LOG.info(
        "AshScan %s -> %s (merge exit %s)",
        scan["metadata"]["name"],
        new_status["phase"],
        summary.merge_exit_code,
    )


def _shard_pod_states(namespace: str, scan_uid: str) -> list[dict[str, Any]]:
    """Per-shard pod state, keyed on the Job controller's own index label.

    The label is what makes a pod attributable to a shard index without the
    operator keeping its own index-to-pod map. That matters beyond tidiness: the
    partition reshuffles by sort position, so any map the operator kept would be
    stale the moment the scanner roster changed.
    """
    _batch, core = _apis()
    try:
        pods = core.list_namespaced_pod(
            namespace, label_selector=f"{LABEL_SCAN_UID}={scan_uid},{LABEL_ROLE}={ROLE_SHARD}"
        )
    except ApiException as err:  # pragma: no cover - requires an API failure
        LOG.warning("could not list shard pods: %s", err)
        return []
    out = []
    for pod in pods.items:
        labels = pod.metadata.labels or {}
        out.append(
            {
                "podName": pod.metadata.name,
                "shardIndex": int(labels.get("batch.kubernetes.io/job-completion-index", -1)),
                "phase": pod.status.phase if pod.status else None,
            }
        )
    return sorted(out, key=lambda item: (item["shardIndex"], item["podName"]))


def _collector_termination_message(namespace: str, job_name: str) -> str | None:
    _batch, core = _apis()
    try:
        pods = core.list_namespaced_pod(namespace, label_selector=f"job-name={job_name}")
    except ApiException as err:  # pragma: no cover
        LOG.warning("could not list collector pods: %s", err)
        return None
    # Newest first: a retried collector's latest attempt is the one that decided.
    ordered = sorted(
        pods.items,
        key=lambda pod: (pod.metadata.creation_timestamp, pod.metadata.name),
        reverse=True,
    )
    for pod in ordered:
        for container in (pod.status.container_statuses if pod.status else None) or []:
            terminated = container.state.terminated if container.state else None
            if terminated is not None and terminated.message:
                return terminated.message
    return None


def _find_scan_by_uid(namespace: str, scan_uid: str) -> dict[str, Any] | None:
    api = kubernetes.client.CustomObjectsApi()
    try:
        listing = api.list_namespaced_custom_object(GROUP, VERSION, namespace, SCAN_PLURAL)
    except ApiException as err:  # pragma: no cover
        LOG.warning("could not list AshScans: %s", err)
        return None
    for item in listing.get("items", []):
        if (item.get("metadata") or {}).get("uid") == scan_uid:
            return item
    return None


def _patch_scan_status(namespace: str, name: str, status: dict[str, Any]) -> None:
    api = kubernetes.client.CustomObjectsApi()
    try:
        api.patch_namespaced_custom_object_status(
            GROUP, VERSION, namespace, SCAN_PLURAL, name, {"status": status}
        )
    except ApiException as err:  # pragma: no cover
        LOG.warning("could not patch AshScan %s status: %s", name, err)
