"""Build the Kubernetes objects one AshScan or AshMcpServer turns into.

Pure functions returning plain dicts, so the shapes are unit-testable without a
cluster and the e2e can assert the same dicts it applies.

Two decisions worth finding here rather than in a diff:

**The config ConfigMap is content-addressed and immutable.** Its name ends in a
digest of everything it contains, and it is created with ``immutable: true``. This
is the structural fix for the split-brain roster hazard. The documented failure is
a config change that reaches shard 0 and not shards 1-3, after which shard 0
partitions an 11-scanner roster and the others partition 10 -- measured, that runs
``checkov`` and ``opengrep`` twice and ``bandit``, ``detect-secrets`` and
``semgrep`` zero times. A mutable ConfigMap makes that reachable, because the
kubelet re-syncs a mounted ConfigMap into a running pod. An immutable,
content-addressed one cannot: a changed config is a different object with a
different name, and a Job already referencing the old name keeps referencing it.
``spec.scanners`` is still passed to every pod when set, as a second and
independent guard.

**Nothing is keyed on shard index across runs.** The partition reshuffles by
sort *position*, not by count: measured, adding an early-sorting scanner name
moves 10 of 10 shards while a late-sorting one moves 0. So a cache keyed on
``(shard_index, image)`` is wrong for every scanner after a roster change. The
only per-index value anywhere here is ``JOB_COMPLETION_INDEX``, read fresh inside
the pod, and the results path, which is scoped to one run's UID.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from ash_operator import contract
from ash_operator.constants import (
    ATOMIC_WRITER_DATA_DIR,
    ATOMIC_WRITER_SOURCES,
    COLLECT_ENTRYPOINT_FILENAME,
    CONFIG_FILENAME,
    CONFIG_MOUNT,
    CONFIG_PATH,
    DEFAULT_COLLECT_RESOURCES,
    DEFAULT_SHARD_RESOURCES,
    GROUP,
    LABEL_CONFIG_DIGEST,
    LABEL_MCP_NAME,
    LABEL_ROLE,
    LABEL_SCAN_NAME,
    LABEL_SCAN_UID,
    OUTPUT_MOUNT,
    RESULTS_MOUNT,
    ROLE_COLLECT,
    ROLE_MCP,
    ROLE_SHARD,
    SCAN_SERVICE_ACCOUNT,
    SHARD_ENTRYPOINT_FILENAME,
    SOURCE_MOUNT,
    TMP_MOUNT,
    VERSION,
)
from ash_operator.volumes import assert_layout_is_sane

_ENTRYPOINT_DIR = Path(__file__).parent / "entrypoints"
_PACKAGE_DIR = Path(__file__).parent

# Shipped into the ConfigMap so the collector imports the operator's own modules
# rather than a second copy. Flat keys because a ConfigMap key cannot contain "/";
# collect-entrypoint.sh reassembles the package.
_COLLECTOR_MODULES = ("constants", "attempts")

# The MCP server's entrypoint. The auth header value is read from the environment
# *inside this script*, which is the whole point: an earlier version put the literal
# string "${ASH_MCP_AUTH_HEADER_VALUE}" into argv and ran `sh -c 'exec "$0" "$@"'`,
# and a positional parameter's value is never re-expanded -- so `ashx` compared
# incoming headers against those 28 characters. Anyone sending the literal
# authenticated; the holder of the real secret got 401. A variable referenced in the
# script *text* is expanded by the shell, which is why the flag is appended here
# rather than passed in.
#
# The empty-value case is refused rather than degraded. `ashx mcp` would reject a
# header name with no value anyway, but exiting 78 (EX_CONFIG) with a message naming
# the Secret key is a better failure than a crash loop whose cause is upstream
# argument validation. Failing closed matters here: the alternative reading -- start
# without auth -- would publish an unauthenticated MCP control surface.
MCP_ENTRYPOINT = """set -u
if [ "${ASH_MCP_AUTH_REQUIRED:-0}" = "1" ]; then
  if [ -z "${ASH_MCP_AUTH_HEADER_VALUE:-}" ]; then
    echo "[ash-mcp] FATAL: auth.headerName is configured but ASH_MCP_AUTH_HEADER_VALUE" >&2
    echo "[ash-mcp] is empty. The Secret key named in auth.valueFrom.secretKeyRef is" >&2
    echo "[ash-mcp] missing or empty. Refusing to start rather than serving MCP with a" >&2
    echo "[ash-mcp] credential nobody can present." >&2
    exit 78
  fi
  exec "$@" --auth-header-value "$ASH_MCP_AUTH_HEADER_VALUE"
fi
exec "$@"
"""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def owner_reference(scan: dict[str, Any], kind: str) -> dict[str, Any]:
    """An ownerReference so every child is garbage-collected with its parent.

    ``blockOwnerDeletion`` is left off. Setting it requires ``delete`` permission
    on the owner's finalizers, which is a privilege this operator does not need
    and a security tool should not hold.
    """
    meta = scan["metadata"]
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": kind,
        "name": meta["name"],
        "uid": meta["uid"],
        "controller": True,
    }


def config_digest(payload: dict[str, str]) -> str:
    """A short digest over every ConfigMap key and value."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def build_run_configmap(
    *,
    scan: dict[str, Any],
    ash_config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return the immutable, content-addressed ConfigMap for one run.

    When the CR carries no ``spec.config``, no ``.ash.yaml`` key is written and the
    entrypoint leaves ``ASH_CONFIG`` unset. Pointing the variable at a file that
    does not exist makes ASH log a missing-config notice on every scan, which
    reads like a failure in a log someone is searching for a real one.
    """
    import yaml

    meta = scan["metadata"]
    data: dict[str, str] = {
        SHARD_ENTRYPOINT_FILENAME: _read(_ENTRYPOINT_DIR / "shard-entrypoint.sh"),
        COLLECT_ENTRYPOINT_FILENAME: _read(_ENTRYPOINT_DIR / "collect-entrypoint.sh"),
        "collect.py": _read(_ENTRYPOINT_DIR / "collect.py"),
    }
    for module in _COLLECTOR_MODULES:
        data[f"_{module}.py"] = _read(_PACKAGE_DIR / f"{module}.py")
    if ash_config:
        # default_flow_style=False and sort_keys=False so the file a human opens
        # looks like the block they wrote in the CR.
        data[CONFIG_FILENAME] = yaml.safe_dump(
            ash_config, default_flow_style=False, sort_keys=False
        )

    digest = config_digest(data)
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": f"{meta['name']}-run-{digest}",
            "namespace": meta["namespace"],
            "labels": {
                LABEL_SCAN_NAME: meta["name"],
                LABEL_SCAN_UID: meta["uid"],
                LABEL_CONFIG_DIGEST: digest,
            },
            "ownerReferences": [owner_reference(scan, "AshScan")],
        },
        # The whole point. A mounted ConfigMap is re-synced into running pods; an
        # immutable one cannot change under a Job that is already running.
        "immutable": True,
        "data": data,
    }


def _hardened_security_context() -> dict[str, Any]:
    """Container security context for a pod that runs a scanner over foreign code.

    ``readOnlyRootFilesystem`` is deliberately **absent** rather than true. It was
    measured elsewhere in this stack to make scanners report clean: a tool that
    cannot write where it expects to comes back MISSING rather than failing. With
    ``fail_on_incomplete_scanners`` on, which is ASH's default, that turns a working
    scan into an ``Incomplete`` one; with it turned off, a MISSING scanner merges
    into a report that reads as a complete scan. Either way a hardening flag that
    converts a scanner into a gap is worse than the write it prevents. The settings
    that are here cost nothing and give up nothing.
    """
    return {
        "allowPrivilegeEscalation": False,
        "privileged": False,
        "runAsNonRoot": True,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _volumes(
    *,
    configmap_name: str,
    source: dict[str, Any],
    results_claim_name: str,
) -> list[dict[str, Any]]:
    return [
        {"name": "ash-source", **source},
        {"name": "ash-output", "emptyDir": {}},
        {"name": "ash-tmp", "emptyDir": {}},
        {
            "name": "ash-config",
            "configMap": {"name": configmap_name, "defaultMode": 0o444},
        },
        {
            "name": "ash-results",
            "persistentVolumeClaim": {"claimName": results_claim_name},
        },
    ]


def _mounts(*, source_read_only: bool = True) -> list[dict[str, Any]]:
    return [
        {"name": "ash-source", "mountPath": SOURCE_MOUNT, "readOnly": source_read_only},
        {"name": "ash-output", "mountPath": OUTPUT_MOUNT},
        {"name": "ash-tmp", "mountPath": TMP_MOUNT},
        {"name": "ash-config", "mountPath": CONFIG_MOUNT, "readOnly": True},
        {"name": "ash-results", "mountPath": RESULTS_MOUNT},
    ]


def scan_source_dir(source: dict[str, Any]) -> str:
    """The directory a shard scans inside the source mount.

    The mount root, except for a volume the kubelet writes with its atomic writer,
    where the root holds every file twice; see ``ATOMIC_WRITER_DATA_DIR``.
    """
    if set(source) & ATOMIC_WRITER_SOURCES:
        return f"{SOURCE_MOUNT}/{ATOMIC_WRITER_DATA_DIR}"
    return SOURCE_MOUNT


def build_shard_job(
    *,
    scan: dict[str, Any],
    spec: dict[str, Any],
    configmap_name: str,
    has_config: bool,
    results_prefix: str,
    results_claim_name: str,
) -> dict[str, Any]:
    """Return the indexed Job that runs every shard.

    ``completionMode: Indexed`` with ``completions == parallelism == shardCount``
    gives each pod a distinct ``JOB_COMPLETION_INDEX``, which maps straight onto
    ``--shard-index``, and makes the pods selectable by the
    ``batch.kubernetes.io/job-completion-index`` label. It does not give a merge
    trigger -- Kubernetes has no equivalent of CodePipeline's ``runOrder + 1`` --
    so the controller watches this Job and creates the collector itself.
    """
    assert_layout_is_sane()
    meta = scan["metadata"]
    shard_count = int(spec["shardCount"])
    contract.validate_shard_selection(0, shard_count)

    # The base argv, without the two shard integers. The entrypoint appends
    # `--shard-index "$ASH_SHARD_INDEX" --shard-count "$ASH_SHARD_COUNT"`, so the
    # substitution is done by the shell at run time and not by Kubernetes at
    # admission.
    #
    # Two routes were tried first and are wrong. A `fieldRef` on
    # `metadata.labels['batch.kubernetes.io/job-completion-index']` cannot work
    # because a fieldRef reads annotations and a few fixed fields, not labels. And
    # `env: [{name: ASH_SHARD_INDEX, value: "$(JOB_COMPLETION_INDEX)"}]` depends on
    # ordering: `$(VAR)` resolves only against variables defined *earlier* in the
    # same container's list, and the Job controller appends
    # JOB_COMPLETION_INDEX rather than prepending it, so the reference would stay
    # a literal string and `ashx scan` would be handed "$(JOB_COMPLETION_INDEX)"
    # where it wants an integer. The shell sees the real environment and has
    # neither problem.
    scan_argv = contract.build_scan_argv(
        source_dir=scan_source_dir(spec["source"]),
        output_dir=OUTPUT_MOUNT,
        shard_index=None,
        shard_count=None,
        scanners=spec.get("scanners"),
        exclude_scanners=spec.get("excludeScanners"),
        extra_arguments=spec.get("extraScanArguments"),
    )

    env = [
        {"name": "ASH_SHARD_COUNT", "value": str(shard_count)},
        {
            "name": "ASH_POD_NAME",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
        },
        {
            "name": "ASH_POD_UID",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}},
        },
        # The attempt identity is the pod name, which the entrypoint reads from
        # ASH_POD_NAME. An Indexed Job names pods <job>-<index>-<random>, so the
        # name is fixed within one attempt and differs across retries -- exactly
        # the identity the attempt-qualified layout needs. Set in the shell rather
        # than as `value: "$(ASH_POD_NAME)"` for the ordering reason above.
        {"name": "ASH_SOURCE_MOUNT", "value": SOURCE_MOUNT},
        {"name": "ASH_OUTPUT_MOUNT", "value": OUTPUT_MOUNT},
        {"name": "ASH_RESULTS_PREFIX", "value": results_prefix},
    ]
    if has_config:
        env.append({"name": "ASH_CONFIG", "value": CONFIG_PATH})

    pod_labels = {
        LABEL_SCAN_NAME: meta["name"],
        LABEL_SCAN_UID: meta["uid"],
        LABEL_ROLE: ROLE_SHARD,
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": f"{meta['name']}-shard",
            "namespace": meta["namespace"],
            "labels": pod_labels,
            "ownerReferences": [owner_reference(scan, "AshScan")],
        },
        "spec": {
            "completionMode": "Indexed",
            "completions": shard_count,
            "parallelism": int(spec.get("parallelism") or shard_count),
            # Default 0. The attempt-qualified layout makes a retry safe, so a
            # higher value is allowed; 0 is the default because it is the option
            # that needs no reasoning about.
            "backoffLimit": int(spec.get("backoffLimit") or 0),
            "ttlSecondsAfterFinished": int(spec.get("ttlSecondsAfterFinished") or 3600),
            "template": {
                "metadata": {"labels": pod_labels},
                "spec": {
                    "restartPolicy": "Never",
                    # A pod that scans foreign source has no business holding an
                    # API token. Nothing in the shard path talks to the API server.
                    "automountServiceAccountToken": False,
                    "serviceAccountName": spec.get("scanServiceAccountName")
                    or SCAN_SERVICE_ACCOUNT,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": int(spec.get("runAsUser") or 1000),
                        "fsGroup": int(spec.get("fsGroup") or 1000),
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "volumes": _volumes(
                        configmap_name=configmap_name,
                        source=spec["source"],
                        results_claim_name=results_claim_name,
                    ),
                    "containers": [
                        {
                            "name": "ash-shard",
                            "image": spec["image"],
                            "imagePullPolicy": spec.get("imagePullPolicy", "IfNotPresent"),
                            "command": ["/bin/sh", f"{CONFIG_MOUNT}/{SHARD_ENTRYPOINT_FILENAME}"],
                            "args": scan_argv,
                            "env": env,
                            "volumeMounts": _mounts(),
                            "resources": copy.deepcopy(
                                spec.get("resources") or DEFAULT_SHARD_RESOURCES
                            ),
                            "securityContext": _hardened_security_context(),
                        }
                    ],
                },
            },
        },
    }


def build_collect_job(
    *,
    scan: dict[str, Any],
    spec: dict[str, Any],
    configmap_name: str,
    has_config: bool,
    results_prefix: str,
    results_claim_name: str,
    merge_output: str,
) -> dict[str, Any]:
    """Return the Job that walks the indices and merges.

    Exactly one, strictly after every shard, and it cannot be skipped: the
    controller creates it only once the shard Job reaches a terminal state, and
    its own index walk refuses a short set. A merge over a subset exits 0 and
    reports a clean scan, which is the single failure mode the whole design is
    built against.
    """
    assert_layout_is_sane()
    meta = scan["metadata"]
    shard_count = int(spec["shardCount"])

    # No --results and no --output-dir here: collect.py appends one --results per
    # index it resolved, after the walk. The controller must not decide which
    # shards exist -- it would have to glob or trust its own bookkeeping, and the
    # walk is the thing that turns a short set into a named refusal.
    merge_argv = contract.build_merge_argv(
        results_dirs=None,
        output_dir=None,
        min_severity=spec.get("minSeverity"),
        fail_on_findings=spec.get("failOnFindings"),
        fail_on_incomplete_scanners=spec.get("failOnIncompleteScanners"),
        output_formats=spec.get("outputFormats"),
    )

    args = [
        "--prefix",
        results_prefix,
        "--shard-count",
        str(shard_count),
        "--merge-output",
        merge_output,
        "--",
        *merge_argv,
    ]
    env = [
        {"name": "ASH_CONFIG_MOUNT", "value": CONFIG_MOUNT},
        {"name": "ASH_PYLIB_DIR", "value": f"{TMP_MOUNT}/ash-operator-pylib"},
    ]
    if has_config:
        env.append({"name": "ASH_CONFIG", "value": CONFIG_PATH})

    pod_labels = {
        LABEL_SCAN_NAME: meta["name"],
        LABEL_SCAN_UID: meta["uid"],
        LABEL_ROLE: ROLE_COLLECT,
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": f"{meta['name']}-collect",
            "namespace": meta["namespace"],
            "labels": pod_labels,
            "ownerReferences": [owner_reference(scan, "AshScan")],
        },
        "spec": {
            # A collector retry re-runs the same walk over the same immutable
            # attempts and reaches the same answer, so a retry is safe -- but 0 is
            # still the default, because a refusal that retries three times before
            # surfacing reads as a flake.
            "backoffLimit": int(spec.get("collectBackoffLimit") or 0),
            "ttlSecondsAfterFinished": int(spec.get("ttlSecondsAfterFinished") or 3600),
            "template": {
                "metadata": {"labels": pod_labels},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "serviceAccountName": spec.get("scanServiceAccountName")
                    or SCAN_SERVICE_ACCOUNT,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": int(spec.get("runAsUser") or 1000),
                        "fsGroup": int(spec.get("fsGroup") or 1000),
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "volumes": _volumes(
                        configmap_name=configmap_name,
                        source=spec["source"],
                        results_claim_name=results_claim_name,
                    ),
                    "containers": [
                        {
                            "name": "ash-collect",
                            "image": spec["image"],
                            "imagePullPolicy": spec.get("imagePullPolicy", "IfNotPresent"),
                            "command": [
                                "/bin/sh",
                                f"{CONFIG_MOUNT}/{COLLECT_ENTRYPOINT_FILENAME}",
                            ],
                            "args": args,
                            "env": env,
                            "volumeMounts": _mounts(),
                            "resources": copy.deepcopy(
                                spec.get("collectResources")
                                or spec.get("resources")
                                or DEFAULT_COLLECT_RESOURCES
                            ),
                            "securityContext": _hardened_security_context(),
                            # How the controller learns the outcome without a
                            # token on this pod or the results volume mounted into
                            # the operator.
                            "terminationMessagePath": "/dev/termination-log",
                            "terminationMessagePolicy": "File",
                        }
                    ],
                },
            },
        },
    }


def build_results_pvc(*, scan: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any] | None:
    """Return the results PVC, or None when the CR supplies its own claim.

    ``ReadWriteMany`` by default, because every shard pod and the collector write
    to and read from it concurrently and they are not guaranteed to land on one
    node. With ``parallelism: 1`` and ``ReadWriteOnce`` a single-node cluster works
    too, which is what the e2e uses.
    """
    existing = (spec.get("results") or {}).get("claimName")
    if existing:
        return None
    meta = scan["metadata"]
    results = spec.get("results") or {}
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": f"{meta['name']}-results",
            "namespace": meta["namespace"],
            "labels": {LABEL_SCAN_NAME: meta["name"], LABEL_SCAN_UID: meta["uid"]},
            "ownerReferences": [owner_reference(scan, "AshScan")],
        },
        "spec": {
            "accessModes": results.get("accessModes") or ["ReadWriteOnce"],
            "resources": {"requests": {"storage": results.get("size") or "2Gi"}},
            **(
                {"storageClassName": results["storageClassName"]}
                if results.get("storageClassName")
                else {}
            ),
        },
    }


def build_mcp_deployment(
    *, server: dict[str, Any], spec: dict[str, Any], configmap_name: str, has_config: bool
) -> dict[str, Any]:
    """Return the Deployment for a long-lived ``ashx mcp`` server.

    A different deployment shape from the shard dispatcher, and the CRD is separate
    for that reason: this is one long-lived process serving MCP over HTTP, not a
    batch fan-out. The two kinds share only the config-delivery mechanism.
    """
    meta = server["metadata"]
    transport = spec.get("transport", "streamable-http")
    port = int(spec.get("port") or 8000)
    mount_path = spec.get("mountPath") or "/mcp"
    auth = spec.get("auth") or {}
    auth_header_name = auth.get("headerName")
    secret_ref = auth.get("valueFrom", {}).get("secretKeyRef")

    argv = contract.build_mcp_argv(
        transport=transport,
        host="0.0.0.0",  # noqa: S104  # nosec B104 - must bind all interfaces for the Service
        port=port,
        mount_path=mount_path,
        stateless_http=bool(spec.get("statelessHttp", False)),
        allowed_hosts=spec.get("allowedHosts"),
        auth_header_name=auth_header_name,
        auth_value_from_environment=bool(auth_header_name),
    )

    env: list[dict[str, Any]] = []
    if has_config:
        env.append({"name": "ASH_CONFIG", "value": CONFIG_PATH})
    if auth_header_name:
        if not secret_ref:
            raise contract.ContractError(
                "auth.headerName requires auth.valueFrom.secretKeyRef. Putting the "
                "expected header value inline would publish a shared secret in the "
                "pod spec, where `kubectl describe pod` shows it."
            )
        env.append(
            {
                "name": "ASH_MCP_AUTH_HEADER_VALUE",
                "valueFrom": {"secretKeyRef": dict(secret_ref)},
            }
        )
        # Tells MCP_ENTRYPOINT that a value is mandatory. Kept separate from the
        # value's own presence so an empty or missing Secret key is a refusal with a
        # message, rather than silently taking the no-auth branch -- which would
        # publish an unauthenticated MCP endpoint for a CR that asked for auth.
        env.append({"name": "ASH_MCP_AUTH_REQUIRED", "value": "1"})

    labels = {LABEL_MCP_NAME: meta["name"], LABEL_ROLE: ROLE_MCP}
    volumes: list[dict[str, Any]] = [{"name": "ash-tmp", "emptyDir": {}}]
    mounts: list[dict[str, Any]] = [{"name": "ash-tmp", "mountPath": TMP_MOUNT}]
    if has_config:
        volumes.append(
            {
                "name": "ash-config",
                "configMap": {"name": configmap_name, "defaultMode": 0o444},
            }
        )
        mounts.append({"name": "ash-config", "mountPath": CONFIG_MOUNT, "readOnly": True})

    # tcpSocket, not httpGet, and this was measured rather than chosen on taste.
    # `ashx mcp --transport streamable-http --mount-path /mcp` answers **401** to a
    # bare GET on that path, and 401 to a well-formed `initialize` POST without a
    # session -- the MCP SDK will not serve a request that is not a protocol
    # handshake. A kubelet httpGet probe treats only 200-399 as success, so an
    # httpGet probe on the mount path can never pass: the pod stays unready, the
    # Deployment never becomes Available, and the symptom is a rollout that times out
    # while the server is working perfectly. Measured in this operator's own e2e,
    # which failed exactly that way before the probe was changed.
    #
    # A probe that spoke MCP properly would need the auth header value, i.e. the
    # shared secret, in the probe definition -- visible in `kubectl describe pod`.
    # A TCP connect proves the process is listening on the port it was told to bind,
    # which is the most a probe can establish without either of those costs.
    probe = {
        "tcpSocket": {"port": port},
        "initialDelaySeconds": 5,
        "periodSeconds": 10,
        "failureThreshold": 3,
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": meta["name"],
            "namespace": meta["namespace"],
            "labels": labels,
            "ownerReferences": [owner_reference(server, "AshMcpServer")],
        },
        "spec": {
            "replicas": int(spec.get("replicas") or 1),
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "serviceAccountName": spec.get("serviceAccountName") or SCAN_SERVICE_ACCOUNT,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": int(spec.get("runAsUser") or 1000),
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "volumes": volumes,
                    "containers": [
                        {
                            "name": "ash-mcp",
                            "image": spec["image"],
                            "imagePullPolicy": spec.get("imagePullPolicy", "IfNotPresent"),
                            # The first positional is a label, not part of the argv:
                            # `sh -c <script> $0 $1 …` binds $0 to it and "$@" to the
                            # rest, so MCP_ENTRYPOINT's `exec "$@"` runs exactly argv.
                            # The auth value is expanded inside the script text, never
                            # passed as a positional -- see MCP_ENTRYPOINT.
                            "command": [
                                "/bin/sh",
                                "-c",
                                MCP_ENTRYPOINT,
                                "ash-mcp-entrypoint",
                                *argv,
                            ],
                            "env": env,
                            "ports": [{"name": "mcp", "containerPort": port}],
                            "volumeMounts": mounts,
                            "resources": spec.get("resources") or {},
                            "securityContext": _hardened_security_context(),
                            "livenessProbe": probe,
                            "readinessProbe": dict(probe, initialDelaySeconds=2),
                        }
                    ],
                },
            },
        },
    }


def build_mcp_service(*, server: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    meta = server["metadata"]
    port = int(spec.get("port") or 8000)
    labels = {LABEL_MCP_NAME: meta["name"], LABEL_ROLE: ROLE_MCP}
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": meta["name"],
            "namespace": meta["namespace"],
            "labels": labels,
            "ownerReferences": [owner_reference(server, "AshMcpServer")],
        },
        "spec": {
            # ClusterIP only. A security tool's control surface does not get a
            # LoadBalancer by default; an adopter who wants one adds an Ingress
            # with their own authentication in front of it.
            "type": "ClusterIP",
            "selector": labels,
            "ports": [{"name": "mcp", "port": port, "targetPort": port}],
        },
    }
