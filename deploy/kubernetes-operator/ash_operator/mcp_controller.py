"""The AshMcpServer reconciler.

**What "MCP server instances" means here, and the decision behind it.** ASH's MCP
configuration surface -- ``AshMcpConfig``, ``MCPResourceManagementConfig``, the
JSON-Patch allowlist in ``RuntimeOverridesConfig`` -- is about ASH *serving* MCP
over streamable HTTP, including a runtime config-override allowlist for clients.
ASH is not a client of other MCP servers: there is no outbound MCP transport, no
server registry, nothing that takes a peer's address. So the three candidate
readings of the requirement do not have equal standing:

* *Launch them* -- the operator runs ``ash mcp`` as a Deployment behind a Service.
  This is implemented.
* *Connect to existing ones* -- there is nothing in ASH to connect with. It would
  mean writing an MCP client ASH does not have, into a security tool, and giving
  it credentials for third-party endpoints.
* *Pass addresses through* -- nothing in ASH consumes an MCP server address, so
  the field would be config that reaches no reader.

So this is the narrowest option that does anything at all, not a choice among
three. It is also a genuinely different deployment shape from the shard
dispatcher: one long-lived process, no fan-out, no merge -- which is why it is a
second CRD and a second reconciler rather than a mode of AshScan. The two share
only the config-delivery mechanism.

If an adopter's requirement is really "ASH should call out to my MCP servers",
that is an ASH feature request and not something this operator can paper over; the
CRD deliberately has no field that would imply otherwise.

**The capability probe.** ``--stateless-http`` is required behind anything that may
route consecutive requests to different replicas. An image whose ASH predates the
flag ignores it: the server then runs stateful, answers 404 to every session id
the platform injects, and still passes a TCP health check. The Deployment's init
container runs ``COLUMNS=200 ash mcp --help`` and refuses to start -- exit 65 --
when stateless was asked for and the flag is absent. ``--allowed-host`` warns
instead of refusing, because an adopter behind a load balancer cannot know the
hostname in advance and a refusal there would block a working deployment.
"""

from __future__ import annotations

import logging
from typing import Any

import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException

from ash_operator import manifests
from ash_operator.constants import (
    CONFIG_MOUNT,
    GROUP,
    MCP_PLURAL,
    TMP_MOUNT,
    VERSION,
)
from ash_operator.contract import ContractError

LOG = logging.getLogger("ash_operator.mcp")

# Exit 65 is EX_DATAERR: the input -- the image -- cannot satisfy the request.
CAPABILITY_PROBE = r"""
set -u
log() { printf '%s %s\n' "[ash-mcp-probe]" "$*" >&2; }
HELP="$(COLUMNS=200 ash mcp --help 2>&1)" || {
  log "FATAL: 'ash mcp --help' failed. This image has no usable ash mcp."
  exit 65
}
if [ "${ASH_REQUIRE_STATELESS_HTTP:-0}" = "1" ]; then
  # Fixed-string grep on the long option, not a regex: the help text is rendered
  # with line wrapping and colour, and a loose pattern would match the prose that
  # describes the flag in an image that does not have it.
  if printf '%s' "$HELP" | grep -qF -- '--stateless-http'; then
    log "image supports --stateless-http"
  else
    log "FATAL: statelessHttp was requested but this image's ash mcp has no"
    log "--stateless-http. Without it the server runs stateful, answers 404 to"
    log "every session id the platform injects, and still passes its health check."
    exit 65
  fi
fi
if [ -n "${ASH_ALLOWED_HOSTS:-}" ]; then
  if printf '%s' "$HELP" | grep -qF -- '--allowed-host'; then
    log "image supports --allowed-host"
  else
    # A warning and not a refusal: an adopter behind a load balancer cannot know
    # the hostname before the load balancer exists, so refusing here would block a
    # deployment that is about to work.
    log "WARNING: allowedHosts was set but this image's ash mcp has no"
    log "--allowed-host. DNS-rebinding protection will use the SDK default, which"
    log "enables it only for a loopback bind."
  fi
fi
exit 0
"""


@kopf.on.create(GROUP, VERSION, MCP_PLURAL)
@kopf.on.update(GROUP, VERSION, MCP_PLURAL)
@kopf.on.resume(GROUP, VERSION, MCP_PLURAL)
def reconcile_mcp(spec, meta, patch, body, **_):
    spec = dict(spec)
    if not spec.get("image"):
        raise kopf.PermanentError(
            "spec.image is required; ASH publishes no public container image."
        )
    server = {"metadata": dict(meta)}
    namespace = meta["namespace"]
    apps = kubernetes.client.AppsV1Api()
    core = kubernetes.client.CoreV1Api()

    ash_config = spec.get("config") or None
    configmap = manifests.build_run_configmap(scan=server, ash_config=ash_config)
    # An AshMcpServer's ConfigMap is owned by an AshMcpServer, not an AshScan.
    configmap["metadata"]["ownerReferences"] = [manifests.owner_reference(server, "AshMcpServer")]
    _apply(lambda b: core.create_namespaced_config_map(namespace, b), configmap, "ConfigMap")

    try:
        deployment = manifests.build_mcp_deployment(
            server=server,
            spec=spec,
            configmap_name=configmap["metadata"]["name"],
            has_config=ash_config is not None,
        )
    except ContractError as err:
        raise kopf.PermanentError(str(err)) from err
    _attach_capability_probe(deployment, spec)
    service = manifests.build_mcp_service(server=server, spec=spec)

    _apply_or_replace(
        create=lambda b: apps.create_namespaced_deployment(namespace, b),
        replace=lambda name, b: apps.patch_namespaced_deployment(name, namespace, b),
        body=deployment,
        what="Deployment",
    )
    _apply(lambda b: core.create_namespaced_service(namespace, b), service, "Service")

    port = int(spec.get("port") or 8000)
    mount = spec.get("mountPath") or "/mcp"
    patch.status["phase"] = "Deployed"
    patch.status["endpoint"] = f"http://{meta['name']}.{namespace}.svc.cluster.local:{port}{mount}"
    patch.status["configMapName"] = configmap["metadata"]["name"]
    patch.status["statelessHttp"] = bool(spec.get("statelessHttp", False))
    kopf.info(body, reason="Deployed", message=f"ash mcp serving on {mount}:{port}")


def _attach_capability_probe(deployment: dict[str, Any], spec: dict[str, Any]) -> None:
    pod_spec = deployment["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    allowed = ",".join(spec.get("allowedHosts") or [])
    pod_spec["initContainers"] = [
        {
            "name": "ash-mcp-capability-probe",
            "image": container["image"],
            "imagePullPolicy": container["imagePullPolicy"],
            "command": ["/bin/sh", "-c", CAPABILITY_PROBE],
            "env": [
                {
                    "name": "ASH_REQUIRE_STATELESS_HTTP",
                    "value": "1" if spec.get("statelessHttp") else "0",
                },
                {"name": "ASH_ALLOWED_HOSTS", "value": allowed},
            ],
            "volumeMounts": [
                m for m in container["volumeMounts"] if m["mountPath"] in (TMP_MOUNT, CONFIG_MOUNT)
            ],
            "securityContext": container["securityContext"],
            "resources": container.get("resources") or {},
        }
    ]


def _apply(create, body: dict[str, Any], what: str) -> None:
    try:
        create(body)
        LOG.info("created %s %s", what, body["metadata"]["name"])
    except ApiException as err:
        if err.status != 409:
            raise
        LOG.debug("%s %s already exists", what, body["metadata"]["name"])


def _apply_or_replace(*, create, replace, body: dict[str, Any], what: str) -> None:
    try:
        create(body)
        LOG.info("created %s %s", what, body["metadata"]["name"])
    except ApiException as err:
        if err.status != 409:
            raise
        replace(body["metadata"]["name"], body)
        LOG.info("patched %s %s", what, body["metadata"]["name"])
