"""In-cluster authentication, because kopf's own piggybacking silently produces none.

**Measured, not assumed.** With kopf 1.37.2 and the official ``kubernetes`` client
36.0.3, an operator pod with a perfectly good projected ServiceAccount token sends
every request as ``system:anonymous`` and the API server answers
``403 forbidden: User "system:anonymous" cannot get path "/api"``. kopf logs
``Activity 'login_via_client' succeeded`` first, so the failure reads as an RBAC
problem rather than an authentication one, and no amount of widening the Role fixes
it.

The mismatch is one dictionary key. ``kubernetes.config.incluster_config``'s
``_set_config`` stores the bearer token as::

    client_configuration.api_key['BearerToken'] = self.token

while kopf's ``login_via_client`` reads it back with::

    header = config.get_api_key_with_prefix('authorization')

``get_api_key_with_prefix('authorization')`` looks up ``api_key['authorization']``,
which the in-cluster loader never sets. It returns ``None``, kopf's
``ConnectionInfo`` is built with ``token=None``, and the login activity reports
success because it did return a ConnectionInfo -- just an anonymous one.

Rather than depend on which spelling a given pair of versions uses, this module
reads the three files the kubelet projects and builds the ConnectionInfo itself.
There is nothing clever in it, and that is the point: the service-account paths have
been stable for the whole life of the projected-token API, whereas the client
library's internal key names are not a contract.

Token rotation is handled too, and has to be: a projected token defaults to a
one-hour lifetime and the kubelet rewrites the file in place. ``expiration`` is set a
few minutes out so kopf's credentials vault re-runs this handler and re-reads the
file, well before the token the operator is holding stops working. Without it a
long-running operator authenticates fine for an hour and then starts 401ing, which
looks like an unrelated outage.
"""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path

import kopf

LOG = logging.getLogger("ash_operator.auth")

SERVICE_ACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TOKEN_FILE = SERVICE_ACCOUNT_DIR / "token"
CA_FILE = SERVICE_ACCOUNT_DIR / "ca.crt"
NAMESPACE_FILE = SERVICE_ACCOUNT_DIR / "namespace"

# Short enough that a rotated token is picked up long before the old one expires,
# long enough that the vault is not re-running the handler constantly. A projected
# token's default lifetime is an hour and the kubelet refreshes it at 80% of that.
REAUTH_INTERVAL = datetime.timedelta(minutes=5)


def in_cluster_connection(
    *,
    service_account_dir: Path = SERVICE_ACCOUNT_DIR,
    env: dict[str, str] | None = None,
    now: datetime.datetime | None = None,
) -> kopf.ConnectionInfo | None:
    """Build a ConnectionInfo from the projected ServiceAccount, or None.

    Returns ``None`` -- rather than raising -- when any part of the in-cluster
    environment is absent, so a developer running the operator against a kubeconfig
    falls through to kopf's own login without having to configure anything.
    """
    environ = os.environ if env is None else env
    host = environ.get("KUBERNETES_SERVICE_HOST")
    port = environ.get("KUBERNETES_SERVICE_PORT") or "443"
    token_file = service_account_dir / "token"
    if not host or not token_file.is_file():
        return None
    try:
        token = token_file.read_text().strip()
    except OSError as err:
        LOG.warning("%s exists but could not be read: %s", token_file, err)
        return None
    if not token:
        # An empty token file is worse than a missing one: it would authenticate as
        # anonymous and the 403 would name RBAC rather than the empty file.
        LOG.warning("%s is empty; refusing to authenticate anonymously", token_file)
        return None

    ca_file = service_account_dir / "ca.crt"
    namespace_file = service_account_dir / "namespace"
    reference = now or datetime.datetime.now(datetime.timezone.utc)
    return kopf.ConnectionInfo(
        server=f"https://{host}:{port}",
        ca_path=str(ca_file) if ca_file.is_file() else None,
        scheme="Bearer",
        token=token,
        default_namespace=(
            namespace_file.read_text().strip() if namespace_file.is_file() else None
        ),
        expiration=reference + REAUTH_INTERVAL,
    )


@kopf.on.login()
def login(**kwargs):
    """Authenticate in-cluster first, then fall back to kopf's own piggybacking."""
    info = in_cluster_connection()
    if info is not None:
        LOG.info("authenticated from the projected ServiceAccount at %s", TOKEN_FILE)
        return info
    LOG.info(
        "no in-cluster ServiceAccount found; falling back to kopf's client-library "
        "login (kubeconfig)"
    )
    return kopf.login_via_client(**kwargs)


def configure_kubernetes_client() -> str:
    """Configure the ``kubernetes`` client the handlers use, separately from kopf.

    Two authenticated clients, not one, and they do not share configuration. kopf
    watches with its own aiohttp session built from the ConnectionInfo above; the
    handlers create Jobs and ConfigMaps through the official ``kubernetes`` client,
    which reads a process-global ``Configuration``. Nothing populates that global as
    a side effect of kopf logging in, so without this call every handler fails with
    ``urllib3.exceptions.LocationValueError: No host specified.`` -- a message that
    names neither Kubernetes nor authentication and reads like a malformed URL in the
    operator's own code.

    ``load_incluster_config`` is the right call here even though kopf cannot read
    what it writes: the bug is in kopf's *reading* of ``api_key['BearerToken']``, and
    the client reads its own key correctly.

    Returns which path was taken, so startup logs say it rather than leaving it to be
    inferred from whether anything later worked.
    """
    import kubernetes.config

    try:
        kubernetes.config.load_incluster_config()
        return "in-cluster"
    except kubernetes.config.ConfigException:
        kubernetes.config.load_kube_config()
        return "kubeconfig"
