"""Operator entrypoint: ``python -m ash_operator``.

Importing both controller modules is what registers their kopf handlers; the
import is the registration, so the unused-import suppressions below are load-
bearing rather than cosmetic.
"""

from __future__ import annotations

import logging

import kopf

from ash_operator import auth as _auth  # noqa: F401 - registers the login handler
from ash_operator import mcp_controller as _mcp  # noqa: F401 - registers handlers
from ash_operator import scan_controller as _scan  # noqa: F401 - registers handlers

LOG = logging.getLogger("ash_operator")


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    # kopf's own authentication does not configure the `kubernetes` client the
    # handlers use to create Jobs and ConfigMaps. Without this, every handler fails
    # with "No host specified." -- see ash_operator.auth for why there are two.
    LOG.info("kubernetes client configured from %s", _auth.configure_kubernetes_client())
    # Events are posted on the custom resources rather than only logged, because
    # `kubectl describe ashscan` is where an adopter looks first, and a refusal that
    # exists only in the operator's log is a refusal nobody sees.
    settings.posting.level = logging.INFO
    # No delete handler is registered anywhere in this operator, so kopf adds no
    # finalizer, and deleting an AshScan is never blocked on the operator being
    # reachable. Child objects carry ownerReferences and are collected by the
    # garbage collector instead. That is the intended arrangement: a stuck
    # finalizer on a security tool's CR turns an operator outage into an
    # undeletable object.
    settings.watching.connect_timeout = 60
    settings.watching.server_timeout = 600


def run() -> None:  # pragma: no cover - exercised by the e2e, not by unit tests
    # Namespaced rather than cluster-wide by default: a security scanner's
    # controller should not need list/watch across every namespace to do its job,
    # and the RBAC that follows from `clusterwide=True` is much broader.
    kopf.run(clusterwide=False)


if __name__ == "__main__":  # pragma: no cover
    run()
