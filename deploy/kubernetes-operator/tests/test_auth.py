"""In-cluster authentication.

The bug this guards against was measured, not hypothesised: kopf 1.37.2 with the
official ``kubernetes`` client 36.0.3 sends every request as ``system:anonymous``
from a pod that has a working projected token, because the client stores the bearer
token under ``api_key['BearerToken']`` and kopf reads ``api_key['authorization']``.
The login activity still reports success, so the symptom is a 403 that names RBAC.
"""

from __future__ import annotations

import datetime

from ash_operator.auth import REAUTH_INTERVAL, in_cluster_connection


def write_service_account(tmp_path, token="tok", ca=True, namespace="ash-system"):
    directory = tmp_path / "serviceaccount"
    directory.mkdir()
    if token is not None:
        (directory / "token").write_text(token)
    if ca:
        (directory / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\n")
    if namespace is not None:
        (directory / "namespace").write_text(namespace)
    return directory


# What the bearer-token test writes into the projected file and expects back.
PROJECTED = "the-projected-token"
ENV = {"KUBERNETES_SERVICE_HOST": "10.96.0.1", "KUBERNETES_SERVICE_PORT": "443"}


class TestInClusterConnection:
    def test_it_carries_the_bearer_token(self, tmp_path):
        directory = write_service_account(tmp_path, token=PROJECTED + "\n")
        info = in_cluster_connection(service_account_dir=directory, env=ENV)
        assert info is not None
        assert info.token == PROJECTED
        assert info.scheme == "Bearer"

    def test_it_points_at_the_api_server_from_the_environment(self, tmp_path):
        directory = write_service_account(tmp_path)
        info = in_cluster_connection(service_account_dir=directory, env=ENV)
        assert info.server == "https://10.96.0.1:443"

    def test_a_missing_port_defaults_to_443(self, tmp_path):
        directory = write_service_account(tmp_path)
        info = in_cluster_connection(
            service_account_dir=directory, env={"KUBERNETES_SERVICE_HOST": "1.2.3.4"}
        )
        assert info.server == "https://1.2.3.4:443"

    def test_it_uses_the_projected_ca(self, tmp_path):
        directory = write_service_account(tmp_path)
        info = in_cluster_connection(service_account_dir=directory, env=ENV)
        assert info.ca_path == str(directory / "ca.crt")
        assert info.insecure in (False, None)

    def test_it_carries_the_pods_namespace(self, tmp_path):
        directory = write_service_account(tmp_path, namespace="somewhere-else")
        info = in_cluster_connection(service_account_dir=directory, env=ENV)
        assert info.default_namespace == "somewhere-else"

    def test_it_sets_an_expiry_so_a_rotated_token_is_re_read(self, tmp_path):
        # A projected token defaults to an hour and the kubelet rewrites the file in
        # place. Without an expiry the operator authenticates fine for an hour and
        # then starts 401ing, which looks like an unrelated outage.
        directory = write_service_account(tmp_path)
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        info = in_cluster_connection(service_account_dir=directory, env=ENV, now=now)
        assert info.expiration == now + REAUTH_INTERVAL
        assert REAUTH_INTERVAL < datetime.timedelta(hours=1)

    def test_it_declines_outside_a_cluster(self, tmp_path):
        directory = write_service_account(tmp_path)
        assert in_cluster_connection(service_account_dir=directory, env={}) is None

    def test_it_declines_when_there_is_no_token_file(self, tmp_path):
        directory = write_service_account(tmp_path, token=None)
        assert in_cluster_connection(service_account_dir=directory, env=ENV) is None

    def test_an_empty_token_file_is_declined_rather_than_used(self, tmp_path):
        # Worse than a missing one: it would authenticate as anonymous, and the 403
        # that follows names RBAC rather than the empty file.
        directory = write_service_account(tmp_path, token="   \n")
        assert in_cluster_connection(service_account_dir=directory, env=ENV) is None

    def test_a_missing_ca_does_not_prevent_login(self, tmp_path):
        # Some clusters project no CA. Declining would be worse than letting the
        # system trust store decide.
        directory = write_service_account(tmp_path, ca=False)
        info = in_cluster_connection(service_account_dir=directory, env=ENV)
        assert info is not None
        assert info.ca_path is None


def test_kopfs_own_piggyback_reads_a_key_the_client_does_not_set():
    """Pin the incompatibility, so an upgrade that fixes it is noticed.

    If this starts failing, one of the two libraries changed and the workaround in
    ``ash_operator.auth`` may no longer be needed. That is a good outcome, and a
    failing test is how it gets noticed rather than the workaround living forever.
    """
    import inspect

    import kopf

    source = inspect.getsource(kopf.login_via_client)
    reads_authorization = "get_api_key_with_prefix('authorization')" in source

    import kubernetes.config.incluster_config as incluster

    setter = inspect.getsource(incluster.InClusterConfigLoader._set_config)
    writes_bearer_token = "api_key['BearerToken']" in setter

    assert reads_authorization and writes_bearer_token, (
        "kopf's login_via_client and the kubernetes client's in-cluster loader now "
        "agree on where the bearer token lives (reads_authorization="
        f"{reads_authorization}, writes_bearer_token={writes_bearer_token}). The "
        "explicit login handler in ash_operator.auth may no longer be necessary; "
        "re-measure before removing it."
    )
