"""The e2e applier's CA bundle lookup finds a bundle where Python's default has none.

A standalone CPython (the uv-managed one on the runner image) reports
``ssl.get_default_verify_paths().cafile`` as None, which the helper used to assert
against. This runs without a cluster, so the lookup is checked on every unit run.
"""

from __future__ import annotations

import ssl

import pytest

from tests.e2e import ca_bundle


class _NoCafile:
    cafile = None
    capath = "/etc/ssl/certs"


def test_a_python_with_no_default_cafile_uses_ssl_cert_file(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: _NoCafile())
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    assert ca_bundle.system_ca_bundle_path() == bundle


def test_with_no_environment_and_no_cafile_the_distribution_bundle_is_found(tmp_path, monkeypatch):
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: _NoCafile())
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.setattr(ca_bundle, "DISTRIBUTION_BUNDLES", (str(tmp_path / "absent"), str(bundle)))
    assert ca_bundle.system_ca_bundle_path() == bundle


def test_the_control_with_nothing_anywhere_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: _NoCafile())
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.setattr(ca_bundle, "DISTRIBUTION_BUNDLES", (str(tmp_path / "absent"),))
    monkeypatch.setitem(__import__("sys").modules, "certifi", None)  # import raises ImportError
    with pytest.raises(AssertionError, match="no CA bundle found"):
        ca_bundle.system_ca_bundle_path()
