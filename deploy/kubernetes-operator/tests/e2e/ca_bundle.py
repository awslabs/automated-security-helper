"""Find a PEM bundle of the system's certificate authorities, on any Python build.

``ssl.get_default_verify_paths().cafile`` is None on a standalone CPython such as the
uv-managed one the runner image installs: its OpenSSL looks for ``/etc/ssl/cert.pem``,
which the distribution does not ship, and only ``capath`` is set. The applier test
needs one real bundle that did not sign kind's API server, so the lookup falls back
through the places a bundle lives.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

#: Where a distribution puts its one-file bundle: Debian and Ubuntu, then Fedora and RHEL.
DISTRIBUTION_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
)


def candidate_bundles() -> list[str]:
    """Every place to look, in order: the environment, the build's default, the distro."""
    candidates = [os.environ.get("SSL_CERT_FILE") or ""]
    candidates.append(ssl.get_default_verify_paths().cafile or "")
    candidates.extend(DISTRIBUTION_BUNDLES)
    try:
        import certifi
    except ImportError:
        pass
    else:
        candidates.append(certifi.where())
    return [c for c in candidates if c]


def system_ca_bundle_path() -> Path:
    for candidate in candidate_bundles():
        if Path(candidate).is_file():
            return Path(candidate)
    raise AssertionError(
        f"no CA bundle found; looked at {candidate_bundles()} and {ssl.get_default_verify_paths()}"
    )
