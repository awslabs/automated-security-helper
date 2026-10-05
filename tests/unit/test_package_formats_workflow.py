# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The push-triggered package-formats caller does not hand signing secrets to the build.

.github/workflows/ash-package-formats.yml runs the whole ash-package.yml matrix on
every branch push. The msix job there signs with MSIX_SIGNING_PFX_* when they are set
and with a throwaway self-signed certificate when they are empty. A called workflow
that is passed no secrets sees them as empty, so leaving `secrets:` off keeps every
branch-push .msix self-signed even after a real certificate is configured.
`secrets: inherit` would instead put a production-signed package of unreviewed code
into a run artifact.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CALLER = REPO_ROOT / ".github" / "workflows" / "ash-package-formats.yml"
CALLEE = REPO_ROOT / ".github" / "workflows" / "ash-package.yml"
BUILD_PS1 = REPO_ROOT / "packaging" / "msix" / "build.ps1"


def _jobs(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


def test_the_caller_passes_no_secrets_to_the_package_build():
    calls = {
        name: job
        for name, job in _jobs(CALLER).items()
        if str(job.get("uses", "")).endswith("/ash-package.yml")
    }
    assert calls, "ash-package-formats.yml no longer calls ash-package.yml"
    for name, job in calls.items():
        assert "secrets" not in job, (
            f"job {name!r} passes secrets ({job['secrets']!r}) to ash-package.yml"
        )


def test_empty_signing_secrets_take_the_self_signed_path():
    # The other half of the argument above: an empty secret has to mean "self-sign",
    # not "fail" and not "skip signing". build.ps1 branches on the base64 input alone.
    text = BUILD_PS1.read_text(encoding="utf-8")
    assert "if ($Base64) {" in text
    assert "New-SelfSignedCertificate" in text
    assert "secrets.MSIX_SIGNING_PFX_BASE64" in CALLEE.read_text(encoding="utf-8")
