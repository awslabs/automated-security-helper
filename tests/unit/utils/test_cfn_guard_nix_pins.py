# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""nix/cfn-guard.nix pins the same release assets as tool_downloads.py.

Nix mode, the container image and `ash dependencies install` must run the same
cfn-guard bytes. nixpkgs has no cfn-guard, so the flake wraps the pinned release
asset; a version or digest bumped in one place and not the other would make Nix mode
quietly run a different binary, or fail with a hash mismatch that names nothing ASH
owns.
"""

import base64
import re
from pathlib import Path

from automated_security_helper.utils.tool_downloads import _DIGESTS, TOOL_VERSIONS

NIX_CFN_GUARD = Path(__file__).resolve().parents[3] / "nix" / "cfn-guard.nix"


def _nix_pins() -> "dict[str, str]":
    text = NIX_CFN_GUARD.read_text(encoding="utf-8")
    pairs = re.findall(r'name = "([^"]+)";\s*hash = "sha256-([A-Za-z0-9+/=]+)";', text)
    return {f"{name}.tar.gz": base64.b64decode(sri).hex() for name, sri in pairs}


def test_nix_and_the_table_agree_on_every_shared_asset():
    nix = _nix_pins()
    # Positive control: a regex that matched nothing would make the loop vacuous.
    assert len(nix) == 4, f"expected 4 nix cfn-guard pins, parsed {nix}"
    for name, digest in nix.items():
        assert _DIGESTS.get(name) == digest, (
            f"nix/cfn-guard.nix pins {name} at {digest} but tool_downloads.py "
            f"pins {_DIGESTS.get(name)}"
        )


def test_nix_and_the_table_agree_on_the_version():
    match = re.search(
        r'^\s*version = "([^"]+)";', NIX_CFN_GUARD.read_text(), re.MULTILINE
    )
    assert match, "nix/cfn-guard.nix has no version line"
    assert match.group(1) == TOOL_VERSIONS["cfn-guard"]


def test_the_flake_puts_it_in_the_scanner_set():
    flake = (NIX_CFN_GUARD.parent.parent / "flake.nix").read_text(encoding="utf-8")
    assert "(cfnGuardFor system)" in flake
    assert "ASH_CFN_GUARD_RULES_DIR" in flake
    assert "install-pinned-tool.py" in flake
