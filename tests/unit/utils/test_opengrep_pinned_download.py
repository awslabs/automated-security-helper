# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""opengrep is installed from a pinned, digest-verified release asset.

Why this file exists
--------------------
Until this change opengrep was the one scanner binary ASH downloaded with no digest
at all. ``OpengrepScanner`` built its install commands from ``get_opengrep_url`` and
``create_url_download_command``, which passes no SHA256, so ``_download_verified``
logged "integrity was not verified" and installed whatever the URL served. The
reusable workflow did the same with a bare ``gh release download``, of no particular
release, and trusted a cache-restored copy on ``[ -x ]`` alone.

What is pinned here
-------------------
* Every platform ASH declares an opengrep install for -- linux and darwin on both
  arches, windows on amd64 -- resolves to a pinned asset with a digest, and the
  scanner plugin's install commands for the default version are exactly the pinned
  ones.
* A digest mismatch refuses the install and leaves nothing at the destination. The
  positive control beside it installs the same bytes under a matching pin, so the
  refusal cannot pass because the path is broken for every input.
* The nix package pins four of the same five assets independently (nix has no
  windows build); its hashes must equal the table's, or nix mode and container mode
  run different opengrep binaries while both claim to be pinned.
* A version bump that leaves the digests behind is refused by name, not left to
  surface as a SHA256 mismatch that reads like a supply-chain substitution.

Nothing here reaches the network: bytes are served through a patched ``urlopen``.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.download_utils import (
    install_pinned_tool,
    read_receipt,
)
from automated_security_helper.utils.tool_downloads import (
    _ASSET_TABLES,
    _DIGESTS,
    TOOL_VERSIONS,
    get_tool_asset,
    supported_platforms,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
NIX_OPENGREP = REPO_ROOT / "nix" / "opengrep.nix"

# The platform/arch pairs OpengrepScanner declared install commands for before this
# change. The pinned table has to cover every one of them, or a platform that used
# to get opengrep would silently stop getting it.
DECLARED_PLATFORMS = [
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
]

PAYLOAD = b"\x7fELF-opengrep-fixture"


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload
        self._read = False

    def read(self, *_args):
        if self._read:
            return b""
        self._read = True
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _serve(payload: bytes):
    return patch(
        "automated_security_helper.utils.download_utils.urllib.request.urlopen",
        side_effect=lambda *_a, **_k: _FakeResponse(payload),
    )


def _pin(filename: str, digest: str):
    patched = dict(_DIGESTS)
    patched[filename] = digest
    return patch.object(tool_downloads, "_DIGESTS", patched)


class TestEveryDeclaredPlatformIsPinned:
    def test_the_table_covers_every_platform_the_scanner_installs_on(self):
        assert sorted(supported_platforms("opengrep")) == DECLARED_PLATFORMS

    @pytest.mark.parametrize("target_platform,arch", DECLARED_PLATFORMS)
    def test_each_platform_resolves_to_a_pinned_bare_executable(
        self, target_platform, arch
    ):
        asset = get_tool_asset("opengrep", target_platform, arch)
        filename = asset.url.rsplit("/", 1)[-1]
        assert asset.sha256 == _DIGESTS[filename]
        assert re.fullmatch(r"[0-9a-f]{64}", asset.sha256)
        assert f"/{TOOL_VERSIONS['opengrep']}/" in asset.url
        assert asset.url.startswith(
            "https://github.com/opengrep/opengrep/releases/download/"
        )
        # opengrep publishes the executable itself, so there is nothing to extract
        # and the pin covers the file that runs.
        assert asset.archive is False
        expected_name = "opengrep.exe" if target_platform == "windows" else "opengrep"
        assert asset.install_as == expected_name

    def test_the_pin_is_the_scanner_default_version(self):
        """One version for the default, the pin and the digests."""
        assert OpengrepScannerConfigOptions().version == TOOL_VERSIONS["opengrep"]

    def test_only_manylinux_is_pinned(self):
        """The scanner hardcodes manylinux; a musllinux pin would be dead weight."""
        names = set(_ASSET_TABLES["opengrep"].values())
        assert not any("musllinux" in n for n in names)


class TestThePluginInstallsThroughThePin:
    def test_default_version_uses_the_pinned_installer_on_every_platform(
        self, test_plugin_context
    ):
        scanner = OpengrepScanner(
            context=test_plugin_context, config=OpengrepScannerConfig()
        )
        for target_platform, arch in DECLARED_PLATFORMS:
            commands = scanner.custom_install_commands[target_platform][arch]
            assert len(commands) == 1
            argv = commands[0].args
            assert "install_pinned_tool" in argv[2], (
                f"{target_platform}/{arch} does not install through the pin: {argv}"
            )
            assert argv[3:6] == ["opengrep", target_platform, arch]

    def test_no_command_for_the_default_version_is_an_unverified_url_download(
        self, test_plugin_context
    ):
        """The regression: install_binary_from_url with no digest."""
        scanner = OpengrepScanner(
            context=test_plugin_context, config=OpengrepScannerConfig()
        )
        for per_arch in scanner.custom_install_commands.values():
            for commands in per_arch.values():
                for command in commands:
                    assert "install_binary_from_url" not in " ".join(command.args)

    def test_a_version_configured_away_from_the_pin_keeps_the_url_download(
        self, test_plugin_context
    ):
        """Documented trade-off, pinned so it cannot change silently.

        There is no digest for a version the table does not pin. That path logs
        that integrity was not verified; refusing it would break configurations
        that name a version today.
        """
        scanner = OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(version="v1.14.0")
            ),
        )
        argv = scanner.custom_install_commands["linux"]["amd64"][0].args
        assert "install_binary_from_url" in argv[2]
        assert "/v1.14.0/" in argv[3]


class TestTheDigestCheckCanFail:
    def test_a_mismatched_digest_installs_nothing(self, tmp_path):
        filename = _ASSET_TABLES["opengrep"][("linux", "amd64")]
        bin_dir = tmp_path / "bin"
        with (
            _pin(filename, "0" * 64),
            _serve(PAYLOAD),
            pytest.raises(ToolDownloadIntegrityError, match="SHA256 mismatch"),
        ):
            install_pinned_tool("opengrep", "linux", "amd64", bin_dir)
        assert not (bin_dir / "opengrep").exists()
        assert list(bin_dir.iterdir()) == [], "a refused download left a file behind"
        assert read_receipt(bin_dir, "opengrep") is None

    def test_the_real_pin_refuses_bytes_that_are_not_the_release(self, tmp_path):
        """Unpatched table: the committed digest itself is what refuses."""
        bin_dir = tmp_path / "bin"
        with (
            _serve(PAYLOAD),
            pytest.raises(ToolDownloadIntegrityError, match="SHA256 mismatch"),
        ):
            install_pinned_tool("opengrep", "linux", "arm64", bin_dir)
        assert not (bin_dir / "opengrep").exists()

    def test_positive_control_matching_digest_installs_the_bytes(self, tmp_path):
        filename = _ASSET_TABLES["opengrep"][("linux", "amd64")]
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        bin_dir = tmp_path / "bin"
        with _pin(filename, digest), _serve(PAYLOAD):
            installed = install_pinned_tool("opengrep", "linux", "amd64", bin_dir)
        assert installed == bin_dir / "opengrep"
        assert installed.read_bytes() == PAYLOAD
        receipt = read_receipt(bin_dir, "opengrep")
        # Bare executable: the pin and the installed file's digest are one value.
        assert receipt["sha256"] == digest
        assert receipt["installed_sha256"] == digest
        assert receipt["version"] == TOOL_VERSIONS["opengrep"]

    def test_a_half_applied_version_bump_is_refused_by_name(self):
        with (
            patch.dict(tool_downloads.TOOL_VERSIONS, {"opengrep": "v9.9.9"}),
            pytest.raises(ToolNotProvisionableError, match="half-applied"),
        ):
            get_tool_asset("opengrep", "linux", "amd64")


class TestNixPinsTheSameBytes:
    def _nix_pins(self) -> dict[str, str]:
        text = NIX_OPENGREP.read_text(encoding="utf-8")
        pairs = re.findall(
            r'name = "([^"]+)";\s*hash = "sha256-([A-Za-z0-9+/=]+)";', text
        )
        return {name: base64.b64decode(sri).hex() for name, sri in pairs}

    def test_nix_and_the_table_agree_on_every_shared_asset(self):
        nix = self._nix_pins()
        # Positive control: a regex that matched nothing would make the loop vacuous.
        assert len(nix) == 4, f"expected 4 nix opengrep pins, parsed {nix}"
        for name, digest in nix.items():
            assert _DIGESTS.get(name) == digest, (
                f"nix/opengrep.nix pins {name} at {digest} but tool_downloads.py "
                f"pins {_DIGESTS.get(name)}"
            )

    def test_nix_and_the_table_agree_on_the_version(self):
        match = re.search(
            r'^\s*version = "([^"]+)";', NIX_OPENGREP.read_text(), re.MULTILINE
        )
        assert match, "nix/opengrep.nix has no version line"
        assert f"v{match.group(1)}" == TOOL_VERSIONS["opengrep"]
