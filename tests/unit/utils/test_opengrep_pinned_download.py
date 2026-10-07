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
* A configured version other than the pin installs only on a platform whose digest
  the configuration supplies (``scanners.opengrep.options.sha256``), through the
  same verified download; without one the install command refuses, and the
  refusal names the key and how to get the value. No path installs unverified.

Nothing here reaches the network: bytes are served through a patched ``urlopen``.
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)
from pydantic import ValidationError

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
    unverified_version_refusal,
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


CUSTOM = "v1.14.0"


def _custom_scanner(test_plugin_context, sha256=None):
    return OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(version=CUSTOM, sha256=sha256 or {})
        ),
    )


def _run_inline(command, tmp_path_dest: Path):
    """Execute a declared ``python -c`` install command in-process.

    The exact ``-c`` source the installer would run, with its exact argv, so what is
    tested is the command and not a re-implementation of it; only the subprocess and
    the socket are absent. The destination argument is replaced with a test path.
    """
    args = list(command.args)
    assert args[1] == "-c"
    argv = ["-c", *args[3:]]
    if len(argv) > 2:
        argv[2] = str(tmp_path_dest)
    with patch.object(sys, "argv", argv):
        exec(compile(args[2], "<install-command>", "exec"), {})  # nosec B102


class TestACustomVersionNeedsItsOwnDigest:
    """A version other than the pin installs only with a configured sha256."""

    def test_without_a_digest_every_platform_is_refused(self, test_plugin_context):
        scanner = _custom_scanner(test_plugin_context)
        for target_platform, arch in DECLARED_PLATFORMS:
            argv = scanner.custom_install_commands[target_platform][arch][0].args
            joined = " ".join(argv)
            assert "install_binary_from_url" not in joined
            assert "install_pinned_tool" not in joined
            assert argv[2] == "import sys; sys.exit(sys.argv[1])"

    def test_the_refusal_names_the_key_and_how_to_get_the_digest(
        self, test_plugin_context
    ):
        scanner = _custom_scanner(test_plugin_context)
        message = scanner.custom_install_commands["linux"]["amd64"][0].args[3]
        assert message == unverified_version_refusal(
            CUSTOM, "linux", "amd64", "opengrep_manylinux_x86"
        )
        assert message == (
            f"Refusing to install opengrep {CUSTOM} on linux/amd64: ASH pins opengrep "
            f"{TOOL_VERSIONS['opengrep']}, and the configuration supplies no SHA256 for "
            "linux/amd64, so the download could not be verified. Either drop "
            "scanners.opengrep.options.version to use the pinned "
            f"{TOOL_VERSIONS['opengrep']}, or add the digest of the release asset "
            "opengrep_manylinux_x86 under scanners.opengrep.options.sha256 as "
            '"linux/amd64": "<sha256>". Get it from the digest GitHub lists for that '
            f"asset (gh api repos/opengrep/opengrep/releases/tags/{CUSTOM} --jq "
            "'.assets[] | select(.name == \"opengrep_manylinux_x86\") | .digest'), or by "
            "running sha256sum opengrep_manylinux_x86 on the downloaded asset."
        )

    def test_the_refusal_command_exits_non_zero_with_the_message(
        self, test_plugin_context
    ):
        """Run for real: the installer must count it as a failed command."""
        import subprocess

        scanner = _custom_scanner(test_plugin_context)
        command = scanner.custom_install_commands["darwin"]["arm64"][0]
        result = subprocess.run(  # nosec B603 - argv built by the plugin, no shell
            command.args, capture_output=True, text=True, timeout=60, check=False
        )
        assert result.returncode == 1
        assert "scanners.opengrep.options.sha256" in result.stderr
        assert "opengrep_osx_arm64" in result.stderr

    def test_a_digest_for_one_platform_does_not_unlock_another(
        self, test_plugin_context
    ):
        scanner = _custom_scanner(test_plugin_context, {"linux/amd64": "a" * 64})
        linux = scanner.custom_install_commands["linux"]["amd64"][0].args
        arm = scanner.custom_install_commands["linux"]["arm64"][0].args
        assert "install_binary_from_url" in linux[2]
        assert arm[2] == "import sys; sys.exit(sys.argv[1])"

    def test_with_a_digest_it_goes_through_the_verified_download(
        self, test_plugin_context
    ):
        scanner = _custom_scanner(test_plugin_context, {"linux/amd64": "A" * 64})
        argv = scanner.custom_install_commands["linux"]["amd64"][0].args
        assert "install_binary_from_url" in argv[2]
        assert "expected_sha256=sys.argv[3]" in argv[2]
        assert argv[3].endswith(f"/{CUSTOM}/opengrep_manylinux_x86")
        assert argv[5] == "a" * 64
        assert argv[6] == "opengrep"

    def test_a_matching_custom_digest_installs(self, test_plugin_context, tmp_path):
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        scanner = _custom_scanner(test_plugin_context, {"linux/amd64": digest})
        command = scanner.custom_install_commands["linux"]["amd64"][0]
        bin_dir = tmp_path / "bin"
        with _serve(PAYLOAD):
            _run_inline(command, bin_dir)
        assert (bin_dir / "opengrep").read_bytes() == PAYLOAD
        assert read_receipt(bin_dir, "opengrep")["sha256"] == digest

    def test_a_mismatched_custom_digest_installs_nothing(
        self, test_plugin_context, tmp_path
    ):
        scanner = _custom_scanner(test_plugin_context, {"linux/amd64": "0" * 64})
        command = scanner.custom_install_commands["linux"]["amd64"][0]
        bin_dir = tmp_path / "bin"
        with (
            _serve(PAYLOAD),
            pytest.raises(ToolDownloadIntegrityError, match="SHA256 mismatch"),
        ):
            _run_inline(command, bin_dir)
        assert not (bin_dir / "opengrep").exists()
        assert read_receipt(bin_dir, "opengrep") is None

    @pytest.mark.parametrize(
        "sha256",
        [
            {"linux/amd64": "not-a-digest"},
            {"linux/amd64": "a" * 63},
            {"linux-amd64": "a" * 64},
            {"windows/arm64": "a" * 64},
        ],
    )
    def test_a_malformed_digest_or_platform_is_a_config_error(self, sha256):
        with pytest.raises(ValidationError):
            OpengrepScannerConfigOptions(version=CUSTOM, sha256=sha256)

    def test_the_pinned_version_ignores_a_configured_digest(self, test_plugin_context):
        """The pin's digests ship with ASH and cannot be overridden from config."""
        scanner = OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(sha256={"linux/amd64": "0" * 64})
            ),
        )
        argv = scanner.custom_install_commands["linux"]["amd64"][0].args
        assert "install_pinned_tool" in argv[2]
        assert "0" * 64 not in argv


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


class TestTheReleaseAssetCacheCoversOpengrep:
    """ASH_TOOL_DOWNLOAD_CACHE wraps the bare-executable path too, not only archives.

    opengrep's asset is the executable itself, so it takes a different branch of
    install_pinned_tool from grype or syft. That branch has to restore from and store
    to the same cache, with the same rule: a cached copy is used only if it hashes to
    the pin, and anything else is deleted and downloaded again.
    """

    @pytest.fixture
    def cache_dir(self, tmp_path, monkeypatch):
        directory = tmp_path / "asset-cache"
        monkeypatch.setenv("ASH_TOOL_DOWNLOAD_CACHE", str(directory))
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path / "home"))
        return directory

    def test_a_download_is_stored_and_a_verified_copy_is_reused(
        self, tmp_path, cache_dir
    ):
        filename = _ASSET_TABLES["opengrep"][("linux", "amd64")]
        digest = hashlib.sha256(PAYLOAD).hexdigest()

        with _pin(filename, digest), _serve(PAYLOAD):
            install_pinned_tool("opengrep", "linux", "amd64", tmp_path / "bin-a")
        assert (cache_dir / filename).read_bytes() == PAYLOAD

        exploding = patch(
            "automated_security_helper.utils.download_utils.download_file",
            side_effect=AssertionError(
                "downloaded opengrep although a verified copy was cached"
            ),
        )
        with _pin(filename, digest), exploding:
            installed = install_pinned_tool(
                "opengrep", "linux", "amd64", tmp_path / "bin-b"
            )
        assert installed == tmp_path / "bin-b" / "opengrep"
        assert installed.read_bytes() == PAYLOAD
        assert read_receipt(tmp_path / "bin-b", "opengrep")["installed_sha256"] == (
            digest
        )
        # Installing moved a copy, not the cached asset itself.
        assert (cache_dir / filename).read_bytes() == PAYLOAD

    def test_a_tampered_cached_asset_is_discarded_and_redownloaded(
        self, tmp_path, cache_dir
    ):
        filename = _ASSET_TABLES["opengrep"][("linux", "amd64")]
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        cache_dir.mkdir(parents=True)
        (cache_dir / filename).write_bytes(b"#!/bin/sh\necho evil\n")

        with _pin(filename, digest), _serve(PAYLOAD) as served:
            installed = install_pinned_tool(
                "opengrep", "linux", "amd64", tmp_path / "bin"
            )

        assert served.called, "the tampered cached opengrep was used, not re-downloaded"
        assert installed.read_bytes() == PAYLOAD
        # The cache now holds the verified download, not the tampered file.
        assert (cache_dir / filename).read_bytes() == PAYLOAD
