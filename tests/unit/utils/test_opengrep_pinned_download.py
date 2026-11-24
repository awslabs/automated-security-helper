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

import ast
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
    windows_zip_refusal,
)
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.download_utils import (
    install_pinned_tool,
    read_receipt,
    receipt_root,
)
from automated_security_helper.utils.tool_downloads import (
    _ASSET_TABLES,
    _DIGESTS,
    TOOL_VERSIONS,
    get_tool_asset,
    supported_platforms,
)

pytestmark = pytest.mark.usefixtures("receipt_home")


@pytest.mark.unit
def test_receipts_from_this_module_stay_out_of_the_real_home(tmp_path):
    """An install writes its receipt under Path.home(), here the test's own home.

    This module wrote two receipts into the developer's real ~/.ash/install-receipts.
    """
    assert receipt_root().is_relative_to(tmp_path), receipt_root()


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
        # The body copy checks the copied bytes against Content-Length
        # (_copy_whole_body), so the stand-in declares its own length.
        self.headers = {"Content-Length": str(len(payload))}

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


@pytest.mark.unit
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
        # opengrep publishes the executable itself on linux and macOS, so there is
        # nothing to extract and the pin covers the file that runs. From v2.0.0 its
        # Windows asset is a zip, which is extracted (and has an executable digest).
        assert asset.archive is (target_platform == "windows")
        assert filename.endswith(".zip") is (target_platform == "windows")
        expected_name = "opengrep.exe" if target_platform == "windows" else "opengrep"
        assert asset.install_as == expected_name

    def test_the_pin_is_the_scanner_default_version(self):
        """One version for the default, the pin and the digests."""
        assert OpengrepScannerConfigOptions().version == TOOL_VERSIONS["opengrep"]

    def test_one_linux_build_per_arch_is_pinned_under_its_2x_name(self):
        """v2.0.0 renamed ``opengrep_manylinux_*`` to ``opengrep_linux_*`` and made
        it one static build, so neither old name has a pin and a musllinux one would
        be dead weight."""
        names = set(_ASSET_TABLES["opengrep"].values())
        assert not any("musllinux" in n or "manylinux" in n for n in names)
        assert {"opengrep_linux_x86", "opengrep_linux_aarch64"} <= names

    def test_the_windows_zip_pins_its_executable_and_every_dll(self):
        asset = get_tool_asset("opengrep", "windows", "amd64")
        assert asset.url.endswith("/opengrep_windows_x86.zip")
        assert asset.member_name == "opengrep.exe"
        assert re.fullmatch(r"[0-9a-f]{64}", asset.executable_sha256)
        # The executable's own digest is not the zip's.
        assert asset.executable_digest != asset.sha256
        names = [name for name, _ in asset.companion_sha256]
        assert len(names) == 6 and names == sorted(names)
        assert all(name.endswith(".dll") for name in names)
        assert all(re.fullmatch(r"[0-9a-f]{64}", d) for _, d in asset.companion_sha256)

    @pytest.mark.parametrize("target_platform,arch", DECLARED_PLATFORMS)
    def test_only_the_windows_asset_has_companions(self, target_platform, arch):
        asset = get_tool_asset("opengrep", target_platform, arch)
        assert bool(asset.companion_sha256) is (target_platform == "windows")


@pytest.mark.unit
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

    @pytest.mark.unit
    def test_without_a_digest_every_platform_is_refused(self, test_plugin_context):
        scanner = _custom_scanner(test_plugin_context)
        for target_platform, arch in DECLARED_PLATFORMS:
            argv = scanner.custom_install_commands[target_platform][arch][0].args
            joined = " ".join(argv)
            assert "install_binary_from_url" not in joined
            assert "install_pinned_tool" not in joined
            assert argv[2] == "import sys; sys.exit(sys.argv[1])"

    @pytest.mark.unit
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

    @pytest.mark.integration
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

    @pytest.mark.unit
    def test_a_digest_for_one_platform_does_not_unlock_another(
        self, test_plugin_context
    ):
        scanner = _custom_scanner(test_plugin_context, {"linux/amd64": "a" * 64})
        linux = scanner.custom_install_commands["linux"]["amd64"][0].args
        arm = scanner.custom_install_commands["linux"]["arm64"][0].args
        assert "install_binary_from_url" in linux[2]
        assert arm[2] == "import sys; sys.exit(sys.argv[1])"

    @pytest.mark.unit
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

    # integration although urlopen is patched: a finished install ends, on macOS, by
    # unquarantining the file with a child xattr process, a path this test takes there.
    @pytest.mark.integration
    def test_a_matching_custom_digest_installs(self, test_plugin_context, tmp_path):
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        scanner = _custom_scanner(test_plugin_context, {"linux/amd64": digest})
        command = scanner.custom_install_commands["linux"]["amd64"][0]
        bin_dir = tmp_path / "bin"
        with _serve(PAYLOAD):
            _run_inline(command, bin_dir)
        assert (bin_dir / "opengrep").read_bytes() == PAYLOAD
        assert read_receipt(bin_dir, "opengrep")["sha256"] == digest

    @pytest.mark.unit
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

    @pytest.mark.unit
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

    @pytest.mark.unit
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


CUSTOM_2X = "v2.1.0"


class TestACustomTwoPointOhVersionUsesTheRenamedAssets:
    """v2.0.0 renamed the Linux assets and zipped the Windows one."""

    def _scanner(self, test_plugin_context, sha256):
        return OpengrepScanner(
            context=test_plugin_context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(version=CUSTOM_2X, sha256=sha256)
            ),
        )

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "arch,asset",
        [("amd64", "opengrep_linux_x86"), ("arm64", "opengrep_linux_aarch64")],
    )
    def test_linux_downloads_the_renamed_asset(self, test_plugin_context, arch, asset):
        scanner = self._scanner(test_plugin_context, {f"linux/{arch}": "a" * 64})
        argv = scanner.custom_install_commands["linux"][arch][0].args
        assert "install_binary_from_url" in argv[2]
        assert argv[3].endswith(f"/{CUSTOM_2X}/{asset}")

    @pytest.mark.unit
    def test_a_missing_linux_digest_names_the_renamed_asset(self, test_plugin_context):
        scanner = self._scanner(test_plugin_context, {})
        message = scanner.custom_install_commands["linux"]["amd64"][0].args[3]
        assert message == unverified_version_refusal(
            CUSTOM_2X, "linux", "amd64", "opengrep_linux_x86"
        )

    @pytest.mark.unit
    @pytest.mark.parametrize("sha256", [{}, {"windows/amd64": "a" * 64}])
    def test_windows_is_refused_with_or_without_a_digest(
        self, test_plugin_context, sha256
    ):
        """A configured version is fetched as one file, and the asset is a zip."""
        scanner = self._scanner(test_plugin_context, sha256)
        argv = scanner.custom_install_commands["windows"]["amd64"][0].args
        assert argv[2] == "import sys; sys.exit(sys.argv[1])"
        assert argv[3] == windows_zip_refusal(CUSTOM_2X, "opengrep_windows_x86.zip")
        assert "opengrep_windows_x86.zip" in argv[3]
        assert "install_binary_from_url" not in " ".join(argv)

    @pytest.mark.unit
    def test_a_one_point_x_windows_version_still_downloads_the_exe(
        self, test_plugin_context
    ):
        scanner = _custom_scanner(test_plugin_context, {"windows/amd64": "a" * 64})
        argv = scanner.custom_install_commands["windows"]["amd64"][0].args
        assert "install_binary_from_url" in argv[2]
        assert argv[3].endswith(f"/{CUSTOM}/opengrep_windows_x86.exe")


def _windows_zip(extra_member: str | None = None) -> tuple[bytes, dict]:
    """A stand-in for the release zip: ``opengrep.exe`` plus six DLL-named files."""
    import io
    import zipfile

    members = {"opengrep.exe": b"MZ-opengrep-exe-fixture"}
    for name, _ in get_tool_asset("opengrep", "windows", "amd64").companion_sha256:
        members[name] = b"MZ-dll-fixture:" + name.encode()
    if extra_member:
        members[extra_member] = b"unpinned"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buffer.getvalue(), members


def _pin_the_zip(archive: bytes, members: dict, *, wrong_dll: str | None = None):
    """Pin the fixture zip, its executable and its DLLs in place of the release's."""
    filename = _ASSET_TABLES["opengrep"][("windows", "amd64")]
    companions = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in members.items()
        if name != "opengrep.exe"
    }
    if wrong_dll:
        companions[wrong_dll] = "0" * 64
    return (
        patch.object(
            tool_downloads,
            "_DIGESTS",
            {**_DIGESTS, filename: hashlib.sha256(archive).hexdigest()},
        ),
        patch.object(
            tool_downloads,
            "_EXECUTABLE_DIGESTS",
            {
                **tool_downloads._EXECUTABLE_DIGESTS,
                filename: hashlib.sha256(members["opengrep.exe"]).hexdigest(),
            },
        ),
        patch.object(tool_downloads, "_COMPANION_DIGESTS", {filename: companions}),
    )


# integration although urlopen is patched: a finished install ends, on macOS, by
# unquarantining the file with a child xattr process, a path these tests take there.
@pytest.mark.integration
class TestTheWindowsZipInstallsTheExecutableAndItsDlls:
    def test_every_member_lands_beside_the_executable(self, tmp_path):
        archive, members = _windows_zip()
        bin_dir = tmp_path / "bin"
        pins = _pin_the_zip(archive, members)
        with pins[0], pins[1], pins[2], _serve(archive):
            installed = install_pinned_tool("opengrep", "windows", "amd64", bin_dir)
        assert installed == bin_dir / "opengrep.exe"
        assert sorted(p.name for p in bin_dir.iterdir()) == sorted(members)
        for name, payload in members.items():
            assert (bin_dir / name).read_bytes() == payload
        receipt = read_receipt(bin_dir, "opengrep.exe")
        assert (
            receipt["installed_sha256"]
            == hashlib.sha256(members["opengrep.exe"]).hexdigest()
        )
        assert receipt["version"] == TOOL_VERSIONS["opengrep"]

    def test_a_member_the_pin_does_not_name_is_not_installed(self, tmp_path):
        archive, members = _windows_zip(extra_member="evil.dll")
        bin_dir = tmp_path / "bin"
        pinned = {k: v for k, v in members.items() if k != "evil.dll"}
        pins = _pin_the_zip(archive, pinned)
        with pins[0], pins[1], pins[2], _serve(archive):
            install_pinned_tool("opengrep", "windows", "amd64", bin_dir)
        assert not (bin_dir / "evil.dll").exists()

    def test_a_dll_that_does_not_match_its_pin_stops_the_install(self, tmp_path):
        archive, members = _windows_zip()
        bin_dir = tmp_path / "bin"
        pins = _pin_the_zip(archive, members, wrong_dll="libzstd-1.dll")
        with (
            pins[0],
            pins[1],
            pins[2],
            _serve(archive),
            pytest.raises(
                ToolDownloadIntegrityError, match="does not match its pinned"
            ),
        ):
            install_pinned_tool("opengrep", "windows", "amd64", bin_dir)
        assert not (bin_dir / "opengrep.exe").exists()
        assert not (bin_dir / "libzstd-1.dll").exists()
        assert read_receipt(bin_dir, "opengrep.exe") is None

    def test_a_zip_missing_a_pinned_dll_stops_the_install(self, tmp_path):
        archive, members = _windows_zip()
        short = {k: v for k, v in members.items() if k != "libgmp-10.dll"}
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            for name, payload in short.items():
                zf.writestr(name, payload)
        archive = buffer.getvalue()
        bin_dir = tmp_path / "bin"
        pins = _pin_the_zip(archive, members)
        with (
            pins[0],
            pins[1],
            pins[2],
            _serve(archive),
            pytest.raises(ToolDownloadIntegrityError, match="no member named"),
        ):
            install_pinned_tool("opengrep", "windows", "amd64", bin_dir)
        assert not (bin_dir / "opengrep.exe").exists()


class TestTheDigestCheckCanFail:
    @pytest.mark.unit
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

    @pytest.mark.unit
    def test_the_real_pin_refuses_bytes_that_are_not_the_release(self, tmp_path):
        """Unpatched table: the committed digest itself is what refuses."""
        bin_dir = tmp_path / "bin"
        with (
            _serve(PAYLOAD),
            pytest.raises(ToolDownloadIntegrityError, match="SHA256 mismatch"),
        ):
            install_pinned_tool("opengrep", "linux", "arm64", bin_dir)
        assert not (bin_dir / "opengrep").exists()

    # integration although urlopen is patched: a finished install ends, on macOS, by
    # unquarantining the file with a child xattr process, a path this test takes there.
    @pytest.mark.integration
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

    @pytest.mark.unit
    def test_a_half_applied_version_bump_is_refused_by_name(self):
        with (
            patch.dict(tool_downloads.TOOL_VERSIONS, {"opengrep": "v9.9.9"}),
            pytest.raises(ToolNotProvisionableError, match="half-applied"),
        ):
            get_tool_asset("opengrep", "linux", "amd64")


@pytest.mark.unit
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


# integration although urlopen is patched: both tests finish an install, which ends, on
# macOS, by unquarantining the file with a child xattr process, a path they take there.
@pytest.mark.integration
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


_TIERS = ("unit", "integration", "e2e")


def _tiers_written_on(node: ast.AST) -> set[str]:
    """The tier markers a function or class carries as decorators."""
    found: set[str] = set()
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (
            isinstance(target, ast.Attribute)
            and target.attr in _TIERS
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "mark"
        ):
            found.add(target.attr)
    return found


def _finishes_an_install(function: ast.FunctionDef) -> bool:
    """Whether the test runs an install that is not expected to be refused.

    A call of ``install_pinned_tool`` or ``_run_inline`` with no ``pytest.raises``
    around it ends in ``write_receipt``, after the macOS unquarantine step.
    """
    installs = False
    refuses = False
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in (
            "install_pinned_tool",
            "_run_inline",
        ):
            installs = True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "raises":
            refuses = True
    return installs and not refuses


@pytest.mark.unit
def test_a_test_that_finishes_an_install_is_integration():
    """A finished install takes the macOS xattr child path, so it is not a unit test.

    ``install_pinned_tool`` and ``install_binary_from_url`` end, on Darwin, by
    ``unquarantine_macos_binary``, which runs ``xattr`` as a child process. The tier
    is read on every path a test can take (tests/NAMING_CONVENTIONS.md), and the
    unit job runs on a macOS runner, so each test here that finishes an install is
    integration, as the sibling that installs through ``install_binary_from_url`` is
    in test_download_utils.py. A refusal raises before that step and stays unit.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    tests: dict[str, tuple[ast.FunctionDef, set[str]]] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            tests[node.name] = (node, _tiers_written_on(node))
        elif isinstance(node, ast.ClassDef):
            from_the_class = _tiers_written_on(node)
            for member in node.body:
                if isinstance(member, ast.FunctionDef) and member.name.startswith(
                    "test_"
                ):
                    tests[f"{node.name}::{member.name}"] = (
                        member,
                        from_the_class | _tiers_written_on(member),
                    )

    finishing = {
        name: tiers for name, (fn, tiers) in tests.items() if _finishes_an_install(fn)
    }

    # Positive control: the finder has to see the installs this file is known to finish.
    assert {
        "TestACustomVersionNeedsItsOwnDigest::test_a_matching_custom_digest_installs",
        "TestTheDigestCheckCanFail::test_positive_control_matching_digest_installs_the_bytes",
        "TestTheReleaseAssetCacheCoversOpengrep::test_a_download_is_stored_and_a_verified_copy_is_reused",
        "TestTheReleaseAssetCacheCoversOpengrep::test_a_tampered_cached_asset_is_discarded_and_redownloaded",
    } <= set(finishing)

    not_integration = {
        name: sorted(tiers)
        for name, tiers in finishing.items()
        if tiers != {"integration"}
    }
    assert not_integration == {}, (
        "these tests finish an install, which starts xattr on macOS, and are not "
        f"integration: {not_integration}"
    )

    # Negative control: a refusal is not counted as finishing, and it stays unit.
    refusal = "TestTheDigestCheckCanFail::test_a_mismatched_digest_installs_nothing"
    assert refusal not in finishing
    assert tests[refusal][1] == {"unit"}
