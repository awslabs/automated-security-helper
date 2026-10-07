# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pinned tool already on disk, byte for byte, is not installed a second time.

Why this exists
---------------
ASH's container image installs syft, grype and trivy into /usr/local/bin from their
pinned release assets, then runs ``ash dependencies install`` as root and again as
the non-root user. Both runs installed the same pinned assets into ASH_BIN_PATH, so
each binary landed in the image up to three times. grype and syft measured 167 MB
of duplicates per stage, and trivy, at 162 MB, would have added 324 MB once it is
installed by a builtin scanner.

What has to hold, and which test holds it
-----------------------------------------
1. Byte-identical to the pin: skipped, and the skipped binary is the one a scan
   resolves (``TestIdenticalBinaryIsNotReinstalled``).
2. Same name, other version: installed (``test_another_version_is_installed``).
3. Same name, same claimed version, different bytes: installed. This is the
   negative control for (1). A check that compared names or version strings would
   pass (1) and fail here (``test_same_version_different_bytes_is_installed``).
4. The skip cannot hide behind a file it is about to overwrite
   (``test_an_unverified_file_at_the_destination_is_not_bypassed``).
5. No executable pin, no skip (``test_no_executable_pin_means_no_skip``).
6. The pin is enforced on install, so a wrong entry in ``_EXECUTABLE_DIGESTS`` fails
   loudly instead of making the skip silently never fire
   (``TestTheExecutablePinIsEnforcedOnInstall``).
7. Outside the container nothing changes: with no verified copy present, the
   installer runs exactly the commands it ran before, prints no new line, and the
   tool lands in the bin path (``TestDependenciesInstall``). The snapshot suite in
   tests/snapshot/dependencies covers the full output of that case unchanged.

Nothing here touches the network. Downloads are served from bytes built in the
test, and the pinned digests are patched to describe those bytes.
"""

import hashlib
import io
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils import download_utils, subprocess_utils
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.download_utils import (
    create_pinned_tool_install_command,
    find_verified_pinned_executable,
    install_pinned_tool,
    pinned_install_already_satisfied,
)
from automated_security_helper.utils.tool_downloads import (
    _ASSET_TABLES,
    _DIGESTS,
    _EXECUTABLE_DIGESTS,
    get_tool_asset,
)

PINNED_GRYPE = b"\x7fELF pinned grype v0.111.0 build\n"
OTHER_VERSION_GRYPE = b"\x7fELF grype v0.110.0 build\n"
# Claims the pinned version in its own bytes, as a rebuilt or tampered binary
# printing the same --version would. Only the bytes differ.
SAME_VERSION_OTHER_BYTES = b"\x7fELF pinned grype v0.111.0 build (rebuilt)\n"

GRYPE_ASSET = _ASSET_TABLES["grype"][("linux", "amd64")]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tarball(member_bytes: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        info = tarfile.TarInfo("grype")
        info.size = len(member_bytes)
        info.mtime = 0
        bundle.addfile(info, io.BytesIO(member_bytes))
    return buffer.getvalue()


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


@pytest.fixture
def pins():
    """Pin grype linux/amd64 to a fixture archive whose member is PINNED_GRYPE."""
    archive = _tarball(PINNED_GRYPE)
    with (
        patch.object(
            tool_downloads, "_DIGESTS", {**_DIGESTS, GRYPE_ASSET: _sha(archive)}
        ),
        patch.object(
            tool_downloads,
            "_EXECUTABLE_DIGESTS",
            {**_EXECUTABLE_DIGESTS, GRYPE_ASSET: _sha(PINNED_GRYPE)},
        ),
    ):
        yield archive


@pytest.fixture
def downloads():
    """Record every download, and serve whatever archive the test assigns."""
    served = SimpleNamespace(archive=None, urls=[])

    def urlopen(request, *args, **kwargs):
        url = getattr(request, "full_url", request)
        served.urls.append(url)
        if served.archive is None:
            raise AssertionError(f"unexpected download of {url}")
        return _FakeResponse(served.archive)

    with patch.object(download_utils.urllib.request, "urlopen", side_effect=urlopen):
        yield served


@pytest.fixture
def on_path(tmp_path, monkeypatch):
    """Make find_executable resolve grype to a file the test chooses, or nothing.

    ``tmp_path / "usr-local-bin"`` stands in for /usr/local/bin and
    ``tmp_path / "ash-bin"`` for ASH_BIN_PATH: they are what
    ``path_independent_dirs`` reports, so a copy put in either one is in a place
    every scan searches. Anywhere else under tmp_path is reachable only through
    PATH.
    """
    resolved = SimpleNamespace(grype=None)

    def find_executable(command, *args, **kwargs):
        return str(resolved.grype) if command == "grype" and resolved.grype else None

    monkeypatch.setattr(subprocess_utils, "find_executable", find_executable)
    monkeypatch.setattr(dependencies_module, "find_executable", find_executable)
    monkeypatch.setattr(
        subprocess_utils,
        "path_independent_dirs",
        lambda: [tmp_path / "ash-bin", tmp_path / "usr-local-bin"],
    )
    return resolved


def _binary(directory: Path, data: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "grype"
    path.write_bytes(data)
    path.chmod(0o755)
    return path


class TestIdenticalBinaryIsNotReinstalled:
    def test_found_on_path_and_verified(self, tmp_path, pins, on_path):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)

        present = find_verified_pinned_executable(
            "grype", "linux", "amd64", tmp_path / "ash-bin"
        )

        assert present is not None
        assert present.path == on_path.grype
        assert present.sha256 == _sha(PINNED_GRYPE)
        assert present.version == tool_downloads.TOOL_VERSIONS["grype"]

    def test_install_downloads_nothing_and_writes_no_copy(
        self, tmp_path, pins, on_path, downloads
    ):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        bin_dir = tmp_path / "ash-bin"

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert downloads.urls == [], "a verified copy was downloaded again"
        assert installed == on_path.grype
        assert not (bin_dir / "grype").exists(), "a second copy was written"

    def test_a_verified_copy_at_the_destination_needs_no_receipt(
        self, tmp_path, pins, on_path, downloads
    ):
        """The non-root image stage: the binary is there, the receipt is not.

        Receipts live under $HOME, and the second `ash dependencies install` in the
        image runs as a different user with a different $HOME, so it never saw the
        first one's receipts and rewrote every binary into a new layer.
        """
        bin_dir = tmp_path / "ash-bin"
        at_destination = _binary(bin_dir, PINNED_GRYPE)

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert downloads.urls == []
        assert installed == at_destination

    def test_the_scanner_resolves_the_binary_that_was_verified(
        self, tmp_path, pins, monkeypatch, downloads
    ):
        """Skipping is only correct if the scan then runs the verified copy.

        Real find_executable, no fake: the verified file is in the stand-in for
        /usr/local/bin, ASH_BIN_PATH is an empty directory, and find_executable --
        what GrypeScanner and run_command both call -- must answer with the same
        file the skip verified. Checked twice: with that directory on PATH, as in
        the image, and with a PATH that does not contain it, as in a scan started
        from a different shell, CI job or cron entry.
        """
        usr_local_bin = tmp_path / "usr-local-bin"
        verified = _binary(usr_local_bin, PINNED_GRYPE)
        bin_dir = tmp_path / "ash-bin"
        bin_dir.mkdir()
        elsewhere = tmp_path / "unrelated"
        elsewhere.mkdir()
        monkeypatch.setattr(
            subprocess_utils, "path_independent_dirs", lambda: [bin_dir, usr_local_bin]
        )
        monkeypatch.setenv("PATH", str(usr_local_bin))
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        subprocess_utils.clear_find_executable_cache()
        try:
            installed = install_pinned_tool(
                "grype", "linux", "amd64", destination=bin_dir
            )
            assert installed == verified
            assert Path(subprocess_utils.find_executable("grype")) == verified

            monkeypatch.setenv("PATH", str(elsewhere))
            subprocess_utils.clear_find_executable_cache()
            assert Path(subprocess_utils.find_executable("grype")) == verified
        finally:
            subprocess_utils.clear_find_executable_cache()

    def test_find_executable_searches_the_same_fallback_dirs(self, monkeypatch):
        """The skip's notion of "found by every scan" is find_executable's own list."""
        monkeypatch.setenv("ASH_BIN_PATH", "/some/ash/bin")
        dirs = subprocess_utils.path_independent_dirs()
        assert dirs[0] == Path("/some/ash/bin")
        if subprocess_utils.platform.system().lower() != "windows":
            assert dirs[1:] == [Path("/usr/local/bin")]


class TestADifferentBinaryIsStillInstalled:
    def test_another_version_is_installed(self, tmp_path, pins, on_path, downloads):
        on_path.grype = _binary(tmp_path / "usr-local-bin", OTHER_VERSION_GRYPE)
        downloads.archive = pins
        bin_dir = tmp_path / "ash-bin"

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert downloads.urls == [get_tool_asset("grype", "linux", "amd64").url]
        assert installed == bin_dir / "grype"
        assert installed.read_bytes() == PINNED_GRYPE
        assert on_path.grype.read_bytes() == OTHER_VERSION_GRYPE, "not ours to touch"

    def test_same_version_different_bytes_is_installed(
        self, tmp_path, pins, on_path, downloads
    ):
        """Negative control for the skip: trust is decided by bytes, not by name.

        Same file name, and a binary that would report the pinned version, but its
        SHA256 is not the pinned one. Accepting it would let anything named grype
        that answers `--version` correctly stand in for the verified release.
        """
        on_path.grype = _binary(tmp_path / "usr-local-bin", SAME_VERSION_OTHER_BYTES)
        assert (
            find_verified_pinned_executable(
                "grype", "linux", "amd64", tmp_path / "ash-bin"
            )
            is None
        )
        downloads.archive = pins

        installed = install_pinned_tool(
            "grype", "linux", "amd64", destination=tmp_path / "ash-bin"
        )

        assert len(downloads.urls) == 1
        assert installed.read_bytes() == PINNED_GRYPE

    def test_the_skip_depends_on_the_pinned_value(self, tmp_path, on_path, pins):
        """Changing one character of the pin must turn an accepted file away.

        Proves the comparison reads the pin rather than, say, comparing the file
        with itself or accepting anything that hashes at all.
        """
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        wrong = _sha(PINNED_GRYPE)[:-1] + (
            "0" if _sha(PINNED_GRYPE)[-1] != "0" else "1"
        )
        with patch.dict(tool_downloads._EXECUTABLE_DIGESTS, {GRYPE_ASSET: wrong}):
            assert (
                find_verified_pinned_executable(
                    "grype", "linux", "amd64", tmp_path / "ash-bin"
                )
                is None
            )

    def test_an_unverified_file_at_the_destination_is_not_bypassed(
        self, tmp_path, pins, on_path, downloads
    ):
        """A verified copy elsewhere does not excuse a stale one at the target.

        In the image the destination is first on PATH, so leaving the stale file
        there would make every scan run it instead of the verified copy.
        """
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        bin_dir = tmp_path / "ash-bin"
        _binary(bin_dir, OTHER_VERSION_GRYPE)
        downloads.archive = pins

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert installed == bin_dir / "grype"
        assert installed.read_bytes() == PINNED_GRYPE

    def test_a_dangling_symlink_at_the_destination_is_not_bypassed(
        self, tmp_path, pins, on_path, downloads
    ):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        bin_dir = tmp_path / "ash-bin"
        bin_dir.mkdir()
        (bin_dir / "grype").symlink_to(tmp_path / "nowhere")
        downloads.archive = pins

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert len(downloads.urls) == 1, "the dangling link let the verified copy win"
        assert installed == bin_dir / "grype"
        assert not installed.is_symlink()
        assert installed.read_bytes() == PINNED_GRYPE

    def test_a_symlink_to_the_right_bytes_at_the_destination_is_replaced(
        self, tmp_path, pins, on_path, downloads
    ):
        """A link's target can change after the check; the install writes a file."""
        target = _binary(tmp_path / "writable-elsewhere", PINNED_GRYPE)
        bin_dir = tmp_path / "ash-bin"
        bin_dir.mkdir()
        (bin_dir / "grype").symlink_to(target)
        downloads.archive = pins

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert len(downloads.urls) == 1
        assert installed == bin_dir / "grype"
        assert not installed.is_symlink()

    def test_a_non_executable_copy_is_reinstalled(
        self, tmp_path, pins, on_path, downloads
    ):
        """The right bytes at mode 0644 would be found by a scan and fail to run."""
        if os.name == "nt":
            pytest.skip("POSIX execute bit")
        bin_dir = tmp_path / "ash-bin"
        _binary(bin_dir, PINNED_GRYPE).chmod(0o644)
        downloads.archive = pins

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert len(downloads.urls) == 1
        assert os.access(installed, os.X_OK)

    def test_a_copy_found_only_through_this_path_is_not_relied_on(
        self, tmp_path, pins, on_path, downloads
    ):
        """The verified bytes, but in a directory only this shell's PATH reaches.

        A scan started from a CI job or cron entry with another PATH would not find
        it and would report the scanner MISSING, so the pinned build is installed
        into the bin directory as before.
        """
        on_path.grype = _binary(tmp_path / "opt-tools", PINNED_GRYPE)
        downloads.archive = pins
        bin_dir = tmp_path / "ash-bin"

        installed = install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert len(downloads.urls) == 1
        assert installed == bin_dir / "grype"

    def test_no_executable_pin_means_no_skip(self, tmp_path, pins, on_path, downloads):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        downloads.archive = pins
        unpinned = {k: v for k, v in _EXECUTABLE_DIGESTS.items() if k != GRYPE_ASSET}
        with patch.object(tool_downloads, "_EXECUTABLE_DIGESTS", unpinned):
            assert get_tool_asset("grype", "linux", "amd64").executable_digest is None
            installed = install_pinned_tool(
                "grype", "linux", "amd64", destination=tmp_path / "ash-bin"
            )
        assert len(downloads.urls) == 1
        assert installed == tmp_path / "ash-bin" / "grype"

    def test_force_installs_over_a_verified_copy(
        self, tmp_path, pins, on_path, downloads
    ):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        downloads.archive = pins
        installed = install_pinned_tool(
            "grype", "linux", "amd64", destination=tmp_path / "ash-bin", force=True
        )
        assert len(downloads.urls) == 1
        assert installed == tmp_path / "ash-bin" / "grype"


class TestTheExecutablePinIsEnforcedOnInstall:
    def test_a_member_that_does_not_match_its_pin_is_refused(
        self, tmp_path, on_path, downloads
    ):
        """The archive matches its pin, the executable inside does not.

        Without this check a wrong _EXECUTABLE_DIGESTS entry would install fine and
        make the skip quietly never fire; with it, the first real install in CI
        fails and names the mismatch.
        """
        archive = _tarball(SAME_VERSION_OTHER_BYTES)
        downloads.archive = archive
        bin_dir = tmp_path / "ash-bin"
        with (
            patch.object(
                tool_downloads, "_DIGESTS", {**_DIGESTS, GRYPE_ASSET: _sha(archive)}
            ),
            patch.object(
                tool_downloads,
                "_EXECUTABLE_DIGESTS",
                {**_EXECUTABLE_DIGESTS, GRYPE_ASSET: _sha(PINNED_GRYPE)},
            ),
            pytest.raises(ToolDownloadIntegrityError, match="pinned executable digest"),
        ):
            install_pinned_tool("grype", "linux", "amd64", destination=bin_dir)

        assert not (bin_dir / "grype").exists(), (
            "a refused executable was left in place"
        )
        assert [p.name for p in bin_dir.iterdir()] == [], "staging file left behind"


class TestTheExecutableDigestTable:
    def test_every_pinned_asset_has_an_executable_digest(self):
        """Without one, a copy already on disk cannot be recognized and is duplicated.

        Asked of ``get_tool_asset`` rather than of the two tables, so an asset that is
        itself the executable -- whose asset digest already covers the bytes that
        run -- counts as covered without a second entry.
        """
        missing = sorted(
            f"{tool} {target_platform}/{arch}"
            for tool, table in _ASSET_TABLES.items()
            for target_platform, arch in table
            if get_tool_asset(tool, target_platform, arch).executable_digest is None
        )
        assert missing == []

    def test_no_orphan_executable_digests(self):
        assert sorted(set(_EXECUTABLE_DIGESTS) - set(_DIGESTS)) == []

    def test_executable_and_archive_digests_differ(self):
        """A copy-paste of the archive digest would never match a binary."""
        same = sorted(k for k, v in _EXECUTABLE_DIGESTS.items() if _DIGESTS[k] == v)
        assert same == []

    def test_assets_carry_their_executable_digest(self):
        asset = get_tool_asset("trivy", "linux", "amd64")
        filename = _ASSET_TABLES["trivy"][("linux", "amd64")]
        assert asset.executable_digest == _EXECUTABLE_DIGESTS[filename]

    def test_a_bare_executable_asset_is_its_own_executable_digest(self):
        """An asset that is the executable needs no second digest.

        No asset in the table is shaped like this yet; the property reads an
        ``archive`` attribute when one exists, and this pins what it does then.
        """
        bare = SimpleNamespace(executable_sha256=None, archive=False, sha256="ab" * 32)
        assert tool_downloads.ToolAsset.executable_digest.fget(bare) == "ab" * 32
        archived = SimpleNamespace(
            executable_sha256=None, archive=True, sha256="ab" * 32
        )
        assert tool_downloads.ToolAsset.executable_digest.fget(archived) is None


class TestRecognizingAPinnedInstallCommand:
    def test_other_commands_are_never_satisfied(self, tmp_path, pins, on_path):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)
        real = create_pinned_tool_install_command(
            "grype", "linux", "amd64", str(tmp_path / "ash-bin")
        ).args
        assert pinned_install_already_satisfied(real) is not None

        tampered_script = list(real)
        tampered_script[2] = real[2] + "; import os"
        for argv in (
            [],
            ["grype"],
            ["uv", "tool", "install", "grype"],
            tampered_script,
            real + ["extra"],
        ):
            assert pinned_install_already_satisfied(argv) is None, argv

    def test_an_unprovisionable_pair_is_left_to_the_command(self, tmp_path):
        argv = create_pinned_tool_install_command(
            "grype", "windows", "arm64", str(tmp_path)
        ).args
        assert pinned_install_already_satisfied(argv) is None


class TestTheVerdictForAVerifiedTool:
    def _outcome(self, **kwargs):
        from automated_security_helper.cli.dependencies import PluginInstallOutcome

        return PluginInstallOutcome(
            name="grype", plugin_type="scanner", command="grype", **kwargs
        )

    def test_status_says_whether_the_verified_copy_is_on_path(self):
        assert (
            self._outcome(commands_satisfied=1, executable="/x/grype").status
            == "VERIFIED PRESENT"
        )
        assert self._outcome(commands_satisfied=1).status == "VERIFIED (not on PATH)"

    def test_a_satisfied_tool_is_not_called_unprovisionable(self):
        assert self._outcome(commands_satisfied=1).declared_no_commands is False

    def test_a_verified_tool_missing_afterwards_is_named(self):
        """Verified, then not found by the post-install sweep: say so."""
        from automated_security_helper.cli.dependencies import _report_and_exit

        panels = io.StringIO()
        with patch.object(
            dependencies_module,
            "console",
            Console(file=panels, width=240, no_color=True),
        ):
            _report_and_exit([self._outcome(commands_satisfied=1)], requested_tools=[])
        printed = panels.getvalue()
        assert "Install ran but tool not found on PATH: grype" in printed
        assert "No install path on this platform" not in printed


class TestDependenciesInstall:
    """`ash dependencies install --tool grype`, through the CLI.

    Assertions read the commands run and the results panel, which go to a console
    this class owns; see TestToolSelection in test_dependencies_verdict.py for why
    CliRunner's own capture cannot be relied on here.
    """

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        self.bin_dir = tmp_path / "ash-bin"
        monkeypatch.setenv("ASH_BIN_PATH", str(self.bin_dir))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(dependencies_module, "get_platform", lambda: "linux")
        monkeypatch.setattr(dependencies_module, "get_architecture", lambda: "amd64")
        monkeypatch.setattr(
            dependencies_module, "clear_find_executable_cache", lambda: None
        )
        self.panels = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=self.panels, width=240, no_color=True),
        )
        self.ran = []
        monkeypatch.setattr(
            dependencies_module,
            "run_command",
            lambda cmd, shell=False: self.ran.append(cmd) or 0,
        )

    def _install(self):
        return CliRunner().invoke(
            dependencies_app, ["--tool", "grype", "--bin-path", str(self.bin_dir)]
        )

    def test_a_verified_copy_is_reported_and_not_reinstalled(
        self, tmp_path, pins, on_path
    ):
        on_path.grype = _binary(tmp_path / "usr-local-bin", PINNED_GRYPE)

        result = self._install()

        assert result.exit_code == 0, self.panels.getvalue()
        assert self.ran == [], "the install command ran for a verified copy"
        printed = self.panels.getvalue()
        assert "VERIFIED PRESENT" in printed
        assert str(on_path.grype) in printed
        assert "Already present, verified against the pinned digest: 1 -- grype" in (
            printed
        )
        assert "No install path on this platform" not in printed

    def test_a_different_binary_is_installed_as_before(self, tmp_path, pins, on_path):
        on_path.grype = _binary(tmp_path / "usr-local-bin", SAME_VERSION_OTHER_BYTES)

        result = self._install()

        assert result.exit_code == 0, self.panels.getvalue()
        assert len(self.ran) == 1 and self.ran[0][3:6] == ["grype", "linux", "amd64"]
        printed = self.panels.getvalue()
        assert "VERIFIED" not in printed
        assert "Already present" not in printed

    def test_nothing_present_behaves_exactly_as_before(self, tmp_path, pins, on_path):
        """Outside the container: nothing pre-installed, so nothing changes.

        The exact pinned install command the plugin declares still runs, and no new
        line is printed. The fake run_command installs nothing, so grype is still
        absent afterwards and the verdict is the one that already existed for a
        requested tool that is not on PATH.
        """
        on_path.grype = None

        result = self._install()

        printed = self.panels.getvalue()
        assert self.ran == [
            create_pinned_tool_install_command(
                "grype", "linux", "amd64", str(self.bin_dir)
            ).args
        ], printed
        assert "Already present" not in printed
        assert "VERIFIED" not in printed
        assert result.exit_code == 1
        assert "requested tool(s) still not on PATH: grype" in printed
