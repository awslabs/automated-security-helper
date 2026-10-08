# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for assets/install-pinned-tool.py, the container build's tool installer.

Why these tests exist
---------------------
The script replaced three ``curl … | sh`` lines in the Dockerfile that installed
syft, grype and trivy from vendor install scripts. Two properties have to hold or
the replacement is worse than what it replaced:

1. A digest that does not match must stop the install. A verifier that cannot fail
   is not a verifier, so :class:`TestTheDigestCheckCanFail` tampers with the
   expected value and asserts both the exit code and that nothing landed in the
   destination. Without the second assertion the test would pass on a script that
   installed the binary and then complained.
2. The versions in the Dockerfile's ``ARG`` lines and the versions in
   ``tool_downloads.py`` must agree. They are two statements of the same fact in
   two files, which is exactly the shape that drifts. The installer reads the
   table, so a stale ``ARG`` would not install the wrong version -- it would make
   the Dockerfile's own documentation wrong about what the image contains, and
   ``RUN syft --version`` would still pass.

Nothing here reaches the network. The tests that need bytes to hash stub
``installer.download`` and build their own tarball in memory, which is also why
they cannot simply serve a fixture over ``file://``: the script refuses any URL
that is not https, and :class:`TestTheHttpsGuard` pins that. The archives are
built rather than committed for the same reason a checksum is not duplicated into
the Dockerfile -- a committed tarball is a binary blob no reviewer reads.
"""

import importlib.util
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.utils.tool_downloads import (
    TOOL_VERSIONS,
    downloadable_tools,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _load_script():
    """Import the script as a module despite its non-identifier filename.

    ``install-pinned-tool.py`` has hyphens, so it cannot be imported by name. It is
    named for the command it becomes on PATH in the image, which is the more
    important of the two audiences.
    """
    spec = importlib.util.spec_from_file_location("_install_pinned_tool", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()

# Pinned tools the image does NOT install with install-pinned-tool, and why.
#
# opengrep reaches the image through `RUN ashx dependencies install`, which resolves it
# from the same table through OpengrepScanner's pinned install commands -- the path it
# always took, now verified. Installing it a second time with install-pinned-tool
# would add a ~42 MB copy to /usr/local/bin for no gain. Named here, rather than
# filtered out of downloadable_tools() inline, so the exemption is one reviewed line,
# and TestOpengrepReachesTheImageThroughThePin checks the path it takes instead.
_PROVISIONED_BY_ASH_DEPENDENCIES_INSTALL = frozenset({"opengrep"})
_INSTALLED_BY_THE_SCRIPT = sorted(
    set(TOOL_VERSIONS) - _PROVISIONED_BY_ASH_DEPENDENCIES_INSTALL
)


# The pinned SHA256 of the syft executable inside syft_1.54.1_linux_amd64.tar.gz.
_SYFT_LINUX_AMD64_EXECUTABLE = "dbf75864e7a7ff9e1fbf00552c31483f693188632a9f68f343cd7653dac513d6"  # pragma: allowlist secret


def _pins_dir(tmp_path: Path, digest_overrides: dict | None = None) -> Path:
    """A standalone copy of the pinned table, optionally with digests rewritten.

    Copied rather than imported so a test can tamper with one digest without
    touching the module the rest of the suite shares.
    """
    root = tmp_path / "pins"
    (root / "utils").mkdir(parents=True)
    (root / "core").mkdir(parents=True)
    (root / "core" / "exceptions.py").write_text(
        (REPO_ROOT / "automated_security_helper" / "core" / "exceptions.py").read_text()
    )
    source = (
        REPO_ROOT / "automated_security_helper" / "utils" / "tool_downloads.py"
    ).read_text()
    for old, new in (digest_overrides or {}).items():
        assert old in source, f"{old} is not in tool_downloads.py; the fixture is stale"
        source = source.replace(old, new)
    (root / "utils" / "tool_downloads.py").write_text(source)
    return root


def _dockerfile_instructions() -> str:
    """The Dockerfile without its comment lines, which name the removed installers."""
    return "\n".join(
        line
        for line in DOCKERFILE.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


class TestTheDockerfileAndTheTableAgree:
    """The ARG lines and TOOL_VERSIONS are the same fact written twice."""

    @pytest.mark.parametrize("tool", _INSTALLED_BY_THE_SCRIPT)
    def test_the_arg_version_matches_the_pinned_version(self, tool):
        arg = f"{tool.upper()}_VERSION"
        match = re.search(
            rf'^ARG {arg}="([^"]+)"$', DOCKERFILE.read_text(), re.MULTILINE
        )
        assert match, f"Dockerfile has no `ARG {arg}=...` line"
        assert match.group(1) == TOOL_VERSIONS[tool], (
            f"Dockerfile pins {arg}={match.group(1)} while tool_downloads.py pins "
            f"{TOOL_VERSIONS[tool]}. The installer reads the table, so the image "
            f"would contain {TOOL_VERSIONS[tool]} and the Dockerfile would be "
            f"describing a version it does not install."
        )

    def test_no_tool_is_still_installed_by_piping_a_script_into_a_shell(self):
        """The regression: `curl … | sh` pins nothing and executes what it fetched.

        Scoped to the three tools rather than to the whole file, because other
        lines legitimately pipe an installer -- uv and the nodesource key among
        them -- and this change is not about those.
        """
        text = DOCKERFILE.read_text()
        for tool in downloadable_tools():
            offenders = [
                line
                for line in text.splitlines()
                if tool in line and "| sh" in line and "curl" in line
            ]
            assert not offenders, (
                f"{tool} is back on the piped-installer path: {offenders}. That "
                f"path verifies no digest and was what failed the build on run "
                f"35246976698."
            )

    def test_every_pinned_tool_is_installed_by_the_dockerfile(self):
        """Positive control for the two tests above.

        Both of them pass vacuously if the install lines are gone entirely -- the
        ARG regex would fail, but a tool dropped from TOOL_VERSIONS would take its
        own parametrized case with it. This pins the other direction.
        """
        text = DOCKERFILE.read_text()
        for tool in _INSTALLED_BY_THE_SCRIPT:
            assert f"install-pinned-tool {tool}" in text, (
                f"{tool} has no `install-pinned-tool {tool}` line in the Dockerfile"
            )

    def test_every_stage_that_needs_uv_installs_the_pinned_one(self):
        """uv is installed in two stages; both must take the pinned path.

        The piped installer was there twice, and replacing one of them would have
        satisfied the per-tool scan above while the other kept running astral.sh's
        script.
        """
        text = _dockerfile_instructions()
        assert text.count("install-pinned-tool uv ") == 2
        assert "astral.sh/uv/install.sh" not in text

    def test_no_remote_script_is_executed_unverified_by_pip(self):
        """get-pip.py was fetched and run unpinned to install a pip already present."""
        assert "get-pip.py" not in _dockerfile_instructions()


class TestOpengrepReachesTheImageThroughThePin:
    """The exempted tool still has to be provisioned, and provisioned verified."""

    def test_the_exemption_names_only_tools_whose_plugin_installs_the_pin(
        self, test_plugin_context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner,
            OpengrepScannerConfig,
        )

        assert _PROVISIONED_BY_ASH_DEPENDENCIES_INSTALL == {"opengrep"}
        scanner = OpengrepScanner(
            context=test_plugin_context, config=OpengrepScannerConfig()
        )
        argv = scanner.custom_install_commands["linux"]["amd64"][0].args
        assert "install_pinned_tool" in argv[2]

    def test_the_image_runs_ash_dependencies_install(self):
        assert 'ashx dependencies install --bin-path "${ASH_BIN_PATH}"' in (
            DOCKERFILE.read_text()
        )


class TestArchResolution:
    @pytest.mark.parametrize(
        "machine,expected",
        [
            ("x86_64", "amd64"),
            ("X86_64", "amd64"),
            ("amd64", "amd64"),
            ("aarch64", "arm64"),
            ("arm64", "arm64"),
        ],
    )
    def test_known_machines_map_to_the_tables_vocabulary(self, machine, expected):
        assert installer.resolve_arch(machine) == expected

    def test_an_unknown_machine_is_refused_rather_than_guessed(self):
        """Installing an amd64 binary on a machine that cannot run it reads in a
        scan report as an execution failure, not as a bad install."""
        with pytest.raises(SystemExit) as raised:
            installer.resolve_arch("s390x")
        assert "s390x" in str(raised.value)


class TestTheExactlyOneMemberRule:
    def test_a_member_in_a_subdirectory_is_still_found(self, tmp_path):
        """A vendor moving the binary out of the archive root must keep working."""
        archive = tmp_path / "a.tar.gz"
        payload = tmp_path / "syft"
        payload.write_text("#!/bin/sh\n")
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(payload, arcname="nested/dir/syft")

        target = tmp_path / "out"
        installer.extract_member(archive, "syft", target)
        assert target.read_text() == "#!/bin/sh\n"

    def test_two_members_of_the_same_name_are_refused(self, tmp_path):
        archive = tmp_path / "a.tar.gz"
        payload = tmp_path / "syft"
        payload.write_text("x")
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(payload, arcname="one/syft")
            bundle.add(payload, arcname="two/syft")

        with pytest.raises(SystemExit) as raised:
            installer.extract_member(archive, "syft", tmp_path / "out")
        assert "refusing to guess" in str(raised.value)

    def test_a_missing_member_is_refused(self, tmp_path):
        archive = tmp_path / "a.tar.gz"
        payload = tmp_path / "other"
        payload.write_text("x")
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(payload, arcname="other")

        with pytest.raises(SystemExit) as raised:
            installer.extract_member(archive, "syft", tmp_path / "out")
        assert "no member named syft" in str(raised.value)

    def test_a_zip_is_read_the_same_way(self, tmp_path):
        """Windows assets are zips, and the member rule has to hold for them too."""
        archive = tmp_path / "a.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("nested/syft.exe", "binary")

        target = tmp_path / "out"
        installer.extract_member(archive, "syft.exe", target)
        assert target.read_text() == "binary"


class TestTheHttpsGuard:
    def test_a_non_https_asset_url_is_refused(self, tmp_path, monkeypatch):
        """The table is reviewed, so this guards a bad edit to it rather than a
        hostile input -- and it is why the tests below stub the transfer instead of
        serving the fixture over file://, which this correctly rejects."""
        pins = _pins_dir(
            tmp_path,
            {
                "https://github.com/anchore/syft/releases/download": "http://example.invalid"
            },
        )
        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")

        with pytest.raises(SystemExit) as raised:
            installer.install("syft", tmp_path / "bin", pins)
        assert "non-https" in str(raised.value)


class TestTheDigestCheckCanFail:
    """A pinned digest that cannot reject anything is decoration.

    ``download`` is stubbed rather than served, because the script refuses any URL
    that is not https and a local fixture cannot be. The stub writes real bytes to
    the real staging path and returns their real digest, so everything after the
    transfer -- the comparison, the extract, the move, the mode -- is the
    production code path. Only the socket is absent.
    """

    @staticmethod
    def _fake_download(payload: bytes, member: str = "syft"):
        """Return ``(download, digest)`` for a fixed archive.

        The archive bytes are built once and then written verbatim on every call.
        Building them per call instead made the digest move between calls -- gzip
        stamps an mtime into its header -- so the positive-control test hashed one
        archive and the installer received a different one, and a correct install
        failed the integrity check. A stub whose output is not reproducible cannot
        be used to test a digest comparison.
        """
        import hashlib
        import io

        buffer = io.BytesIO()
        # mtime=0 rather than relying on the buffer being reused, so the value is
        # pinned at the source of the nondeterminism as well.
        with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            info.mtime = 0
            bundle.addfile(info, io.BytesIO(payload))
        archive_bytes = buffer.getvalue()

        def download(url: str, target: Path) -> str:
            target.write_bytes(archive_bytes)
            return hashlib.sha256(archive_bytes).hexdigest()

        return download, hashlib.sha256(archive_bytes).hexdigest()

    def test_a_mismatch_exits_three_and_installs_nothing(self, tmp_path, monkeypatch):
        pins = _pins_dir(
            tmp_path,
            {
                "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47": "0"  # pragma: allowlist secret
                * 64
            },
        )
        download, _ = self._fake_download(b"#!/bin/sh\n")
        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
        monkeypatch.setattr(installer, "download", download)

        bin_dir = tmp_path / "bin"
        with pytest.raises(SystemExit) as raised:
            installer.install("syft", bin_dir, pins)

        assert raised.value.code == installer._EXIT_INTEGRITY, (
            "an integrity failure must be distinguishable from a network failure, "
            "because with-retry must not retry it"
        )
        assert not bin_dir.exists() or list(bin_dir.iterdir()) == [], (
            "the binary was installed anyway. A digest check that reports a "
            "mismatch and still leaves the executable in place has verified "
            "nothing -- the next build layer runs it regardless."
        )

    def test_a_matching_digest_installs(self, tmp_path, monkeypatch):
        """Positive control: the test above must fail on the digest, not on the
        plumbing it shares with the success path.

        Without this, deleting the download entirely would satisfy the mismatch
        assertions -- nothing installed, and any exit code could be made to match.
        """
        payload = b"#!/bin/sh\necho fake\n"
        # The digest comes from the archive bytes themselves, so the comparison in
        # the installer is a real one rather than a value both sides were handed.
        download, real_digest = self._fake_download(payload)

        import hashlib

        pins = _pins_dir(
            tmp_path,
            {
                "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47": real_digest,  # pragma: allowlist secret
                # The executable digest too: the fixture's member is not the real
                # syft, and the installer checks the member against its own pin.
                _SYFT_LINUX_AMD64_EXECUTABLE: hashlib.sha256(payload).hexdigest(),
            },
        )
        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
        monkeypatch.setattr(installer, "download", download)

        bin_dir = tmp_path / "bin"
        installed = installer.install("syft", bin_dir, pins)

        assert installed.is_file()
        assert installed.read_bytes() == payload
        assert os.access(installed, os.X_OK), (
            "the installed file must be executable, or the next Dockerfile layer's "
            "`RUN syft --version` fails with a permission error"
        )


class TestABareExecutableAsset:
    """opengrep publishes the executable itself; there is no archive to open."""

    def test_a_bare_asset_is_installed_as_is_after_verification(
        self, tmp_path, monkeypatch
    ):
        import hashlib

        payload = b"\x7fELF-opengrep"

        def download(url: str, target: Path) -> str:
            target.write_bytes(payload)
            return hashlib.sha256(payload).hexdigest()

        pins = _pins_dir(
            tmp_path,
            {
                "a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7": hashlib.sha256(  # pragma: allowlist secret
                    payload
                ).hexdigest()
            },
        )
        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
        monkeypatch.setattr(installer, "download", download)

        installed = installer.install("opengrep", tmp_path / "bin", pins)
        assert installed == tmp_path / "bin" / "opengrep"
        assert installed.read_bytes() == payload
        assert os.access(installed, os.X_OK)

    def test_a_bare_asset_that_does_not_match_installs_nothing(
        self, tmp_path, monkeypatch
    ):
        """Unpatched table: the committed opengrep digest is what refuses."""

        def download(url: str, target: Path) -> str:
            import hashlib

            target.write_bytes(b"not the release")
            return hashlib.sha256(b"not the release").hexdigest()

        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
        monkeypatch.setattr(installer, "download", download)

        bin_dir = tmp_path / "bin"
        with pytest.raises(SystemExit) as raised:
            installer.install("opengrep", bin_dir, _pins_dir(tmp_path))
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not bin_dir.exists() or list(bin_dir.iterdir()) == []


class TestTheExecutableDigestIsChecked:
    """The extracted executable is checked against its own pin, not only the archive.

    That second check is what lets ``ashx dependencies install`` later recognize the
    binary this script put in /usr/local/bin and leave it alone instead of writing
    another copy into ASH_BIN_PATH. If the check could not fail, a wrong entry in
    ``_EXECUTABLE_DIGESTS`` would ship unnoticed and the dedupe would silently never
    happen.
    """

    def _setup(self, tmp_path, monkeypatch, payload, executable_digest):
        import hashlib

        download, archive_digest = TestTheDigestCheckCanFail._fake_download(payload)
        pins = _pins_dir(
            tmp_path,
            {
                "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47": archive_digest,  # pragma: allowlist secret
                _SYFT_LINUX_AMD64_EXECUTABLE: executable_digest
                or hashlib.sha256(payload).hexdigest(),
            },
        )
        monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
        monkeypatch.setattr(installer, "download", download)
        return pins

    def test_a_member_that_misses_its_pin_exits_three_and_installs_nothing(
        self, tmp_path, monkeypatch
    ):
        pins = self._setup(tmp_path, monkeypatch, b"#!/bin/sh\n", "0" * 64)
        bin_dir = tmp_path / "bin"
        with pytest.raises(SystemExit) as raised:
            installer.install("syft", bin_dir, pins)
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not bin_dir.exists() or list(bin_dir.iterdir()) == []

    def test_an_identical_binary_at_the_destination_is_not_fetched_again(
        self, tmp_path, monkeypatch
    ):
        payload = b"#!/bin/sh\necho pinned\n"
        pins = self._setup(tmp_path, monkeypatch, payload, None)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "syft").write_bytes(payload)
        (bin_dir / "syft").chmod(0o755)

        def no_download(url, target):
            raise AssertionError("downloaded a binary that was already in place")

        monkeypatch.setattr(installer, "download", no_download)
        assert installer.install("syft", bin_dir, pins) == bin_dir / "syft"

    def test_a_symlink_to_identical_bytes_is_replaced_with_a_file(
        self, tmp_path, monkeypatch
    ):
        """A link's target can change after the check, so only a real file counts."""
        payload = b"#!/bin/sh\necho pinned\n"
        pins = self._setup(tmp_path, monkeypatch, payload, None)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "syft").write_bytes(payload)
        (elsewhere / "syft").chmod(0o755)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "syft").symlink_to(elsewhere / "syft")

        fetched = []
        real_download = installer.download
        monkeypatch.setattr(
            installer,
            "download",
            lambda url, target: fetched.append(url) or real_download(url, target),
        )
        installed = installer.install("syft", bin_dir, pins)
        # Asserted as "it was fetched and installed", not as "the result is no longer
        # a link": what the final move does to a link is platform behavior (Windows
        # writes through it), while refusing the link as proof is this script's.
        assert len(fetched) == 1, "a symlink was accepted as the installed binary"
        assert installed.read_bytes() == payload

    def test_a_different_binary_at_the_destination_is_replaced(
        self, tmp_path, monkeypatch
    ):
        payload = b"#!/bin/sh\necho pinned\n"
        pins = self._setup(tmp_path, monkeypatch, payload, None)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "syft").write_bytes(b"#!/bin/sh\necho something else\n")
        # Executable, so only the digest comparison can be what turns it away.
        (bin_dir / "syft").chmod(0o755)

        installed = installer.install("syft", bin_dir, pins)
        assert installed.read_bytes() == payload

    def test_identical_bytes_that_cannot_execute_are_reinstalled(
        self, tmp_path, monkeypatch
    ):
        """At mode 0644 the next layer's `RUN syft --version` would fail."""
        payload = b"#!/bin/sh\necho pinned\n"
        pins = self._setup(tmp_path, monkeypatch, payload, None)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "syft").write_bytes(payload)
        (bin_dir / "syft").chmod(0o644)

        installed = installer.install("syft", bin_dir, pins)
        assert os.access(installed, os.X_OK)


class TestLoadPinsLeavesSysModulesAlone:
    """The regression these tests could not see in themselves.

    ``load_pins`` has to occupy ``automated_security_helper.core.exceptions`` in
    ``sys.modules`` while it executes ``tool_downloads.py``, because that is the
    name tool_downloads imports from. An earlier version left the path-loaded copy
    registered there. Everything in this file still passed -- nothing here compares
    exception classes -- and
    ``tests/unit/plugin_modules/scanners/test_grep_scanner_base.py`` failed two
    tests instead, with the ScannerError it was asserting on escaping
    ``pytest.raises``, because that class object was no longer the one the scanner
    raised. Under xdist the corrupted table reached every test that shared the
    worker, so the visible failure was in a module unrelated to this change.

    The assertion is on identity rather than on presence: a restore that put back
    *a* module under that name while leaving a different object there would fix
    nothing.
    """

    def test_the_real_exceptions_module_is_still_the_one_imported(self, tmp_path):
        from automated_security_helper.core import exceptions as real_exceptions

        before = sys.modules["automated_security_helper.core.exceptions"]
        installer.load_pins(_pins_dir(tmp_path))
        after = sys.modules["automated_security_helper.core.exceptions"]

        assert after is before is real_exceptions, (
            "load_pins swapped the real exceptions module for its path-loaded "
            "copy, so ScannerError et al. now name two different classes and "
            "every `pytest.raises` on them in this process silently stops matching"
        )

    def test_the_real_tool_downloads_module_is_still_the_one_imported(self, tmp_path):
        from automated_security_helper.utils import tool_downloads as real_pins

        installer.load_pins(_pins_dir(tmp_path))

        assert (
            sys.modules["automated_security_helper.utils.tool_downloads"] is real_pins
        )

    def test_the_loaded_table_still_works_after_the_restore(self, tmp_path):
        """The restore must not break the module it just returned.

        It keeps working because it has already executed and its globals hold the
        exception class directly; if that stopped being true, the installer would
        fail on its next attribute access instead of here.
        """
        pins = installer.load_pins(_pins_dir(tmp_path))

        asset = pins.get_tool_asset("syft", "linux", "amd64")
        assert asset.version == TOOL_VERSIONS["syft"]
        with pytest.raises(Exception):
            pins.get_tool_asset("trivy", "windows", "arm64")

    def test_nothing_is_left_behind_when_the_names_were_absent(self, tmp_path):
        """An absent key must be removed again, not left holding a stub.

        ``core.exceptions`` is imported by the time this test runs, so the absent
        case is exercised on a name that is not: the loader registers
        ``automated_security_helper.core`` as a bare namespace stub, and leaving
        that behind would shadow the real subpackage for any later import.
        """
        saved = {
            name: sys.modules.pop(name, None)
            for name in ("automated_security_helper.core",)
        }
        try:
            installer.load_pins(_pins_dir(tmp_path))
            assert "automated_security_helper.core" not in sys.modules, (
                "a namespace stub was left registered for a name that had none, "
                "which shadows the real subpackage on the next import"
            )
        finally:
            for name, module in saved.items():
                if module is not None:
                    sys.modules[name] = module


class TestTheScriptRunsWithNothingInstalled:
    """The container build invokes this before the ASH wheel exists.

    The point of loading tool_downloads.py by path is that it works with only the
    standard library. If an import creeps in that needs a dependency, this test is
    the one that notices -- the rest of the file runs inside the project's own
    virtualenv, where everything is present.
    """

    def test_help_works_under_a_bare_interpreter(self):
        result = subprocess.run(  # nosec B603 — fixed interpreter and script path
            [sys.executable, "-I", "-S", str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "install a pinned ash scanner binary" in result.stdout.lower()

    def test_resolving_a_pin_needs_no_third_party_import(self, tmp_path):
        """`-S` drops site-packages, so any dependency import fails here."""
        pins = _pins_dir(tmp_path)
        probe = (
            "import sys; sys.path.insert(0, %r);"
            "import importlib.util;"
            "spec = importlib.util.spec_from_file_location('m', %r);"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
            "a = m.load_pins(__import__('pathlib').Path(%r))"
            ".get_tool_asset('syft', 'linux', 'amd64');"
            "print(a.version, a.sha256)"
        ) % (str(SCRIPT.parent), str(SCRIPT), str(pins))
        result = subprocess.run(  # nosec B603 — fixed interpreter, generated probe
            [sys.executable, "-I", "-S", "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert TOOL_VERSIONS["syft"] in result.stdout


# ---------------------------------------------------------------------------
# Third-party license and notice files
#
# The image build's ASH_THIRD_PARTY_DIR makes every `install-pinned-tool <tool>`
# install the tool's license files too, read from the archive it has just verified,
# and refuse a tool with no entry in THIRD_PARTY_LICENSES. These tests hold the
# installer to the properties the image's compliance rests on: the files land, they
# land only when everything verified, a tampered file stops the build, and the
# verification step at the end of the build can say no.
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402

from automated_security_helper.utils.tool_downloads import (  # noqa: E402
    THIRD_PARTY_LICENSES,
)

_SYFT_ARCHIVE_DIGEST = "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47"  # pragma: allowlist secret
_TRIVY_ARCHIVE_DIGEST = "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"  # pragma: allowlist secret
_TRIVY_LINUX_AMD64_EXECUTABLE = "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e"  # pragma: allowlist secret

# The fixture archives below hold a shell script, not the real syft or trivy, and the
# installer checks the extracted member against its own executable pin. Re-pinning
# the executable to the fixture's bytes keeps each test's failure (or success) about
# the license files it is testing, not about the member.
_FAKE_MEMBER = b"#!/bin/sh\n"
_FAKE_MEMBER_PINS = {
    _SYFT_LINUX_AMD64_EXECUTABLE: hashlib.sha256(_FAKE_MEMBER).hexdigest(),
    _TRIVY_LINUX_AMD64_EXECUTABLE: hashlib.sha256(_FAKE_MEMBER).hexdigest(),
}


def _tarball(members: dict) -> bytes:
    """A reproducible tar.gz: mtime pinned, so its digest is stable across calls."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o755
            bundle.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class _Server:
    """Stands in for ``installer.download``: serves fixed bytes per URL, records calls."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list = []

    def __call__(self, url: str, target: Path) -> str:
        self.calls.append(url)
        if url not in self.responses:
            raise AssertionError(f"unexpected download of {url}")
        target.write_bytes(self.responses[url])
        return _sha(self.responses[url])


def _url_file_overrides(payloads: dict) -> dict:
    """Digest overrides making every URL-pinned license file match ``payloads[url]``."""
    overrides = {}
    for entry in THIRD_PARTY_LICENSES.values():
        for license_file in entry.files:
            if license_file.url in payloads:
                overrides[license_file.sha256] = _sha(payloads[license_file.url])
    return overrides


def _linux_amd64(monkeypatch):
    monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(installer.platform, "system", lambda: "Linux")


def _syft_url() -> str:
    from automated_security_helper.utils.tool_downloads import get_tool_asset

    return get_tool_asset("syft", "linux", "amd64").url


def _trivy_url() -> str:
    from automated_security_helper.utils.tool_downloads import get_tool_asset

    return get_tool_asset("trivy", "linux", "amd64").url


_TRIVY_NOTICE_URL = next(
    f.url for f in THIRD_PARTY_LICENSES["trivy"].files if f.name == "NOTICE"
)


class TestLicenseFilesTravelWithTheBinary:
    def test_archive_license_lands_beside_the_binary(self, tmp_path, monkeypatch):
        archive = _tarball({"syft": b"#!/bin/sh\n", "LICENSE": b"syft license\n"})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        server = _Server({_syft_url(): archive})
        _linux_amd64(monkeypatch)
        monkeypatch.setattr(installer, "download", server)

        third_party = tmp_path / "doc" / "third-party"
        installer.install("syft", tmp_path / "bin", pins, third_party)

        directory = third_party / "syft"
        assert (directory / "LICENSE").read_bytes() == b"syft license\n"
        source = (directory / "SOURCE").read_text()
        assert THIRD_PARTY_LICENSES["syft"].commit in source
        assert _syft_url() in source, "SOURCE should name the asset it came from"
        assert (tmp_path / "bin" / "syft").read_bytes() == b"#!/bin/sh\n"
        assert server.calls == [_syft_url()], "an archive member needs no download"
        if os.name != "nt":
            assert directory.stat().st_mode & 0o777 == 0o755
            assert (directory / "LICENSE").stat().st_mode & 0o777 == 0o644

    def test_a_url_file_is_fetched_and_verified(self, tmp_path, monkeypatch):
        archive = _tarball({"trivy": b"#!/bin/sh\n", "LICENSE": b"trivy license\n"})
        notice = b"Trivy\nCopyright Aqua Security\n"
        pins = _pins_dir(
            tmp_path,
            {
                _TRIVY_ARCHIVE_DIGEST: _sha(archive),
                **_FAKE_MEMBER_PINS,
                **_url_file_overrides({_TRIVY_NOTICE_URL: notice}),
            },
        )
        monkeypatch.setattr(
            installer,
            "download",
            _Server({_trivy_url(): archive, _TRIVY_NOTICE_URL: notice}),
        )
        _linux_amd64(monkeypatch)

        third_party = tmp_path / "third-party"
        installer.install("trivy", tmp_path / "bin", pins, third_party)

        assert (third_party / "trivy" / "NOTICE").read_bytes() == notice
        assert (third_party / "trivy" / "LICENSE").read_bytes() == b"trivy license\n"

    def test_a_tampered_url_file_exits_three_and_installs_nothing(
        self, tmp_path, monkeypatch
    ):
        """The NOTICE digest is left at the real one; the server sends other bytes."""
        archive = _tarball({"trivy": b"#!/bin/sh\n", "LICENSE": b"trivy license\n"})
        pins = _pins_dir(
            tmp_path, {_TRIVY_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(
            installer,
            "download",
            _Server({_trivy_url(): archive, _TRIVY_NOTICE_URL: b"substituted\n"}),
        )
        _linux_amd64(monkeypatch)

        third_party = tmp_path / "third-party"
        with pytest.raises(SystemExit) as raised:
            installer.install("trivy", tmp_path / "bin", pins, third_party)

        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not (third_party / "trivy").exists()
        assert not (tmp_path / "bin" / "trivy").exists(), (
            "the binary was installed although its license files failed to verify"
        )

    def test_an_archive_without_its_license_installs_nothing(
        self, tmp_path, monkeypatch
    ):
        archive = _tarball({"syft": b"#!/bin/sh\n"})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(installer, "download", _Server({_syft_url(): archive}))
        _linux_amd64(monkeypatch)

        with pytest.raises(SystemExit) as raised:
            installer.install("syft", tmp_path / "bin", pins, tmp_path / "tp")

        assert "no member named LICENSE" in str(raised.value)
        assert not (tmp_path / "bin" / "syft").exists()
        assert not (tmp_path / "tp" / "syft").exists()

    def test_a_tool_without_an_entry_is_refused_before_downloading(
        self, tmp_path, monkeypatch
    ):
        """What a scanner pull request that forgets its entry hits in the build."""
        pins = _pins_dir(
            tmp_path,
            {
                '    "syft": ThirdPartyLicense(\n        tool="syft",': (
                    '    "notsyft": ThirdPartyLicense(\n        tool="notsyft",'
                )
            },
        )
        server = _Server({})
        monkeypatch.setattr(installer, "download", server)
        _linux_amd64(monkeypatch)

        with pytest.raises(SystemExit) as raised:
            installer.install("syft", tmp_path / "bin", pins, tmp_path / "tp")

        assert "THIRD_PARTY_LICENSES" in str(raised.value)
        assert server.calls == []

    def test_an_entry_for_another_version_is_refused(self, tmp_path, monkeypatch):
        pins = _pins_dir(
            tmp_path,
            {
                'version="v1.54.1",\n        license="Apache-2.0",\n'
                '        repository="https://github.com/anchore/syft"': (
                    'version="v1.0.0",\n        license="Apache-2.0",\n'
                    '        repository="https://github.com/anchore/syft"'
                )
            },
        )
        server = _Server({})
        monkeypatch.setattr(installer, "download", server)
        _linux_amd64(monkeypatch)

        with pytest.raises(SystemExit) as raised:
            installer.install("syft", tmp_path / "bin", pins, tmp_path / "tp")

        assert "half-applied" in str(raised.value)
        assert server.calls == []

    def test_without_the_dir_only_the_binary_is_written(self, tmp_path, monkeypatch):
        """The uv-reqs stage and a developer run: no license work, no entry needed."""
        archive = _tarball({"syft": b"#!/bin/sh\n"})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(installer, "download", _Server({_syft_url(): archive}))
        _linux_amd64(monkeypatch)

        installer.install("syft", tmp_path / "bin", pins)

        assert sorted(p.name for p in tmp_path.iterdir()) == ["bin", "pins"]

    def test_a_reinstall_replaces_the_directory_rather_than_merging(
        self, tmp_path, monkeypatch
    ):
        archive = _tarball({"syft": b"#!/bin/sh\n", "LICENSE": b"new\n"})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(installer, "download", _Server({_syft_url(): archive}))
        _linux_amd64(monkeypatch)
        stale = tmp_path / "tp" / "syft" / "NOTICE"
        stale.parent.mkdir(parents=True)
        stale.write_text("from an older entry")

        installer.install("syft", tmp_path / "bin", pins, tmp_path / "tp")

        assert not stale.exists()
        assert (tmp_path / "tp" / "syft" / "LICENSE").read_bytes() == b"new\n"

    @pytest.mark.parametrize("bad", ["../escape", "a/b", "..", ""])
    def test_a_name_that_leaves_its_directory_is_refused(self, bad):
        with pytest.raises(SystemExit):
            installer._plain_name(bad, "license file name")


class TestLicensesOnly:
    def test_opengrep_gets_its_files_and_a_source_section(self, tmp_path, monkeypatch):
        entry = THIRD_PARTY_LICENSES["opengrep"]
        payloads = {f.url: f"{f.name} text\n".encode() for f in entry.files}
        pins = _pins_dir(tmp_path, _url_file_overrides(payloads))
        monkeypatch.setattr(installer, "download", _Server(payloads))

        rc = installer.main(
            [
                "--licenses-only",
                "opengrep",
                "--third-party-dir",
                str(tmp_path / "tp"),
                "--pins-dir",
                str(pins),
            ]
        )

        assert rc == 0
        directory = tmp_path / "tp" / "opengrep"
        assert (directory / "LICENSE").read_bytes() == b"LICENSE text\n"
        assert (directory / "COPYRIGHT").read_bytes() == b"COPYRIGHT text\n"
        source = (directory / "SOURCE").read_text()
        assert "Corresponding source" in source
        for command in entry.source_checkout:
            assert command in source

    def test_a_tool_whose_files_are_in_its_archive_is_refused(self, tmp_path):
        """--licenses-only has no archive; it must not invent a second download."""
        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "syft", _pins_dir(tmp_path), tmp_path / "tp"
            )
        assert "release archive" in str(raised.value)
        assert not (tmp_path / "tp" / "syft").exists()

    def test_the_mode_works_under_a_bare_interpreter(self):
        result = subprocess.run(  # nosec B603 - fixed interpreter and script path
            [sys.executable, "-I", "-S", str(SCRIPT), "--verify-third-party", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "--licenses-only" in result.stdout


@pytest.mark.parametrize(
    "output,version,expected",
    [
        ("uv 0.12.23 (x86_64-unknown-linux-gnu)", "0.12.23", True),
        ("Version: 0.69.3\n", "0.69.3", True),
        ("1.15.1\n", "1.15.1", True),
        ("Haskell Dockerfile Linter v2.12.0.", "2.12.0", True),
        ("uv 0.12.0", "0.12.23", False),
        ("uv 0.12.23", "0.12.2", False),
        ("1.15.10", "1.15.1", False),
        ("11.2", "1.2", False),
        ("0.12.23.1", "0.12.23", False),
    ],
)
def test_the_version_match_is_a_whole_version(output, version, expected):
    assert installer.reports_version(output, version) is expected


@pytest.mark.skipif(
    os.name == "nt",
    reason="runs only in the Linux image build; the fixtures are POSIX executables",
)
class TestVerifyThirdParty:
    """The last step of the image build. Each negative case is one mutation of a
    tree on which the positive case passes, so a failure is about that mutation."""

    @staticmethod
    def _tree(tmp_path: Path):
        """A complete third-party tree, a PATH of fake executables, and the pins."""
        # Keyed by pin, not by tool: semgrep's LICENSE and COPYRIGHT are
        # byte-identical to opengrep's and share their digests, so two files
        # sharing a pin must share bytes here too.
        payloads = {
            f.url: f"file pinned to {f.sha256}\n".encode()
            for entry in THIRD_PARTY_LICENSES.values()
            for f in entry.files
            if f.url
        }
        pins = _pins_dir(tmp_path, _url_file_overrides(payloads))
        third_party = tmp_path / "tp"
        bin_dir = tmp_path / "path-bin"
        bin_dir.mkdir()
        for entry in THIRD_PARTY_LICENSES.values():
            directory = third_party / entry.tool
            directory.mkdir(parents=True)
            for f in entry.files:
                (directory / f.name).write_bytes(
                    payloads[f.url] if f.url else b"archive member\n"
                )
            (directory / "SOURCE").write_text(entry.source_notice())
            for name in entry.executable_names:
                exe = bin_dir / name
                exe.write_text(
                    f'#!/bin/sh\nmkdir -p "$HOME/.cache" && touch "$HOME/.cache/{name}"\n'
                    f'echo "{name} {entry.version.lstrip("v")}"\n'
                )
                exe.chmod(0o755)
        return pins, third_party, str(bin_dir)

    def test_a_complete_tree_passes_and_gets_an_index(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        assert installer.verify_third_party(pins, third_party, path, []) == []
        index = json.loads((third_party / "index.json").read_text())
        assert [row["tool"] for row in index["tools"]] == sorted(THIRD_PARTY_LICENSES)

    def _fails(self, pins, third_party, path, needle, site_dirs=()):
        site_dirs = list(site_dirs)
        problems = installer.verify_third_party(pins, third_party, path, site_dirs)
        assert any(needle in p for p in problems), problems
        assert not (third_party / "index.json").exists(), (
            "the index lists what was verified, so it must not be written on failure"
        )

    def test_a_missing_file(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (third_party / "trivy" / "NOTICE").unlink()
        self._fails(pins, third_party, path, "NOTICE is missing")

    def test_a_tampered_url_file(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (third_party / "opengrep" / "LICENSE").write_text("not the LGPL\n")
        self._fails(pins, third_party, path, "does not match its pinned SHA256")

    def test_a_file_only_root_can_read(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (third_party / "syft" / "LICENSE").chmod(0o600)
        self._fails(pins, third_party, path, "not world-readable")

    def test_a_source_file_naming_another_commit(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (third_party / "uv" / "SOURCE").write_text("uv\n")
        self._fails(pins, third_party, path, "does not name commit")

    def test_an_executable_reporting_another_version(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        exe = Path(path) / "grype"
        exe.write_text('#!/bin/sh\necho "grype 0.119.0"\n')
        self._fails(pins, third_party, path, "does not report 0.120.1")

    def test_an_executable_missing_from_path(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (Path(path) / "uv").unlink()
        self._fails(pins, third_party, path, "uv: uv is not on PATH")

    def test_a_secondary_executable_may_be_absent(self, tmp_path):
        """After #740 the release archive installs uv alone; uvx then exists only
        as the PyPI wheel's copy, which this check leaves out."""
        pins, third_party, path = self._tree(tmp_path)
        (Path(path) / "uvx").unlink()
        assert installer.verify_third_party(pins, third_party, path, []) == []

    @staticmethod
    def _python_owned_copy(
        tmp_path: Path, name: str, version: str
    ) -> "tuple[str, list]":
        """A bin dir whose ``name`` a fake dist-info RECORD claims, as pip's does."""
        site = tmp_path / "site-packages"
        dist = site / "uv-0.0.0.dist-info"
        dist.mkdir(parents=True)
        bin_dir = tmp_path / "py-bin"
        bin_dir.mkdir()
        exe = bin_dir / name
        exe.write_text(f'#!/bin/sh\necho "{name} {version}"\n')
        exe.chmod(0o755)
        (dist / "RECORD").write_text(f"../py-bin/{name},sha256=x,1\n")
        return str(bin_dir), [str(site)]

    def test_a_python_package_copy_is_not_version_checked(self, tmp_path):
        """The uv wheel ASH depends on floats within pyproject's range. Its copy
        first on PATH, at another version, must not fail the build; the release
        binary behind it is the one the entry describes, and is still checked."""
        pins, third_party, path = self._tree(tmp_path)
        py_bin, site_dirs = self._python_owned_copy(tmp_path, "uv", "0.12.99")
        searched = os.pathsep.join([py_bin, path])
        assert (
            installer.verify_third_party(pins, third_party, searched, site_dirs) == []
        )
        (third_party / "index.json").unlink()
        (Path(path) / "uv").write_text('#!/bin/sh\necho "uv 0.1.0"\n')
        self._fails(pins, third_party, searched, "does not report 0.12.23", site_dirs)

    def test_every_release_copy_is_checked_not_only_the_first(self, tmp_path):
        """grype is in both /usr/local/bin and /.ash/bin in the image."""
        pins, third_party, path = self._tree(tmp_path)
        second = tmp_path / "second-bin"
        second.mkdir()
        (second / "grype").write_text('#!/bin/sh\necho "grype 0.119.0"\n')
        (second / "grype").chmod(0o755)
        searched = os.pathsep.join([path, str(second)])
        self._fails(pins, third_party, searched, "second-bin/grype --version")

    def test_only_a_python_package_copy_of_the_primary_fails(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (Path(path) / "uv").unlink()
        py_bin, site_dirs = self._python_owned_copy(tmp_path, "uv", "0.12.23")
        searched = os.pathsep.join([py_bin, path])
        self._fails(
            pins, third_party, searched, "other than as a Python package", site_dirs
        )

    def test_a_directory_with_no_entry(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        (third_party / "retired-tool").mkdir()
        self._fails(
            pins, third_party, path, "retired-tool: directory with no license entry"
        )

    def test_a_missing_directory_for_an_entry(self, tmp_path):
        pins, third_party, path = self._tree(tmp_path)
        shutil.rmtree(third_party / "syft")
        self._fails(pins, third_party, path, "syft: ")

    def test_version_queries_cannot_write_into_the_real_home(
        self, tmp_path, monkeypatch
    ):
        """opengrep unpacks 208 MB into $HOME/.cache on --version; in the build
        that was a 218 MB layer. The fake executables touch $HOME/.cache/<name>."""
        pins, third_party, path = self._tree(tmp_path)
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        assert installer.verify_third_party(pins, third_party, path, []) == []
        assert list(home.iterdir()) == []


class TestTheGuardsTheReviewFoundUntested:
    """Each of these guards survived a mutation probe before it had a test."""

    def test_a_non_https_license_url_is_refused(self, tmp_path, monkeypatch):
        archive = _tarball({"trivy": b"#!/bin/sh\n", "LICENSE": b"trivy license\n"})
        pins = _pins_dir(
            tmp_path,
            {
                _TRIVY_ARCHIVE_DIGEST: _sha(archive),
                **_FAKE_MEMBER_PINS,
                'return f"https://raw.githubusercontent.com/': (
                    'return f"http://raw.githubusercontent.com/'
                ),
            },
        )
        monkeypatch.setattr(installer, "download", _Server({_trivy_url(): archive}))
        _linux_amd64(monkeypatch)

        with pytest.raises(SystemExit) as raised:
            installer.install("trivy", tmp_path / "bin", pins, tmp_path / "tp")

        assert "non-https" in str(raised.value)
        assert not (tmp_path / "bin" / "trivy").exists()

    def test_main_reads_the_dir_from_the_environment(self, tmp_path, monkeypatch):
        """The Dockerfile sets ASH_THIRD_PARTY_DIR and nothing else; if main()
        stopped reading it, every pinned install would ship without licenses."""
        archive = _tarball({"syft": b"#!/bin/sh\n", "LICENSE": b"syft license\n"})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(installer, "download", _Server({_syft_url(): archive}))
        _linux_amd64(monkeypatch)
        monkeypatch.setenv("ASH_THIRD_PARTY_DIR", str(tmp_path / "tp"))

        rc = installer.main(
            ["syft", "-b", str(tmp_path / "bin"), "--pins-dir", str(pins)]
        )

        assert rc == 0
        assert (tmp_path / "tp" / "syft" / "LICENSE").read_bytes() == b"syft license\n"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
    def test_modes_are_set_even_under_a_restrictive_umask(self, tmp_path, monkeypatch):
        """The final image runs as a non-root user, who must read these."""
        archive = _tarball({"syft": b"#!/bin/sh\n", "LICENSE": b"syft license\n"})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(installer, "download", _Server({_syft_url(): archive}))
        _linux_amd64(monkeypatch)

        previous = os.umask(0o077)
        try:
            installer.install("syft", tmp_path / "bin", pins, tmp_path / "tp")
        finally:
            os.umask(previous)

        directory = tmp_path / "tp" / "syft"
        assert directory.stat().st_mode & 0o777 == 0o755
        for name in ("LICENSE", "SOURCE"):
            assert (directory / name).stat().st_mode & 0o777 == 0o644

    def test_an_empty_license_file_is_refused(self, tmp_path, monkeypatch):
        archive = _tarball({"syft": b"#!/bin/sh\n", "LICENSE": b""})
        pins = _pins_dir(
            tmp_path, {_SYFT_ARCHIVE_DIGEST: _sha(archive), **_FAKE_MEMBER_PINS}
        )
        monkeypatch.setattr(installer, "download", _Server({_syft_url(): archive}))
        _linux_amd64(monkeypatch)

        with pytest.raises(SystemExit) as raised:
            installer.install("syft", tmp_path / "bin", pins, tmp_path / "tp")

        assert "is empty" in str(raised.value)
        assert not (tmp_path / "bin" / "syft").exists()


# ---------------------------------------------------------------------------
# The Python tools: bandit, checkov and semgrep
#
# `ashx dependencies install` installs them with `uv tool install`, so there is no
# release archive; the archive is the wheel, and what it shipped is in the installed
# dist-info under `uv tool dir`. These tests stand a fake uv tool directory up in
# tmp_path and point the installer at it, so nothing touches the real one.
# ---------------------------------------------------------------------------


def _record_hash(payload: bytes) -> str:
    """A RECORD hash: urlsafe base64 of the SHA256, padding stripped."""
    import base64

    return (
        base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def _uv_tool_env(
    tool_dir: Path,
    distribution: str,
    version: str,
    files: dict,
    record_overrides: "dict | None" = None,
) -> Path:
    """A uv tool environment holding ``distribution``'s dist-info with ``files``.

    ``files`` maps a path inside the dist-info (``licenses/LICENSE``) to its bytes.
    RECORD lists each with its real hash unless ``record_overrides`` says otherwise.
    """
    site = tool_dir / distribution / "lib" / "python3.12" / "site-packages"
    dist_info = site / f"{distribution}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n\nbody\n"
    )
    rows = []
    for relative, payload in files.items():
        (dist_info / relative).parent.mkdir(parents=True, exist_ok=True)
        (dist_info / relative).write_bytes(payload)
        digest = (record_overrides or {}).get(relative, _record_hash(payload))
        rows.append(f"{dist_info.name}/{relative},sha256={digest},{len(payload)}")
    rows.append(f"{dist_info.name}/RECORD,,")
    (dist_info / "RECORD").write_text("\n".join(rows) + "\n")
    return dist_info


def _semgrep():
    """semgrep's entry, its installed version and its URL per file name.

    Looked up per test rather than at import, so a table without the entry fails
    these tests one by one instead of failing the whole module's collection.
    """
    entry = THIRD_PARTY_LICENSES["semgrep"]
    return entry, entry.version.lstrip("v"), {f.name: f.url for f in entry.files}


class TestPythonToolLicenses:
    @pytest.fixture
    def tool_dir(self, tmp_path, monkeypatch):
        directory = tmp_path / "uv-tools"
        directory.mkdir()
        monkeypatch.setattr(installer, "uv_tool_dir", lambda: directory)
        return directory

    def test_semgrep_falls_back_to_the_pinned_files_when_its_wheel_has_none(
        self, tmp_path, monkeypatch, tool_dir
    ):
        """semgrep's real wheel: METADATA and RECORD, no license file at all."""
        entry, version, urls = _semgrep()
        _uv_tool_env(tool_dir, "semgrep", version, {})
        payloads = {url: f"{name} text\n".encode() for name, url in urls.items()}
        pins = _pins_dir(tmp_path, _url_file_overrides(payloads))
        server = _Server(payloads)
        monkeypatch.setattr(installer, "download", server)

        installer.install_licenses_only("semgrep", pins, tmp_path / "tp")

        directory = tmp_path / "tp" / "semgrep"
        assert (directory / "LICENSE").read_bytes() == b"LICENSE text\n"
        assert (directory / "COPYRIGHT").read_bytes() == b"COPYRIGHT text\n"
        assert sorted(server.calls) == sorted(urls.values())
        source = (directory / "SOURCE").read_text()
        for needle in (
            "Corresponding source",
            "https://github.com/semgrep/semgrep",
            f"tag:        {entry.version}",
            entry.commit,
            f"PyPI semgrep=={version}",
        ):
            assert needle in source, needle

    def test_a_fetched_license_that_misses_its_digest_is_refused(
        self, tmp_path, monkeypatch, tool_dir
    ):
        """The pins are the real ones; the server sends other bytes."""
        _, version, urls = _semgrep()
        _uv_tool_env(tool_dir, "semgrep", version, {})
        monkeypatch.setattr(
            installer,
            "download",
            _Server(dict.fromkeys(urls.values(), b"substituted\n")),
        )

        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "semgrep", _pins_dir(tmp_path), tmp_path / "tp"
            )

        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not (tmp_path / "tp" / "semgrep").exists()

    def test_dist_info_licenses_are_preferred_when_present(
        self, tmp_path, monkeypatch, tool_dir
    ):
        """A wheel that ships the file is read, not re-fetched; the pin still holds."""
        _, version, urls = _semgrep()
        shipped = {"LICENSE": b"LGPL text\n", "COPYRIGHT": b"Semgrep copyright\n"}
        _uv_tool_env(
            tool_dir,
            "semgrep",
            version,
            {f"licenses/{name}": payload for name, payload in shipped.items()},
        )
        pins = _pins_dir(
            tmp_path,
            _url_file_overrides(
                {urls[name]: payload for name, payload in shipped.items()}
            ),
        )
        server = _Server({})
        monkeypatch.setattr(installer, "download", server)

        installer.install_licenses_only("semgrep", pins, tmp_path / "tp")

        assert server.calls == [], "the wheel shipped the files; nothing to fetch"
        for name, payload in shipped.items():
            assert (tmp_path / "tp" / "semgrep" / name).read_bytes() == payload

    def test_a_dist_info_copy_that_misses_the_pin_is_refused(
        self, tmp_path, monkeypatch, tool_dir
    ):
        """Preferred is not unchecked: the image's bytes must not depend on which
        of the two places they came from."""
        _, version, _ = _semgrep()
        _uv_tool_env(
            tool_dir,
            "semgrep",
            version,
            {"licenses/LICENSE": b"some other text\n", "COPYRIGHT": b"c\n"},
        )
        monkeypatch.setattr(installer, "download", _Server({}))

        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "semgrep", _pins_dir(tmp_path), tmp_path / "tp"
            )

        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not (tmp_path / "tp" / "semgrep").exists()

    @pytest.mark.parametrize("tool", ["bandit", "checkov"])
    def test_a_wheel_license_is_copied_from_its_dist_info(
        self, tmp_path, monkeypatch, tool_dir, tool
    ):
        entry = THIRD_PARTY_LICENSES[tool]
        _uv_tool_env(
            tool_dir,
            tool,
            entry.version,
            {"licenses/LICENSE": b"Apache License\n"},
        )
        server = _Server({})
        monkeypatch.setattr(installer, "download", server)

        installer.install_licenses_only(tool, _pins_dir(tmp_path), tmp_path / "tp")

        assert (tmp_path / "tp" / tool / "LICENSE").read_bytes() == b"Apache License\n"
        assert server.calls == []
        assert entry.commit in (tmp_path / "tp" / tool / "SOURCE").read_text()

    def test_a_dist_info_file_that_misses_its_record_hash_is_refused(
        self, tmp_path, tool_dir
    ):
        _uv_tool_env(
            tool_dir,
            "bandit",
            THIRD_PARTY_LICENSES["bandit"].version,
            {"licenses/LICENSE": b"Apache License\n"},
            record_overrides={"licenses/LICENSE": _record_hash(b"another file")},
        )

        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "bandit", _pins_dir(tmp_path), tmp_path / "tp"
            )

        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not (tmp_path / "tp" / "bandit").exists()

    def test_a_wheel_without_the_file_its_entry_expects_is_refused(
        self, tmp_path, tool_dir
    ):
        _uv_tool_env(tool_dir, "bandit", THIRD_PARTY_LICENSES["bandit"].version, {})

        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "bandit", _pins_dir(tmp_path), tmp_path / "tp"
            )

        assert "is not in" in str(raised.value)
        assert not (tmp_path / "tp" / "bandit").exists()

    def test_another_installed_version_is_refused(self, tmp_path, tool_dir):
        """What an unpinned `ashx dependencies install` would leave behind."""
        _uv_tool_env(tool_dir, "semgrep", "1.0.0", {})

        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "semgrep", _pins_dir(tmp_path), tmp_path / "tp"
            )

        assert "--uv-tool-pins" in str(raised.value)
        assert not (tmp_path / "tp" / "semgrep").exists()

    def test_a_tool_that_is_not_installed_is_refused(self, tmp_path, tool_dir):
        with pytest.raises(SystemExit) as raised:
            installer.install_licenses_only(
                "checkov", _pins_dir(tmp_path), tmp_path / "tp"
            )
        assert "found 0" in str(raised.value)


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv on PATH")
def test_uv_tool_dir_is_a_plain_path_even_when_color_is_forced(monkeypatch):
    """Measured: with FORCE_COLOR set, `uv tool dir` wraps the path in ANSI codes
    even when its stdout is a pipe, and the dist-info lookup then found nothing."""
    monkeypatch.setenv("FORCE_COLOR", "3")
    location = str(installer.uv_tool_dir())
    assert "\x1b" not in location
    assert Path(location).is_absolute()


class TestUvToolPins:
    def test_every_python_tool_is_pinned_to_its_entry(self, tmp_path):
        argv = installer.uv_tool_pins(_pins_dir(tmp_path))
        expected = []
        for tool in sorted(THIRD_PARTY_LICENSES):
            entry = THIRD_PARTY_LICENSES[tool]
            if entry.distribution:
                expected += [
                    "--config-overrides",
                    f"scanners.{tool}.options.tool_version==="
                    + entry.version.lstrip("v"),
                ]
        assert argv == expected
        assert {"bandit", "checkov", "semgrep"} <= {
            a.split(".")[1] for a in argv if a.startswith("scanners.")
        }

    def test_ash_reads_them_as_exact_version_constraints(self, tmp_path):
        """The overrides go through ASH's own parser in the image; check the value
        that reaches each scanner is an exact pin, not a range or a string with a
        stray `=`."""
        from automated_security_helper.config.resolve_config import (
            apply_config_overrides,
        )
        from automated_security_helper.config.ash_config import AshConfig

        argv = installer.uv_tool_pins(_pins_dir(tmp_path))
        config = apply_config_overrides(AshConfig(), argv[1::2])
        for tool in ("bandit", "checkov", "semgrep"):
            version = THIRD_PARTY_LICENSES[tool].version.lstrip("v")
            assert getattr(config.scanners, tool).options.tool_version == (
                f"=={version}"
            )

    def test_the_mode_prints_them_under_a_bare_interpreter(self, tmp_path):
        """The Dockerfile word-splits this output into `ashx dependencies install`."""
        pins = _pins_dir(tmp_path)
        result = subprocess.run(  # nosec B603 - fixed interpreter and script path
            [
                sys.executable,
                "-I",
                "-S",
                str(SCRIPT),
                "--uv-tool-pins",
                "--pins-dir",
                str(pins),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.split() == installer.uv_tool_pins(pins)
