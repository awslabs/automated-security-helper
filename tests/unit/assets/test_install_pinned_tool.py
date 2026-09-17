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


class TestTheDockerfileAndTheTableAgree:
    """The ARG lines and TOOL_VERSIONS are the same fact written twice."""

    @pytest.mark.parametrize("tool", sorted(TOOL_VERSIONS))
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
        for tool in downloadable_tools():
            assert f"install-pinned-tool {tool}" in text, (
                f"{tool} has no `install-pinned-tool {tool}` line in the Dockerfile"
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
                "590650c2743b83f327d1bf9bec64f6f83b7fec504187bb84f500c862bf8f2a0f": "0"
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

        pins = _pins_dir(
            tmp_path,
            {
                "590650c2743b83f327d1bf9bec64f6f83b7fec504187bb84f500c862bf8f2a0f": real_digest
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
