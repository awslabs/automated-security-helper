# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""install-pinned-tool's exit status says why it stopped.

with-retry repeats an attempt for every status that is not on its no-retry list,
so a request that can never succeed has to leave with a status of its own and a
one-line message, not a traceback with status 1:

* A tool, bundle or platform the table has no entry for, and a table entry that
  is half-applied, exit ``_EXIT_USAGE``. ``install`` and ``install_bundle`` used
  to let ``ToolNotProvisionableError`` escape, which Python reports as exit 1.
* A rules bundle whose pinned archive has a layout the installer refuses (an
  unsafe member name, two members of one name, a member over the size cap, no rule
  files) exits ``_EXIT_INTEGRITY``, as the in-process installer treats the same
  archives. The archive already matched its digest, so another attempt would
  read the same bytes.
* A license file pinned by URL with no digest is refused before the fetch. It
  used to be fetched and then crash on ``None.lower()``.

Nothing here reaches the network or starts a process.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import types
import warnings
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_codes", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


def _linux(monkeypatch, machine: str = "x86_64", system: str = "Linux") -> None:
    monkeypatch.setattr(installer.platform, "machine", lambda: machine)
    monkeypatch.setattr(installer.platform, "system", lambda: system)


def _pins(**members):
    """A stand-in for the loaded table, with only the members a test gives it."""
    return types.SimpleNamespace(ToolNotProvisionableError=LookupError, **members)


class TestARequestThatCannotSucceedExitsUsage:
    def test_an_unknown_tool(self, tmp_path, monkeypatch, capsys):
        _linux(monkeypatch)
        with pytest.raises(SystemExit) as raised:
            installer.install("no-such-tool", tmp_path / "bin", PACKAGE_ROOT)
        assert raised.value.code == installer._EXIT_USAGE
        assert "no-such-tool" in str(raised.value)
        assert "no-such-tool" in capsys.readouterr().err

    def test_a_platform_the_tool_has_no_asset_for(self, tmp_path, monkeypatch):
        """A stand-in table that has no asset, so the real one can gain one safely."""
        _linux(monkeypatch, machine="aarch64", system="Windows")
        asked = []

        def no_asset(tool, platform_name, arch):
            asked.append((tool, platform_name, arch))
            raise LookupError(f"{tool} has no asset for {platform_name}/{arch}")

        def must_not_download(url, target):
            raise AssertionError(f"reached the network for {url}")

        monkeypatch.setattr(
            installer, "load_pins", lambda root: _pins(get_tool_asset=no_asset)
        )
        monkeypatch.setattr(installer, "download", must_not_download)

        with pytest.raises(SystemExit) as raised:
            installer.install("trivy", tmp_path / "bin", PACKAGE_ROOT)

        assert raised.value.code == installer._EXIT_USAGE
        assert asked == [("trivy", "windows", "arm64")]
        assert "windows/arm64" in str(raised.value)

    def test_a_machine_the_table_does_not_know(self):
        with pytest.raises(SystemExit) as raised:
            installer.resolve_arch("s390x")
        assert raised.value.code == installer._EXIT_USAGE
        assert "s390x" in str(raised.value)

    def test_an_unknown_rules_bundle(self, tmp_path):
        with pytest.raises(SystemExit) as raised:
            installer.install_bundle("no-such-bundle", tmp_path / "rules", PACKAGE_ROOT)
        assert raised.value.code == installer._EXIT_USAGE
        assert "no-such-bundle" in str(raised.value)

    def test_a_missing_license_entry(self):
        def missing(tool):
            raise LookupError(f"{tool} has no entry")

        pins = _pins(get_third_party_license=missing)
        with pytest.raises(SystemExit) as raised:
            installer._third_party_entry(pins, "demo")
        assert raised.value.code == installer._EXIT_USAGE

    def test_a_half_applied_version_bump(self):
        entry = types.SimpleNamespace(version="1.0.0")
        pins = _pins(get_third_party_license=lambda tool: entry)
        with pytest.raises(SystemExit) as raised:
            installer._third_party_entry(pins, "demo", "2.0.0")
        assert raised.value.code == installer._EXIT_USAGE
        assert "half-applied" in str(raised.value)

    def test_a_non_https_asset_url(self, tmp_path, monkeypatch):
        _linux(monkeypatch)
        asset = types.SimpleNamespace(
            tool="demo", version="1.0.0", url="http://example.invalid/demo.tar.gz"
        )
        pins = _pins(get_tool_asset=lambda tool, platform_name, arch: asset)
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)
        with pytest.raises(SystemExit) as raised:
            installer.install("demo", tmp_path / "bin", PACKAGE_ROOT)
        assert raised.value.code == installer._EXIT_USAGE
        assert "non-https" in str(raised.value)

    def test_a_non_https_bundle_url(self, tmp_path, monkeypatch):
        bundle = types.SimpleNamespace(url="http://example.invalid/rules.zip")
        pins = _pins(get_rules_bundle=lambda name: bundle)
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)
        with pytest.raises(SystemExit) as raised:
            installer.install_bundle("demo", tmp_path / "rules", PACKAGE_ROOT)
        assert raised.value.code == installer._EXIT_USAGE
        assert "non-https" in str(raised.value)

    def test_a_refusal_installs_nothing(self, tmp_path, monkeypatch):
        """Control: the refusal leaves the destination as it found it."""
        _linux(monkeypatch)
        with pytest.raises(SystemExit):
            installer.install("no-such-tool", tmp_path / "bin", PACKAGE_ROOT)
        assert not (tmp_path / "bin").exists() or not any((tmp_path / "bin").iterdir())


def _rules_zip(entries: "list[tuple[str, bytes]]") -> bytes:
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        # A repeated member name is the point of one case; zipfile warns about it.
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in entries:
                archive.writestr(name, data)
    return buffer.getvalue()


_RULES = types.SimpleNamespace(member_dir="output", member_suffix=".guard")


def _members(entries):
    with zipfile.ZipFile(io.BytesIO(_rules_zip(entries))) as archive:
        return installer._bundle_members(archive, _RULES)


class TestAnArchiveTheInstallerRefusesExitsIntegrity:
    def test_an_unsafe_member_name(self):
        with pytest.raises(SystemExit) as raised:
            _members([("output/bad name.guard", b"x")])
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert "unsafe name" in str(raised.value)

    def test_two_members_of_one_name(self):
        with pytest.raises(SystemExit) as raised:
            _members([("output/a.guard", b"x"), ("output/a.guard", b"y")])
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert "two members" in str(raised.value)

    def test_a_member_over_the_size_cap(self, monkeypatch):
        monkeypatch.setattr(installer, "_MAX_MEMBER_BYTES", 10)
        with pytest.raises(SystemExit) as raised:
            _members([("output/a.guard", b"x" * 11)])
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert "size cap" in str(raised.value)

    def test_no_rule_files(self):
        with pytest.raises(SystemExit) as raised:
            _members([("output/README.md", b"x")])
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert "holds no" in str(raised.value)

    def test_the_messages_reach_standard_error(self, capsys):
        with pytest.raises(SystemExit):
            _members([("output/README.md", b"x")])
        assert "holds no .guard files" in capsys.readouterr().err

    def test_members_that_expand_past_the_total_cap(self, tmp_path, monkeypatch):
        """Each member is under the per-member cap; together they are over the total."""
        monkeypatch.setattr(installer, "_MAX_TOTAL_BYTES", 100)
        archive = _rules_zip(
            [("output/a.guard", b"x" * 60), ("output/b.guard", b"y" * 60)]
        )
        bundle = types.SimpleNamespace(
            name="demo-rules",
            version="1.0.0",
            url="https://example.invalid/rules.zip",
            sha256=hashlib.sha256(archive).hexdigest(),
            contents_sha256="",
            member_dir="output",
            member_suffix=".guard",
        )
        pins = _pins(get_rules_bundle=lambda name: bundle)
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)

        def download(url, target):
            target.write_bytes(archive)
            return hashlib.sha256(archive).hexdigest()

        monkeypatch.setattr(installer, "download", download)
        with pytest.raises(SystemExit) as raised:
            installer.install_bundle("demo-rules", tmp_path / "rules", PACKAGE_ROOT)
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert list((tmp_path / "rules").iterdir()) == []


class TestALicenseUrlWithoutADigest:
    def test_it_is_refused_before_it_is_fetched(self, tmp_path, monkeypatch):
        license_file = types.SimpleNamespace(
            name="LICENSE",
            url="https://example.invalid/LICENSE",
            sha256=None,
            from_archive=False,
        )
        entry = types.SimpleNamespace(
            tool="demo",
            files=(license_file,),
            source_notice=lambda installed_from=None: "demo\n",
        )
        fetched = []

        def download(url, target):
            fetched.append(url)
            target.write_bytes(b"text\n")
            return hashlib.sha256(b"text\n").hexdigest()

        monkeypatch.setattr(installer, "download", download)
        with pytest.raises(SystemExit) as raised:
            installer.stage_third_party(entry, None, tmp_path, installed_from=None)
        assert raised.value.code == installer._EXIT_USAGE
        assert "no pinned SHA256" in str(raised.value)
        assert fetched == []
