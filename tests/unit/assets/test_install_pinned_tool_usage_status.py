# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Deterministic refusals leave with the usage status, not status 1.

with-retry repeats an attempt for every status that is not on its no-retry list.
Status 1 is also what a dropped connection leaves with, so a refusal written as
``raise SystemExit(message)`` was retried three times before the same message
came back. These refusals depend only on the pinned table, the verified archive
or the installed environment, so another attempt reads the same bytes:

* ``_require_exactly_one`` (an archive with no member of the wanted name, or
  two) and a member that cannot be opened.
* ``_plain_name`` (a table value that would leave the directory it names).
* A license file that is empty, one the wheel does not ship, and one read from a
  release archive when there is none.
* ``uv`` missing from PATH, the installed dist-info missing or at another
  version, and a rules bundle the table has no entry for (``--check``).

``uv tool dir`` failing to run stays status 1: a timeout or an OS error there
can be transient.

Nothing here reaches the network or starts a process.
"""

from __future__ import annotations

import importlib.util
import tarfile
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_usage", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


def _tar_with(tmp_path: Path, *names: str) -> Path:
    archive = tmp_path / "bundle.tar"
    with tarfile.open(archive, "w") as bundle:
        for name in names:
            source = tmp_path / "payload"
            source.write_bytes(b"x")
            bundle.add(source, arcname=name)
    return archive


def _license_file(name: str = "LICENSE", from_archive: bool = True):
    return types.SimpleNamespace(
        name=name, sha256="", from_archive=from_archive, url=""
    )


def _entry(*files, tool: str = "demo", version: str = "v1.0.0"):
    return types.SimpleNamespace(
        tool=tool,
        version=version,
        files=tuple(files),
        source_notice=lambda installed_from=None: f"{tool}\n",
    )


class TestAnArchiveThatCannotYieldTheExecutable:
    def test_no_member_of_that_name(self, tmp_path, capsys):
        archive = _tar_with(tmp_path, "other")
        with pytest.raises(SystemExit) as raised:
            installer.extract_member(archive, "demo", tmp_path / "out")
        assert raised.value.code == installer._EXIT_USAGE
        assert "no member named demo" in str(raised.value)
        assert capsys.readouterr().err.count("no member named demo") == 1

    def test_two_members_of_that_name(self, tmp_path):
        archive = _tar_with(tmp_path, "a/demo", "b/demo")
        with pytest.raises(SystemExit) as raised:
            installer.extract_member(archive, "demo", tmp_path / "out")
        assert raised.value.code == installer._EXIT_USAGE
        assert "refusing to guess" in str(raised.value)

    def test_a_member_that_cannot_be_opened(self, tmp_path, monkeypatch):
        member = types.SimpleNamespace(name="demo", isfile=lambda: True)

        class Bundle:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def getmembers(self):
                return [member]

            def extractfile(self, wanted):
                return None

        monkeypatch.setattr(installer.tarfile, "open", lambda archive: Bundle())
        with pytest.raises(SystemExit) as raised:
            installer.extract_member(tmp_path / "a.tar", "demo", tmp_path / "out")
        assert raised.value.code == installer._EXIT_USAGE
        assert "is not readable" in str(raised.value)

    def test_one_member_still_extracts(self, tmp_path):
        """Control: the refusals above do not touch the working case."""
        archive = _tar_with(tmp_path, "dir/demo")
        installer.extract_member(archive, "demo", tmp_path / "out")
        assert (tmp_path / "out").read_bytes() == b"x"


class TestATableValueThatIsNotAFileName:
    @pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b"])
    def test_it_is_refused(self, name):
        with pytest.raises(SystemExit) as raised:
            installer._plain_name(name, "tool name")
        assert raised.value.code == installer._EXIT_USAGE
        assert "not a plain file name" in str(raised.value)

    def test_a_plain_name_passes(self):
        assert installer._plain_name("LICENSE", "license file name") == "LICENSE"


class TestAnInstalledEnvironmentThatIsNotTheOneThePinNames:
    def test_uv_missing_from_path(self, monkeypatch):
        monkeypatch.setattr(installer, "_on_absolute_path", lambda name: None)
        with pytest.raises(SystemExit) as raised:
            installer.uv_tool_dir()
        assert raised.value.code == installer._EXIT_USAGE
        assert "uv was not found" in str(raised.value)

    def test_uv_failing_to_run_is_still_status_one(self, monkeypatch):
        """Control: an OS error or a timeout there may clear on another attempt."""
        monkeypatch.setattr(installer, "_on_absolute_path", lambda name: "/x/uv")

        def fails(*args, **kwargs):
            raise OSError("exec format error")

        monkeypatch.setattr(installer.subprocess, "run", fails)
        with pytest.raises(SystemExit) as raised:
            installer.uv_tool_dir()
        assert raised.value.code != installer._EXIT_USAGE
        assert isinstance(raised.value.code, str)

    def test_no_dist_info(self, tmp_path):
        entry = types.SimpleNamespace(
            distribution="demo-dist", tool="demo", version="1"
        )
        with pytest.raises(SystemExit) as raised:
            installer.find_dist_info(entry, tmp_path)
        assert raised.value.code == installer._EXIT_USAGE
        assert "found 0" in str(raised.value)

    def test_dist_info_at_another_version(self, tmp_path):
        dist_info = (
            tmp_path
            / "demo-dist"
            / "lib"
            / "python3.12"
            / "site-packages"
            / "demo_dist-1.0.0.dist-info"
        )
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_text(
            "Version: 1.0.0\n\nbody\n", encoding="utf-8"
        )
        entry = types.SimpleNamespace(
            distribution="demo-dist", tool="demo", version="v2.0.0"
        )
        with pytest.raises(SystemExit) as raised:
            installer.find_dist_info(entry, tmp_path)
        assert raised.value.code == installer._EXIT_USAGE
        assert "half-applied" in str(raised.value)

    def test_dist_info_at_the_pinned_version_is_returned(self, tmp_path):
        """Control: the same layout at the right version passes."""
        dist_info = (
            tmp_path
            / "demo-dist"
            / "lib"
            / "python3.12"
            / "site-packages"
            / "demo_dist-2.0.0.dist-info"
        )
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_text(
            "Version: 2.0.0\n\nbody\n", encoding="utf-8"
        )
        entry = types.SimpleNamespace(
            distribution="demo-dist", tool="demo", version="v2.0.0"
        )
        assert installer.find_dist_info(entry, tmp_path) == dist_info


class TestALicenseFileThatCannotBeStaged:
    def test_an_empty_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            installer,
            "extract_member",
            lambda archive, name, destination: destination.write_bytes(b""),
        )
        with pytest.raises(SystemExit) as raised:
            installer.stage_third_party(
                _entry(_license_file()), tmp_path / "a.tar", tmp_path / "stage", None
            )
        assert raised.value.code == installer._EXIT_USAGE
        assert "is empty" in str(raised.value)

    def test_a_non_empty_file_stages(self, tmp_path, monkeypatch):
        """Control: the same stubbed extraction with content is accepted."""
        monkeypatch.setattr(
            installer,
            "extract_member",
            lambda archive, name, destination: destination.write_bytes(b"text"),
        )
        staged = installer.stage_third_party(
            _entry(_license_file()), tmp_path / "a.tar", tmp_path / "stage", None
        )
        assert (staged / "LICENSE").read_bytes() == b"text"

    def test_a_file_the_wheel_does_not_ship(self, tmp_path):
        dist_info = tmp_path / "demo_dist-1.0.0.dist-info"
        dist_info.mkdir()
        (dist_info / "RECORD").write_text("", encoding="utf-8")
        with pytest.raises(SystemExit) as raised:
            installer.stage_third_party(
                _entry(_license_file()), None, tmp_path / "stage", None, dist_info
            )
        assert raised.value.code == installer._EXIT_USAGE
        assert "is not in" in str(raised.value)

    def test_an_archive_file_with_no_archive(self, tmp_path):
        with pytest.raises(SystemExit) as raised:
            installer.stage_third_party(
                _entry(_license_file()), None, tmp_path / "stage", None
            )
        assert raised.value.code == installer._EXIT_USAGE
        assert "release archive" in str(raised.value)


class TestARulesBundleTheTableDoesNotKnow:
    def test_the_check_mode_refuses_it(self, tmp_path, monkeypatch):
        def unknown(name):
            raise LookupError(f"{name} is not a bundle")

        pins = types.SimpleNamespace(
            ToolNotProvisionableError=LookupError, get_rules_bundle=unknown
        )
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)
        with pytest.raises(SystemExit) as raised:
            installer.installed_bundle_problem("nope", tmp_path, tmp_path)
        assert raised.value.code == installer._EXIT_USAGE
        assert "nope is not a bundle" in str(raised.value)
