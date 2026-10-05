# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""packaging/assert-package-contents.py accepts real packages and refuses broken ones.

Every format the gate covers gets the same pair: a fixture with the real artifact's
structure must be ACCEPTED, and an empty, corrupt or tampered one must be REJECTED.
Without the accept half, a gate that fails unconditionally would look like a working
one; without the reject half, one that passes unconditionally would.

The fixtures are not invented layouts. Their member lists are pinned below to what real
builds produced:

* MSIX: the `msix` job in .github/workflows/ash-package.yml (makeappx pack, signtool
  sign), downloaded from its run artifact. The previous version of this gate rejected
  that exact package with four violations: three launchers as native-binary and
  AppxMetadata/CodeIntegrity.cat as unrecognised. test_the_real_msix_layout_is_accepted
  is the regression test for that.
* .nupkg: `choco pack` 2.7.4 on the tree packaging/chocolatey/build.ps1 stages.
* Flatpak: flatpak-builder 1.4.4 against org.freedesktop.Sdk 24.08, build-dir/files.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / "packaging" / "assert-package-contents.py"

REAL_MSIX_MEMBERS = sorted(
    [
        "wheels/automated_security_helper-3.7.0-py3-none-any.whl",
        "assets/StoreLogo.png",
        "assets/Square44x44Logo.png",
        "assets/Square150x150Logo.png",
        "ash.exe",
        "ashv3.exe",
        "automated-security-helper.exe",
        "AppxManifest.xml",
        "AppxBlockMap.xml",
        "[Content_Types].xml",
        "AppxMetadata/CodeIntegrity.cat",
        "AppxSignature.p7x",
    ]
)
REAL_NUPKG_MEMBERS = sorted(
    [
        "_rels/.rels",
        "ash.nuspec",
        "tools/chocolateyinstall.ps1",
        "tools/chocolateyuninstall.ps1",
        "tools/README.chocolatey",
        "tools/wheels/automated_security_helper-3.7.0-py3-none-any.whl",
        "[Content_Types].xml",
        "package/services/metadata/core-properties/52ca197f1977441c930d901c8e109379.psmdcp",
    ]
)
REAL_FLATPAK_FILES = sorted(
    [
        "bin/ash",
        "manifest.json",
        "share/ash/wheels/automated_security_helper-3.7.0-py3-none-any.whl",
    ]
)
REAL_FLATPAK_LINKS = {"bin/ashv3": "ash", "bin/automated-security-helper": "ash"}

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location(
        "ash_package_contents_gate", GATE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


def _verdict(gate, target: str) -> tuple[str, str]:
    """("accepted" | "rejected" | "refused", what was reported)."""
    try:
        if target.startswith("tree:"):
            _, violations = gate.check_flatpak_tree(target[5:])
        else:
            _, violations = gate.check_package(target)
    except gate.GateError as error:
        return "refused", str(error)
    return ("rejected" if violations else "accepted"), "\n".join(violations)


def _msix(gate, tmp_path: Path, members: dict[str, bytes], name="x.msix") -> str:
    return str(gate.write_zip(tmp_path / name, members))


class TestFixturesHaveTheRealStructure:
    def test_msix_fixture_matches_the_ci_built_package(self, gate):
        assert sorted(gate.fixture_msix_members()) == REAL_MSIX_MEMBERS

    def test_nupkg_fixture_matches_choco_pack(self, gate):
        assert sorted(gate.fixture_nupkg_members()) == REAL_NUPKG_MEMBERS

    def test_flatpak_fixture_matches_flatpak_builder(self, gate, tmp_path):
        root = gate.write_flatpak_tree(tmp_path / "files")
        files, links = gate.read_tree(str(root))

        assert sorted(files) == REAL_FLATPAK_FILES
        assert links == REAL_FLATPAK_LINKS

    def test_fixture_launchers_are_managed_and_the_native_control_is_not(self, gate):
        assert gate.is_managed_pe(gate.fixture_managed_pe())
        assert not gate.is_managed_pe(gate.fixture_native_pe())
        assert not gate.is_managed_pe(ELF)


class TestMsix:
    def test_the_real_msix_layout_is_accepted(self, gate, tmp_path):
        """Three launchers plus CodeIntegrity.cat: the false rejection, fixed."""
        verdict, detail = _verdict(
            gate, _msix(gate, tmp_path, gate.fixture_msix_members())
        )

        assert verdict == "accepted", detail

    def test_an_unsigned_msix_is_accepted(self, gate, tmp_path):
        members = gate.fixture_msix_members(signed=False)

        assert _verdict(gate, _msix(gate, tmp_path, members))[0] == "accepted"

    def test_an_empty_msix_is_refused(self, gate, tmp_path):
        assert _verdict(gate, _msix(gate, tmp_path, {}))[0] == "refused"

    def test_a_truncated_msix_is_refused(self, gate, tmp_path):
        good = Path(_msix(gate, tmp_path, gate.fixture_msix_members(), "good.msix"))
        bad = tmp_path / "bad.msix"
        bad.write_bytes(good.read_bytes()[: good.stat().st_size // 2])

        verdict, detail = _verdict(gate, str(bad))

        assert verdict == "refused" and "not a zip" in detail

    def test_a_non_zip_named_msix_is_refused(self, gate, tmp_path):
        bad = tmp_path / "bad.msix"
        bad.write_bytes(b"MZ" + b"\x00" * 100)

        assert _verdict(gate, str(bad))[0] == "refused"

    @pytest.mark.parametrize(
        "dropped", ["AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml"]
    )
    def test_an_msix_missing_a_footprint_file_is_refused(self, gate, tmp_path, dropped):
        members = {k: v for k, v in gate.fixture_msix_members().items() if k != dropped}

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "refused" and dropped in detail

    def test_an_msix_without_its_wheel_is_rejected(self, gate, tmp_path):
        members = gate.fixture_msix_members()
        del members[f"wheels/{gate.FIXTURE_WHEEL}"]

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "exactly 1 ASH wheel" in detail

    def test_a_member_injected_after_packing_is_rejected(self, gate, tmp_path):
        members = gate.fixture_msix_members({"assets/grype": ELF}, in_blockmap=False)

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected"
        assert "not in AppxBlockMap.xml" in detail and "native-binary" in detail

    def test_a_member_altered_after_packing_is_rejected(self, gate, tmp_path):
        members = gate.fixture_msix_members()
        launcher = bytearray(members["ash.exe"])
        launcher[-1] ^= 1
        members["ash.exe"] = bytes(launcher)

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "block hashes" in detail

    def test_an_undeclared_exe_is_rejected_even_if_managed(self, gate, tmp_path):
        members = gate.fixture_msix_members({"trivy.exe": gate.fixture_managed_pe()})

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "native-binary" in detail

    def test_a_native_binary_under_a_launcher_name_is_rejected(self, gate, tmp_path):
        members = gate._rebuild_blockmap(
            gate.fixture_msix_members(), {"ash.exe": gate.fixture_native_pe()}
        )

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "not a managed" in detail

    def test_the_launcher_set_comes_from_the_packaged_manifest(self, gate, tmp_path):
        """Drop ashv3 from the manifest and ashv3.exe becomes an undeclared binary."""
        members = gate.fixture_msix_members(
            executables=("ash.exe", "automated-security-helper.exe")
        )

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "ashv3.exe" in detail

    def test_a_launcher_that_is_not_a_console_script_is_rejected(self, gate, tmp_path):
        """Declared in the manifest, managed, small -- and still not one of ASH's."""
        members = gate._rebuild_blockmap(
            gate.fixture_msix_members(
                executables=(*gate.FIXTURE_LAUNCHERS, "trivy.exe")
            ),
            {"trivy.exe": gate.fixture_managed_pe()},
        )

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "not a console script" in detail

    def test_a_console_script_with_no_launcher_is_rejected(self, gate, tmp_path):
        members = {
            k: v
            for k, v in gate.fixture_msix_members(
                executables=("ash.exe", "automated-security-helper.exe")
            ).items()
            if k != "ashv3.exe"
        }
        members = gate._rebuild_blockmap(members, {})

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "no launcher for" in detail

    def test_a_bundled_virtualenv_is_rejected(self, gate, tmp_path):
        members = gate.fixture_msix_members(
            {"python/Lib/site-packages/pydantic/__init__.py": b"#\n"}
        )

        assert _verdict(gate, _msix(gate, tmp_path, members))[0] == "rejected"

    def test_an_embedded_wheel_failing_the_wheel_gate_is_rejected(self, gate, tmp_path):
        bad_wheel = io.BytesIO()
        with zipfile.ZipFile(bad_wheel, "w") as archive:
            for name in gate.GATE.LEGITIMATE_WHEEL_MEMBERS:
                archive.writestr(name, b"# ash\n")
            archive.writestr(
                "automated_security_helper/vendor/semgrep/__init__.py", b"#\n"
            )
        members = gate._rebuild_blockmap(
            gate.fixture_msix_members(),
            {f"wheels/{gate.FIXTURE_WHEEL}": bad_wheel.getvalue()},
        )

        verdict, detail = _verdict(gate, _msix(gate, tmp_path, members))

        assert verdict == "rejected" and "FAILS" in detail


class TestNupkg:
    def test_the_real_nupkg_layout_is_accepted(self, gate, tmp_path):
        path = str(gate.write_zip(tmp_path / "ash.nupkg", gate.fixture_nupkg_members()))

        verdict, detail = _verdict(gate, path)

        assert verdict == "accepted", detail

    def test_an_empty_nupkg_is_refused(self, gate, tmp_path):
        assert (
            _verdict(gate, str(gate.write_zip(tmp_path / "e.nupkg", {})))[0]
            == "refused"
        )

    def test_a_nupkg_missing_its_install_script_is_refused(self, gate, tmp_path):
        members = gate.fixture_nupkg_members()
        del members["tools/chocolateyinstall.ps1"]

        assert (
            _verdict(gate, str(gate.write_zip(tmp_path / "m.nupkg", members)))[0]
            == "refused"
        )

    def test_a_binary_in_tools_is_rejected(self, gate, tmp_path):
        members = gate.fixture_nupkg_members({"tools/grype.exe": ELF})

        verdict, detail = _verdict(
            gate, str(gate.write_zip(tmp_path / "b.nupkg", members))
        )

        assert verdict == "rejected" and "native-binary" in detail

    def test_a_dependency_wheel_is_rejected(self, gate, tmp_path):
        members = gate.fixture_nupkg_members(
            {"tools/wheels/pydantic-2.13.5-py3-none-any.whl": gate.fixture_wheel()}
        )

        verdict, detail = _verdict(
            gate, str(gate.write_zip(tmp_path / "d.nupkg", members))
        )

        assert verdict == "rejected" and "not an ASH wheel" in detail


class TestFlatpakTree:
    def test_the_real_flatpak_tree_is_accepted(self, gate, tmp_path):
        root = gate.write_flatpak_tree(tmp_path / "files")

        verdict, detail = _verdict(gate, "tree:" + str(root))

        assert verdict == "accepted", detail

    def test_an_empty_tree_is_refused(self, gate, tmp_path):
        (tmp_path / "files").mkdir()

        assert _verdict(gate, "tree:" + str(tmp_path / "files"))[0] == "refused"

    def test_a_tree_without_its_wheel_is_rejected(self, gate, tmp_path):
        root = gate.write_flatpak_tree(tmp_path / "files")
        (root / f"share/ash/wheels/{gate.FIXTURE_WHEEL}").unlink()

        verdict, detail = _verdict(gate, "tree:" + str(root))

        assert verdict == "rejected" and "exactly 1 ASH wheel" in detail

    def test_a_scanner_binary_in_the_tree_is_rejected(self, gate, tmp_path):
        root = gate.write_flatpak_tree(
            tmp_path / "files", extra_files={"bin/trivy": ELF}
        )

        verdict, detail = _verdict(gate, "tree:" + str(root))

        assert verdict == "rejected" and "native-binary" in detail

    def test_a_replaced_launcher_is_rejected(self, gate, tmp_path):
        root = gate.write_flatpak_tree(
            tmp_path / "files", launcher=b"#!/bin/sh\nexec grype\n"
        )

        verdict, detail = _verdict(gate, "tree:" + str(root))

        assert verdict == "rejected" and "byte-identical" in detail

    def test_a_launcher_name_that_is_not_a_console_script_is_rejected(
        self, gate, tmp_path
    ):
        root = gate.write_flatpak_tree(
            tmp_path / "files", extra_links={"bin/grype": "ash"}
        )

        verdict, detail = _verdict(gate, "tree:" + str(root))

        assert verdict == "rejected" and "not a console script" in detail

    def test_installed_distributions_are_rejected(self, gate, tmp_path):
        root = gate.write_flatpak_tree(
            tmp_path / "files",
            extra_files={"lib/python3.12/site-packages/x-1.0.dist-info/RECORD": b""},
        )

        assert _verdict(gate, "tree:" + str(root))[0] == "rejected"


class TestGateAsAWhole:
    def test_the_self_test_passes(self, gate, capsys):
        assert gate.run_self_test(sys.stdout) == 0, capsys.readouterr().out

    def test_the_gate_contract_holds(self, gate, capsys):
        assert gate.assert_gate_contract(sys.stdout) == 0, capsys.readouterr().out

    def test_the_cli_exits_zero_one_and_two(self, gate, tmp_path):
        good = str(gate.write_zip(tmp_path / "g.msix", gate.fixture_msix_members()))
        bad = str(
            gate.write_zip(
                tmp_path / "b.msix", gate.fixture_msix_members({"notes.txt": b"x"})
            )
        )
        empty = str(gate.write_zip(tmp_path / "e.msix", {}))

        assert gate.main(["gate", good]) == 0
        assert gate.main(["gate", bad]) == 1
        assert gate.main(["gate", empty]) == 2
        assert gate.main(["gate"]) == 2

    def test_a_flatpak_bundle_is_not_mistaken_for_a_checked_input(self, gate, tmp_path):
        bundle = tmp_path / "ash.flatpak"
        bundle.write_bytes(b"xdg-app\x00")

        assert gate.main(["gate", str(bundle)]) == 2
