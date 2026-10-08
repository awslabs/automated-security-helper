# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""packaging/assert-planted-scanner-rejected.py, and the two Windows legs that run it.

The script runs on the real .msix and .nupkg only on a Windows runner. Its decisions
do not depend on Windows, so they are held here against packages with the real
layout (the gate's own fixtures, whose member lists tests/unit/test_package_contents_gate.py
pins to CI-built packages):

* a clean package passes and its planted copy is refused, for the planted member;
* the script fails when the gate does not refuse the copy, when the gate refuses it
  for some other reason only, and when the unmodified package does not pass;
* both Windows scripts run it on the package they built, after the gate step, and
  fail the leg when it fails.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "packaging" / "assert-planted-scanner-rejected.py"
GATE_PATH = REPO_ROOT / "packaging" / "assert-package-contents.py"
MSIX_LEG = REPO_ROOT / "packaging" / "msix" / "verify-on-windows.ps1"
CHOCOLATEY_LEG = REPO_ROOT / "packaging" / "chocolatey" / "verify-on-windows.ps1"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def plant():
    return _load(SCRIPT, "ash_planted_scanner_negative")


@pytest.fixture(scope="module")
def gate():
    return _load(GATE_PATH, "ash_package_contents_gate_for_plant_tests")


@pytest.fixture
def msix(gate, tmp_path):
    (tmp_path / "built").mkdir(exist_ok=True)
    return gate.write_zip(tmp_path / "built" / "ash.msix", gate.fixture_msix_members())


@pytest.fixture
def nupkg(gate, tmp_path):
    (tmp_path / "built").mkdir(exist_ok=True)
    return gate.write_zip(
        tmp_path / "built" / "ash.4.0.0.nupkg", gate.fixture_nupkg_members()
    )


@pytest.mark.parametrize(
    ("package", "member"),
    [("msix", "assets/grype"), ("nupkg", "tools/grype.exe")],
)
def test_the_real_layout_passes_and_its_planted_copy_is_refused(
    plant, request, tmp_path, capsys, package, member
):
    built = request.getfixturevalue(package)
    rc = plant.main([str(built), "--work", str(tmp_path / "work")])
    printed = capsys.readouterr().out
    assert rc == 0, printed
    assert f"OK: the gate refused the real {built.name} with {member}" in printed
    planted = tmp_path / "work" / f"planted-{built.name}"
    with zipfile.ZipFile(planted) as copy, zipfile.ZipFile(built) as original:
        assert sorted(copy.namelist()) == sorted([*original.namelist(), member])
        for name in original.namelist():
            assert copy.read(name) == original.read(name), name
    # The input itself is untouched: the workflows upload it.
    with zipfile.ZipFile(built) as original:
        assert member not in original.namelist()


def test_a_gate_that_waves_the_plant_through_fails_the_control(
    plant, msix, tmp_path, monkeypatch, capsys
):
    # The negative control's own negative: the script has to fail when the gate
    # accepts the planted copy, or it would pass with the content check deleted.
    real = plant.run_gate
    monkeypatch.setattr(
        plant,
        "run_gate",
        lambda path: (
            (0, "package contents OK") if "planted-" in path.name else real(path)
        ),
    )
    assert plant.main([str(msix), "--work", str(tmp_path / "work")]) == 1
    assert "was not refused" in capsys.readouterr().out


def test_a_rejection_for_another_reason_only_fails_the_control(
    plant, msix, tmp_path, monkeypatch, capsys
):
    # For an .msix the plant is also absent from AppxBlockMap.xml. A gate that only
    # checked the block map would refuse the copy for that and never look at what the
    # member is, so that rejection alone must not count.
    real = plant.run_gate

    def blockmap_only(path):
        if "planted-" not in path.name:
            return real(path)
        return 1, (
            f"  - {path}: assets/grype is in the zip but not in AppxBlockMap.xml, so it "
            "is not part of the package makeappx built\n"
        )

    monkeypatch.setattr(plant, "run_gate", blockmap_only)
    assert plant.main([str(msix), "--work", str(tmp_path / "work")]) == 1
    assert "not with a native-binary verdict on assets/grype" in capsys.readouterr().out


def test_the_real_gate_names_the_planted_member_not_only_the_block_map(
    plant, msix, tmp_path
):
    # What the check above guards against, measured on the real gate: its report on
    # the planted .msix carries both verdicts, and names_the_plant finds the content one.
    planted = tmp_path / "planted-ash.msix"
    spec = plant.plant_for(msix)
    plant.write_planted_copy(msix, planted, spec)
    rc, output = plant.run_gate(planted)
    assert rc == 1
    assert "not in AppxBlockMap.xml" in output
    assert plant.names_the_plant(output, spec)
    assert not plant.names_the_plant(
        output, plant.Plant("assets/Logo.png", b"", "a member that was not planted")
    )


def test_an_unmodified_package_that_fails_the_gate_stops_the_control(
    plant, gate, tmp_path, capsys
):
    (tmp_path / "built").mkdir()
    broken = gate.write_zip(
        tmp_path / "built" / "ash.msix", gate.fixture_msix_members({"trivy.exe": b"MZ"})
    )
    assert plant.main([str(broken), "--work", str(tmp_path / "work")]) == 1
    assert "on the unmodified ash.msix" in capsys.readouterr().out
    assert not (tmp_path / "work" / "planted-ash.msix").exists()


def test_the_planted_copy_never_lands_beside_the_real_package(plant, msix, capsys):
    assert plant.main([str(msix), "--work", str(msix.parent / "sub")]) == 2
    assert "the directory the real package was built into" in capsys.readouterr().err


def test_a_member_already_present_is_not_overwritten(plant, gate, tmp_path):
    (tmp_path / "built").mkdir()
    members = gate.fixture_nupkg_members({"tools/grype.exe": b"already here"})
    built = gate.write_zip(tmp_path / "built" / "ash.nupkg", members)
    spec = plant.plant_for(built)
    with pytest.raises(ValueError, match="already has a member named tools/grype.exe"):
        plant.write_planted_copy(built, tmp_path / "copy.nupkg", spec)


# --------------------------------------------------------------------------
# The legs run it, on the package they built, after the gate, and act on its exit.
# --------------------------------------------------------------------------


def _step(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin : text.index(end, begin)]


def test_the_msix_leg_plants_into_the_signed_package_it_built():
    text = MSIX_LEG.read_text(encoding="utf-8")
    gate_step = text.index("packaging/assert-package-contents.py') $msix")
    step = _step(text, "Write-Step '2c.", "Write-Step '3.")
    assert text.index("Write-Step '2c.") > gate_step, "must run after the gate passes"
    call = re.search(
        r"assert-planted-scanner-rejected\.py'\) \$msix --work \(Join-Path \$work ",
        step,
    )
    assert call, (
        "the leg must plant into $msix, the signed build/msix package, under $work"
    )
    assert "uv run --script" in step, "the MSIX gate needs the script's defusedxml"
    assert re.search(r"if \(\$LASTEXITCODE -ne 0\) \{\s*Fail ", step), (
        "a failed control must fail the leg"
    )


def test_the_chocolatey_leg_plants_into_the_nupkg_it_built():
    text = CHOCOLATEY_LEG.read_text(encoding="utf-8")
    gate_step = text.index("'packaging\\assert-package-contents.py'), $nupkg)")
    step = _step(text, "Write-Host '== 3b2.", 'Write-Host "== 3c.')
    assert text.index("Write-Host '== 3b2.") > gate_step, (
        "must run after the gate passes"
    )
    assert re.search(
        r"assert-planted-scanner-rejected\.py'\), \$nupkg, '--work', \(Join-Path \$Work ",
        step,
    ), "the leg must plant into $nupkg, the package it packed, under $Work"
    assert re.search(r"if \(\$r\.Rc -ne 0\) \{\s*Fail-Verification ", step), (
        "a failed control must fail the leg"
    )
