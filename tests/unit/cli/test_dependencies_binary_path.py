# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--binary-path <scanner>=<path>``: force a binary, never run it.

The flag bypasses binary detection for one scanner: its install commands are not
run, the path is validated (absolute, exists, a regular executable file, not a
symlink, outside the scanned tree), recorded with its SHA-256 in the install-receipt
store, and the verdict resolves the scanner to it by a file check. ASH hashes the
file and never executes it; the forced file here writes a marker if it is ever run.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.install_providers import read_forced_binaries
from tests.unit.cli.dependencies_install_support import build_scene, run_install

pytestmark = pytest.mark.unit


@pytest.fixture
def forced_file(tmp_path):
    """An executable file that touches a marker if it is ever executed."""
    marker = tmp_path / "FORCED-BINARY-WAS-RUN"
    elsewhere = tmp_path / "tools"
    elsewhere.mkdir()
    binary = elsewhere / "checkov"
    binary.write_text(f"#!/bin/sh\ntouch {marker}\n")
    binary.chmod(0o755)
    return binary, marker


@pytest.fixture
def src_tree(tmp_path):
    """The working directory the command treats as the scanned tree."""
    tree = tmp_path / "src-tree"
    tree.mkdir()
    return tree


def _scene(monkeypatch, tmp_path, src_tree, **kwargs):
    scene = build_scene(monkeypatch, tmp_path, **kwargs)
    monkeypatch.chdir(src_tree)
    return scene


def test_install_commands_are_skipped_and_counted_forced(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, marker = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree, find_on_path=lambda c: None)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 0, scene.text
    assert "FORCED (--binary-path)" in scene.text, scene.text
    assert str(binary) in scene.text, scene.text
    assert not marker.exists(), "the forced binary was executed"


def test_a_receipt_with_the_bytes_sha256_lands_under_receipt_root(
    tmp_path, monkeypatch, forced_file, src_tree
):
    import hashlib

    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")

    recorded = read_forced_binaries()
    assert set(recorded) == {"checkov"}, recorded
    assert recorded["checkov"]["path"] == str(binary)
    assert (
        recorded["checkov"]["sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    )
    assert recorded["checkov"]["recorded_by"] == "ash dependencies install"


def test_an_empty_path_erases_the_record(tmp_path, monkeypatch, forced_file, src_tree):
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")
    assert "checkov" in read_forced_binaries()

    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", "checkov=")

    assert "checkov" not in read_forced_binaries()


def test_the_sweep_resolves_to_a_forced_path_that_stays_usable(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)

    def vanish(*_a, **_k):
        binary.chmod(0o644)

    from automated_security_helper.cli import dependencies as dependencies_module

    # The file stops being executable after it was validated and before the sweep:
    # a file check at sweep time, not the record, decides.
    monkeypatch.setattr(dependencies_module, "clear_find_executable_cache", vanish)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")

    assert scene.result.exit_code == 1, scene.text
    assert "FORCED (binary not usable)" in scene.text, scene.text


def test_the_record_forces_the_next_flag_less_run(
    tmp_path, monkeypatch, forced_file, src_tree
):
    """The record is READ, which is what recording it promises: the next
    ``ash dependencies install`` with no flags consults it before PATH or uv,
    skips the scanner's install commands, and resolves it to the forced path --
    judged afresh by a file check and the recorded SHA-256, never executed."""
    binary, marker = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")
    assert scene.result.exit_code == 0, scene.text

    scene = _scene(monkeypatch, tmp_path, src_tree, find_on_path=lambda c: None)
    run_install(scene, monkeypatch, tmp_path)

    assert scene.calls == [], scene.calls
    assert scene.result.exit_code == 0, scene.text
    assert "FORCED (recorded --binary-path)" in scene.text, scene.text
    assert str(binary) in scene.text, scene.text
    assert not marker.exists(), "the forced binary was executed"


def test_a_stale_record_is_named_and_the_install_runs_as_usual(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")

    # Same path, same mode, other content: no longer the validated binary.
    binary.write_text("#!/bin/sh\necho replaced\n")
    binary.chmod(0o755)
    scene = _scene(
        monkeypatch, tmp_path, src_tree, find_on_path=lambda c: f"/usr/bin/{c}"
    )
    run_install(scene, monkeypatch, tmp_path)

    text = " ".join(scene.text.split())
    assert "Ignoring the recorded forced binary for checkov" in text, text
    assert scene.argvs != [], scene.argvs


def test_the_sweep_rejects_a_content_replacement_at_the_forced_path(
    tmp_path, monkeypatch, forced_file, src_tree
):
    """The recorded SHA-256 is re-checked where the decision is made: a regular,
    executable file at the same path whose bytes changed between validation and
    the sweep is not the validated binary."""
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)

    def replace(*_a, **_k):
        binary.write_text("#!/bin/sh\necho replaced\n")
        binary.chmod(0o755)

    from automated_security_helper.cli import dependencies as dependencies_module

    monkeypatch.setattr(dependencies_module, "clear_find_executable_cache", replace)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")

    assert scene.result.exit_code == 1, scene.text
    assert "FORCED (binary not usable)" in scene.text, scene.text


def test_an_alias_cased_erase_key_erases_the_record(
    tmp_path, monkeypatch, forced_file, src_tree
):
    """Records are written under the canonical plugin name, so an erase key is
    resolved the same way: ``--binary-path Checkov=`` erases checkov's record
    rather than popping a key that was never there."""
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")
    assert "checkov" in read_forced_binaries()

    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", "Checkov=")

    assert "checkov" not in read_forced_binaries()


@pytest.mark.parametrize(
    "entry, message",
    [
        ("checkov", "is not <scanner>=<absolute path>"),
        ("=/usr/bin/true", "is not <scanner>=<absolute path>"),
        ("checkov=relative/checkov", "the path is not absolute"),
        ("checkov=/nonexistent/checkov", "the path does not exist"),
    ],
)
def test_malformed_relative_and_missing_entries_are_each_refused(
    tmp_path, monkeypatch, src_tree, entry, message
):
    scene = _scene(monkeypatch, tmp_path, src_tree)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", entry)

    assert scene.result.exit_code == 2, scene.text
    assert message in " ".join(scene.text.split()), scene.text
    assert scene.calls == [], scene.calls


def test_a_non_executable_file_and_a_symlink_are_refused(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, _ = forced_file
    plain = tmp_path / "tools" / "plain"
    plain.write_text("x")
    plain.chmod(0o644)
    link = tmp_path / "tools" / "link"
    link.symlink_to(binary)
    scene = _scene(monkeypatch, tmp_path, src_tree)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--binary-path",
        f"checkov={plain}",
    )
    assert scene.result.exit_code == 2, scene.text
    assert "the file is not executable" in " ".join(scene.text.split()), scene.text

    scene = _scene(monkeypatch, tmp_path, src_tree)
    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={link}")
    assert scene.result.exit_code == 2, scene.text
    assert "the path is a symlink" in " ".join(scene.text.split()), scene.text


def test_an_unknown_key_is_refused_naming_the_selection(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"nosuch={binary}")

    assert scene.result.exit_code == 2, scene.text
    text = " ".join(scene.text.split())
    assert "nosuch is not a plugin this run installs for" in text, text
    assert "Selected: checkov" in text, text
    assert scene.calls == [], scene.calls


def test_a_key_naming_a_plugin_with_no_external_program_is_refused(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree, command=None)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={binary}")

    assert scene.result.exit_code == 2, scene.text
    assert "runs no external program" in " ".join(scene.text.split()), scene.text


def test_an_in_tree_path_is_refused_without_the_opt_in(tmp_path, monkeypatch, src_tree):
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    in_tree = src_tree / "checkov"
    in_tree.write_text("#!/bin/sh\n")
    in_tree.chmod(0o755)
    scene = _scene(monkeypatch, tmp_path, src_tree)

    run_install(scene, monkeypatch, tmp_path, "--binary-path", f"checkov={in_tree}")

    assert scene.result.exit_code == 2, scene.text
    assert "inside the scanned source tree" in " ".join(scene.text.split()), scene.text


def test_every_bad_entry_is_listed_in_one_refusal(
    tmp_path, monkeypatch, forced_file, src_tree
):
    binary, _ = forced_file
    scene = _scene(monkeypatch, tmp_path, src_tree)

    run_install(
        scene,
        monkeypatch,
        tmp_path,
        "--binary-path",
        "checkov=relative",
        "--binary-path",
        f"nosuch={binary}",
    )

    text = " ".join(scene.text.split())
    assert scene.result.exit_code == 2, scene.text
    assert "the path is not absolute" in text and "nosuch is not a plugin" in text, text
