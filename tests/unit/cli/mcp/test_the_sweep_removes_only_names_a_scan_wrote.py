# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan-copy name is one of ours only when its id is a scan's own UUID.

A scan's profile copy is named ``.ash-scan-<scan id>.<the profile's name>``,
and two readers key on that shape: the sweep that removes leftover copies at
the next bind, and the naming that shows a copy as the profile it copies.
The prefix and a dot alone also match names an operator could write, so both
readers demand the id segment be a UUID in the scan writer's own spelling
(``str(uuid.uuid4())``: lowercase hyphenated hex). The sweep must never
unlink a file it cannot prove a scan wrote, and a refusal about an
operator's own file must name that file, not a sibling that may not exist.
"""

import uuid
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.resolve_config import lint_hint
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)


def _profile_dir(tmp_path):
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return profile


def _bind(profile):
    return mcp_tools._materialize_or_error(
        lambda session_id, config: str(profile), None, None
    )


@pytest.fixture(autouse=True)
def _unlinks_stay_inside_the_tests_own_tmp(tmp_path, monkeypatch):
    """Disarm guard for a delete path under test: any unlink outside this
    test's own tmp_path is refused loudly instead of running."""
    real_unlink = Path.unlink

    def guarded_unlink(self, missing_ok=False):
        if not Path(self).resolve().is_relative_to(tmp_path.resolve()):
            raise AssertionError(f"unlink outside the test's tmp_path: {self}")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", guarded_unlink)


@pytest.mark.parametrize(
    "name", [".ash-scan-mynotes.txt", ".ash-scan-foo.bar"], ids=["notes", "foo-bar"]
)
def test_an_operators_copy_shaped_file_survives_the_sweep(tmp_path, monkeypatch, name):
    """The name parses as prefix + id + dot + name, but its id is no UUID,
    so no scan wrote it: the bind's sweep leaves it alone."""
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    profile = _profile_dir(tmp_path)
    users = profile.with_name(name)
    users.write_text("the operator's own dot-file, not a scan copy\n", encoding="utf-8")

    assert _bind(profile) == str(profile)

    assert users.is_file(), "the sweep removed a file no scan wrote"


def test_an_uppercase_id_is_not_a_scan_copys(tmp_path, monkeypatch):
    """The writer spells its ids lowercase; a near-miss spelling is not proof
    a scan wrote the file, so the sweep keeps it."""
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    profile = _profile_dir(tmp_path)
    near_miss = profile.with_name(f".ash-scan-{str(uuid.uuid4()).upper()}.notes.txt")
    near_miss.write_text(
        "spelled like ours, written by someone else\n", encoding="utf-8"
    )

    assert _bind(profile) == str(profile)

    assert near_miss.is_file(), "the sweep removed a file no scan wrote"


def test_a_symlink_wearing_a_scan_copys_name_survives_the_sweep(tmp_path, monkeypatch):
    """The writer takes its names exclusively (``O_CREAT | O_EXCL``), which
    never creates a symbolic link, so a link wearing a scan-spelled name is
    provably not a scan's copy: the sweep leaves the link alone, and the file
    it points at as it was."""
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    profile = _profile_dir(tmp_path)
    victim = profile.parent / "a-file-the-sweep-must-not-touch.txt"
    victim_content = "the victim's own content\n"
    victim.write_text(victim_content, encoding="utf-8")
    planted = profile.with_name(f".ash-scan-{uuid.uuid4()}.{profile.name}")
    planted.symlink_to(victim)

    assert _bind(profile) == str(profile)

    assert planted.is_symlink(), "the sweep removed a link no scan wrote"
    assert victim.read_text(encoding="utf-8") == victim_content


def test_a_real_leftover_scan_copy_is_swept(tmp_path, monkeypatch):
    """The control: a copy under a scan-spelled UUID whose scan the registry
    does not hold, written by this process on this host, is a leftover, and the
    bind removes it."""
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    profile = _profile_dir(tmp_path)
    leftover = mcp_tools._scan_snapshot_path(profile, str(uuid.uuid4()))
    leftover.write_text(profile.read_text(encoding="utf-8"), encoding="utf-8")

    assert _bind(profile) == str(profile)

    assert not leftover.exists(), "a leftover scan copy survived the sweep"


@pytest.fixture
def operators_config(tmp_path):
    config = tmp_path / "repo" / ".ash-scan-x.ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: the-operators-own\n", encoding="utf-8")
    return config


def test_an_operators_copy_shaped_config_is_named_as_written(operators_config):
    """A config whose name wears the prefix but no scan UUID is the
    operator's own file: messages name it as written, never the sibling
    under the trailing name, which may not exist."""
    shown = describe_config_path(operators_config)

    assert shown == operators_config.as_posix(), shown


def test_the_lint_hint_for_an_operators_file_lints_that_file(operators_config):
    hint = lint_hint(operators_config)

    assert "--config " + operators_config.as_posix() in hint, hint


def test_a_registered_scan_copys_name_maps_to_the_profile(tmp_path):
    """The control: a copy a live scan registered, named with a scan-spelled
    UUID, is shown as the profile it copies, whose name a reader can find
    after the run."""
    copy = tmp_path / f".ash-scan-{uuid.uuid4()}.ash.yaml"
    config_sources.register_scan_copy(copy)
    try:
        shown = describe_config_path(copy)
    finally:
        config_sources.discard_scan_copy(copy)

    assert shown == (tmp_path / "ash.yaml").as_posix(), shown


def test_an_unregistered_file_with_a_genuine_scan_copy_name_is_named_as_written(
    tmp_path,
):
    """A name parsing as a scan copy's proves nothing about who wrote the
    file: an operator's own file, or a leftover from a run that died, can
    wear it. No live scan registered it, so it is described as written, not
    as a sibling that may be a different file."""
    leftover = tmp_path / f".ash-scan-{uuid.uuid4()}.ash.yaml"

    assert describe_config_path(leftover) == leftover.as_posix()


def test_the_lint_hint_for_an_unregistered_scan_copy_named_file_lints_that_file(
    tmp_path,
):
    leftover = tmp_path / f".ash-scan-{uuid.uuid4()}.ash.yaml"

    hint = lint_hint(leftover)

    assert "--config " + leftover.as_posix() in hint, hint


def test_a_copy_stops_mapping_once_the_writer_discards_it(tmp_path):
    copy = tmp_path / f".ash-scan-{uuid.uuid4()}.ash.yaml"
    config_sources.register_scan_copy(copy)
    assert describe_config_path(copy) == (tmp_path / "ash.yaml").as_posix()

    config_sources.discard_scan_copy(copy)

    assert describe_config_path(copy) == copy.as_posix()


def test_the_writer_registers_its_copy_and_the_runner_discard_unregisters_it(
    tmp_path,
):
    """The real writer: the copy it creates maps to the profile while it
    exists, and the runner's discard of it ends the mapping."""
    profile = _profile_dir(tmp_path)
    scan_id = str(uuid.uuid4())

    copy = mcp_tools._snapshot_profile_for_scan(
        profile, scan_id, snapshot_path=mcp_tools._scan_snapshot_path(profile, scan_id)
    )
    try:
        assert describe_config_path(copy) == profile.as_posix()
    finally:
        config_sources.discard_scan_copy(copy)
        copy.unlink(missing_ok=True)

    assert describe_config_path(copy) == copy.as_posix()
