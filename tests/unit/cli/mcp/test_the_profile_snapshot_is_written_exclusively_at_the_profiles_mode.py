# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan's profile copy is created exclusively and keeps the profile's mode.

The copy sits beside the session's profile and holds the same content, so it
must not be readable more widely than the profile itself: a profile the
operator keeps at 0600 whose copy appears at the umask's default would show
the file's settings to every local reader for the scan's duration. And the
copy's name must be taken exclusively: writing through a name that already
exists would truncate that file, or follow a link planted there to a file
outside the config directory. A name already present is not this scan's to
remove either -- the refusal leaves it as it was.
"""

import os
import stat

import pytest

from automated_security_helper.cli import mcp_tools

pytestmark = pytest.mark.unit

#: A scan id as the writer spells one (``str(uuid.uuid4())``): the copy's name
#: must parse as a scan copy's (config_sources.parse_scan_copy_name), and only
#: the UUID spelling does.
A_SCAN_ID = "9d1f8c2a-6b3e-4f5a-8c7d-2e1b0a9f4d6c"


def _a_profile(tmp_path, mode):
    profile = tmp_path / "ash.yaml"
    profile.write_text("project_name: a-held-profile\n", encoding="utf-8")
    profile.chmod(mode)
    return profile


def _written_copy(profile):
    """The writer, called as the runner calls it: the planned name handed in."""
    return mcp_tools._snapshot_profile_for_scan(
        profile,
        A_SCAN_ID,
        snapshot_path=mcp_tools._scan_snapshot_path(profile, A_SCAN_ID),
    )


def test_the_copy_is_created_at_mode_0600_exactly(tmp_path, monkeypatch):
    """The exclusive take itself happens at 0600, never a wider mode.

    The copy ends at the profile's own bits, so the cells around this one
    pass whatever mode the CREATE uses: a create at the umask's default
    followed by the chmod would leave the profile's content group- and
    world-readable for the write's duration, and nothing else would catch
    it. The pin reads the mode argument the create passes, on a profile
    whose final bits differ from 0600 so the create's mode and the chmod's
    cannot stand in for each other."""
    recorded = []
    real_open = os.open

    def recording_open(path, flags, mode=0o777, *args, **kwargs):
        if flags & os.O_CREAT:
            recorded.append(mode)
        return real_open(path, flags, mode, *args, **kwargs)

    profile = _a_profile(tmp_path, 0o640)
    # A context, not undo(): undo() would also revert every patch an autouse
    # fixture made on this monkeypatch instance.
    with monkeypatch.context() as patched:
        patched.setattr(os, "open", recording_open)
        previous_umask = os.umask(0o022)
        try:
            snapshot = _written_copy(profile)
        finally:
            os.umask(previous_umask)
    try:
        copy_mode = stat.S_IMODE(snapshot.stat().st_mode)
        assert (recorded, copy_mode) == ([0o600], 0o640), (
            [oct(mode) for mode in recorded],
            oct(copy_mode),
        )
    finally:
        snapshot.unlink()


def test_the_copy_keeps_the_profiles_mode(tmp_path):
    """A 0600 profile's copy is 0600, not the umask's default."""
    profile = _a_profile(tmp_path, 0o600)
    # Control: with the default umask the write path under test would
    # otherwise create a group- and world-readable file.
    previous_umask = os.umask(0o022)
    try:
        snapshot = _written_copy(profile)
    finally:
        os.umask(previous_umask)
    try:
        copy_mode = stat.S_IMODE(snapshot.stat().st_mode)
        assert copy_mode == 0o600, oct(copy_mode)
        assert snapshot.read_bytes() == profile.read_bytes()
    finally:
        snapshot.unlink(missing_ok=True)


def test_a_name_already_present_refuses_without_following_or_removing_it(tmp_path):
    """A link planted at the copy's name refuses the scan, untouched.

    The copy's name is deterministic (the scan id beside the profile), so a
    writer in the config directory could plant a symlink there before the
    scan. Writing through it would overwrite the link's target; the refusal
    must leave both the target and the planted name as they were, and its
    reason stays type-only.
    """
    profile = _a_profile(tmp_path, 0o644)
    victim = tmp_path / "a-file-the-copy-must-not-reach.txt"
    victim_content = "the victim's own content\n"
    victim.write_text(victim_content, encoding="utf-8")
    planted = mcp_tools._scan_snapshot_path(profile, A_SCAN_ID)
    planted.symlink_to(victim)

    with pytest.raises(mcp_tools.ProfileSnapshotUnavailable) as refused:
        mcp_tools._snapshot_profile_for_scan(profile, A_SCAN_ID, snapshot_path=planted)

    assert "could not be copied" in str(refused.value)
    assert "FileExistsError" in str(refused.value)
    assert str(victim) not in str(refused.value)
    # The target was not written through the planted name, and the name --
    # which this call did not create -- was not removed.
    assert victim.read_text(encoding="utf-8") == victim_content
    assert planted.is_symlink()


def test_the_copy_is_written_on_a_platform_without_fchmod(tmp_path, monkeypatch):
    """Without ``os.fchmod`` the copy is still written at the profile's mode.

    ``os.fchmod`` is POSIX-only until Python 3.13, and this project supports
    older interpreters on Windows. On such a platform the write path must not
    crash reaching for the missing function -- an AttributeError there is not
    an OSError, so it would escape the refusal arm as a raw traceback instead
    of the type-only ProfileSnapshotUnavailable sentence. The name was taken
    exclusively, so applying the bits by name reaches the same file.
    """
    monkeypatch.delattr(os, "fchmod")
    profile = _a_profile(tmp_path, 0o600)
    previous_umask = os.umask(0o022)
    try:
        snapshot = _written_copy(profile)
    finally:
        os.umask(previous_umask)
    try:
        copy_mode = stat.S_IMODE(snapshot.stat().st_mode)
        assert copy_mode == 0o600, oct(copy_mode)
        assert snapshot.read_bytes() == profile.read_bytes()
    finally:
        snapshot.unlink(missing_ok=True)


def test_without_fchmod_a_non_0600_profiles_mode_still_lands(tmp_path, monkeypatch):
    """Without ``os.fchmod``, a profile whose mode is not 0600 keeps it.

    The cell above proves the no-fchmod path writes the copy, but its profile
    is 0600 and the name is created at 0600, so a by-name chmod that never
    ran would be invisible there: the create's own mode already matches. Only
    a profile at another mode separates "the fallback applied the bits" from
    "the create's 0600 was left standing", so this cell holds the group-read
    bit the operator granted (0640) across the copy.
    """
    monkeypatch.delattr(os, "fchmod")
    profile = _a_profile(tmp_path, 0o640)
    previous_umask = os.umask(0o022)
    try:
        snapshot = _written_copy(profile)
    finally:
        os.umask(previous_umask)
    try:
        copy_mode = stat.S_IMODE(snapshot.stat().st_mode)
        assert copy_mode == 0o640, oct(copy_mode)
        assert snapshot.read_bytes() == profile.read_bytes()
    finally:
        snapshot.unlink(missing_ok=True)


def test_the_copy_is_opened_with_the_platforms_binary_flag(tmp_path, monkeypatch):
    """Where the platform defines ``os.O_BINARY``, the open includes it.

    On Windows a file opened without O_BINARY goes through text-mode newline
    translation, so the copy would not be byte-identical to the profile. The
    flag does not exist on POSIX, so this cell plants one and captures the
    flags the open was given; the planted bit is stripped before the real
    open so the file itself is created normally.
    """
    planted_binary_bit = 0x8000
    monkeypatch.setattr(os, "O_BINARY", planted_binary_bit, raising=False)
    captured_flags = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        captured_flags.append(flags)
        return real_open(path, flags & ~planted_binary_bit, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    profile = _a_profile(tmp_path, 0o644)

    snapshot = _written_copy(profile)
    try:
        assert captured_flags, "the copy was not opened through os.open"
        assert captured_flags[0] & planted_binary_bit, hex(captured_flags[0])
        assert snapshot.read_bytes() == profile.read_bytes()
    finally:
        snapshot.unlink(missing_ok=True)


def test_a_call_that_names_no_snapshot_path_is_refused(tmp_path):
    """The copy's name is the caller's to compute, once, never the writer's.

    The runner records the planned path before the file exists and discards
    that path in its cleanup. A writer that computes a name of its own could
    write under a different name than the recorded one -- the host identity
    the name embeds can read differently on a second call -- so a call that
    hands no path is refused before anything is written.
    """
    profile = _a_profile(tmp_path, 0o600)

    with pytest.raises(TypeError):
        mcp_tools._snapshot_profile_for_scan(profile, A_SCAN_ID)

    assert list(tmp_path.iterdir()) == [profile]


def test_a_snapshot_path_in_another_directory_is_refused(tmp_path):
    """A planned path outside the profile's own directory writes nothing.

    The copy must sit beside the profile, so a chain the profile extends
    resolves exactly as the profile's own and the sweep of leftover copies,
    which globs the profile's directory, can see it. A path elsewhere is
    refused with ProfileSnapshotUnavailable before the file is created. The
    runner records the planned path before it calls the writer and resets that
    record on ProfileSnapshotUnavailable, so this refusal takes the same one
    reset path as a copy that fails to write.
    """
    profile = _a_profile(tmp_path, 0o600)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    foreign = elsewhere / mcp_tools._scan_snapshot_path(profile, A_SCAN_ID).name

    with pytest.raises(mcp_tools.ProfileSnapshotUnavailable):
        mcp_tools._snapshot_profile_for_scan(profile, A_SCAN_ID, snapshot_path=foreign)

    assert list(elsewhere.iterdir()) == []


def test_a_snapshot_path_the_name_grammar_rejects_is_refused(tmp_path):
    """A name ``parse_scan_copy_name`` does not admit writes nothing.

    The sweep of leftover copies judges a candidate only when its name
    parses as a scan copy's; a file written under any other name could never
    be placed by it and would sit beside the session's config for good. The
    writer refuses it with ProfileSnapshotUnavailable, the exception the
    runner resets its recorded path on, so the one reset path covers this
    refusal too.
    """
    profile = _a_profile(tmp_path, 0o600)
    unparseable = profile.with_name(f".ash-scan-not-a-scan-id.{profile.name}")

    with pytest.raises(mcp_tools.ProfileSnapshotUnavailable):
        mcp_tools._snapshot_profile_for_scan(
            profile, A_SCAN_ID, snapshot_path=unparseable
        )

    assert not unparseable.exists()


ANOTHER_SCAN_ID = "5a7c3e19-8d2b-4f60-b1c4-7e9a0d3f2b86"


def test_a_name_that_parses_to_another_scan_or_profile_is_refused_and_left_alone(
    tmp_path,
):
    """A well-formed copy name that is not this scan's and this profile's.

    The name parses as a scan copy's, so the grammar guard passes it, but it
    belongs to another scan or to a sibling profile in the same directory.
    Writing under it would put this scan's content in another scan's copy, and
    the runner's discard of the recorded path would then remove that copy. The
    writer refuses it with ProfileSnapshotUnavailable and a file already at the
    name, which this call did not create, stays as it was. A name that matches
    the scan id and ends in the profile's own name is written as before."""
    profile = _a_profile(tmp_path, 0o600)
    another_scan = mcp_tools._scan_snapshot_path(profile, ANOTHER_SCAN_ID)
    another_profile = profile.with_name(
        mcp_tools._scan_snapshot_path(profile, A_SCAN_ID).name.removesuffix(
            profile.name
        )
        + "other.yaml"
    )
    planted_content = "another copy's content\n"
    for planted in (another_scan, another_profile):
        planted.write_text(planted_content, encoding="utf-8")
        with pytest.raises(mcp_tools.ProfileSnapshotUnavailable) as refused:
            mcp_tools._snapshot_profile_for_scan(
                profile, A_SCAN_ID, snapshot_path=planted
            )
        assert "does not belong to this scan and this profile" in str(refused.value)
        assert planted.read_text(encoding="utf-8") == planted_content
        assert planted.exists()

    own = mcp_tools._scan_snapshot_path(profile, A_SCAN_ID)
    written = _written_copy(profile)
    try:
        assert written == own
        assert written.exists()
        assert written.read_bytes() == profile.read_bytes()
    finally:
        written.unlink(missing_ok=True)
        another_scan.unlink(missing_ok=True)
        another_profile.unlink(missing_ok=True)
