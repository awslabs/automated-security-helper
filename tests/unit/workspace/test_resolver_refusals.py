# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolution refusals that used to be tracebacks, acceptances or silences.

Each case names a shape the resolver met and answered wrongly: a NUL byte in a
config path raised a bare ``ValueError``; two spellings of one directory, or two
keys one case apart, passed the overlap and key checks and would be scanned and
written twice; an unexaminable project raised a bare ``PermissionError``;
three pins compatible two at a time were accepted though no version satisfies
all three; a remote client's policy entries went unmarked; and the operator's
registered config was never held to the UTF-8 gate.
"""

import json
import os
from types import SimpleNamespace

import pytest

from automated_security_helper.core.exceptions import (
    WorkspaceDefinitionError,
    WorkspacePathNotUtf8Error,
)
from automated_security_helper.workspace import resolver
from automated_security_helper.workspace.resolver import (
    _refuse_config_files_that_are_not_utf8,
    _validate_scanner_pins,
    resolve_workspace,
)
from automated_security_helper.workspace.scanner_pins import (
    PinVerdict,
    compare_pin_set,
    compare_pins,
)

pytestmark = pytest.mark.unit


def _workspace(root, folders, name="dev.code-workspace"):
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _project(root, relative):
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    return project


def _recorded(key, **pins):
    return SimpleNamespace(key=key, scanner_pins=pins)


def _definition(tmp_path):
    return SimpleNamespace(path=tmp_path / "dev.code-workspace")


class TestConfigPathsAreCheckedBeforeAnyRead:
    def test_a_nul_byte_in_a_config_path_is_a_definition_error(self, tmp_path):
        """An embedded NUL escaped the UTF-8 gate as a bare ``ValueError`` from
        ``Path.resolve``. It is now read off the text, so the refusal does not
        depend on which inputs this Python's pathlib refuses."""
        with pytest.raises(WorkspaceDefinitionError, match="NUL character"):
            _refuse_config_files_that_are_not_utf8("pol\x00icy.yaml", None)
        with pytest.raises(WorkspaceDefinitionError, match="NUL character"):
            _refuse_config_files_that_are_not_utf8(None, str(tmp_path / "a\x00.yaml"))
        with pytest.raises(WorkspaceDefinitionError, match="NUL character"):
            _refuse_config_files_that_are_not_utf8(None, None, "pro\x00file.yaml")

    def test_a_nul_byte_is_refused_without_asking_the_filesystem_layer(
        self, tmp_path, monkeypatch
    ):
        """A pathlib whose ``resolve`` returned normally for a NUL would have let
        it through the old ``except ValueError`` gate; the text read does not."""
        monkeypatch.setattr(resolver.Path, "resolve", lambda self, strict=False: self)

        with pytest.raises(WorkspaceDefinitionError, match="NUL character"):
            _refuse_config_files_that_are_not_utf8("pol\x00icy.yaml", None)

    def test_a_nul_byte_reaches_the_operator_through_resolve_workspace(self, tmp_path):
        _project(tmp_path, "api")
        workspace = _workspace(tmp_path, ["api"])

        with pytest.raises(WorkspaceDefinitionError, match="NUL character"):
            resolve_workspace(workspace, workspace_config="pol\x00icy.yaml")

    def test_the_registered_config_is_held_to_the_utf8_gate(self, tmp_path):
        """The plan records ``trusted_config`` as the operator's config, so its
        path has to be UTF-8 like the policy file's and the default config's."""
        with pytest.raises(WorkspacePathNotUtf8Error, match="registered config"):
            _refuse_config_files_that_are_not_utf8(
                None, None, str(tmp_path / "pro\udcfffile.yaml")
            )

    def test_utf8_paths_pass_the_gate(self, tmp_path):
        _refuse_config_files_that_are_not_utf8(
            str(tmp_path / "policy.yaml"),
            str(tmp_path / "default.yaml"),
            str(tmp_path / "profile.yaml"),
        )


class TestEntriesAreComparedAsDirectoriesNotAsText:
    @pytest.fixture
    def case_folding_filesystem(self, monkeypatch):
        """Stand in for a filesystem on which ``api`` and ``API`` are one
        directory while ``realpath`` keeps each spelling (macOS APFS): two
        spellings that fold together get one identity."""
        real = resolver._directory_identity

        def identity(path, cache):
            if path not in cache:
                real_identity = real(path, {})
                cache[path] = (
                    (1, hash(str(path).casefold()) % 1_000_000_007 + 1)
                    if real_identity is not None
                    else None
                )
            return cache[path]

        monkeypatch.setattr(resolver, "_directory_identity", identity)

    def test_two_spellings_of_one_directory_are_refused(
        self, tmp_path, case_folding_filesystem
    ):
        _project(tmp_path, "api")
        _project(tmp_path, "API")
        workspace = _workspace(tmp_path, ["api", "API"])

        with pytest.raises(WorkspaceDefinitionError, match="same directory"):
            resolve_workspace(workspace)

    def test_a_nested_entry_spelled_in_another_case_is_refused(
        self, tmp_path, case_folding_filesystem
    ):
        _project(tmp_path, "api")
        _project(tmp_path, "API/sub")
        workspace = _workspace(tmp_path, ["api", "API/sub"])

        with pytest.raises(WorkspaceDefinitionError, match="is inside"):
            resolve_workspace(workspace)

    def test_distinct_directories_still_pass_on_a_filesystem_that_folds_case(
        self, tmp_path, case_folding_filesystem
    ):
        """Control for the two refusals above, run under the same stub: names
        that differ by more than case are two directories there too, so the
        stub joins what folds together and nothing else."""
        _project(tmp_path, "api")
        _project(tmp_path, "docs")
        workspace = _workspace(tmp_path, ["api", "docs"])

        plan = resolve_workspace(workspace)

        assert sorted(project.key for project in plan.projects) == ["api", "docs"]

    def test_a_volume_that_reports_no_inode_is_judged_by_text_alone(
        self, tmp_path, monkeypatch
    ):
        """``st_ino == 0`` identifies nothing (some Windows network shares, RAM
        disks and FUSE mounts report it), and ``samefile`` read every pair of
        such directories as one, refusing every workspace on the volume."""
        real_stat = os.stat

        def stat_without_inodes(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            fields = list(result)
            fields[1] = 0  # st_ino
            return os.stat_result(tuple(fields))

        monkeypatch.setattr(resolver.os, "stat", stat_without_inodes)
        _project(tmp_path, "api")
        _project(tmp_path, "docs")
        workspace = _workspace(tmp_path, ["api", "docs"])

        plan = resolve_workspace(workspace)

        assert sorted(project.key for project in plan.projects) == ["api", "docs"]

    def test_the_overlap_check_reads_each_directory_once(self, tmp_path, monkeypatch):
        """Identities are read once per path and compared in memory: with N
        entries at depth 2 the check stats at most the entries and their
        ancestors below the root, not every pair's whole chain to ``/``."""
        misses: list = []
        real = resolver._directory_identity

        def counting(path, cache):
            if path not in cache:
                misses.append(path)
            return real(path, cache)

        monkeypatch.setattr(resolver, "_directory_identity", counting)
        entries = [f"team{n}/svc" for n in range(8)]
        for entry in entries:
            _project(tmp_path, entry)
        workspace = _workspace(tmp_path, entries)

        resolve_workspace(workspace)

        # 8 entries plus their 8 ``teamN`` parents: 16 reads; a pairwise samefile
        # walk to ``/`` made several hundred.
        assert len(misses) <= 3 * len(entries), misses


class TestKeysThatDifferOnlyByCaseAreRefused:
    def test_two_keys_one_case_apart_name_one_output_directory(self, tmp_path):
        """``Api/sub`` and ``api-sub`` are two directories everywhere, and their
        keys ``Api-sub`` and ``api-sub`` are one output directory on macOS and
        Windows."""
        _project(tmp_path, "Api/sub")
        _project(tmp_path, "api-sub")
        workspace = _workspace(tmp_path, ["Api/sub", "api-sub"])

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(workspace)

        message = str(excinfo.value)
        assert "differ only by case" in message
        assert "Api-sub" in message
        assert "api-sub" in message

    def test_identical_keys_keep_their_own_message(self, tmp_path):
        _project(tmp_path, "api/sub")
        _project(tmp_path, "api-sub")
        workspace = _workspace(tmp_path, ["api/sub", "api-sub"])

        with pytest.raises(WorkspaceDefinitionError, match="same project key"):
            resolve_workspace(workspace)


class TestAnUnexaminableProjectIsNotATraceback:
    @pytest.fixture
    def locked_parent(self, tmp_path):
        locked = tmp_path / "locked"
        _project(locked, "api")
        locked.chmod(0o000)
        try:
            if os.access(locked / "api", os.R_OK):  # pragma: no cover - root
                pytest.skip("running as a user that ignores directory permissions")
            yield locked
        finally:
            locked.chmod(0o755)

    def test_it_is_refused_by_default(self, tmp_path, locked_parent):
        """The message names the real cause on every Python version: on 3.14
        ``Path.is_dir()`` read the locked parent as absent, so the same project
        was reported as missing there and as unexaminable on 3.10-3.13."""
        workspace = _workspace(tmp_path, ["locked/api"])

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(workspace)

        message = str(excinfo.value)
        assert "locked/api" in message
        assert "cannot be examined" in message, message
        assert "does not exist" not in message, message

    def test_it_is_skipped_under_allow_missing_projects(self, tmp_path, locked_parent):
        _project(tmp_path, "web")
        workspace = _workspace(tmp_path, ["web", "locked/api"])

        plan = resolve_workspace(workspace, allow_missing_projects=True)

        skipped = {entry.project: entry for entry in plan.skipped_projects}
        assert set(skipped) == {"locked-api"}
        assert "cannot be examined" in (skipped["locked-api"].detail or "")

    def test_a_missing_project_is_still_reported_as_missing(self, tmp_path):
        """Control for the stat read: an absent entry, and a file on the way to
        one, read as "does not exist as a directory", never as unexaminable."""
        (tmp_path / "file").write_text("", encoding="utf-8")
        workspace = _workspace(tmp_path, ["absent", "file/api"])

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(workspace)

        message = str(excinfo.value)
        assert message.count("does not exist as a directory") == 2, message
        assert "cannot be examined" not in message, message


class TestTheSessionComesFromOneSource:
    def test_two_sessions_that_disagree_are_refused_before_anything_is_read(
        self, tmp_path
    ):
        """``session_id`` beside ``client_config_rules`` carrying another session
        would judge the operator config for one session and the projects for
        the other; the call is a caller's error and is refused as one."""
        with pytest.raises(ValueError, match="differs from"):
            resolve_workspace(
                tmp_path / "never-read.code-workspace",
                client_config_rules=SimpleNamespace(session_id="b"),
                session_id="a",
            )

    def test_a_matching_session_or_one_source_is_accepted(self, tmp_path):
        _project(tmp_path, "api")
        workspace = _workspace(tmp_path, ["api"])

        resolve_workspace(workspace, session_id="a")
        resolve_workspace(workspace)


class TestPinsAreCheckedAsASetNotPairwise:
    TRIO = {"api": ">=1,<3", "web": ">=2,<4", "docs": "!=2.*"}

    def test_the_trio_is_compatible_two_at_a_time(self):
        pins = list(self.TRIO.values())
        for index, first in enumerate(pins):
            for second in pins[index + 1 :]:
                assert compare_pins(first, second) is PinVerdict.COMPATIBLE

    def test_but_no_one_version_satisfies_all_three(self):
        assert compare_pin_set(list(self.TRIO.values())) is PinVerdict.INCOMPATIBLE

    def test_the_workspace_is_refused_naming_every_pin(self, tmp_path):
        projects = [_recorded(key, semgrep=pin) for key, pin in self.TRIO.items()]

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            _validate_scanner_pins(_definition(tmp_path), projects)

        message = str(excinfo.value)
        assert "together" in message
        for key, pin in self.TRIO.items():
            assert f"'{pin}' (required by {key})" in message

    def test_three_jointly_satisfiable_pins_are_accepted(self, tmp_path):
        projects = [
            _recorded("a", semgrep=">=1,<3"),
            _recorded("b", semgrep=">=2,<4"),
            _recorded("c", semgrep="!=2.0.*"),
        ]

        _validate_scanner_pins(_definition(tmp_path), projects)
        assert compare_pin_set([">=1,<3", ">=2,<4", "!=2.0.*"]) is PinVerdict.COMPATIBLE

    @pytest.mark.parametrize(
        "pins,expected",
        [
            ([], PinVerdict.COMPATIBLE),
            ([">=1.0rc1"], PinVerdict.COMPATIBLE),
            ([">=1.0rc1", ">=1.0rc1", " >=1.0rc1"], PinVerdict.COMPATIBLE),
            ([">=1.0rc1", ">=2"], PinVerdict.UNDECIDABLE),
            ([">=1", "<3"], PinVerdict.COMPATIBLE),
            ([">=1", "<1"], PinVerdict.INCOMPATIBLE),
            ([">=1", ">=1", "<1"], PinVerdict.INCOMPATIBLE),
        ],
    )
    def test_compare_pin_set_reads_like_compare_pins(self, pins, expected):
        assert compare_pin_set(pins) is expected
        if len(pins) == 2:
            assert compare_pin_set(pins) is compare_pins(*pins)


class TestARemoteClientsPolicyIsDelivered:
    POLICY = (
        "workspace:\n"
        "  suppressions:\n"
        "    - path: 'api/tests/**'\n"
        "      reason: tests\n"
        "  ignore_paths:\n"
        "    - path: '**/vendor'\n"
        "      reason: third party\n"
    )

    def _entries(self, plan):
        (project,) = plan.projects
        return list(project.policy_suppressions) + list(project.policy_ignore_paths)

    def test_entries_are_marked_under_a_remote_client(self, tmp_path, monkeypatch):
        """The loader already read the file as the client's under
        ``remote_client``; the delivered flag read it as the operator's, so its
        entries were pushed unmarked and unchecked."""
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        _project(tmp_path, "api")
        workspace = _workspace(tmp_path, ["api"])
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        (ash_dir / "ash-workspace.yaml").write_text(self.POLICY, encoding="utf-8")

        entries = self._entries(resolve_workspace(workspace, remote_client=True))

        assert len(entries) == 2
        assert all(entry.client_supplied is True for entry in entries)

    def test_entries_stay_unmarked_for_a_local_operator(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        _project(tmp_path, "api")
        workspace = _workspace(tmp_path, ["api"])
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        (ash_dir / "ash-workspace.yaml").write_text(self.POLICY, encoding="utf-8")

        entries = self._entries(resolve_workspace(workspace))

        assert len(entries) == 2
        assert all(entry.client_supplied is False for entry in entries)
