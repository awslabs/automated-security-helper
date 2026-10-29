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
        """``Path.resolve`` raises ``ValueError`` for an embedded NUL, which
        escaped the UTF-8 gate as a traceback."""
        with pytest.raises(WorkspaceDefinitionError, match="control characters"):
            _refuse_config_files_that_are_not_utf8("pol\x00icy.yaml", None)
        with pytest.raises(WorkspaceDefinitionError, match="control characters"):
            _refuse_config_files_that_are_not_utf8(None, str(tmp_path / "a\x00.yaml"))

    def test_a_nul_byte_reaches_the_operator_through_resolve_workspace(self, tmp_path):
        _project(tmp_path, "api")
        workspace = _workspace(tmp_path, ["api"])

        with pytest.raises(WorkspaceDefinitionError, match="control characters"):
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
        directory while ``realpath`` keeps each spelling (macOS APFS)."""
        real = os.path.samefile

        def samefile(first, second):
            if str(first).casefold() == str(second).casefold():
                return True
            return real(first, second)

        monkeypatch.setattr(resolver.os.path, "samefile", samefile)

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

    def test_distinct_directories_on_a_case_sensitive_filesystem_still_pass(
        self, tmp_path
    ):
        """Without the folding filesystem the two are two directories; the
        overlap check lets them through and the key check decides."""
        _project(tmp_path, "api")
        _project(tmp_path, "docs")
        workspace = _workspace(tmp_path, ["api", "docs"])

        plan = resolve_workspace(workspace)

        assert sorted(project.key for project in plan.projects) == ["api", "docs"]


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
        workspace = _workspace(tmp_path, ["locked/api"])

        with pytest.raises(WorkspaceDefinitionError, match="locked/api"):
            resolve_workspace(workspace)

    def test_it_is_skipped_under_allow_missing_projects(self, tmp_path, locked_parent):
        _project(tmp_path, "web")
        workspace = _workspace(tmp_path, ["web", "locked/api"])

        plan = resolve_workspace(workspace, allow_missing_projects=True)

        skipped = {entry.project: entry for entry in plan.skipped_projects}
        assert set(skipped) == {"locked-api"}
        assert skipped["locked-api"].detail


class TestPinsAreCheckedAsASetNotPairwise:
    TRIO = {"a": ">=1,<3", "b": ">=2,<4", "c": "!=2.*"}

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
        for pin in self.TRIO.values():
            assert pin in message

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
            ([">=1", ">=1", "<1"], PinVerdict.INCOMPATIBLE),
        ],
    )
    def test_compare_pin_set_reads_like_compare_pins(self, pins, expected):
        assert compare_pin_set(pins) is expected


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
