# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Policy discovery fails closed, a policy path is read as named, and a
suppression's package_path is pushed down with its path.

The module docstring of ``workspace/policy.py`` says a policy file that cannot
be read is refused, because applying no policy while the operator believes a
ceiling is in force is the fail-open outcome. Discovery used to break that rule
for an entry that exists but is not a readable regular file: a dangling link, a
link loop or a directory at a policy file name read as "no policy".

A policy path with ``..`` through a symlinked directory names one file to the
filesystem and another once the ``..`` is collapsed as text; the loader used to
collapse it and so read a file other than the one it had checked for.
"""

import os
from pathlib import Path

import pytest

from automated_security_helper.config.ash_workspace_config import (
    WorkspacePolicyConfig,
)
from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.workspace.policy import (
    discover_workspace_policy_file,
    load_workspace_policy,
    policy_for_project,
    resolve_workspace_policy,
)

pytestmark = pytest.mark.unit

POLICY_NAME = "ash-workspace.yaml"


def _symlink_or_skip(link: Path, target, target_is_directory=False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _threshold(body: str) -> str:
    return f"workspace:\n  max_severity_threshold: {body}\n"


class TestAPolicyEntryThatIsNotAFileIsRefused:
    def test_a_dangling_link_at_a_policy_name_is_refused(self, tmp_path):
        _symlink_or_skip(tmp_path / POLICY_NAME, tmp_path / "gone.yaml")

        with pytest.raises(WorkspaceDefinitionError, match="not there"):
            discover_workspace_policy_file(tmp_path)
        with pytest.raises(WorkspaceDefinitionError, match="not there"):
            resolve_workspace_policy(tmp_path)

    def test_a_directory_at_a_policy_name_is_refused(self, tmp_path):
        (tmp_path / ".ash" / POLICY_NAME).mkdir(parents=True)

        with pytest.raises(WorkspaceDefinitionError, match="directory"):
            discover_workspace_policy_file(tmp_path)

    def test_a_link_loop_at_a_policy_name_is_refused(self, tmp_path):
        link = tmp_path / POLICY_NAME
        _symlink_or_skip(link, link)

        with pytest.raises(WorkspaceDefinitionError, match="could not be examined"):
            discover_workspace_policy_file(tmp_path)

    def test_a_dangling_link_beside_a_real_policy_is_still_refused(self, tmp_path):
        """Ambiguity is refused, never ranked, and a broken entry is not an
        absence that lets the real file win."""
        (tmp_path / POLICY_NAME).write_text(_threshold("HIGH"), encoding="utf-8")
        _symlink_or_skip(tmp_path / ".ash-workspace.yaml", tmp_path / "gone.yaml")

        with pytest.raises(WorkspaceDefinitionError):
            discover_workspace_policy_file(tmp_path)

    def test_an_unsearchable_policy_directory_is_refused_not_a_traceback(
        self, tmp_path
    ):
        """Python 3.10-3.13 raised the bare PermissionError from Path.is_file();
        3.14 read the directory as holding no policy."""
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        (ash_dir / POLICY_NAME).write_text(_threshold("HIGH"), encoding="utf-8")
        ash_dir.chmod(0o000)
        try:
            if os.access(ash_dir / POLICY_NAME, os.R_OK):  # pragma: no cover - root
                pytest.skip("running as a user that ignores directory permissions")
            with pytest.raises(WorkspaceDefinitionError, match="could not be examined"):
                discover_workspace_policy_file(tmp_path)
        finally:
            ash_dir.chmod(0o755)

    def test_an_absent_policy_is_still_no_policy(self, tmp_path):
        """The one non-refusal the module docstring allows."""
        assert discover_workspace_policy_file(tmp_path) is None
        assert resolve_workspace_policy(tmp_path) == (None, None)


class TestAPolicyPathIsReadAsNamed:
    """``ws/L/../pol.yaml`` with ``L`` a link into ``ws/elsewhere/sub`` names
    ``ws/elsewhere/pol.yaml`` to the filesystem; collapsed as text it is
    ``ws/pol.yaml``, a different file."""

    @pytest.fixture
    def two_files(self, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "sub").mkdir(parents=True)
        (elsewhere / POLICY_NAME).write_text(_threshold("HIGH"), encoding="utf-8")
        (tmp_path / POLICY_NAME).write_text(_threshold("LOW"), encoding="utf-8")
        _symlink_or_skip(tmp_path / "L", elsewhere / "sub", target_is_directory=True)
        return tmp_path / "L" / ".." / POLICY_NAME

    def test_an_explicit_policy_path_reads_the_file_it_names(self, two_files):
        policy, source = resolve_workspace_policy(
            two_files.parent.parent.parent, explicit=two_files
        )

        assert policy.workspace.max_severity_threshold == "HIGH"
        assert ".." in source.parts

    def test_load_workspace_policy_reads_the_file_it_names(self, two_files):
        policy = load_workspace_policy(two_files)

        assert policy.workspace.max_severity_threshold == "HIGH"

    def test_discovery_under_a_root_spelled_through_a_link_reads_that_root(
        self, two_files
    ):
        root = two_files.parent

        discovered = discover_workspace_policy_file(root)
        policy, _ = resolve_workspace_policy(root)

        assert discovered is not None
        assert ".." in discovered.parts
        assert policy.workspace.max_severity_threshold == "HIGH"


class TestAPackagePathIsPushedDownWithThePath:
    POLICY = WorkspacePolicyConfig(
        suppressions=[
            AshSuppression(
                path="**/*.js",
                reason="vendored copy",
                package_path="api/node_modules/left-pad",
            )
        ]
    )

    def _pushed(self, prefix):
        return policy_for_project(
            self.POLICY,
            project_prefix=prefix,
            project_threshold="MEDIUM",
            project_scanners=(),
        ).suppressions

    def test_the_package_path_is_rewritten_into_the_projects_coordinates(self):
        """A finding's package_path is project-relative, so a workspace-relative
        one never matched it."""
        (pushed,) = self._pushed("api")

        assert pushed.path == "**/*.js"
        assert pushed.package_path == "node_modules/left-pad"

    def test_a_package_copy_in_another_project_drops_the_entry(self):
        assert self._pushed("web") == ()

    def test_the_policy_object_is_not_mutated(self):
        self._pushed("api")

        assert self.POLICY.suppressions[0].package_path == "api/node_modules/left-pad"
