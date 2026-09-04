# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two workspace execution knobs, and why they live in ASH's own config.

``workspace_file.py`` deliberately ignores the ``settings`` block of a
``.code-workspace`` file, so these cannot be read from there. They are execution
knobs rather than policy -- neither can change any project's verdict -- which is
why they can land in Phase 2a ahead of the workspace policy block in Phase 3.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    AshConfig,
    WorkspaceExecutionConfig,
)


class TestDefaults:
    def test_max_parallel_projects_defaults_to_unset(self):
        """Unset, not 4: the real default is derived from the host's CPU count."""
        assert WorkspaceExecutionConfig().max_parallel_projects is None

    def test_project_timeout_defaults_to_none(self):
        assert WorkspaceExecutionConfig().project_timeout is None

    def test_ash_config_carries_a_default_workspace_block(self):
        assert isinstance(AshConfig().workspace, WorkspaceExecutionConfig)


class TestResolvedParallelism:
    def test_an_explicit_value_is_honoured(self):
        config = WorkspaceExecutionConfig(max_parallel_projects=7)
        assert config.resolved_max_parallel_projects() == 7

    def test_the_derived_default_is_capped_at_four(self):
        config = WorkspaceExecutionConfig()
        assert config.resolved_max_parallel_projects(cpu_count=64) == 4

    def test_a_host_exactly_at_the_cap_gets_the_cap(self):
        """The boundary itself, which 64-above and 2-below both step over.

        Worth its own case because callers assert the literal 4 for a host at or
        above the cap. A macOS runner reports 3 and so lands below it, which is
        what turned an unpatched `== 4` in the builder tests into `assert 3 == 4`
        on every macOS row while Linux stayed green.
        """
        config = WorkspaceExecutionConfig()
        assert config.resolved_max_parallel_projects(cpu_count=4) == 4

    def test_the_derived_default_follows_a_small_host(self):
        config = WorkspaceExecutionConfig()
        assert config.resolved_max_parallel_projects(cpu_count=2) == 2

    def test_the_derived_default_never_returns_zero(self):
        """os.cpu_count() can return None, and a pool of zero workers deadlocks."""
        config = WorkspaceExecutionConfig()
        assert config.resolved_max_parallel_projects(cpu_count=None) == 1
        assert config.resolved_max_parallel_projects(cpu_count=0) == 1

    def test_the_real_host_produces_a_usable_bound(self):
        assert WorkspaceExecutionConfig().resolved_max_parallel_projects() >= 1


class TestValidation:
    def test_zero_parallel_projects_is_rejected(self):
        with pytest.raises(ValidationError):
            WorkspaceExecutionConfig(max_parallel_projects=0)

    def test_a_non_positive_timeout_is_rejected(self):
        with pytest.raises(ValidationError):
            WorkspaceExecutionConfig(project_timeout=0)

    def test_an_unknown_key_is_rejected(self):
        """extra=forbid so a typo surfaces rather than being silently ignored."""
        with pytest.raises(ValidationError):
            WorkspaceExecutionConfig(max_paralell_projects=4)


class TestConfigFileRoundTrip:
    def test_the_block_is_read_from_a_config_file(self, tmp_path):
        config_file = tmp_path / "ash.yaml"
        config_file.write_text(
            "project_name: fixture\nworkspace:\n"
            "  max_parallel_projects: 2\n  project_timeout: 90.5\n",
            encoding="utf-8",
        )
        config = AshConfig.from_file(config_file)
        assert config.workspace.max_parallel_projects == 2
        assert config.workspace.project_timeout == pytest.approx(90.5)

    def test_a_config_without_the_block_still_loads(self, tmp_path):
        config_file = tmp_path / "ash.yaml"
        config_file.write_text("project_name: fixture\n", encoding="utf-8")
        config = AshConfig.from_file(config_file)
        assert config.workspace.max_parallel_projects is None
