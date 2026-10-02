# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Failure paths of config discovery and `extends` that must not be silent.

Each test pins a case where the first implementation either fell back to the
default config without saying so, let an unrelated pyproject.toml break a
working config, or let a base outside the repository be read.
"""

import os
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError

DEFAULT_PROJECT_NAME = AshConfig().project_name


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


class TestMalformedDirectivesFailClosed:
    """These raised exception types resolve_config's catch-all turned into defaults."""

    @pytest.mark.parametrize(
        "patch_yaml",
        [
            "[{op: [add], path: /project_name, value: x}]",
            "[{op: {a: b}, path: /project_name, value: x}]",
            "[{op: replace, path: '/global_settings/ignore_paths/²', value: x}]",
        ],
    )
    def test_malformed_patch_raises(self, tmp_path, patch_yaml):
        _write(
            tmp_path / ".ash.yaml",
            "project_name: marker\nglobal_settings:\n  ignore_paths: []\n"
            f"patch: {patch_yaml}\n",
        )
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)

    def test_nul_in_extends_raises(self, tmp_path):
        _write(tmp_path / ".ash.yaml", 'project_name: marker\nextends: "a\\0b.yaml"\n')
        with pytest.raises(ASHConfigValidationError, match="NUL"):
            resolve_config(source_dir=tmp_path)


class TestUnrelatedPyprojectCannotBreakAWorkingConfig:
    def test_non_utf8_pyproject_is_ignored_when_a_dedicated_file_exists(self, tmp_path):
        _write(tmp_path / ".ash" / ".ash.yaml", "project_name: marker\n")
        (tmp_path / "pyproject.toml").write_bytes(
            "[project]\nname = 'café'\n".encode("latin-1")
        )
        assert resolve_config(source_dir=tmp_path).project_name == "marker"

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs POSIX permissions that root ignores",
    )
    def test_unreadable_pyproject_is_ignored_when_a_dedicated_file_exists(
        self, tmp_path
    ):
        _write(tmp_path / ".ash" / ".ash.yaml", "project_name: marker\n")
        pyproject = _write(tmp_path / "pyproject.toml", '[project]\nname = "x"\n')
        pyproject.chmod(0)
        try:
            assert resolve_config(source_dir=tmp_path).project_name == "marker"
        finally:
            pyproject.chmod(0o644)

    def test_broken_tool_ash_is_ignored_when_a_dedicated_file_exists(self, tmp_path):
        _write(tmp_path / ".ash" / ".ash.yaml", "project_name: marker\n")
        _write(tmp_path / "pyproject.toml", '[tool]\nash = "x"\n')
        assert resolve_config(source_dir=tmp_path).project_name == "marker"

    def test_broken_tool_ash_still_fails_when_it_is_the_only_source(self, tmp_path):
        _write(tmp_path / "pyproject.toml", '[tool]\nash = "x"\n')
        with pytest.raises(ASHConfigValidationError, match="must be a table"):
            resolve_config(source_dir=tmp_path)

    def test_non_utf8_pyproject_declaring_tool_ash_fails_closed(self, tmp_path):
        (tmp_path / "pyproject.toml").write_bytes(
            "[tool.ash]\nproject_name = 'café'\n".encode("latin-1")
        )
        with pytest.raises(ASHConfigValidationError, match="UTF-8"):
            resolve_config(source_dir=tmp_path)

    def test_pyproject_with_a_byte_order_mark_is_read(self, tmp_path):
        (tmp_path / "pyproject.toml").write_bytes(
            b"\xef\xbb\xbf[tool.ash]\nproject_name = 'bom'\n"
        )
        assert resolve_config(source_dir=tmp_path).project_name == "bom"


class TestConfinementDoesNotWidenToTheCwd:
    def test_explicit_config_without_source_dir_is_confined_to_its_project(
        self, tmp_path, monkeypatch
    ):
        # The cwd is an ancestor of both the repo and the target. Before the
        # fix the cwd became the root, so this base was readable.
        _write(tmp_path / "private" / "hosts.yaml", "project_name: leaked\n")
        config = _write(
            tmp_path / "src" / "repo" / ".ash" / ".ash.yaml",
            "extends: ../../../private/hosts.yaml\n",
        )
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(config_path=config)

    def test_failed_test_op_does_not_print_the_value_it_read(self, tmp_path):
        _write(
            tmp_path / "base.yaml",
            "project_name: p\nexternal_reports_to_include: [secret-marker-value]\n",
        )
        _write(
            tmp_path / ".ash.yaml",
            """
            extends: base.yaml
            patch:
              - {op: test, path: /external_reports_to_include/0, value: guess}
            """,
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=tmp_path)
        assert "secret-marker-value" not in str(excinfo.value)
        assert "does not equal" in str(excinfo.value)

    def test_dotdot_escape_is_refused_before_touching_the_target(self, tmp_path):
        # The escaping path does not exist; the refusal must still name the
        # confinement, not a missing file, so it never got as far as a lookup.
        repo = tmp_path / "repo"
        _write(repo / ".ash.yaml", "extends: ../nowhere/base.yaml\n")
        with pytest.raises(ASHConfigValidationError, match="outside the directory"):
            resolve_config(source_dir=repo)


class TestEveryReaderUsesTheSameDiscovery:
    def test_exit_code_fields_read_an_ashrc_file(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _resolve_config_fail_on_findings,
            _resolve_config_fail_on_incomplete_scanners,
        )

        _write(
            tmp_path / ".ashrc.yaml",
            "project_name: p\nfail_on_findings: false\n"
            "fail_on_incomplete_scanners: false\n",
        )
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_findings(opts) is False
        assert _resolve_config_fail_on_incomplete_scanners(opts) is False

    def test_exit_code_fields_follow_extends(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _resolve_config_fail_on_findings,
        )

        _write(tmp_path / "base.yaml", "project_name: p\nfail_on_findings: false\n")
        _write(tmp_path / "pyproject.toml", '[tool.ash]\nextends = "base.yaml"\n')
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_findings(opts) is False

    def test_workspace_settings_read_pyproject(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _resolve_workspace_execution_config,
        )

        _write(
            tmp_path / "pyproject.toml",
            "[tool.ash]\nproject_name = 'p'\n[tool.ash.workspace]\n"
            "max_parallel_projects = 3\n",
        )
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")
        assert _resolve_workspace_execution_config(opts).max_parallel_projects == 3


class TestMcpConfigTools:
    def test_get_config_keeps_the_repo_as_the_root_for_a_dot_ash_file(self, tmp_path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        _write(tmp_path / "shared" / "base.yaml", "project_name: shared-base\n")
        config = _write(
            tmp_path / ".ash" / ".ash.yaml", "extends: ../shared/base.yaml\n"
        )
        assert mcp_get_config(config_path=str(config))["project_name"] == "shared-base"
        assert mcp_get_config(search_dir=str(tmp_path))["project_name"] == "shared-base"

    def test_get_config_raw_reads_the_tool_ash_table(self, tmp_path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        _write(
            tmp_path / "pyproject.toml",
            '[project]\nname = "x"\n[tool.ash]\nproject_name = "raw-table"\n',
        )
        raw = mcp_get_config(search_dir=str(tmp_path), raw=True)
        assert raw == {"project_name": "raw-table"}

    def test_validate_content_cannot_extend_files_beside_it(self, tmp_path):
        import tempfile

        from automated_security_helper.cli.mcp_tools import mcp_validate_config

        # A file a client did not send, in the shared temp directory.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", dir=tempfile.gettempdir(), delete=False
        ) as other:
            other.write("project_name: not-sent-by-the-client\n")
        try:
            result = mcp_validate_config(
                config_content=f"project_name: p\nextends: ../{Path(other.name).name}\n"
            )
            assert result["valid"] is False
            messages = " ".join(e["message"] for e in result["errors"])
            assert "extends" in messages
            result = mcp_validate_config(
                config_content=f"project_name: p\nextends: {Path(other.name).name}\n"
            )
            assert result["valid"] is False
        finally:
            Path(other.name).unlink(missing_ok=True)
