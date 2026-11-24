# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checkov leaves VCS server-configuration frameworks out by default and keeps
their cache directories out of the filesystem root and scanned tree.

Running checkov from ``/`` (``CheckovScanner._subprocess_cwd``) with the
default ``--framework all`` caused checkov's ``gitlab_configuration`` runner in
GitLab CI (where ``CI_SERVER_URL`` and ``CI_JOB_TOKEN`` are set) to write to
``/gitlab_conf``, failing with ``PermissionError: '/gitlab_conf'`` for non-root
users and polluting ``/`` for root. ``github_configuration`` and
``bitbucket_configuration`` behave the same way.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from typing import get_args

from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _KNOWN_VCS_CONFIGURATION_FRAMEWORKS,
    _VCS_CONF_DIR_ENV_VARS,
    _VCS_CONFIG_FETCH_ENV_VARS,
    _VCS_CONFIGURATION_FRAMEWORKS,
    _vcs_conf_dir_env_vars,
    _vcs_config_fetch_env_vars,
    _vcs_configuration_frameworks,
    CheckFrameworks,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


def _scanner(source: Path, output: Path, **opts) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _flag_values(extra_args, flag: str) -> list[str]:
    return [arg.value for arg in extra_args if arg.key == flag and arg.value]


class TestVcsConfigurationFrameworkDerivation:
    """The skip set is derived from the ``CheckFrameworks`` mirror by checkov's
    naming rule for VCS configuration runners, not hardcoded per vendor.

    These gates make drift loud: a derivation that stops covering the measured
    floor, a derived member outside the structural rule, or an environment
    variable that stops matching the pattern checkov's VCS DALs read fails
    here. The companion integration gate
    (tests/integration/scanners/test_checkov_real_config_and_paths.py) checks
    the mirror itself against the installed checkov's registry.
    """

    def test_derived_set_covers_measured_floor(self):
        assert set(_VCS_CONFIGURATION_FRAMEWORKS) >= {
            "github_configuration",
            "gitlab_configuration",
            "bitbucket_configuration",
        }

    def test_every_derived_member_matches_structural_rule(self):
        mirror = set(get_args(CheckFrameworks))
        for framework in _VCS_CONFIGURATION_FRAMEWORKS:
            assert framework.endswith("_configuration")
            # A non-empty vendor name precedes the suffix.
            assert framework.removesuffix("_configuration")
            assert framework in mirror

    def test_env_var_derivation_matches_checkov_measured_pattern(self):
        # Measured at checkov 3.4.5: gitlab/dal.py:18 and :67,
        # github/dal.py:24 and :225, bitbucket/dal.py:18 and :77.
        conf_dirs = dict(_VCS_CONF_DIR_ENV_VARS)
        assert conf_dirs["CKV_GITLAB_CONF_DIR_NAME"] == "gitlab_conf"
        assert conf_dirs["CKV_GITHUB_CONF_DIR_NAME"] == "github_conf"
        assert conf_dirs["CKV_BITBUCKET_CONF_DIR_NAME"] == "bitbucket_conf"
        assert set(_VCS_CONFIG_FETCH_ENV_VARS) >= {
            "CKV_GITLAB_CONFIG_FETCH_DATA",
            "CKV_GITHUB_CONFIG_FETCH_DATA",
            "CKV_BITBUCKET_CONFIG_FETCH_DATA",
        }
        # One cache-directory tuple and one fetch toggle per skipped framework.
        assert len(_VCS_CONF_DIR_ENV_VARS) == len(_VCS_CONFIGURATION_FRAMEWORKS)
        assert len(_VCS_CONFIG_FETCH_ENV_VARS) == len(_VCS_CONFIGURATION_FRAMEWORKS)

    def test_new_configuration_framework_is_auto_covered(self):
        derived = _vcs_configuration_frameworks(
            ["all", "terraform", "gitea_configuration"]
        )
        assert "gitea_configuration" in derived
        assert ("CKV_GITEA_CONF_DIR_NAME", "gitea_conf") in _vcs_conf_dir_env_vars(
            derived
        )
        assert "CKV_GITEA_CONFIG_FETCH_DATA" in _vcs_config_fetch_env_vars(derived)
        assert set(derived) >= set(_KNOWN_VCS_CONFIGURATION_FRAMEWORKS)

    def test_non_matching_names_are_not_vcs_configuration_frameworks(self):
        derived = _vcs_configuration_frameworks(
            ["_configuration", "gitlab_ci", "github_actions", "terraform", "all"]
        )
        assert set(derived) == set(_KNOWN_VCS_CONFIGURATION_FRAMEWORKS)

    def test_empty_framework_list_falls_back_to_measured_floor(self):
        assert _vcs_configuration_frameworks([]) == tuple(
            sorted(_KNOWN_VCS_CONFIGURATION_FRAMEWORKS)
        )


class TestVcsConfigurationFrameworkDefaults:
    def test_default_all_skips_vcs_configuration_frameworks(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out")

        frameworks = _flag_values(scanner.args.extra_args, "--framework")
        skipped = _flag_values(scanner.args.extra_args, "--skip-framework")

        assert frameworks == ["all"]
        for vcs_fw in _VCS_CONFIGURATION_FRAMEWORKS:
            assert vcs_fw in skipped
        # File-scanning CI frameworks must remain enabled.
        for ci_file_fw in ("gitlab_ci", "github_actions", "bitbucket_pipelines"):
            assert ci_file_fw not in skipped

    def test_user_skip_frameworks_preserved_without_duplicates(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(
            source,
            tmp_path / "out",
            skip_frameworks=["secrets", "gitlab_configuration"],
        )

        skipped = _flag_values(scanner.args.extra_args, "--skip-framework")
        assert "secrets" in skipped
        for vcs_fw in _VCS_CONFIGURATION_FRAMEWORKS:
            assert skipped.count(vcs_fw) == 1

    @pytest.mark.parametrize("vcs_fw", _VCS_CONFIGURATION_FRAMEWORKS)
    def test_explicit_vcs_configuration_framework_is_not_skipped(
        self, tmp_path, vcs_fw
    ):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out", frameworks=[vcs_fw])

        frameworks = _flag_values(scanner.args.extra_args, "--framework")
        skipped = _flag_values(scanner.args.extra_args, "--skip-framework")

        assert frameworks == [vcs_fw]
        assert vcs_fw not in skipped

    def test_external_config_file_framework_all_still_skips_vcs_configs(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        config_file = tmp_path / "operator" / ".checkov.yaml"
        config_file.parent.mkdir()
        config_file.write_text("framework:\n  - all\n", encoding="utf-8")

        scanner = _scanner(source, tmp_path / "out", config_file=str(config_file))
        skipped = _flag_values(scanner.args.extra_args, "--skip-framework")

        for vcs_fw in _VCS_CONFIGURATION_FRAMEWORKS:
            assert vcs_fw in skipped

    def test_external_config_file_explicit_vcs_framework_is_not_skipped(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        config_file = tmp_path / "operator" / ".checkov.yaml"
        config_file.parent.mkdir()
        config_file.write_text(
            "framework:\n  - gitlab_configuration\n", encoding="utf-8"
        )

        scanner = _scanner(source, tmp_path / "out", config_file=str(config_file))
        frameworks = _flag_values(scanner.args.extra_args, "--framework")
        skipped = _flag_values(scanner.args.extra_args, "--skip-framework")

        assert frameworks == ["gitlab_configuration"]
        assert "gitlab_configuration" not in skipped


class TestVcsConfDirEnvironment:
    def test_execute_scan_points_vcs_conf_dirs_inside_results_dir(
        self, tmp_path, monkeypatch
    ):
        for var_name, _ in _VCS_CONF_DIR_ENV_VARS:
            monkeypatch.delenv(var_name, raising=False)

        source = tmp_path / "src"
        source.mkdir()
        (source / ".gitlab-ci.yml").write_text("stages: [test]\n", encoding="utf-8")
        output = tmp_path / "out"
        scanner = _scanner(source, output)

        _, results_file, env = scanner._execute_scan(source, "source", [])
        expected_parent = Path(os.path.abspath(results_file.parent))

        assert env is not None
        for var_name, conf_subdir in _VCS_CONF_DIR_ENV_VARS:
            configured = Path(env[var_name])
            assert configured.is_absolute()
            assert configured == expected_parent / conf_subdir
            assert source not in configured.parents
            assert var_name not in os.environ

    def test_execute_scan_preserves_operator_vcs_conf_dir_env_var(
        self, tmp_path, monkeypatch
    ):
        custom_dir = str(tmp_path / "custom-gitlab-conf")
        monkeypatch.setenv("CKV_GITLAB_CONF_DIR_NAME", custom_dir)

        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out")

        _, _, env = scanner._execute_scan(source, "source", [])
        assert env is not None
        assert env["CKV_GITLAB_CONF_DIR_NAME"] == custom_dir

    def test_offline_scan_disables_vcs_config_fetch(self, tmp_path, monkeypatch):
        for fetch_var in _VCS_CONFIG_FETCH_ENV_VARS:
            monkeypatch.delenv(fetch_var, raising=False)

        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(
            source, tmp_path / "out", frameworks=["gitlab_configuration"], offline=True
        )

        _, _, env = scanner._execute_scan(source, "source", [])
        assert env is not None
        for fetch_var in _VCS_CONFIG_FETCH_ENV_VARS:
            assert env[fetch_var] == "False"

    def test_online_scan_does_not_force_vcs_config_fetch_off(
        self, tmp_path, monkeypatch
    ):
        for fetch_var in _VCS_CONFIG_FETCH_ENV_VARS:
            monkeypatch.delenv(fetch_var, raising=False)

        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(
            source, tmp_path / "out", frameworks=["gitlab_configuration"], offline=False
        )

        with patch.object(CheckovScanner, "_scanner_offline", return_value=False):
            _, _, env = scanner._execute_scan(source, "source", [])
        assert env is not None
        for fetch_var in _VCS_CONFIG_FETCH_ENV_VARS:
            assert fetch_var not in env

    def test_scan_in_gitlab_ci_env_passes_skip_framework_and_conf_dir(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")
        monkeypatch.setenv("CI_JOB_TOKEN", "job-token")
        monkeypatch.setenv("CI_PROJECT_ID", "42")
        monkeypatch.delenv("CKV_GITLAB_CONF_DIR_NAME", raising=False)

        source = tmp_path / "src"
        source.mkdir()
        (source / ".gitlab-ci.yml").write_text("stages: [test]\n", encoding="utf-8")
        scanner = _scanner(source, tmp_path / "out")
        results_file = scanner.results_dir / "source" / "results_sarif.sarif"
        captured: dict = {}

        def fake_subprocess(*args, **kwargs):
            captured["command"] = kwargs["command"]
            captured["env"] = kwargs["env"]
            captured["cwd"] = kwargs["cwd"]
            results_file.parent.mkdir(parents=True, exist_ok=True)
            results_file.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {"tool": {"driver": {"name": "checkov"}}, "results": []}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            return {"returncode": 0, "stdout": "", "stderr": ""}

        with (
            patch.object(scanner, "validate_plugin_dependencies", return_value=True),
            patch.object(scanner, "_run_subprocess", side_effect=fake_subprocess),
        ):
            scanner.dependencies_satisfied = True
            report = scanner.scan(source, target_type="source")

        assert report is not None
        cmd = captured["command"]
        skipped = [
            cmd[i + 1] for i, tok in enumerate(cmd[:-1]) if tok == "--skip-framework"
        ]
        for vcs_fw in _VCS_CONFIGURATION_FRAMEWORKS:
            assert vcs_fw in skipped
        assert Path(captured["env"]["CKV_GITLAB_CONF_DIR_NAME"]) == (
            Path(os.path.abspath(results_file.parent)) / "gitlab_conf"
        )
