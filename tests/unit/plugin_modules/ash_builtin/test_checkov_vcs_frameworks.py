# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Drift gates for the derived checkov VCS server-configuration framework set.

checkov_vcs_frameworks derives the set from the ``CheckFrameworks`` mirror by
checkov's naming rule for its VCS configuration runners instead of hardcoding
the vendors. These gates make drift loud: a derivation that stops covering the
measured floor, a derived member outside the structural rule, or an environment
variable that stops matching the pattern checkov's VCS DALs read fails here,
and a planted new ``*_configuration`` framework must be covered automatically.
The companion integration gate
(tests/integration/scanners/test_checkov_real_config_and_paths.py) checks the
mirror itself against the installed checkov's registry.
"""

from typing import get_args

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckFrameworks,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_vcs_frameworks import (
    KNOWN_VCS_CONFIGURATION_FRAMEWORKS,
    vcs_conf_dir_env_vars,
    vcs_config_fetch_env_vars,
    vcs_configuration_frameworks,
)

pytestmark = pytest.mark.unit

_DERIVED = vcs_configuration_frameworks(get_args(CheckFrameworks))


class TestVcsConfigurationFrameworkDerivation:
    def test_derived_set_covers_measured_floor(self):
        assert set(_DERIVED) >= {
            "github_configuration",
            "gitlab_configuration",
            "bitbucket_configuration",
        }

    def test_every_derived_member_matches_structural_rule(self):
        mirror = set(get_args(CheckFrameworks))
        for framework in _DERIVED:
            assert framework.endswith("_configuration")
            # A non-empty vendor name precedes the suffix.
            assert framework.removesuffix("_configuration")
            assert framework in mirror

    def test_env_var_derivation_matches_checkov_measured_pattern(self):
        # Measured at checkov 3.4.5: gitlab/dal.py:18 and :67,
        # github/dal.py:24 and :225, bitbucket/dal.py:18 and :77.
        conf_dirs = dict(vcs_conf_dir_env_vars(_DERIVED))
        assert conf_dirs["CKV_GITLAB_CONF_DIR_NAME"] == "gitlab_conf"
        assert conf_dirs["CKV_GITHUB_CONF_DIR_NAME"] == "github_conf"
        assert conf_dirs["CKV_BITBUCKET_CONF_DIR_NAME"] == "bitbucket_conf"
        assert set(vcs_config_fetch_env_vars(_DERIVED)) >= {
            "CKV_GITLAB_CONFIG_FETCH_DATA",
            "CKV_GITHUB_CONFIG_FETCH_DATA",
            "CKV_BITBUCKET_CONFIG_FETCH_DATA",
        }
        # One cache-directory tuple and one fetch toggle per framework.
        assert len(vcs_conf_dir_env_vars(_DERIVED)) == len(_DERIVED)
        assert len(vcs_config_fetch_env_vars(_DERIVED)) == len(_DERIVED)

    def test_new_configuration_framework_is_auto_covered(self):
        derived = vcs_configuration_frameworks(
            ["all", "terraform", "gitea_configuration"]
        )
        assert "gitea_configuration" in derived
        assert ("CKV_GITEA_CONF_DIR_NAME", "gitea_conf") in vcs_conf_dir_env_vars(
            derived
        )
        assert "CKV_GITEA_CONFIG_FETCH_DATA" in vcs_config_fetch_env_vars(derived)
        assert set(derived) >= set(KNOWN_VCS_CONFIGURATION_FRAMEWORKS)

    def test_non_matching_names_are_not_vcs_configuration_frameworks(self):
        derived = vcs_configuration_frameworks(
            ["_configuration", "gitlab_ci", "github_actions", "terraform", "all"]
        )
        assert set(derived) == set(KNOWN_VCS_CONFIGURATION_FRAMEWORKS)

    def test_empty_framework_list_falls_back_to_measured_floor(self):
        assert vcs_configuration_frameworks([]) == tuple(
            sorted(KNOWN_VCS_CONFIGURATION_FRAMEWORKS)
        )
