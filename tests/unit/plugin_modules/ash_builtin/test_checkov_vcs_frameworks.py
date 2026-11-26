# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The VCS server-configuration framework floor and its environment variables.

These are unit pins of what ASH computes from the floor (the three frameworks
measured at checkov 3.4.5). They do not read checkov, so they cannot see
checkov drift: the integration test
(tests/integration/scanners/test_checkov_real_config_and_paths.py) compares the
installed checkov's registry with the mirror and the floor.
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
)

pytestmark = pytest.mark.unit


class TestVcsConfigurationFrameworkFloor:
    def test_floor_is_the_three_measured_frameworks_sorted(self):
        assert KNOWN_VCS_CONFIGURATION_FRAMEWORKS == (
            "bitbucket_configuration",
            "github_configuration",
            "gitlab_configuration",
        )

    def test_every_floor_member_is_in_the_mirror(self):
        # Fails when an edit drops a floor name from the typing mirror.
        assert set(KNOWN_VCS_CONFIGURATION_FRAMEWORKS) <= set(get_args(CheckFrameworks))

    def test_env_var_helpers_apply_the_measured_pattern_to_the_floor(self):
        # The pattern read at checkov 3.4.5: gitlab/dal.py:18 and :67,
        # github/dal.py:24 and :225, bitbucket/dal.py:18 and :77.
        conf_dirs = dict(vcs_conf_dir_env_vars(KNOWN_VCS_CONFIGURATION_FRAMEWORKS))
        assert conf_dirs == {
            "CKV_BITBUCKET_CONF_DIR_NAME": "bitbucket_conf",
            "CKV_GITHUB_CONF_DIR_NAME": "github_conf",
            "CKV_GITLAB_CONF_DIR_NAME": "gitlab_conf",
        }
        assert vcs_config_fetch_env_vars(KNOWN_VCS_CONFIGURATION_FRAMEWORKS) == (
            "CKV_BITBUCKET_CONFIG_FETCH_DATA",
            "CKV_GITHUB_CONFIG_FETCH_DATA",
            "CKV_GITLAB_CONFIG_FETCH_DATA",
        )
