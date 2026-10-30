# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``confine_operator_only_options`` without a repository record settles nothing.

``repository`` is what the repository's files wrote for the operator-only
options. Without it nothing was recorded, so no option is known to be the
repository's: the configuration keeps the values it has, and nothing is
reported as taking the trusted base's.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    confine_operator_only_options,
)

pytestmark = pytest.mark.unit

OPTION = ("scanners", "detect-secrets", "max_worker_output_mib")


def _config_with_limit(limit: int) -> AshConfig:
    return AshConfig.model_validate(
        {"scanners": {"detect-secrets": {"options": {"max_worker_output_mib": limit}}}}
    )


def _settle(config: AshConfig, repository):
    return confine_operator_only_options(
        config,
        AshConfig(),
        [],
        [],
        repository=repository,
        checkout_membership=False,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )


def test_no_repository_record_leaves_the_scanner_limit_as_it_is():
    config = _config_with_limit(1024)

    settled = _settle(config, None)

    assert settled == set()
    assert config.scanners.detect_secrets.options.max_worker_output_mib == 1024


def test_a_repository_record_of_the_limit_settles_it_to_the_trusted_base():
    """The control: a file of the repository wrote the limit, so it takes the
    trusted base's value, 256."""
    config = _config_with_limit(1024)
    repository = RepositorySettings(trees=[])
    repository.found.append(
        ("scanners", "detect-secrets", "detect-secrets", "max_worker_output_mib", 1024)
    )

    settled = _settle(config, repository)

    assert settled == {OPTION}
    assert config.scanners.detect_secrets.options.max_worker_output_mib == 256
