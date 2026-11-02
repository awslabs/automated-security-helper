# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""validate_config_path admits every config format the loader reads.

The config loader discovers ``.ashrc.toml``, ``ashrc.toml`` and a
``pyproject.toml`` with a ``[tool.ash]`` table, and a workspace scan hands each
project's discovered source to ``register_scan`` as its ``config_path``.
``validate_config_path`` then checked the suffix against YAML and JSON only, so
a project configured by TOML was refused as an invalid extension and the whole
scan failed before it started.
"""

import pytest

from automated_security_helper.core.resource_management.error_handling import (
    validate_config_path,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("name", [".ashrc.toml", "ashrc.toml", "pyproject.toml"])
def test_a_toml_config_source_is_admitted(tmp_path, name):
    config = tmp_path / name
    config.write_text("[tool.ash]\n", encoding="utf-8")

    assert validate_config_path(config) is None


def test_an_unknown_extension_is_still_refused(tmp_path):
    config = tmp_path / "ash.ini"
    config.write_text("[ash]\n", encoding="utf-8")

    error = validate_config_path(config)

    assert error is not None
    assert ".toml" in error.context["valid_extensions"]


def test_register_scan_accepts_a_project_configured_by_pyproject(tmp_path):
    """The end-to-end shape of the refusal: registration, not validation alone."""
    project = tmp_path / "proj"
    project.mkdir()
    config = project / "pyproject.toml"
    config.write_text('[tool.ash]\nproject_name = "proj"\n', encoding="utf-8")

    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project),
        output_directory=str(project / ".ash" / "ash_output"),
        config_path=str(config),
    )

    assert scan_id
    # The path is kept, not admitted by dropping it: a registration that
    # cleared config_path would silently ignore the project's [tool.ash] table.
    assert registry.get_scan(scan_id).config_path == str(config)
