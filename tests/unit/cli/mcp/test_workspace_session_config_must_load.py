# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan's session config that does not load is a config error (exit 3).

``_gate_client_overrides`` reads the session's config to check a client's
``config_overrides`` against its runtime-override allowlist. A session config that
did not parse raised the YAML parser's own error, which the workspace tools map to
exit 1, an internal error. It is the operator's config that is broken, so it is
reported the way a scan reports it: ``ASHConfigValidationError``, exit 3.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp.workspace import (
    _exit_code_for,
    _gate_client_overrides,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("global_settings:\n  suppressions: [unclosed\n", id="yaml_syntax"),
        pytest.param(b"project_name: x\n# \xff\xfe\n", id="not_utf8"),
    ],
)
def test_a_session_config_that_does_not_load_is_a_config_error(tmp_path, content):
    profile = tmp_path / "profile.yaml"
    if isinstance(content, bytes):
        profile.write_bytes(content)
    else:
        profile.write_text(content, encoding="utf-8")

    with pytest.raises(ASHConfigValidationError, match="profile.yaml") as excinfo:
        _gate_client_overrides(["project_name=x"], str(profile))

    assert _exit_code_for(excinfo.value) == 3
