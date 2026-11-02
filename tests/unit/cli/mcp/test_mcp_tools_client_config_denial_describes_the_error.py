# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pre-scan config check that cannot finish describes its error, never quoting the input.

``_client_config_denial`` put the raw text of the exception into its response
and its log line: for the rules that could not be read, and for a check that
raised. A pydantic validation error's own text quotes the refused input, which
can be a value of the operator's or the client's config, and the response goes
to a remote client. Both arms now use the described error, as
``create_error_response`` does.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.config import client_config_policy
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

REMOTE = "client-1"
CONFIG = "project_name: x\nfail_on_findings: false\n"
QUOTED_INPUT = "value-the-error-quotes-verbatim"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "scan-root"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()
    # The uploads below record a delivered source for the session id, and the
    # record is process-wide: left behind, a later module that assumes the same
    # session delivered nothing reads this test's tree as its own.
    from automated_security_helper.cli.mcp.source_delivery import (
        _drop_session_source_dir,
    )

    _drop_session_source_dir(REMOTE)


def _upload(files: Dict[str, str]) -> Path:
    from automated_security_helper.cli.mcp.source_delivery import (
        set_source_zip_chunk,
        set_source_zip_finalize,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    data = buffer.getvalue()
    set_source_zip_chunk(
        "u1", 0, base64.b64encode(data).decode("ascii"), True, session_id=REMOTE
    )
    return set_source_zip_finalize(
        "u1", hashlib.sha256(data).hexdigest(), session_id=REMOTE
    )


class _ConfigThatQuotesItsInput(BaseModel):
    """A config-shaped model whose validation errors quote the input.

    AshConfig hides inputs in its own errors (``hide_input_in_errors``), so an
    error built from it carries no token for the denial to strip, and the
    stand-in's own precondition below fails before the arm under test is
    reached. This model keeps pydantic's default, which quotes the refused
    value as ``input_value=...``, so the control holds.
    """

    global_settings: Dict[str, Any]


def _a_validation_error_quoting(value: str) -> ValidationError:
    try:
        _ConfigThatQuotesItsInput.model_validate({"global_settings": value})
    except ValidationError as exc:
        assert value in str(exc), "the stand-in error does not quote its input"
        return exc
    raise AssertionError("the stand-in model accepted a string for global_settings")


def test_a_check_that_raises_describes_the_error(monkeypatch, caplog) -> None:
    error = _a_validation_error_quoting(QUOTED_INPUT)
    source = _upload({"ash.yaml": CONFIG})

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(client_config_policy, "apply_client_config_rules", broken)

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        response = mcp_tools._client_config_denial(
            str(source / "ash.yaml"), source, REMOTE, "scan_directory"
        )

    assert response is not None and response["success"] is False, response
    assert response["error_type"] == "scan_start_failure", response
    # The described error names the model it refused ("1 validation error for
    # <title>"), not the exception's class name: the stand-in's own title is
    # the proof that the arm described this error and no other.
    assert "validation error for _ConfigThatQuotesItsInput" in response["error"], (
        response
    )
    assert QUOTED_INPUT not in response["error"], response
    # The log line the module docstring names: described, never quoting. The
    # logger does not propagate to the root handler caplog installs, so the
    # capture names it, and the line is asserted to be there: an absence read
    # from a log that captured nothing proves nothing.
    assert "Config policy check failed before the scan" in caplog.text, caplog.text
    assert QUOTED_INPUT not in caplog.text, caplog.text


def test_rules_that_cannot_be_read_describe_the_error(monkeypatch, caplog) -> None:
    error = _a_validation_error_quoting(QUOTED_INPUT)
    source = _upload({"ash.yaml": CONFIG})

    # Whatever the call's shape: a stub that took one positional argument raised
    # its own TypeError when the caller passed two, and the response then
    # described that error, without the quoted input, so the test passed
    # without reaching the arm it exists for.
    def unreadable(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(mcp_tools, "_session_client_rules", unreadable)

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        response = mcp_tools._client_config_denial(
            str(source / "ash.yaml"), source, REMOTE, "scan_directory"
        )

    assert response is not None and response["success"] is False, response
    assert response["error_type"] == mcp_tools.CONFIG_POLICY_UNREADABLE, response
    # The arm was reached: the error it describes is the stand-in's own kind.
    # The described error names the model it refused ("1 validation error for
    # <title>"), not the exception's class name: the stand-in's own title is
    # the proof that the arm described this error and no other.
    assert "validation error for _ConfigThatQuotesItsInput" in response["error"], (
        response
    )
    assert QUOTED_INPUT not in response["error"], response
    assert "Session config rules not read before the scan" in caplog.text, caplog.text
    assert QUOTED_INPUT not in caplog.text, caplog.text
