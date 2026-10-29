# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal of an ASH_CONFIG file that does not parse carries no parser error.

The parser's own words can quote the file, and the text an error shows walks
``__context__`` without looking at ``__suppress_context__``, so a refusal
raised inside the handler that caught the parser's error would show that error
again. The refusal is raised after the handler has ended. A load arm that
neither returns nor raises is a defect that fails loudly, never a silent
fall-through to the defaults.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import default_config
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

UNPARSED = "project_name: [unclosed\n"


def _refusal_of(call):
    with pytest.raises(ASHConfigValidationError) as info:
        call()
    return info.value


def test_the_default_config_s_parse_refusal_has_no_exception_context(
    tmp_path, monkeypatch
):
    config = tmp_path / "unparsed.yaml"
    config.write_text(UNPARSED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    refused = _refusal_of(default_config.get_default_config)

    assert "could not be parsed" in str(refused), str(refused)
    assert refused.__context__ is None, repr(refused.__context__)
    assert refused.__cause__ is None, repr(refused.__cause__)
    assert refused.ash_config_file == config


def test_the_tree_pre_check_s_parse_refusal_has_no_exception_context(
    tmp_path, monkeypatch
):
    config = tmp_path / "unparsed.yaml"
    config.write_text(UNPARSED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    refused = _refusal_of(
        lambda: default_config.default_config_document_for_tree(tmp_path)
    )

    assert "could not be parsed" in str(refused), str(refused)
    assert refused.__context__ is None, repr(refused.__context__)
    assert refused.__cause__ is None, repr(refused.__cause__)


def test_an_unreadable_file_is_still_refused_from_its_os_error(tmp_path, monkeypatch):
    """The must-not twin: only the parse arm drops its cause. A file that
    cannot be read keeps the OSError as the cause, so the MCP answer's
    category says it could not be read."""
    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "gone.yaml"))
    config = tmp_path / "gone.yaml"
    config.write_text("project_name: ok\n", encoding="utf-8")

    def unreadable():
        raise PermissionError(13, "planted: denied")

    refused = _refusal_of(
        lambda: default_config._load_as_the_ash_config_files(
            config, str(config), unreadable
        )
    )

    assert "could not read" in str(refused), str(refused)
    assert isinstance(refused.__cause__, PermissionError), repr(refused.__cause__)


def test_a_parse_arm_that_yields_no_reason_fails_loudly(tmp_path, monkeypatch):
    """A reason that comes back empty must not let the load fall through to a
    caller that would go on with the defaults."""
    from automated_security_helper.config import config_sources

    config = tmp_path / "unparsed.yaml"
    config.write_text(UNPARSED, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    monkeypatch.setattr(config_sources, "unparsed_config_reason", lambda *a: None)

    with pytest.raises(AssertionError, match="neither returned nor raised"):
        default_config.get_default_config()
