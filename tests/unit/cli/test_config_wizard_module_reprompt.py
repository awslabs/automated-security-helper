# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The wizard asks again for a module a scan refuses, as it is typed.

Why this file exists
--------------------
The wizard checked the plugin modules once, after every prompt was answered, and
a module outside ASH's plugin namespace then ended the command with exit 3 and
threw every answer away. A typed module is now judged when it is typed: a refused
one is named, not added, and the prompt comes again; a module inside the
namespace that no installed package provides yet is added, as it always was.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import _typed_module_refusal, config_app
from tests.utils.wizard_script import script_wizard

pytestmark = pytest.mark.unit


def test_a_refused_module_in_the_middle_does_not_end_the_session(tmp_path, monkeypatch):
    """Red at the base: the bad entry was kept until the end, then exit 3 and no
    file. The answers after it were typed for nothing."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    script_wizard(
        monkeypatch,
        ["demo", "no_such_plugin_module_zz", "automated_security_helper.fake_ok", ""],
    )
    target = tmp_path / "new.yaml"

    result = CliRunner().invoke(config_app, ["wizard", "--config", str(target)])

    assert result.exit_code == 0, result.output
    text = target.read_text(encoding="utf-8")
    assert "no_such_plugin_module_zz" not in text
    assert "automated_security_helper.fake_ok" in text


def test_a_module_outside_the_namespace_is_refused_and_one_inside_is_not():
    assert _typed_module_refusal("no_such_plugin_module_zz") is not None
    assert _typed_module_refusal("automated_security_helper.fake_ok") is None
