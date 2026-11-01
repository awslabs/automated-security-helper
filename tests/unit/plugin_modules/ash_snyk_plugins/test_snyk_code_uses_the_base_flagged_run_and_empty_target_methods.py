# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk-code's ``scan()`` reads a flagged run and an empty target through the base.

``ScannerPluginBase`` owns ``_refuse_flagged_response`` and
``_target_is_empty``. ``SnykCodeScanner`` overrides ``scan()``, and it kept a
copy of each: a method that read the plugin's values hook bare, and a
module-level function. The copy of the method made a timed-out run report the
hook's exception when the hook raised, where the base method reports the
timeout. With the copies removed, the scanner's ``scan()`` resolves both to the
base.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
PluginContext.model_rebuild()


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


@pytest.fixture
def scanner(tmp_path) -> SnykCodeScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    return SnykCodeScanner(context=context, config=SnykCodeScannerConfig())


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke on HOOKCANARY-33")


def test_a_timed_out_run_still_says_timed_out_when_the_values_hook_raises(scanner):
    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response({"timed_out": True}, 5)

    message = str(excinfo.value)
    assert "SnykCodeScanner timed out" in message, message
    assert "HOOKCANARY" not in message, message


def test_a_recorded_failure_keeps_its_name_when_the_values_hook_raises(scanner):
    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response(
                {"signaled": True, "error": "ended by SIGTERM"}, None
            )

    message = str(excinfo.value)
    assert "did not finish" in message, message
    assert "HOOKCANARY" not in message, message


def test_the_scanner_has_no_copy_of_the_base_flagged_run_method(scanner):
    assert (
        type(scanner)._refuse_flagged_response
        is ScannerPluginBase._refuse_flagged_response
    )


def test_the_module_has_no_copy_of_the_base_empty_target_probe(scanner):
    assert not hasattr(snyk_code_scanner, "_target_is_empty")
    assert type(scanner)._target_is_empty is ScannerPluginBase._target_is_empty
