# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trivy scanners read a flagged run and an empty target through the base.

``ScannerPluginBase`` owns ``_refuse_flagged_response`` and
``_target_is_empty``. The shared trivy base kept a copy of the first, which read
the plugin's values hook bare, and ``trivy-repo`` (which overrides ``scan()``)
kept a copy of the second as a module-level function. The shared copy is the one
both trivy scanners resolved to, the builtin ``trivy`` scanner's template
``scan()`` included: a timed-out run reported the hook's exception when the hook
raised, where the base method reports the timeout. With the copies removed, both
scanners resolve to the base.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)

pytestmark = pytest.mark.unit

TRIVY_VARIABLES = (
    "TRIVY_CONFIG",
    "TRIVY_IGNOREFILE",
    "TRIVY_SECRET_CONFIG",
    "TRIVY_SCANNERS",
    "TRIVY_CACHE_DIR",
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for name in TRIVY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


def _context(tmp_path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    return context


@pytest.fixture(params=["trivy", "trivy-repo"])
def scanner(request, tmp_path):
    if request.param == "trivy":
        return TrivyScanner(
            context=_context(tmp_path),
            config=TrivyScannerConfig(options=TrivyScannerConfigOptions(offline=False)),
        )
    return TrivyRepoScanner(
        context=_context(tmp_path),
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(ignore_unfixed=False)
        ),
    )


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke on HOOKCANARY-33")


def test_a_timed_out_run_still_says_timed_out_when_the_values_hook_raises(scanner):
    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response({"timed_out": True}, 5)

    message = str(excinfo.value)
    assert f"{type(scanner).__name__} timed out" in message, message
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


def test_the_trivy_repo_module_has_no_copy_of_the_base_empty_target_probe(tmp_path):
    scanner = TrivyRepoScanner(
        context=_context(tmp_path),
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(ignore_unfixed=False)
        ),
    )

    assert not hasattr(trivy_repo_scanner, "_target_is_empty")
    assert type(scanner)._target_is_empty is ScannerPluginBase._target_is_empty
