# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanners read a flagged run and an empty target through the base.

``ScannerPluginBase`` owns ``_refuse_flagged_response`` and
``_target_is_empty``. The scanners that override ``scan()`` (syft, ferret-scan,
snyk-code, trivy-repo) each kept a copy of both: a method that read the plugin's
values hook bare, and a module-level function. The shared trivy base kept a copy
of the method too, which the builtin ``trivy`` scanner's template ``scan()``
resolved to. A timed-out run reported the hook's exception when the hook raised,
where the base method reports the timeout. With the copies removed every one of
them resolves both to the base.

One module over the five scanner classes, where there were four near-identical
ones. What each scanner's ``scan()`` does with the refusal is in
``test_scan_overrides_report_a_flagged_run_as_the_base_words_it.py``.
"""

from __future__ import annotations

from contextlib import ExitStack
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import syft_scanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_ferret_plugins import ferret_scanner
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
    FerretScannerConfig,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
PluginContext.model_rebuild()

TRIVY_VARIABLES = (
    "TRIVY_CONFIG",
    "TRIVY_IGNOREFILE",
    "TRIVY_SECRET_CONFIG",
    "TRIVY_SCANNERS",
    "TRIVY_CACHE_DIR",
)

#: The scanners whose plugin runs through uv: their construction probes for it.
USES_UV = ("ferret-scan", "snyk-code")

#: The module of each scanner that overrode ``scan()`` and kept a module-level
#: copy of the empty-target probe. The builtin ``trivy`` scanner has none.
MODULES_THAT_KEPT_A_PROBE = {
    "syft": syft_scanner,
    "ferret-scan": ferret_scanner,
    "snyk-code": snyk_code_scanner,
    "trivy-repo": trivy_repo_scanner,
}


@pytest.fixture(params=["syft", "ferret-scan", "snyk-code", "trivy", "trivy-repo"])
def case(request, tmp_path, monkeypatch):
    """``(name, scanner)`` for one of the five scanner classes."""
    name = request.param
    for variable in TRIVY_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    if name == "syft":
        monkeypatch.setenv("ASH_OFFLINE", "YES")
    else:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
    stack = ExitStack()
    request.addfinalizer(stack.close)
    if name in USES_UV:
        stack.enter_context(
            patch.object(UVToolRunner, "is_uv_available", return_value=False)
        )
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    if name == "syft":
        scanner = SyftScanner(
            context=context,
            config=SyftScannerConfig(options=SyftScannerConfigOptions()),
        )
    elif name == "ferret-scan":
        scanner = FerretScanScanner(context=context, config=FerretScannerConfig())
    elif name == "snyk-code":
        scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    elif name == "trivy":
        scanner = TrivyScanner(
            context=context,
            config=TrivyScannerConfig(options=TrivyScannerConfigOptions(offline=False)),
        )
    else:
        scanner = TrivyRepoScanner(
            context=context,
            config=TrivyRepoScannerConfig(
                options=TrivyRepoScannerConfigOptions(ignore_unfixed=False)
            ),
        )
    return name, scanner


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke on HOOKCANARY-33")


def test_a_timed_out_run_still_says_timed_out_when_the_values_hook_raises(case):
    _name, scanner = case

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response({"timed_out": True}, 5)

    message = str(excinfo.value)
    assert f"{type(scanner).__name__} timed out" in message, message
    assert "HOOKCANARY" not in message, message


def test_a_recorded_failure_keeps_its_name_when_the_values_hook_raises(case):
    _name, scanner = case

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response(
                {"signaled": True, "error": "ended by SIGTERM"}, None
            )

    message = str(excinfo.value)
    assert "did not finish" in message, message
    assert "HOOKCANARY" not in message, message


def test_the_scanner_has_no_copy_of_the_base_flagged_run_method(case):
    _name, scanner = case

    assert (
        type(scanner)._refuse_flagged_response
        is ScannerPluginBase._refuse_flagged_response
    )


def test_the_scanner_has_no_copy_of_the_base_empty_target_probe(case):
    name, scanner = case

    module = MODULES_THAT_KEPT_A_PROBE.get(name)
    if module is not None:
        assert not hasattr(module, "_target_is_empty")
    assert type(scanner)._target_is_empty is ScannerPluginBase._target_is_empty
