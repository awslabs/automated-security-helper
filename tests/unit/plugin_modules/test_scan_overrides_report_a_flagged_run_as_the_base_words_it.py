# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan()`` of syft and trivy-repo reports a flagged run as the base words it.

``ScannerPluginBase._refuse_flagged_response`` raises for a run the subprocess
layer flagged (timed out, could not start), and shapes its text through the one
guarded read of the plugin's values hook, so a hook that raises cannot replace
the timeout as the error. Both scanners override ``scan()`` and call it inside a
catch-all. The catch-all built a second message from the refusal: syft's read
the hook bare, so a hook that raised replaced "timed out" with its own failure;
trivy-repo's read it guarded, but with no usable answer swapped the value-free
headline for the generic failed text. The tests that call the method directly
pass on both, so these call ``scan()``.

The hook here breaks only once the tool has run (the way a hook reading the
environment can), so nothing before the run depends on how a scanner treats a
hook that was never usable.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)

pytestmark = pytest.mark.unit

HOOK_CANARY = "HOOKCANARY-33"

TRIVY_VARIABLES = (
    "TRIVY_CONFIG",
    "TRIVY_IGNOREFILE",
    "TRIVY_SECRET_CONFIG",
    "TRIVY_SCANNERS",
    "TRIVY_CACHE_DIR",
)


@pytest.fixture(params=["syft", "trivy-repo"])
def scanner(request, tmp_path, monkeypatch):
    for variable in TRIVY_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    if request.param == "syft":
        monkeypatch.setenv("ASH_OFFLINE", "YES")
    else:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    if request.param == "syft":
        built = SyftScanner(
            context=context,
            config=SyftScannerConfig(options=SyftScannerConfigOptions()),
        )
    else:
        built = TrivyRepoScanner(
            context=context,
            config=TrivyRepoScannerConfig(
                options=TrivyRepoScannerConfigOptions(ignore_unfixed=False)
            ),
        )
    built.dependencies_satisfied = True
    built.end_time = None
    return built


def _scan(scanner, response: dict, *, values_hook: str):
    """``scan()`` on the source directory, the tool run answering ``response``.

    ``values_hook`` is ``works`` (the scanner's own hook) or ``breaks after the
    run`` (the hook answers until the tool has run, then raises).
    """
    ran: list[bool] = []
    real_hook = scanner._values_to_redact

    def run(command, **kwargs):
        ran.append(True)
        return response

    def hook(*_args, **_kwargs):
        if values_hook == "breaks after the run" and ran:
            raise RuntimeError(f"hook broke on {HOOK_CANARY}")
        return real_hook()

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
        patch.object(scanner, "_values_to_redact", side_effect=hook),
    ):
        return scanner.scan(
            target=Path(scanner.context.source_dir), target_type="source"
        )


@pytest.mark.parametrize("values_hook", ["works", "breaks after the run"])
@pytest.mark.parametrize(
    "response, words",
    [
        pytest.param(
            {"returncode": -9, "timed_out": True}, "timed out", id="timed-out"
        ),
        pytest.param(
            {"returncode": 127, "spawn_failed": True},
            "could not start its tool",
            id="could-not-start",
        ),
    ],
)
def test_a_flagged_run_is_reported_as_the_base_words_it(
    scanner, response, words, values_hook
):
    name = type(scanner).__name__

    with pytest.raises(ScannerError) as raised:
        _scan(scanner, response, values_hook=values_hook)

    message = str(raised.value)
    assert f"{name} {words}" in message, message
    assert "scan failed" not in message, message
    assert HOOK_CANARY not in message, message
    assert scanner.end_time is not None


def test_an_error_that_is_not_a_flagged_run_is_still_redacted_when_the_hook_raises(
    scanner,
):
    def broken_hook(*_args, **_kwargs):
        raise RuntimeError(f"hook broke on {HOOK_CANARY}")

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_values_to_redact", side_effect=broken_hook),
        patch.object(
            scanner,
            "_resolve_arguments",
            side_effect=RuntimeError("cannot read zz-secret-value here"),
        ),
    ):
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    message = str(raised.value)
    assert "scan failed" in message, message
    assert "values hook" in message, message
    assert "zz-secret-value" not in message, message
    assert HOOK_CANARY not in message, message
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert scanner.end_time is not None
