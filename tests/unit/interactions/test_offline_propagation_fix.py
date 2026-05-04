# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test: --offline must set ASH_OFFLINE env var in local mode.

When ``run_ash_scan(offline=True)`` is called in local mode, the function
must write ``os.environ["ASH_OFFLINE"] = "YES"`` before the orchestrator
is created so that downstream components (e.g. Grype, Semgrep) see it.
"""

import os
import pytest
from unittest.mock import patch, MagicMock


@pytest.mark.unit
def test_offline_flag_sets_env_var(tmp_path):
    """When offline=True, ASH_OFFLINE must be set before the orchestrator runs."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()

    captured_env = {}

    # Build a mock orchestrator whose __init__ records the env state
    class FakeOrchestrator:
        def __init__(self, **kwargs):
            captured_env["ASH_OFFLINE"] = os.environ.get("ASH_OFFLINE")
            self.config = MagicMock()
            self.config.fail_on_findings = False

        def execute_scan(self, phases=None):
            return MagicMock(
                runs=[],
                model_dump_json=MagicMock(return_value="{}"),
            )

    # Patch at the *source* module because run_ash_scan imports lazily inside
    # the function body via ``from automated_security_helper.core.orchestrator
    # import ASHScanOrchestrator``.
    with (
        patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator",
            FakeOrchestrator,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[],
        ),
    ):
        # Clear any pre-existing value
        old = os.environ.pop("ASH_OFFLINE", None)
        try:
            from automated_security_helper.interactions.run_ash_scan import run_ash_scan

            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                offline=True,
                fail_on_findings=False,
                show_summary=False,
            )
        except SystemExit:
            pass  # run_ash_scan may call sys.exit; that's fine for this test
        finally:
            # Restore previous env state
            if old is not None:
                os.environ["ASH_OFFLINE"] = old
            else:
                os.environ.pop("ASH_OFFLINE", None)

    assert captured_env.get("ASH_OFFLINE") == "YES", (
        "ASH_OFFLINE was not set to 'YES' when offline=True"
    )


@pytest.mark.unit
def test_offline_false_does_not_set_env_var(tmp_path):
    """When offline=False (default), ASH_OFFLINE must NOT be forced to YES."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()

    captured_env = {}

    class FakeOrchestrator:
        def __init__(self, **kwargs):
            captured_env["ASH_OFFLINE"] = os.environ.get("ASH_OFFLINE")
            self.config = MagicMock()
            self.config.fail_on_findings = False

        def execute_scan(self, phases=None):
            return MagicMock(
                runs=[],
                model_dump_json=MagicMock(return_value="{}"),
            )

    with (
        patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator",
            FakeOrchestrator,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics",
            return_value=[],
        ),
    ):
        old = os.environ.pop("ASH_OFFLINE", None)
        try:
            from automated_security_helper.interactions.run_ash_scan import run_ash_scan

            run_ash_scan(
                source_dir=str(source),
                output_dir=str(output),
                offline=False,
                fail_on_findings=False,
                show_summary=False,
            )
        except SystemExit:
            pass
        finally:
            if old is not None:
                os.environ["ASH_OFFLINE"] = old
            else:
                os.environ.pop("ASH_OFFLINE", None)

    assert captured_env.get("ASH_OFFLINE") is None, (
        "ASH_OFFLINE should not be set when offline=False"
    )
