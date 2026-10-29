# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bandit is graded against the global severity threshold unless its config sets one.

``ScannerOptionsBase.severity_threshold`` is None by default, and None means
"follow ``global_settings.severity_threshold``": the executor grades each target
with ``resolve_scanner_threshold(options.severity_threshold, config)``, and the
summary, the scanner row and the exit code read the same helper. Bandit's options
class declared the field again, as a str with the default ``"ALL"``, so bandit was
always graded at ALL and the global threshold was ignored for it: a repository
whose only bandit findings were LOW failed the scan under the default MEDIUM.

The bandit command line does not depend on the field. ASH passes ``--severity-level
all`` to bandit itself and applies the threshold to what bandit reports, so the
last test pins that the argument stays ``all`` whatever the threshold is.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.utils.severity_ladder import resolve_scanner_threshold

AshConfig.model_rebuild()

LADDER = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _config(global_threshold: str, bandit_threshold: str | None = None) -> AshConfig:
    sections: dict = {"global_settings": {"severity_threshold": global_threshold}}
    if bandit_threshold is not None:
        sections["scanners"] = {
            "bandit": {"options": {"severity_threshold": bandit_threshold}}
        }
    return AshConfig.model_validate({"project_name": "zz-bandit-threshold", **sections})


def _summary_threshold(config: AshConfig) -> tuple:
    """The (threshold, source) the summary and the exit code use for bandit."""
    model = SimpleNamespace(ash_config=config)
    return ScannerStatisticsCalculator.get_scanner_threshold_info(model, "bandit")


def test_bandit_options_carry_no_threshold_of_their_own() -> None:
    assert BanditScannerConfigOptions().severity_threshold is None
    assert BanditScannerConfig().options.severity_threshold is None


@pytest.mark.parametrize("global_threshold", LADDER)
def test_the_executors_threshold_for_bandit_is_the_global_one(
    global_threshold: str,
) -> None:
    """ScannerExecutor passes the scanner config's own option to the resolver."""
    config = _config(global_threshold)
    own = BanditScannerConfig().options.severity_threshold

    assert resolve_scanner_threshold(own, config) == (global_threshold, "global")


@pytest.mark.parametrize("global_threshold", LADDER)
def test_the_summary_threshold_for_bandit_is_the_global_one(
    global_threshold: str,
) -> None:
    assert _summary_threshold(_config(global_threshold)) == (
        global_threshold,
        "global",
    )


@pytest.mark.parametrize(
    "own, global_threshold",
    [("LOW", "HIGH"), ("HIGH", "LOW"), ("ALL", "MEDIUM"), ("MEDIUM", "ALL")],
)
def test_an_explicit_bandit_threshold_still_wins(
    own: str, global_threshold: str
) -> None:
    """Control: the fix removes a default, not the scanner-level override."""
    config = _config(global_threshold, own)
    configured = config.scanners.bandit.options.severity_threshold

    assert configured == own
    assert resolve_scanner_threshold(configured, config) == (own, "config")
    assert _summary_threshold(config) == (own, "config")


@pytest.mark.usefixtures("no_tool_probes")
@pytest.mark.parametrize("own", [None, "ALL", "HIGH"])
def test_the_bandit_argument_stays_all_whatever_the_threshold(
    tmp_path, own: str | None
) -> None:
    """Control: bandit is asked for every severity; the gate is applied afterwards."""
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)

    # No keyword for the unset case: it must build before the fix too, where None
    # is not a value of the field.
    options = BanditScannerConfigOptions(
        **({} if own is None else {"severity_threshold": own})
    )
    scanner = BanditScanner(
        context=context, config=BanditScannerConfig(options=options)
    )

    values = [
        arg.value for arg in scanner.args.extra_args if arg.key == "--severity-level"
    ]
    assert values == ["all"]
