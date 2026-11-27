"""The guard that stops a refused grep scanner from running files the refusal's code.

semgrep and opengrep record why they decline (``dependency_unavailable_reason``)
instead of raising at construction, and ``_execute_scan`` raises that reason again
if the scanner is dispatched anyway. Both guards filed every reason as
``offline_rule_cache_unusable``, though two of the places that set a reason are not
about the cache: the refusal of the configured rules, which runs online and
offline, and the copy of the tool found only inside the scanned tree. Each setter
now records its own code with its reason, and the guards file it.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import (
    DEFAULT_SENTENCES,
    ReasonCode,
    reason_of,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    opengrep_scanner as opengrep_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

SCANNERS = {
    "semgrep": (SemgrepScanner, SemgrepScannerConfig, SemgrepScannerConfigOptions),
    "opengrep": (
        OpengrepScanner,
        OpengrepScannerConfig,
        OpengrepScannerConfigOptions,
    ),
}
CACHE_ENV = {
    "semgrep": "SEMGREP_RULES_CACHE_DIR",
    "opengrep": "OPENGREP_RULES_CACHE_DIR",
}


def _context(base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    source = base / "source"
    source.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _scanner(name, tmp_path, monkeypatch, **options):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for variable in CACHE_ENV.values():
        monkeypatch.delenv(variable, raising=False)
    scanner_class, config_class, options_class = SCANNERS[name]
    scanner = scanner_class(
        context=_context(tmp_path),
        config=config_class(options=options_class(**options)),
    )
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / name
    return scanner


def _refusal(scanner, tmp_path):
    """What the scan-time guard raises for the reason construction recorded."""
    with pytest.raises(Exception) as raised:
        scanner._execute_scan(
            target=tmp_path / "source", target_type="source", global_ignore_paths=[]
        )
    return raised.value


def _code_of(error):
    reason = reason_of(error)
    assert reason is not None, f"{type(error).__name__} carries no reason"
    return reason.code


@pytest.mark.parametrize("name", ["semgrep", "opengrep"])
class TestEachSetterRecordsItsOwnCode:
    def test_an_offline_scan_with_no_rule_cache_keeps_the_cache_code(
        self, name, tmp_path, monkeypatch
    ):
        scanner = _scanner(name, tmp_path, monkeypatch, offline=True)

        assert scanner.dependency_unavailable_reason, "offline with no cache records"
        assert _code_of(_refusal(scanner, tmp_path)) == (
            ReasonCode.OFFLINE_RULE_CACHE_UNUSABLE
        )

    def test_an_offline_cache_inside_the_scanned_tree_keeps_the_cache_code(
        self, name, tmp_path, monkeypatch
    ):
        cache = tmp_path / "source" / "rules-cache"
        cache.mkdir(parents=True)
        (cache / "a.yaml").write_text("rules: []\n", encoding="utf-8")
        scanner = _scanner(name, tmp_path, monkeypatch, offline=True)
        monkeypatch.setenv(CACHE_ENV[name], str(cache))
        scanner._process_config_options()

        assert scanner.dependency_unavailable_reason
        assert _code_of(_refusal(scanner, tmp_path)) == (
            ReasonCode.OFFLINE_RULE_CACHE_UNUSABLE
        )

    @pytest.mark.parametrize("offline", [False, True])
    def test_configured_rules_that_do_not_exist_are_a_missing_file(
        self, name, offline, tmp_path, monkeypatch
    ):
        gone = tmp_path / "elsewhere" / "rules.yml"
        scanner = _scanner(
            name, tmp_path, monkeypatch, config=str(gone), offline=offline
        )

        assert scanner.dependency_unavailable_reason
        code = _code_of(_refusal(scanner, tmp_path))
        assert code == ReasonCode.CONFIG_FILE_MISSING, code
        assert code != ReasonCode.OFFLINE_RULE_CACHE_UNUSABLE

    @pytest.mark.parametrize("offline", [False, True])
    def test_configured_rules_inside_the_scanned_tree_are_a_refused_option(
        self, name, offline, tmp_path, monkeypatch
    ):
        (tmp_path / "source").mkdir(exist_ok=True)
        inside = tmp_path / "source" / "rules.yml"
        inside.write_text("rules: []\n", encoding="utf-8")
        scanner = _scanner(
            name, tmp_path, monkeypatch, config=str(inside), offline=offline
        )

        assert scanner.dependency_unavailable_reason
        code = _code_of(_refusal(scanner, tmp_path))
        assert code == ReasonCode.OPTION_REFUSED, code


class TestTheCopyOfTheToolInsideTheScannedTree:
    def test_opengrep_refuses_it_as_a_tool_it_cannot_use(self, tmp_path, monkeypatch):
        scanner = _scanner("opengrep", tmp_path, monkeypatch)
        monkeypatch.setattr(opengrep_module, "find_executable", lambda name: None)
        monkeypatch.setattr(
            opengrep_module,
            "in_tree_refusal",
            lambda name: "opengrep was found only inside the scanned tree",
        )

        assert scanner._validate_tool_dependencies() is False

        assert scanner.dependency_unavailable_reason == (
            "opengrep was found only inside the scanned tree"
        )
        code = _code_of(_refusal(scanner, tmp_path))
        assert code == ReasonCode.TOOL_NOT_USABLE, code
        assert code in DEFAULT_SENTENCES

    def test_the_guard_inside_the_rebuild_files_the_same_code(
        self, tmp_path, monkeypatch
    ):
        scanner = _scanner("opengrep", tmp_path, monkeypatch)
        scanner._metrics_decision_pending = True
        scanner._record_unavailable(
            "opengrep was found only inside the scanned tree",
            ReasonCode.TOOL_NOT_USABLE,
        )

        with (
            patch.object(scanner, "emit_metrics_flag", return_value=True),
            patch.object(scanner, "_process_config_options"),
            pytest.raises(Exception) as raised,
        ):
            scanner._resolve_scan_arguments(
                tmp_path / "source", tmp_path / "results.sarif"
            )

        assert _code_of(raised.value) == ReasonCode.TOOL_NOT_USABLE


class TestAReasonSomeoneElseSetsIsNotFiledUnderAnotherCode:
    def test_a_reason_set_with_no_code_is_a_failed_run_not_a_cache(
        self, tmp_path, monkeypatch
    ):
        scanner = _scanner("opengrep", tmp_path, monkeypatch)
        scanner._record_unavailable("its rules are refused", ReasonCode.OPTION_REFUSED)
        scanner.dependency_unavailable_reason = "a later writer's own reason"

        code = _code_of(_refusal(scanner, tmp_path))

        assert code == ReasonCode.RUN_FAILED, code

    def test_the_code_is_the_one_recorded_with_the_current_reason(
        self, tmp_path, monkeypatch
    ):
        scanner = _scanner("opengrep", tmp_path, monkeypatch)
        scanner._record_unavailable("first", ReasonCode.CONFIG_FILE_MISSING)
        scanner._record_unavailable("second", ReasonCode.OPTION_REFUSED)

        assert _code_of(_refusal(scanner, tmp_path)) == ReasonCode.OPTION_REFUSED
