# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bounds and operator settings the shared trivy base reads, for trivy and trivy-repo.

Each test here pins one reading that went wrong before:

- ``trivy_timeout`` wrote a bound past what a Go duration holds, which trivy
  refuses as an invalid duration before scanning; the unbounded value is used.
- ``trivy_severity`` and ``_package_from_message`` split on ``str.splitlines``,
  which also breaks on characters a file name can hold, so tree-derived text in
  the ``Artifact:`` line could supply a ``Severity:`` or ``Package:`` line.
- the misconfiguration-scanner list read from ``trivy --help`` was cached by
  path alone, so a trivy upgraded in place kept the old release's names.
- the ``--skip-files`` / ``--skip-dirs`` tokens for ignored paths had no bound,
  so a large tree could keep trivy from starting (ARG_MAX).
- ASH's own skip flags replaced the operator's ``TRIVY_SKIP_DIRS`` /
  ``TRIVY_SKIP_FILES`` and config-file lists instead of adding to them.
- a ``--skip-dirs`` path holding a line break was passed as written, which
  trivy's CSV read cuts at the break.
- the operator's own skip entries, given back as flags, went through pflag's CSV
  reader unquoted: a ``"`` failed the run and a line break skipped another path.
- ``TRIVY_SEVERITY`` and the other filtering variables narrowed the report with
  nothing in the run saying so.
- the offline cache check judged only ``TRIVY_CACHE_DIR`` and warned about every
  offline scan whose default cache held a database.
- a missing secret-rules file failed a scan that never reads one.
- the offline Terraform-check removal ignored the operator's own
  misconfiguration-scanner list.
- the operator's list reached trivy as written: a list variable split on commas
  alone (trivy splits on whitespace too), and a name trivy does not know passed
  through, which makes trivy run every misconfiguration scanner.
- the builtin trivy scanner redacted neither ``TRIVY_IGNOREFILE`` nor
  ``TRIVY_SECRET_CONFIG``, which it reads from the environment.
- a trivy config file that is not UTF-8 raised out of the scanner-set read.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    _MAX_GO_DURATION_SECONDS,
    _SKIP_ARGS_BUDGET,
    _TRIVY_DEFAULT_SCANNERS,
    OUTPUT_RESTRICTING_TRIVY_ENV,
    UNBOUNDED_TRIVY_TIMEOUT,
    TrivyScannerBase,
    skip_dirs_value,
    trivy_default_misconfig_scanners,
    trivy_severity,
    trivy_timeout,
)
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
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG

pytestmark = pytest.mark.unit

TRIVY_VARIABLES = (
    "TRIVY_CONFIG",
    "TRIVY_IGNOREFILE",
    "TRIVY_SECRET_CONFIG",
    "TRIVY_SCANNERS",
    "TRIVY_CACHE_DIR",
    "TRIVY_SKIP_DIRS",
    "TRIVY_SKIP_FILES",
    "TRIVY_MISCONFIG_SCANNERS",
    *OUTPUT_RESTRICTING_TRIVY_ENV,
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    """No test here inherits a TRIVY_ setting or ASH_OFFLINE from the shell."""
    for name in TRIVY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    return context


def _repo_scanner(tmp_path: Path, **options) -> TrivyRepoScanner:
    options.setdefault("ignore_unfixed", False)
    return TrivyRepoScanner(
        context=_context(tmp_path),
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )


def _builtin_scanner(
    tmp_path: Path, *, operator: bool = False, **options
) -> TrivyScanner:
    """A builtin trivy scanner; ``operator=True`` records the config as the
    operator's own (built from no file in the scanned tree), which a setting the
    repository may not choose (``scanners``) needs to be kept: the scanner judges
    the provenance as it is constructed (``_honor_scanner_set``), so it is
    recorded before."""
    options.setdefault("offline", False)
    context = _context(tmp_path)
    if operator:
        record_provenance(context.config, in_tree=[])
    return TrivyScanner(
        context=context,
        config=TrivyScannerConfig(options=TrivyScannerConfigOptions(**options)),
    )


def _logged(scanner) -> tuple[list[str], object]:
    """A patch of the scanner's log that collects the messages."""
    messages: list[str] = []
    return messages, patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: messages.append(str(m))
    )


# --- the timeout bound -------------------------------------------------------------


def test_a_timeout_past_what_a_go_duration_holds_is_passed_as_unbounded():
    """trivy refuses more than 2**63 - 1 nanoseconds as an invalid duration, and
    exits 1 before it scans; 292 years is no deadline either way."""
    assert trivy_timeout(_MAX_GO_DURATION_SECONDS + 1) == UNBOUNDED_TRIVY_TIMEOUT
    assert trivy_timeout(float(2**63)) == UNBOUNDED_TRIVY_TIMEOUT


def test_control_a_bound_a_go_duration_holds_is_passed_in_seconds():
    assert trivy_timeout(_MAX_GO_DURATION_SECONDS) == f"{_MAX_GO_DURATION_SECONDS}s"
    assert trivy_timeout(90) == "90s"


# --- line splitting in trivy's messages --------------------------------------------


def _run(message: str, *, level: str = "note", tags=("LOW",)):
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Trivy",
                            "rules": [
                                {
                                    "id": "AVD-AWS-0001",
                                    "properties": {"tags": list(tags)},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "AVD-AWS-0001",
                            "ruleIndex": 0,
                            "level": level,
                            "message": {"text": message},
                        }
                    ],
                }
            ],
        }
    )
    run = report.runs[0]
    rules = run.tool.driver.rules or []
    return run.results[0], rules, {rule.id: rule for rule in rules}


@pytest.mark.parametrize("separator", [" ", "\x0c", "\x1c", "\x85"])
def test_a_severity_line_split_off_by_a_name_character_does_not_decide(separator):
    """A file name can hold a line separator, a form feed, a file separator or a
    next-line character; ``str.splitlines`` breaks on each, ``\\n`` alone does
    not. With no ``Severity:`` line of trivy's own, the rule's tag decides."""
    message = (
        f"Artifact: iac/evil{separator}Severity: CRITICAL.tf\n"
        "Type: terraform\nMisconfiguration AVD-AWS-0001\nMessage: Bucket has no logging"
    )

    assert trivy_severity(*_run(message)) == "LOW"


def test_control_trivys_own_severity_line_is_read():
    message = (
        "Artifact: iac/main.tf\nType: terraform\nMisconfiguration AVD-AWS-0001\n"
        "Severity: HIGH\nMessage: Bucket has no logging"
    )

    assert trivy_severity(*_run(message, level="error", tags=("HIGH",))) == "HIGH"


def test_a_package_line_inside_a_non_package_message_gives_no_package():
    """trivy writes ``Package:`` as the FIRST line of a vulnerability message; a
    misconfiguration or secret message starts with ``Artifact:``, and a later
    line its path supplied must not give it a package identity."""
    message = (
        "Artifact: iac/evil\nPackage: injected\nInstalled Version: 9.9\n"
        "Type: terraform\nSeverity: LOW"
    )

    assert TrivyScannerBase._package_from_message(message) == (None, None)


def test_control_a_vulnerability_message_names_its_package_and_version():
    message = "Package: lodash\nInstalled Version: 4.17.0\nVulnerability CVE-1\n"

    assert TrivyScannerBase._package_from_message(message) == ("lodash", "4.17.0")
    assert TrivyScannerBase._package_from_message(
        "Package: lodash\nSeverity: HIGH"
    ) == (
        "lodash",
        None,
    )
    assert TrivyScannerBase._package_from_message(None) == (None, None)


# --- the misconfiguration-scanner list cache ----------------------------------------


def _help_output(names: str):
    return lambda *args, **kwargs: SimpleNamespace(
        stdout=f"      --misconfig-scanners strings   list (default [{names}])\n",
        stderr="",
    )


def _own_misconfig_memo(monkeypatch) -> None:
    """An empty memo for the test, in place of the one the unit tier installs.

    The unit tier's tool guard replaces ``_DEFAULT_MISCONFIG_SCANNERS`` with a memo
    that already holds "unknown" for every trivy, so no ``--help`` is ever run
    (tests/utils/tool_guard.py, ``stub_tool_probes``). These tests are about the
    memo itself and answer the ``--help`` read with their own double, so they need
    a real, empty one; clearing the guard's memo would leave it answering for every
    key still.
    """
    monkeypatch.setattr(trivy_base, "_DEFAULT_MISCONFIG_SCANNERS", {})


def test_a_trivy_replaced_in_place_has_its_default_list_read_again(
    tmp_path, monkeypatch
):
    """Keyed by path alone, a long-running process would pass the old release's
    names to the new one, and a name trivy does not know makes it run every
    misconfiguration scanner, the Terraform checks included."""
    _own_misconfig_memo(monkeypatch)
    binary = tmp_path / "trivy"
    binary.write_text("old release\n")
    os.utime(binary, (1_600_000_000, 1_600_000_000))
    monkeypatch.setattr(
        trivy_base.subprocess_utils, "run_command", _help_output("azure-arm,terraform")
    )
    assert trivy_default_misconfig_scanners(str(binary), ["repository"]) == [
        "azure-arm",
        "terraform",
    ]

    binary.write_text("new release, same path\n")
    os.utime(binary, (1_700_000_000, 1_700_000_000))
    monkeypatch.setattr(
        trivy_base.subprocess_utils, "run_command", _help_output("dockerfile")
    )

    assert trivy_default_misconfig_scanners(str(binary), ["repository"]) == [
        "dockerfile"
    ]


def test_control_an_unchanged_trivy_is_read_once(tmp_path, monkeypatch):
    _own_misconfig_memo(monkeypatch)
    binary = tmp_path / "trivy"
    binary.write_text("release\n")
    calls = []

    def read(*args, **kwargs):
        calls.append(args)
        return _help_output("dockerfile")()

    monkeypatch.setattr(trivy_base.subprocess_utils, "run_command", read)
    first = trivy_default_misconfig_scanners(str(binary), ["repository"])
    second = trivy_default_misconfig_scanners(str(binary), ["repository"])

    assert first == second == ["dockerfile"]
    assert len(calls) == 1


# --- the skip-arguments budget ------------------------------------------------------


def test_ignored_paths_past_the_argument_budget_are_left_out_with_a_warning(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    many = [f"ignored/{index}/{'x' * 200}.txt" for index in range(10_000)]
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: many)
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._link_skip_args(source, [])

    assert 0 < len(tokens) < len(many)
    assert sum(len(os.fsencode(token)) + 1 for token in tokens) <= _SKIP_ARGS_BUDGET
    assert all(token.startswith("--skip-files=") for token in tokens)
    (warning,) = [m for m in messages if "not given to trivy" in m]
    assert str(len(many) - len(tokens)) in warning


def test_control_a_few_ignored_paths_are_all_passed(tmp_path, monkeypatch):
    scanner = _repo_scanner(tmp_path)
    monkeypatch.setattr(
        trivy_base, "trivy_skip_files", lambda *a, **k: ["a.txt", "b/c.txt"]
    )
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: ["vendor/"])
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._link_skip_args(Path(scanner.context.source_dir), [])

    assert tokens == [
        "--skip-files=a.txt",
        "--skip-files=b/c.txt",
        "--skip-dirs=vendor/",
    ]
    assert messages == []


# --- the operator's own skip lists --------------------------------------------------


def test_the_operators_skip_variables_are_given_back_beside_ashs_skip_flags(tmp_path):
    """trivy reads a list flag from one source only: ASH's --skip-dirs would replace
    TRIVY_SKIP_DIRS rather than add to it."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {
        "TRIVY_SKIP_DIRS": "vendor, build",
        "TRIVY_SKIP_FILES": "k.pem",
    }

    tokens = scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"])

    assert tokens == ["--skip-dirs=vendor", "--skip-dirs=build", "--skip-files=k.pem"]


def test_the_operators_config_file_skip_lists_are_given_back_too(tmp_path):
    scanner = _repo_scanner(tmp_path)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "scan:\n  skip-files:\n    - secrets.txt\n  skip-dirs: 'a,b'\n",
        encoding="utf-8",
    )

    tokens = scanner._operator_skip_args(
        [f"--config={operator.as_posix()}", "--skip-dirs=.ash/ash_output"]
    )

    assert tokens == ["--skip-dirs=a", "--skip-dirs=b", "--skip-files=secrets.txt"]


def test_the_environment_beats_the_config_file_and_a_present_token_is_not_doubled(
    tmp_path,
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor"}
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text("scan:\n  skip-dirs: [from-config]\n", encoding="utf-8")

    tokens = scanner._operator_skip_args(
        [f"--config={operator.as_posix()}", "--skip-dirs=vendor", "--skip-files=x"]
    )

    assert tokens == []


def test_control_with_no_skip_flag_of_ashs_trivy_reads_the_operators_lists_itself(
    tmp_path,
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor"}

    assert scanner._operator_skip_args(["--format", "sarif"]) == []


def test_an_operator_entry_holding_a_quote_is_passed_as_a_csv_field(tmp_path):
    """As a flag the value goes through pflag's CSV reader, which the variable
    never did; an unquoted ``"`` fails the whole trivy run as a bare quote."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": 'a"b'}

    tokens = scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"])

    assert tokens == ['--skip-dirs="a""b"']


def test_an_operator_config_entry_holding_a_comma_is_passed_as_one_field(tmp_path):
    scanner = _repo_scanner(tmp_path)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text("scan:\n  skip-dirs:\n    - 'x,y'\n", encoding="utf-8")

    tokens = scanner._operator_skip_args(
        [f"--config={operator.as_posix()}", "--skip-dirs=.ash/ash_output"]
    )

    assert tokens == ['--skip-dirs="x,y"']


def test_an_operator_config_entry_holding_a_line_break_is_left_out_without_its_text(
    tmp_path,
):
    """The CSV reader takes one line, so trivy would skip a different path; the
    warning names the key and the entry's position, never the entry, which the
    operator's file chose."""
    scanner = _repo_scanner(tmp_path)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(
        'scan:\n  skip-dirs:\n    - "zz-line\\nbreak-zz"\n    - vendor\n',
        encoding="utf-8",
    )
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._operator_skip_args(
            [f"--config={operator.as_posix()}", "--skip-dirs=.ash/ash_output"]
        )

    assert tokens == ["--skip-dirs=vendor"]
    (warning,) = messages
    assert "entry 1 of scan.skip-dirs" in warning
    assert "zz-line" not in warning and "\n" not in warning


def test_control_an_operator_entry_without_csv_characters_is_passed_as_written(
    tmp_path,
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor/*"}

    assert scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"]) == [
        "--skip-dirs=vendor/*"
    ]


# --- a skip-dirs path holding a line break ------------------------------------------


@pytest.mark.parametrize("name", ["out\nput", "out\rput"])
def test_a_skip_dirs_path_holding_a_line_break_is_not_passed(tmp_path, name):
    """trivy reads the value as one line of CSV and would skip a different
    directory; the directory is read and ASH drops its findings there."""
    scanner = _repo_scanner(tmp_path)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        value = scanner._skip_dirs_value(Path(name), "source")

    assert value is None
    (warning,) = messages
    assert "line break" in warning
    assert "\n" not in warning and "\r" not in warning


def test_control_a_skip_dirs_path_is_escaped_as_trivy_reads_it(tmp_path):
    scanner = _repo_scanner(tmp_path)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        value = scanner._skip_dirs_value(Path("a*b/[c]"), "source")

    assert value == skip_dirs_value("a*b/[c]")
    assert messages == []


# --- the filtering environment ------------------------------------------------------


def test_the_restricting_variables_are_the_trivy_flags_that_drop_results():
    assert set(OUTPUT_RESTRICTING_TRIVY_ENV) == {
        "TRIVY_SEVERITY",
        "TRIVY_IGNORE_UNFIXED",
        "TRIVY_IGNORE_STATUS",
        "TRIVY_IGNORE_POLICY",
        "TRIVY_SKIP_DIRS",
        "TRIVY_SKIP_FILES",
        "TRIVY_VEX",
    }


def test_filtering_variables_in_trivys_environment_are_named_without_their_values(
    tmp_path,
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {
        "TRIVY_SEVERITY": "zz-value-zz",
        "TRIVY_VEX": "/operator/zz-vex-path",
    }
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    (warning,) = [m for m in messages if "restrict" in m]
    assert "TRIVY_SEVERITY, TRIVY_VEX are set" in warning
    assert "zz-value-zz" not in warning and "zz-vex-path" not in warning


def test_the_filtering_warning_is_given_once(tmp_path):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_IGNORE_UNFIXED": "true"}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()
        scanner._process_config_options()

    assert len([m for m in messages if "restrict" in m]) == 1


def test_control_an_environment_without_filters_is_not_warned_about(tmp_path):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SEVERITY": "  ", "TRIVY_DEBUG": "true"}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    assert not [m for m in messages if "restrict" in m]


# --- the offline cache check --------------------------------------------------------


def test_offline_without_trivy_cache_dir_the_default_cache_is_judged_by_name(
    tmp_path, monkeypatch
):
    """The validator judged only TRIVY_CACHE_DIR, so with it unset every offline
    scan was told the variable was not set, whatever its default cache held."""
    scanner = _repo_scanner(tmp_path, offline=True)
    absent = tmp_path / "cache" / "absent"
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: absent)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    (warning,) = messages
    assert absent.as_posix() in warning
    assert "environment variable not set" not in warning


def test_control_offline_with_a_default_cache_present_nothing_is_said(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, offline=True)
    present = tmp_path / "cache" / "trivy"
    present.mkdir(parents=True)
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: present)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    assert messages == []


def test_offline_with_trivy_cache_dir_set_the_validator_judges_that_directory(
    tmp_path, monkeypatch
):
    empty = tmp_path / "operator-cache"
    empty.mkdir()
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(empty))
    scanner = _repo_scanner(tmp_path, offline=True)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    assert messages, "an empty cache named by TRIVY_CACHE_DIR has no database"
    assert all("environment variable not set" not in m for m in messages)


# --- a secret-rules file a scan never reads -----------------------------------------


def test_a_missing_secret_config_does_not_fail_a_scan_without_the_secret_scanner(
    tmp_path, caplog
):
    missing = tmp_path / "operator" / "trivy-secret.yaml"
    scanner = _builtin_scanner(tmp_path, secret_config_file=str(missing))

    with caplog.at_level("WARNING"):
        final_args, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    (value,) = [
        a.split("=", 1)[1] for a in final_args if a.startswith("--secret-config=")
    ]
    assert Path(value).name == "trivy-secret-empty.yaml"
    assert "scanners.trivy.options.secret_config_file does not name a file" in (
        caplog.text
    )
    assert missing.as_posix() not in caplog.text


def test_control_a_missing_secret_config_fails_a_scan_that_runs_the_secret_scanner(
    tmp_path,
):
    missing = tmp_path / "operator" / "trivy-secret.yaml"
    # The operator's config: a ``scanners`` list the repository set is dropped
    # with a warning, and a scan without ``secret`` never reads the file.
    scanner = _builtin_scanner(
        tmp_path,
        operator=True,
        secret_config_file=str(missing),
        scanners=["vuln", "secret"],
    )

    with pytest.raises(ScannerError, match="secret_config_file"):
        scanner._execute_scan(Path(scanner.context.source_dir), "source", [])


# --- the operator's misconfiguration-scanner list, offline ------------------------


#: What this trivy prints for --misconfig-scanners: the names it knows.
KNOWN_MISCONFIG_SCANNERS = ["azure-arm", "dockerfile", "kubernetes", "terraform"]


def _knows(monkeypatch, names=KNOWN_MISCONFIG_SCANNERS) -> None:
    """The ``--help`` read answers ``names``; None for a list that cannot be read."""
    monkeypatch.setattr(
        trivy_repo_scanner,
        "trivy_default_misconfig_scanners",
        lambda binary, subcommands: names,
    )


EMPTY_CONFIG_ARGS = ["trivy", "repository", f"--config={EMPTY_TOOL_CONFIG}", "/src"]


def _misconfig_flags(args) -> list[str]:
    return [a for a in args if a.startswith("--misconfig-scanners")]


def test_offline_the_operators_misconfig_scanners_are_kept_without_terraform(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "terraform,dockerfile",
    }
    _knows(monkeypatch)

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert "--misconfig-scanners=dockerfile" in args, args


def test_offline_the_operators_config_file_misconfig_scanners_are_read(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "scan:\n  scanners: [misconfig]\nmisconfiguration:\n"
        "  scanners: [terraform, kubernetes]\n",
        encoding="utf-8",
    )
    _knows(monkeypatch)
    final_args = ["trivy", "repository", f"--config={operator.as_posix()}", "/src"]

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(final_args)

    assert "--misconfig-scanners=kubernetes" in args, args


def test_offline_an_operator_list_of_terraform_alone_runs_no_misconfig_checks(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "terraform",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    assert any("the operator chose" in m for m in messages), messages


# --- the operator's names are read as trivy reads them, and checked -----------------


def test_a_space_separated_misconfig_list_is_read_as_two_names(tmp_path, monkeypatch):
    """viper splits a list variable on whitespace before trivy splits it on commas,
    so "terraform dockerfile" is two names to trivy. Read as one name it would be
    passed as written, a name trivy does not know, and trivy would then run every
    misconfiguration scanner, the Terraform checks included."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "terraform dockerfile",
    }
    _knows(monkeypatch)

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert _misconfig_flags(args) == ["--misconfig-scanners=dockerfile"], args


def test_a_space_separated_scanners_variable_turns_misconfig_on(tmp_path):
    scanner = _repo_scanner(tmp_path, scanners=[])
    scanner.extra_env = {"TRIVY_SCANNERS": "vuln misconfig"}

    assert scanner._effective_scanners(EMPTY_CONFIG_ARGS) == ["vuln", "misconfig"]


def test_a_capitalized_terraform_is_the_terraform_scanner(tmp_path, monkeypatch):
    """Matched by name, not by spelling: ``Terraform`` passed as written is a name
    trivy does not know, and would have run every scanner rather than none."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "Terraform",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    assert any("the operator chose" in m for m in messages), messages


def test_a_name_trivy_does_not_know_is_dropped_with_a_warning_without_its_text(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "zz-typo-zz,Dockerfile,terraform",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert _misconfig_flags(args) == ["--misconfig-scanners=dockerfile"], args
    (dropped,) = [m for m in messages if "not names this trivy knows" in m]
    assert "1 of the 3" in dropped
    assert "TRIVY_MISCONFIG_SCANNERS" in dropped
    assert "zz-typo-zz" not in dropped


def test_an_operator_list_of_unknown_names_alone_runs_no_misconfig_checks(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "zz-typo-zz",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    (skipped,) = [m for m in messages if "skipped offline" in m]
    assert "none of the 1" in skipped
    assert "zz-typo-zz" not in skipped


def test_an_operator_list_with_trivys_list_unreadable_runs_no_misconfig_checks(
    tmp_path, monkeypatch
):
    """The names cannot be checked, and a name trivy does not know would run every
    misconfiguration scanner: fail closed, as with no list at all."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "dockerfile",
    }
    _knows(monkeypatch, None)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    (skipped,) = [m for m in messages if "skipped offline" in m]
    assert "could not read trivy's list" in skipped
    assert "TRIVY_MISCONFIG_SCANNERS" in skipped


def test_control_a_known_name_repeated_in_two_spellings_is_passed_once(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "dockerfile,DOCKERFILE kubernetes",
    }
    _knows(monkeypatch)

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert _misconfig_flags(args) == ["--misconfig-scanners=dockerfile,kubernetes"]


# --- the update step is given the values to redact with ---------------------------


def test_the_database_update_is_given_the_scanners_values_to_redact(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    seen = {}

    def prepare(tool, cache, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(trivy_base, "prepare_content_db", prepare)
    monkeypatch.setattr(trivy_base, "find_executable", lambda name: f"/bin/{name}")

    scanner._shared_update_flags(["trivy", "repository", "/src"])

    assert "values" in seen
    assert tuple(seen["values"]) == tuple(scanner._values_to_redact())


# --- the environment values both scanners redact -----------------------------------


def test_the_builtin_trivy_scanner_redacts_the_input_file_variables(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TRIVY_IGNOREFILE", "/operator/zz-ignore-path")
    monkeypatch.setenv("TRIVY_SECRET_CONFIG", "/operator/zz-secret-path")
    monkeypatch.setenv("TRIVY_CONFIG", "/operator/zz-config-path")
    scanner = _builtin_scanner(tmp_path)

    values = scanner._environment_values()

    assert "/operator/zz-ignore-path" in values
    assert "/operator/zz-secret-path" in values
    # TRIVY_CONFIG's value is shown, escaped, in the refusal that names it.
    assert "/operator/zz-config-path" not in values


# --- the sandbox's cache paths ------------------------------------------------------


def test_the_sandbox_mounts_gos_temporary_directory_fallback_for_the_cache():
    """With XDG_CACHE_HOME set to a relative path trivy's cache falls back to
    $TMPDIR/trivy, which was not mounted."""
    assert "$TMPDIR/trivy" in TrivyScannerBase.sandbox_requirements.cache_paths


# --- a config file that is not UTF-8 ----------------------------------------------


def test_a_trivy_config_that_is_not_utf8_sets_no_scanners_and_raises_nothing(tmp_path):
    scanner = _repo_scanner(tmp_path, scanners=[])
    bad = tmp_path / "operator" / "trivy.yaml"
    bad.parent.mkdir()
    bad.write_bytes(b"\xff\xfescan:\n  scanners: [misconfig]\n")

    assert scanner._effective_scanners([f"--config={bad.as_posix()}"]) == list(
        _TRIVY_DEFAULT_SCANNERS
    )


def test_control_a_readable_config_file_sets_the_scanners(tmp_path):
    scanner = _repo_scanner(tmp_path, scanners=[])
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text("scan:\n  scanners: license,misconfig\n", encoding="utf-8")

    assert scanner._effective_scanners([f"--config={operator.as_posix()}"]) == [
        "license",
        "misconfig",
    ]
