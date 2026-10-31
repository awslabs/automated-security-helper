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
  so a large tree could keep trivy from starting (ARG_MAX); then one bound sized
  for Linux, past Windows' command-line limit, with the file tokens ahead of the
  directory tokens that prune whole subtrees.
- ASH's own skip flags replaced the operator's ``TRIVY_SKIP_DIRS`` /
  ``TRIVY_SKIP_FILES`` and config-file lists instead of adding to them.
- a ``--skip-dirs`` path holding a line break was passed as written, which
  trivy's CSV read cuts at the break.
- the operator's own skip entries, given back as flags, went through pflag's CSV
  reader unquoted: a ``"`` failed the run and a line break skipped another path.
- ``TRIVY_SEVERITY`` and the other filtering variables narrowed the report with
  nothing in the run saying so; then the set left out ``TRIVY_PKG_TYPES``,
  ``TRIVY_PKG_RELATIONSHIPS`` and ``TRIVY_IGNORED_LICENSES``, fired on a variable
  set to ``false``, and said nothing for an honored ignore file.
- ``trivy_timeout`` raised on a bound that is not a finite number.
- the offline cache check judged only ``TRIVY_CACHE_DIR`` and warned about every
  offline scan whose default cache held a database; then it warned about a
  database a scan without ``vuln`` never opens; then it took any existing default
  cache directory for one holding a database.
- before the first scan the operator's config file was not read, so the offline
  dependency check judged trivy's default scanners for a scan whose
  ``scan.scanners`` sends it elsewhere.
- a missing secret-rules file failed a scan that never reads one.
- the offline Terraform-check removal ignored the operator's own
  misconfiguration-scanner list.
- the operator's list reached trivy as written: a list variable split on commas
  alone (trivy splits on whitespace too), and a name trivy does not know passed
  through, which makes trivy run every misconfiguration scanner.
- turning the misconfiguration scanner off reached trivy only through a
  ``--scanners`` token ASH had passed; a set from ``TRIVY_SCANNERS`` or the config
  file was left as trivy read it, so trivy ran the checks the warning called
  skipped.
- the builtin trivy scanner redacted neither ``TRIVY_IGNOREFILE`` nor
  ``TRIVY_SECRET_CONFIG``, which it reads from the environment.
- a trivy config file that is not UTF-8 raised out of the scanner-set read.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.base import scanner_plugin
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    _MAX_GO_DURATION_SECONDS,
    _SKIP_ARGS_BUDGET,
    _SKIP_ARGS_FLOOR,
    _TRIVY_DEFAULT_SCANNERS,
    OUTPUT_RESTRICTING_TRIVY_ENV,
    UNBOUNDED_TRIVY_TIMEOUT,
    TrivyScannerBase,
    skip_args_budget,
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
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils import link_exclusions
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


def _platform(monkeypatch, name: str) -> None:
    """The trivy base reads ``name`` as the platform, and nothing else does.

    ``sys.platform`` patched for the whole process also flips the path-trust and
    config code a test reaches with POSIX temporary paths. The base reads the
    platform in two places only (the skip budget and the size of a skip token), so
    its own ``sys`` is replaced."""
    monkeypatch.setattr(trivy_base, "sys", SimpleNamespace(platform=name))


def test_a_patched_platform_is_the_trivy_bases_alone(monkeypatch):
    real = sys.platform
    _platform(monkeypatch, "linux" if real == "win32" else "win32")

    assert sys.platform == real
    assert trivy_base.sys.platform != real


# --- the timeout bound -------------------------------------------------------------


def test_a_timeout_past_what_a_go_duration_holds_is_passed_as_unbounded():
    """trivy refuses more than 2**63 - 1 nanoseconds as an invalid duration, and
    exits 1 before it scans; 292 years is no deadline either way."""
    assert trivy_timeout(_MAX_GO_DURATION_SECONDS + 1) == UNBOUNDED_TRIVY_TIMEOUT
    assert trivy_timeout(float(2**63)) == UNBOUNDED_TRIVY_TIMEOUT


def test_control_a_bound_a_go_duration_holds_is_passed_in_seconds():
    assert trivy_timeout(_MAX_GO_DURATION_SECONDS) == f"{_MAX_GO_DURATION_SECONDS}s"
    assert trivy_timeout(90) == "90s"


@pytest.mark.parametrize("seconds", [float("inf"), float("nan")])
def test_a_bound_that_is_not_a_finite_number_is_passed_as_unbounded(seconds):
    """``math.ceil`` raises on infinity and on NaN before the Go bound is reached;
    neither is a deadline."""
    assert trivy_timeout(seconds) == UNBOUNDED_TRIVY_TIMEOUT


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


#: Characters a file name can hold that ``str.splitlines`` breaks on and ``\n``
#: does not: the line separator (U+2028), a form feed, a file separator and the
#: next-line character.
NAME_LINE_BREAKS = ["\N{LINE SEPARATOR}", "\x0c", "\x1c", "\x85"]


@pytest.mark.parametrize("separator", NAME_LINE_BREAKS)
def test_a_severity_line_split_off_by_a_name_character_does_not_decide(separator):
    """A file name can hold a line separator, a form feed, a file separator or a
    next-line character; ``str.splitlines`` breaks on each, ``\\n`` alone does
    not. With no ``Severity:`` line of trivy's own, the rule's tag decides. The
    injected line is closed by a second separator, so under ``splitlines`` it
    reads exactly ``Severity: CRITICAL``; written as ``CRITICAL.tf`` the old code
    passed too, since that is not a severity."""
    message = (
        f"Artifact: iac/evil{separator}Severity: CRITICAL{separator}.tf\n"
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


@pytest.mark.parametrize("separator", NAME_LINE_BREAKS)
def test_a_version_line_split_off_by_a_name_character_does_not_decide(separator):
    """A package name holding one of the characters must not supply the
    ``Installed Version:`` line: under ``splitlines`` the name's tail read as the
    second line and gave the version 9.9; the real second line does."""
    message = (
        f"Package: lodash{separator}Installed Version: 9.9\n"
        "Installed Version: 4.17.0\nVulnerability CVE-1\n"
    )

    name, version = TrivyScannerBase._package_from_message(message)

    assert version == "4.17.0"
    assert name == f"lodash{separator}Installed Version: 9.9"


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


def test_control_a_few_ignored_paths_are_all_passed_directories_first(
    tmp_path, monkeypatch
):
    """A ``--skip-dirs`` token prunes a whole subtree where a ``--skip-files``
    token covers one file, so the directories go first and are the last dropped."""
    scanner = _repo_scanner(tmp_path)
    monkeypatch.setattr(
        trivy_base, "trivy_skip_files", lambda *a, **k: ["a.txt", "b/c.txt"]
    )
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: ["vendor/"])
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._link_skip_args(Path(scanner.context.source_dir), [])

    assert tokens == [
        "--skip-dirs=vendor/",
        "--skip-files=a.txt",
        "--skip-files=b/c.txt",
    ]
    assert messages == []


def test_under_a_small_budget_the_directory_tokens_survive_the_file_tokens(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: ["a.txt"])
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: ["vendor/"])
    monkeypatch.setattr(trivy_base, "skip_args_budget", lambda environment: 25)

    with patch.object(scanner, "_plugin_log"):
        tokens = scanner._link_skip_args(Path(scanner.context.source_dir), [])

    assert tokens == ["--skip-dirs=vendor/"]


def test_skip_tokens_at_the_windows_budget_keep_the_whole_command_line_in_limit(
    tmp_path, monkeypatch
):
    """CreateProcess holds the whole command line, in UTF-16 units after
    ``list2cmdline`` has quoted it, to 32,767; a budget near 1 MB kept trivy from
    starting there. The limit is on the whole line, so the check builds one: the
    tokens that fit the budget, with the rest of a trivy command around them."""
    scanner = _repo_scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    many = [f"ignored/{index}/{'x' * 200}.txt" for index in range(1_000)]
    _platform(monkeypatch, "win32")
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: many)
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._link_skip_args(source, [])

    command = [
        "trivy",
        "repository",
        "--format",
        "sarif",
        "--output",
        "C:\\Users\\scanner\\output\\" + "o" * 200,
        *tokens,
        "C:\\Users\\scanner\\source\\" + "s" * 200,
    ]
    line = subprocess.list2cmdline(command)
    assert 0 < len(tokens) < len(many)
    assert len(line.encode("utf-16-le")) // 2 <= 32_767


def test_no_skip_token_is_built_on_windows_so_its_budget_bounds_nothing_yet(
    tmp_path, monkeypatch
):
    """The budget above is for tokens that are not built there today: the helpers
    that make them answer nothing when ``os.sep`` is not ``/``. If one starts to,
    this fails, and the budget test above stops being a spare."""
    monkeypatch.setattr(link_exclusions.os, "sep", "\\")

    assert link_exclusions.trivy_skip_dirs(tmp_path) == []
    assert link_exclusions.trivy_skip_files(tmp_path) == []


def test_the_budget_elsewhere_reads_the_hosts_arg_max_less_the_environment(
    monkeypatch,
):
    arg_max = 2_000_000
    # ``raising=False``: Windows has no ``os.sysconf`` to replace, and this test
    # plays a Linux host there too (the platform is patched above the call).
    _platform(monkeypatch, "linux")
    monkeypatch.setattr(trivy_base.os, "sysconf", lambda name: arg_max, raising=False)

    assert skip_args_budget({}) == _SKIP_ARGS_BUDGET
    assert skip_args_budget({"A": "x" * 100_000}) == arg_max // 2 - (1 + 100_000 + 2)
    assert skip_args_budget({"A": "x" * 2_000_000}) == _SKIP_ARGS_FLOOR


def test_control_a_host_that_does_not_answer_gets_the_ceiling(monkeypatch):
    def unknown(name):
        raise ValueError(name)

    _platform(monkeypatch, "linux")
    monkeypatch.setattr(trivy_base.os, "sysconf", unknown, raising=False)

    assert skip_args_budget({"A": "x" * 100_000}) == _SKIP_ARGS_BUDGET


def test_a_host_without_sysconf_gets_the_ceiling(monkeypatch):
    """The ``AttributeError`` arm of the budget: a non-Windows platform whose ``os``
    has no ``sysconf`` (what a Windows interpreter is once the platform check is
    taken out of the way) gets the ceiling, not a crash."""
    _platform(monkeypatch, "linux")
    monkeypatch.delattr(trivy_base.os, "sysconf", raising=False)

    assert not hasattr(trivy_base.os, "sysconf")
    assert skip_args_budget({"A": "x" * 100_000}) == _SKIP_ARGS_BUDGET


# --- the operator's own skip lists --------------------------------------------------


def test_the_operators_skip_variables_are_given_back_beside_ashs_skip_flags(tmp_path):
    """trivy reads a list flag from one source only: ASH's --skip-dirs would replace
    TRIVY_SKIP_DIRS rather than add to it."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {
        "TRIVY_SKIP_DIRS": "vendor,build",
        "TRIVY_SKIP_FILES": "k.pem",
    }

    tokens = scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"])

    assert tokens == ["--skip-dirs=vendor", "--skip-dirs=build", "--skip-files=k.pem"]


def test_an_empty_operator_skip_entry_is_nothing(tmp_path):
    """An entry with no characters between two commas, or after the last one, is
    no path. Whitespace is not empty: see the comma-list tests below."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor,,build,"}

    assert scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"]) == [
        "--skip-dirs=vendor",
        "--skip-dirs=build",
    ]


def test_a_list_variable_holding_a_comma_is_split_on_commas_alone(tmp_path):
    """trivy's ``Flag.cast`` splits a value that holds a comma on commas and never
    on whitespace, so a directory with a space in its name is one entry. Split on
    both, ``build dir`` was read as ``build`` and ``dir``: a ``build`` directory
    skipped that the operator's own trivy would not skip."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor,build dir"}

    assert scanner._environment_list("TRIVY_SKIP_DIRS") == ["vendor", "build dir"]
    assert scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"]) == [
        "--skip-dirs=vendor",
        "--skip-dirs=build dir",
    ]


def test_a_comma_list_keeps_the_edge_whitespace_of_its_entries(tmp_path):
    """trivy does not trim the entries of a comma-separated value, so ``" build"``
    is a different path from ``"build"``; it is passed as written, CSV-quoted."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor, build,\t"}

    assert scanner._environment_list("TRIVY_SKIP_DIRS") == ["vendor", " build", "\t"]
    assert scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"]) == [
        "--skip-dirs=vendor",
        '--skip-dirs=" build"',
        '--skip-dirs="\t"',
    ]


def test_control_a_list_variable_without_a_comma_is_split_on_whitespace(tmp_path):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_FILES": " a.txt \t b.txt\n"}

    assert scanner._environment_list("TRIVY_SKIP_FILES") == ["a.txt", "b.txt"]


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
        "TRIVY_PKG_TYPES",
        "TRIVY_PKG_RELATIONSHIPS",
        "TRIVY_IGNORED_LICENSES",
    }


@pytest.mark.parametrize("spelling", ["false", "False", "FALSE", "f", "0", " false "])
def test_a_filtering_variable_set_to_false_is_not_a_filter(tmp_path, spelling):
    """``TRIVY_IGNORE_UNFIXED=false`` is the default written out; warning about it
    would train a reader to ignore the warning, as grype's config-key warning
    reads a falsy key."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_IGNORE_UNFIXED": spelling}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    assert not [m for m in messages if "restrict" in m], messages


@pytest.mark.parametrize("spelling", ["no", "NO", "off", "n", "yes", "on", "2", "tRuE"])
def test_a_spelling_trivy_does_not_read_as_true_is_not_a_filter(tmp_path, spelling):
    """trivy reads a boolean setting through a conversion that accepts only the
    spellings ``strconv.ParseBool`` does as true and reads every other value as
    false: ``TRIVY_IGNORE_UNFIXED=no`` filters nothing, so the warning that the
    report is restricted would be false. ``yes`` and ``on`` are false too."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_IGNORE_UNFIXED": spelling}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    assert not [m for m in messages if "restrict" in m], messages


@pytest.mark.parametrize("spelling", ["1", "t", "T", "TRUE", "true", "True"])
def test_every_spelling_trivy_reads_as_true_is_a_filter(tmp_path, spelling):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_IGNORE_UNFIXED": spelling}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    (warning,) = [m for m in messages if "restrict" in m]
    assert "TRIVY_IGNORE_UNFIXED is set" in warning


def test_control_a_filtering_variable_set_to_true_or_a_value_is_a_filter(tmp_path):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_IGNORE_UNFIXED": "true", "TRIVY_PKG_TYPES": "os"}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    (warning,) = [m for m in messages if "restrict" in m]
    assert "TRIVY_IGNORE_UNFIXED, TRIVY_PKG_TYPES are set" in warning


@pytest.mark.parametrize(
    ("name", "spelling"),
    [("TRIVY_SKIP_DIRS", "0"), ("TRIVY_PKG_TYPES", "false"), ("TRIVY_SEVERITY", "f")],
)
def test_a_false_spelling_turns_off_only_the_boolean_filter(tmp_path, name, spelling):
    """TRIVY_IGNORE_UNFIXED is the one boolean among the filtering variables. A
    list or path variable set to ``0`` or ``false`` is a value trivy reads
    literally (a directory named ``0`` is skipped), so it is a filter and is
    warned about like any other value."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {name: spelling}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._process_config_options()

    (warning,) = [m for m in messages if "restrict" in m]
    assert f"{name} is set" in warning


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
    (present / "db").mkdir(parents=True)
    (present / "db" / "trivy.db").write_bytes(b"")
    (present / "db" / "metadata.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: present)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    assert messages == []


def test_offline_a_default_cache_with_the_database_but_no_metadata_is_warned_about(
    tmp_path, monkeypatch
):
    """trivy reads ``db/metadata.json`` beside ``db/trivy.db`` and refuses
    ``--skip-db-update`` when either is missing (``NeedsUpdate``, trivy's db
    package at v0.69.3), so a cache holding only the database file is no cache an
    offline scan can read. The control above holds both files."""
    scanner = _repo_scanner(tmp_path, offline=True)
    partial = tmp_path / "cache" / "trivy"
    (partial / "db").mkdir(parents=True)
    (partial / "db" / "trivy.db").write_bytes(b"")
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: partial)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    (warning,) = messages
    assert partial.as_posix() in warning
    assert "db/metadata.json" in warning
    assert "db/trivy.db" not in warning


def test_offline_a_default_cache_without_a_database_is_warned_about(
    tmp_path, monkeypatch
):
    """An existing directory was taken as a cache with a database: a fresh XDG
    directory, or a cache another tool made, passed in silence."""
    scanner = _repo_scanner(tmp_path, offline=True)
    empty = tmp_path / "cache" / "trivy"
    empty.mkdir(parents=True)
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: empty)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    (warning,) = messages
    assert empty.as_posix() in warning
    assert "db/trivy.db" in warning


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


def test_offline_the_cache_check_says_nothing_for_a_scan_that_never_opens_the_db(
    tmp_path, monkeypatch
):
    """A missing database is no finding about a scan whose scanners never read it."""
    scanner = _repo_scanner(tmp_path, scanners=["misconfig"], offline=True)
    absent = tmp_path / "cache" / "absent"
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: absent)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._check_offline_cache()

    assert messages == []


# --- the operator's config file before the first scan -------------------------------


def _operator_config_in_env(tmp_path, monkeypatch, body: str) -> Path:
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(body, encoding="utf-8")
    monkeypatch.setenv("TRIVY_CONFIG", str(operator))
    return operator


def test_the_dependency_check_reads_the_operators_scanners_before_the_first_scan(
    tmp_path, monkeypatch
):
    """Offline, with no database, a scan the operator's config sends to misconfig
    alone never opens the database; it was reported MISSING all the same because
    the config file was read only once a scan had chosen it."""
    _operator_config_in_env(tmp_path, monkeypatch, "scan:\n  scanners: [misconfig]\n")
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")

    def no_db(ctx):
        raise ValueError("no trivy database was found")

    monkeypatch.setattr(staleness, "_built_from_trivy", no_db)
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)

    assert scanner._effective_scanners() == ["misconfig"]
    assert scanner.validate_plugin_dependencies() is True
    assert not scanner.dependency_unavailable_reason


def test_control_an_operator_config_that_keeps_vuln_still_needs_the_database(
    tmp_path, monkeypatch
):
    _operator_config_in_env(tmp_path, monkeypatch, "scan:\n  scanners: [vuln]\n")
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")

    def no_db(ctx):
        raise ValueError("no trivy database was found")

    monkeypatch.setattr(staleness, "_built_from_trivy", no_db)
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)

    assert scanner.validate_plugin_dependencies() is False
    assert "no vulnerability database" in scanner.dependency_unavailable_reason


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


def _scanners_value(args) -> str:
    """The value of the one ``--scanners`` token trivy is given."""
    tokens = [i for i, a in enumerate(args) if a == "--scanners"]
    assert len(tokens) == 1, args
    return args[tokens[0] + 1]


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
    """The set came from TRIVY_SCANNERS, so the command carried no --scanners
    token to take misconfig out of; trivy read the variable as before and ran the
    misconfiguration scanner under a warning saying it was skipped. The command
    now gets the set without misconfig as an explicit token."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "vuln,misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "terraform",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    assert _scanners_value(args) == "vuln"
    assert args[:3] == ["trivy", "repository", "--scanners"], args
    assert any("the operator chose" in m for m in messages), messages


def test_offline_a_config_file_set_without_misconfig_is_passed_as_a_token(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "scan:\n  scanners: [vuln, misconfig, secret]\nmisconfiguration:\n"
        "  scanners: [terraform]\n",
        encoding="utf-8",
    )
    _knows(monkeypatch)
    final_args = ["trivy", "repository", f"--config={operator.as_posix()}", "/src"]

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(final_args)

    assert not _misconfig_flags(args), args
    assert _scanners_value(args) == "vuln,secret"


def test_offline_a_scanner_set_of_misconfig_alone_is_refused(tmp_path, monkeypatch):
    """Nothing is left to run once misconfig is out, so the scan is refused with
    the reason, as it already was when the option named the set."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "terraform",
    }
    _knows(monkeypatch)

    with (
        patch.object(scanner, "_plugin_log"),
        pytest.raises(ScannerError, match="the operator chose"),
    ):
        scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)


def test_control_the_option_named_set_loses_misconfig_in_its_own_token(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=["vuln", "misconfig"], offline=True)
    scanner.extra_env = {"TRIVY_MISCONFIG_SCANNERS": "terraform"}
    _knows(monkeypatch)
    final_args = ["trivy", "repository", "--scanners", "vuln,misconfig", "/src"]

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(final_args)

    assert _scanners_value(args) == "vuln"
    assert args == ["trivy", "repository", "--scanners", "vuln", "/src"]


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
        "TRIVY_SCANNERS": "vuln,misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "Terraform",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    assert _scanners_value(args) == "vuln"
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
    (dropped,) = [m for m in messages if "not in this trivy's default list" in m]
    assert "1 of the 3" in dropped
    # Said as it is: the help prints the default list only, so a name outside it
    # is dropped whether or not trivy would accept it.
    assert "prints the default list only" in dropped
    assert "TRIVY_MISCONFIG_SCANNERS" in dropped
    assert "zz-typo-zz" not in dropped


def test_an_operator_list_of_unknown_names_alone_runs_no_misconfig_checks(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "vuln,misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "zz-typo-zz",
    }
    _knows(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    assert _scanners_value(args) == "vuln"
    (skipped,) = [m for m in messages if "skipped offline" in m]
    assert "none of the 1" in skipped
    assert "in this trivy's default list" in skipped
    assert "zz-typo-zz" not in skipped


def test_an_operator_list_with_trivys_list_unreadable_runs_no_misconfig_checks(
    tmp_path, monkeypatch
):
    """The names cannot be checked, and a name trivy does not know would run every
    misconfiguration scanner: fail closed, as with no list at all."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "vuln,misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "dockerfile",
    }
    _knows(monkeypatch, None)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert not _misconfig_flags(args), args
    assert _scanners_value(args) == "vuln"
    (skipped,) = [m for m in messages if "skipped offline" in m]
    assert "could not read trivy's list" in skipped
    assert "TRIVY_MISCONFIG_SCANNERS" in skipped


def test_control_a_known_name_repeated_in_two_spellings_is_passed_once(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {
        "TRIVY_SCANNERS": "misconfig",
        "TRIVY_MISCONFIG_SCANNERS": "dockerfile,DOCKERFILE,kubernetes",
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


# --- an honored ignore file is said to restrict the report --------------------------


def test_an_honored_environment_ignore_file_is_warned_about_by_variable(
    tmp_path, monkeypatch
):
    """trivy drops every finding the file lists with nothing else saying so; the
    warning names the variable, never the path, which the environment chose."""
    scanner = _repo_scanner(tmp_path)
    operator = tmp_path / "operator" / "zz-ignore-path"
    operator.parent.mkdir()
    operator.write_text("CVE-2018-18074\n", encoding="utf-8")
    monkeypatch.setenv("TRIVY_IGNOREFILE", str(operator))
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        passed = scanner._ignore_file()
        scanner._ignore_file()

    assert Path(passed) == operator.resolve()
    (warning,) = [m for m in messages if "withheld" in m]
    assert "TRIVY_IGNOREFILE" in warning
    assert "zz-ignore-path" not in warning


def test_an_honored_ignore_file_option_is_warned_about_by_key(tmp_path):
    operator = tmp_path / "operator" / "zz-ignore-path"
    operator.parent.mkdir()
    operator.write_text("CVE-2018-18074\n", encoding="utf-8")
    scanner = _repo_scanner(tmp_path, ignore_file=str(operator))
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner._ignore_file()

    (warning,) = [m for m in messages if "withheld" in m]
    assert "scanners.trivy-repo.options.ignore_file" in warning
    assert "zz-ignore-path" not in warning


def test_control_a_refused_in_tree_ignore_file_restricts_nothing_and_is_not_warned(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    inside = Path(scanner.context.source_dir) / "ignore-rules"
    inside.write_text("CVE-2018-18074\n", encoding="utf-8")
    monkeypatch.setenv("TRIVY_IGNOREFILE", str(inside))
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        passed = scanner._ignore_file()

    assert not Path(passed).resolve().is_relative_to(inside.parent.resolve())
    assert not [m for m in messages if "withheld" in m], messages


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


# --- the scanner set is read as trivy reads it -------------------------------------


@pytest.mark.parametrize(
    "written",
    ['"vuln misconfig"', '"vuln,misconfig"', "[vuln, misconfig]"],
)
def test_a_config_file_scanner_string_is_split_on_whitespace_and_commas(
    tmp_path, written
):
    """trivy reads a list setting given as one string through the same conversion
    for the config file as for the environment: on commas when the value holds
    one, else on whitespace. Read on commas alone, ``"vuln misconfig"`` was one
    unknown name, so the offline Terraform checks ran and the update gate and
    staleness check saw no scanner."""
    scanner = _repo_scanner(tmp_path, scanners=[])
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(f"scan:\n  scanners: {written}\n", encoding="utf-8")

    assert scanner._effective_scanners([f"--config={operator.as_posix()}"]) == [
        "vuln",
        "misconfig",
    ]


def test_a_config_file_list_string_with_a_comma_is_not_also_split_on_spaces(
    tmp_path,
):
    """The config file and the environment share one rule: a value that holds a
    comma is split on commas alone, so ``"vuln,misconfig secret"`` is ``vuln``
    and one name with a space in it, in the file as in ``TRIVY_SCANNERS``. A
    splitter that also cut on whitespace would read three scanners from the file
    and two from the environment, and would turn the config file's
    ``skip-dirs: "vendor,build dir"`` into skips of ``build`` and ``dir``."""
    value = "vuln,misconfig secret"
    from_env = _repo_scanner(tmp_path, scanners=[])
    from_env.extra_env = {"TRIVY_SCANNERS": value}
    from_file = _repo_scanner(tmp_path, scanners=[])
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(
        f'scan:\n  scanners: "{value}"\n  skip-dirs: "vendor,build dir"\n',
        encoding="utf-8",
    )
    config_args = [f"--config={operator.as_posix()}"]

    in_env = from_env._effective_scanners(EMPTY_CONFIG_ARGS)
    in_file = from_file._effective_scanners(config_args)

    assert in_file == ["vuln", "misconfig secret"]
    assert in_env == in_file
    assert from_file._config_file_list(config_args, "scan", "skip-dirs") == [
        "vendor",
        "build dir",
    ]


def test_a_config_file_list_string_with_a_space_after_the_comma_is_not_trimmed(
    tmp_path,
):
    """The config file's list string goes through the conversion the environment
    does, which does not trim: ``"vendor, build"`` is ``vendor`` and `` build``, so
    trivy skips a directory named `` build``, not ``build``. The file was trimmed,
    so a ``build`` directory the operator's own trivy would scan was skipped and its
    findings withheld. ``"vuln, misconfig"`` as a scanner set is read the same way
    in the file as in ``TRIVY_SCANNERS``: the second name carries its space."""
    value = "vendor, build"
    from_env = _repo_scanner(tmp_path, scanners=[])
    from_env.extra_env = {"TRIVY_SKIP_DIRS": value, "TRIVY_SCANNERS": "vuln, misconfig"}
    from_file = _repo_scanner(tmp_path, scanners=[])
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(
        f'scan:\n  skip-dirs: "{value}"\n  scanners: "vuln, misconfig"\n',
        encoding="utf-8",
    )
    config_args = [f"--config={operator.as_posix()}"]
    ashs_own = "--skip-dirs=.ash/ash_output"

    in_file = from_file._config_file_list(config_args, "scan", "skip-dirs")

    assert in_file == ["vendor", " build"]
    assert from_env._environment_list("TRIVY_SKIP_DIRS") == in_file
    assert from_file._operator_skip_args([*config_args, ashs_own]) == [
        "--skip-dirs=vendor",
        '--skip-dirs=" build"',
    ]
    assert from_env._operator_skip_args([ashs_own]) == [
        "--skip-dirs=vendor",
        '--skip-dirs=" build"',
    ]
    assert from_file._effective_scanners(config_args) == ["vuln", " misconfig"]
    assert from_env._effective_scanners(EMPTY_CONFIG_ARGS) == ["vuln", " misconfig"]


def test_control_an_empty_entry_of_a_config_file_list_string_is_still_dropped(
    tmp_path,
):
    scanner = _repo_scanner(tmp_path)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text('scan:\n  skip-dirs: "vendor,,build,"\n', encoding="utf-8")

    assert scanner._config_file_list(
        [f"--config={operator.as_posix()}"], "scan", "skip-dirs"
    ) == ["vendor", "build"]


@pytest.mark.parametrize(
    ("spelling", "name"),
    [
        ("config", "misconfig"),
        ("misconf", "misconfig"),
        ("misconfiguration", "misconfig"),
        ("vulnerability", "vuln"),
    ],
)
def test_the_other_spellings_trivy_accepts_for_a_scanner_are_read_as_that_scanner(
    tmp_path, spelling, name
):
    """trivy normalizes ``config`` (deprecated), ``misconf``, ``misconfiguration``
    and ``vulnerability`` for ``--scanners``, ``TRIVY_SCANNERS`` and the config
    file alike. A test on the canonical name missed all of them."""
    scanner = _repo_scanner(tmp_path, scanners=[])
    scanner.extra_env = {"TRIVY_SCANNERS": f"{spelling},secret"}
    assert scanner._effective_scanners(EMPTY_CONFIG_ARGS) == [name, "secret"]

    from_file = _repo_scanner(tmp_path, scanners=[])
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(f"scan:\n  scanners: [{spelling}, secret]\n", encoding="utf-8")
    assert from_file._effective_scanners([f"--config={operator.as_posix()}"]) == [
        name,
        "secret",
    ]


def test_offline_the_terraform_checks_are_left_out_of_a_set_written_with_config(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)
    scanner.extra_env = {"TRIVY_SCANNERS": "vuln,config"}
    _knows(monkeypatch)

    with patch.object(scanner, "_plugin_log"):
        args = scanner._offline_misconfig_args(EMPTY_CONFIG_ARGS)

    assert _misconfig_flags(args) == [
        "--misconfig-scanners=azure-arm,dockerfile,kubernetes"
    ], args


# --- the offline database check ----------------------------------------------------


def test_a_probe_that_found_no_database_is_missing_with_a_redacted_reason(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)

    def no_database(ctx):
        raise ValueError("no database under /operator/zz-canary-zz")

    monkeypatch.setattr(staleness, "_built_from_trivy", no_database)
    messages, logging_patch = _logged(scanner)

    with (
        logging_patch,
        patch.object(
            scanner, "_values_to_redact", return_value=["/operator/zz-canary-zz"]
        ),
    ):
        assert scanner._offline_database_available() is False

    reason = scanner.dependency_unavailable_reason
    assert "no vulnerability database" in reason, reason
    assert "zz-canary-zz" not in reason, reason
    assert not [m for m in messages if "zz-canary-zz" in m], messages


def test_a_probe_that_timed_out_does_not_make_the_scanner_missing(
    tmp_path, monkeypatch
):
    """A ``trivy version`` that outlives its bound says nothing about the cache. The
    scan goes on, as it did before the probe existed, and trivy reports a missing
    database itself; graded MISSING, a scan that could have run was skipped."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)

    def too_slow(ctx):
        raise subprocess.TimeoutExpired(["trivy", "version"], 60)

    monkeypatch.setattr(staleness, "_built_from_trivy", too_slow)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        assert scanner._offline_database_available() is True

    assert not scanner.dependency_unavailable_reason
    assert [m for m in messages if "could not check" in m], messages


def test_a_bug_in_the_probe_is_not_read_as_a_missing_database(tmp_path, monkeypatch):
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)

    def broken(ctx):
        raise AttributeError("a bug in the probe")

    monkeypatch.setattr(staleness, "_built_from_trivy", broken)

    with pytest.raises(AttributeError, match="a bug in the probe"):
        scanner._offline_database_available()


@pytest.mark.parametrize(
    "failure",
    [PermissionError(13, "Permission denied"), FileNotFoundError(2, "No such file")],
    ids=["permission-denied", "no-such-file"],
)
def test_a_probe_the_system_could_not_run_does_not_make_the_scanner_missing(
    tmp_path, monkeypatch, failure
):
    """``OSError`` is what the probe raises for a trivy that cannot be started and
    for a cache directory it cannot look into. Like a timeout it says nothing about
    the database: the scan goes on, with a warning, and trivy reports a missing
    database itself."""
    scanner = _repo_scanner(tmp_path, scanners=[], offline=True)

    def cannot_run(ctx):
        raise failure

    monkeypatch.setattr(staleness, "_built_from_trivy", cannot_run)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        assert scanner._offline_database_available() is True

    assert not scanner.dependency_unavailable_reason
    assert [m for m in messages if "could not check" in m], messages


# The probe run against a real trivy binary is in
# tests/integration/scanners/test_trivy_offline_database_probe_real_binary.py: the
# tests here replace the probe, so they do not depend on the machine they run on.


# --- which lockfile entry a result names -------------------------------------------


def _lock_entries(tmp_path: Path, packages: dict) -> list:
    from automated_security_helper.utils.package_identity import (
        load_npm_lock_entries,
    )

    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"": {}, **packages}}, indent=2),
        encoding="utf-8",
    )
    entries = load_npm_lock_entries(lockfile)
    assert entries, "the lockfile should have been read"
    return entries


def test_a_scoped_package_entry_is_the_package_a_result_names(tmp_path):
    (entry,) = _lock_entries(
        tmp_path, {"node_modules/@scope/pkg": {"version": "1.0.0"}}
    )
    assert trivy_base._same_package(entry, "@scope/pkg", "1.0.0") is True
    assert trivy_base._same_package(entry, "pkg", "1.0.0") is False
    assert trivy_base._same_package(entry, "@scope/pkg", "2.0.0") is False


def test_an_aliased_entry_is_named_by_the_package_it_installs(tmp_path):
    """``node_modules/old-name`` installing ``real-name``: trivy reports the
    package by its real name, which the lockfile's ``name`` field carries."""
    (entry,) = _lock_entries(
        tmp_path,
        {"node_modules/old-name": {"name": "real-name", "version": "3.1.4"}},
    )
    assert trivy_base._same_package(entry, "real-name", "3.1.4") is True
    assert trivy_base._same_package(entry, "old-name", "3.1.4") is False


def test_a_versionless_link_entry_is_matched_by_name_alone(tmp_path):
    (entry,) = _lock_entries(
        tmp_path, {"node_modules/workspace-lib": {"resolved": "lib", "link": True}}
    )
    assert entry.version is None
    assert trivy_base._same_package(entry, "workspace-lib", "9.9.9") is True
    assert trivy_base._same_package(entry, "other-lib", None) is False


def test_an_entry_without_the_expected_fields_raises_instead_of_matching_nothing():
    """A default of ``None`` made a schema mismatch read as "not this package" for
    every result, with no sign that package identity had stopped working."""
    with pytest.raises(AttributeError):
        trivy_base._same_package(SimpleNamespace(key="node_modules/a"), "a", "1.0.0")


# --- the operator's skip entries share the argument budget -------------------------


def test_the_operators_skip_entries_are_held_to_what_is_left_of_the_budget(
    tmp_path, monkeypatch
):
    """The operator's entries, moved onto the command line because ASH passes a skip
    flag of its own, take what the skip tokens already on it leave of the budget.
    A large generated list in the operator's file was passed whole, past the size
    a program is started with. Which tokens are already there is the callers' to
    decide: they size the operator's entries before the links' and ignored paths'
    tokens, see the tests that run a whole scan below."""
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa,bbbb,cccc,dddd"}
    ashs_own = "--skip-dirs=x"
    one_token = len("--skip-dirs=aaaa") + 1
    # Room for ASH's token and exactly one of the operator's.
    monkeypatch.setattr(
        trivy_base,
        "skip_args_budget",
        lambda environment: len(ashs_own) + 1 + one_token,
    )
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._operator_skip_args([ashs_own])

    assert tokens == ["--skip-dirs=aaaa"], tokens
    (warning,) = [m for m in messages if "exceed the size" in m]
    assert warning.startswith("3 entries"), warning
    # Where the overflow starts: the variable and the first entry left out, never
    # an entry's text.
    assert "from entry 2 of TRIVY_SKIP_DIRS on, are not given" in warning, warning
    assert "bbbb" not in warning and "dddd" not in warning


def test_a_single_entry_over_the_budget_is_reported_in_the_singular(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa"}
    ashs_own = "--skip-dirs=x"
    monkeypatch.setattr(
        trivy_base, "skip_args_budget", lambda environment: len(ashs_own) + 1
    )
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._operator_skip_args([ashs_own])

    assert tokens == []
    (warning,) = _operator_warnings(messages)
    assert warning.startswith("1 entry of the operator's"), warning
    assert "from entry 1 of TRIVY_SKIP_DIRS on, is not given" in warning, warning
    assert "That entry does not apply" in warning, warning
    assert "it would exceed" in warning, warning


def test_a_second_overflow_from_another_source_is_reported_too(tmp_path, monkeypatch):
    """One scanner object scans the source and then the converted copy, and the
    warning was remembered under one fixed key, so the second target's overflow, a
    different list, was never said. Keyed on where it starts and how large it is, a
    different overflow is reported and the same one is still said once."""
    scanner = _repo_scanner(tmp_path)
    ashs_own = "--skip-dirs=x"
    monkeypatch.setattr(
        trivy_base, "skip_args_budget", lambda environment: len(ashs_own) + 1
    )
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa,bbbb"}
        scanner._operator_skip_args([ashs_own])
        scanner._operator_skip_args([ashs_own])
        scanner.extra_env = {"TRIVY_SKIP_FILES": "cccc"}
        scanner._operator_skip_args([ashs_own])

    first, second = _operator_warnings(messages)
    assert first.startswith("2 entries"), first
    assert "from entry 1 of TRIVY_SKIP_DIRS on" in first, first
    assert second.startswith("1 entry"), second
    assert "from entry 1 of TRIVY_SKIP_FILES on" in second, second


def test_control_the_operators_skip_entries_all_fit_a_budget_that_holds_them(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa,bbbb"}
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        tokens = scanner._operator_skip_args(["--skip-dirs=x"])

    assert tokens == ["--skip-dirs=aaaa", "--skip-dirs=bbbb"], tokens
    assert not [m for m in messages if "exceed the size" in m], messages


# --- a tree that fills ASH's share still carries the operator's skip entries -------

#: One ignored-file token ``_link_skip_args`` builds, as the budget counts it.
_IGNORED_FILE_TOKEN = len("--skip-files=ignored/000.txt") + 1


def _ignored_files(count: int) -> list[str]:
    return [f"ignored/{index:03d}.txt" for index in range(count)]


def _fill_the_budget_for_ten_ignored_files(monkeypatch, *, spare: int = 5) -> None:
    """Forty ignored files, and a budget that ten of their tokens fill to within
    ``spare`` bytes, so the operator's entry fits only if the links leave room."""
    monkeypatch.setattr(
        trivy_base, "trivy_skip_files", lambda *a, **k: _ignored_files(40)
    )
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    monkeypatch.setattr(
        trivy_base,
        "skip_args_budget",
        lambda environment: 10 * _IGNORED_FILE_TOKEN + spare,
    )


def _operator_warnings(messages: list[str]) -> list[str]:
    return [m for m in messages if "operator's skip" in m]


def test_a_tree_that_fills_ashs_budget_still_carries_the_operators_skip_variable(
    tmp_path, monkeypatch
):
    """The links' tokens were built first and took the whole budget, so the
    operator's one-entry ``TRIVY_SKIP_DIRS=vendor``, which trivy no longer reads
    once ASH passes a skip flag of its own, was dropped. ASH's tokens have a
    fallback (ASH drops the findings of a path trivy reads); the operator's have
    none, so they are sized first and the links get what is left."""
    scanner = _builtin_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor"}
    _fill_the_budget_for_ten_ignored_files(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    assert "--skip-dirs=vendor" in argv, argv
    assert len([a for a in argv if a.startswith("--skip-files=")]) == 9, argv
    assert not _operator_warnings(messages), messages


def test_a_tree_that_fills_ashs_budget_still_carries_the_operators_config_skip_files(
    tmp_path, monkeypatch
):
    _operator_config_in_env(
        tmp_path, monkeypatch, "scan:\n  skip-files:\n    - secrets.txt\n"
    )
    scanner = _builtin_scanner(tmp_path)
    _fill_the_budget_for_ten_ignored_files(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    assert "--skip-files=secrets.txt" in argv, argv
    assert not _operator_warnings(messages), messages


def test_trivy_repo_also_keeps_the_operators_skip_variable_when_ashs_budget_is_full(
    tmp_path, monkeypatch
):
    for module in (scanner_plugin, trivy_repo_scanner):
        if hasattr(module, "find_executable"):
            monkeypatch.setattr(module, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor"}
    scanner.dependencies_satisfied = True
    _fill_the_budget_for_ten_ignored_files(monkeypatch)
    report = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": []}],
    }
    argv: list[str] = []

    def _run(self, command, **kwargs):
        argv[:] = [str(a) for a in command]
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(TrivyRepoScanner, "_run_subprocess", autospec=True) as double,
        patch.object(scanner, "_plugin_log"),
    ):
        double.side_effect = _run
        scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    assert "--skip-dirs=vendor" in argv, argv
    assert len([a for a in argv if a.startswith("--skip-files=")]) == 9, argv


def test_the_operator_warning_fires_only_when_the_operators_own_list_overflows(
    tmp_path, monkeypatch
):
    """Beside one skip token of ASH's own (an output directory) the budget holds two
    of the operator's four entries: the other two are named in one warning, the
    links get nothing, and the first two entries are still given to trivy."""
    scanner = _builtin_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa,bbbb,cccc,dddd"}
    _fill_the_budget_for_ten_ignored_files(monkeypatch)
    ashs_own = "--skip-dirs=out"
    one_entry = len("--skip-dirs=aaaa") + 1
    monkeypatch.setattr(
        trivy_base,
        "skip_args_budget",
        lambda environment: len(ashs_own) + 1 + 2 * one_entry + 3,
    )
    messages, logging_patch = _logged(scanner)

    with (
        logging_patch,
        patch.object(
            TrivyScannerBase, "_output_dir_skip_args", return_value=[ashs_own]
        ),
    ):
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    assert [a for a in argv if a.startswith("--skip-dirs=")] == [
        ashs_own,
        "--skip-dirs=aaaa",
        "--skip-dirs=bbbb",
    ], argv
    assert not [a for a in argv if a.startswith("--skip-files=")], argv
    (warning,) = _operator_warnings(messages)
    assert warning.startswith("2 entries"), warning


#: The operator's long second entry and the first entry's token, as a skip-dirs
#: token is counted: the long one does not fit beside the short one.
_SHORT_ENTRY = "aaaa"
_LONG_ENTRY = "x" * 40
_SHORT_ENTRY_TOKEN = len(f"--skip-dirs={_SHORT_ENTRY}") + 1


def _leave_room_for_one_ignored_file_after_the_short_entry(monkeypatch) -> None:
    """Forty ignored files and a budget that holds the short entry, not the long
    one, with 10 bytes to spare beyond one ignored-file token: the share the
    sizing leaves over is big enough for one link token."""
    monkeypatch.setattr(
        trivy_base, "trivy_skip_files", lambda *a, **k: _ignored_files(40)
    )
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    monkeypatch.setattr(
        trivy_base,
        "skip_args_budget",
        lambda environment: _SHORT_ENTRY_TOKEN + _IGNORED_FILE_TOKEN + 10,
    )


def _skip_tokens(argv: list[str]) -> list[str]:
    return [a for a in argv if a.startswith(("--skip-dirs", "--skip-files"))]


def test_an_operator_list_that_does_not_fit_is_left_to_trivy_not_cut_by_the_leftover(
    tmp_path, monkeypatch
):
    """With no skip flag of ASH's own on the command line trivy reads the operator's
    whole list from its variable. The sizing fills the budget to within one entry,
    and the 39 bytes it left over let one ignored file in, which made ASH pass a
    skip flag, moved the operator's list onto the command line and dropped its
    tail: whether the tail applied turned on a few bytes. The links now get
    nothing, so no flag of ASH's replaces the list, and what they leave out is
    said as ASH's own, which has a fallback."""
    scanner = _builtin_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": f"{_SHORT_ENTRY},{_LONG_ENTRY}"}
    _leave_room_for_one_ignored_file_after_the_short_entry(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    assert _skip_tokens(argv) == [], argv
    assert not _operator_warnings(messages), messages
    (links_warning,) = [m for m in messages if "ignored path(s)" in m]
    assert links_warning.startswith("40 ignored path(s)"), links_warning


def test_trivy_repo_also_leaves_an_operator_list_that_does_not_fit_to_trivy(
    tmp_path, monkeypatch
):
    for module in (scanner_plugin, trivy_repo_scanner):
        if hasattr(module, "find_executable"):
            monkeypatch.setattr(module, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": f"{_SHORT_ENTRY},{_LONG_ENTRY}"}
    scanner.dependencies_satisfied = True
    _leave_room_for_one_ignored_file_after_the_short_entry(monkeypatch)
    report = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": []}],
    }
    argv: list[str] = []

    def _run(self, command, **kwargs):
        argv[:] = [str(a) for a in command]
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    messages, logging_patch = _logged(scanner)
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(TrivyRepoScanner, "_run_subprocess", autospec=True) as double,
        logging_patch,
    ):
        double.side_effect = _run
        scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    assert argv, "the double was not run"
    assert _skip_tokens(argv) == [], argv
    assert not _operator_warnings(messages), messages


def test_control_a_list_that_fits_beside_the_short_entry_alone_is_still_given(
    tmp_path, monkeypatch
):
    """The short entry fits, the links get what it leaves and the operator's own
    list is still carried beside them: nothing changes for a list that fits."""
    scanner = _builtin_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": _SHORT_ENTRY}
    _leave_room_for_one_ignored_file_after_the_short_entry(monkeypatch)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    assert f"--skip-dirs={_SHORT_ENTRY}" in argv, argv
    assert len([a for a in argv if a.startswith("--skip-files=")]) == 1, argv
    assert not _operator_warnings(messages), messages


def test_the_operator_overflow_warning_names_the_scan_it_is_about(
    tmp_path, monkeypatch
):
    """One scanner object scans the source and then the converted copy. The warning
    named neither, and was said under a key without the scan, so the second scan's
    overflow, usually a different count because only the source carries the
    output-directory flag, was left unsaid or read as the first one's."""
    scanner = _builtin_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa,bbbb,cccc,dddd"}
    ashs_own = "--skip-dirs=out"
    one_entry = len("--skip-dirs=aaaa") + 1
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: [])
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    monkeypatch.setattr(
        trivy_base,
        "skip_args_budget",
        lambda environment: len(ashs_own) + 1 + 2 * one_entry + 3,
    )
    records: list[tuple[str, dict]] = []

    with (
        patch.object(
            scanner,
            "_plugin_log",
            side_effect=lambda m, **k: records.append((str(m), k)),
        ),
        patch.object(
            TrivyScannerBase, "_output_dir_skip_args", return_value=[ashs_own]
        ),
    ):
        for target_type in ("source", "converted"):
            scanner._execute_scan(Path(scanner.context.source_dir), target_type, [])

    warned = [(m, k) for m, k in records if "operator's skip" in m]
    assert len(warned) == 2, warned
    (first, first_kwargs), (second, second_kwargs) = warned
    assert first.startswith("2 entries"), first
    assert "not apply to the source scan" in first, first
    assert first_kwargs["target_type"] == "source", first_kwargs
    assert second.startswith("2 entries"), second
    assert "not apply to the converted scan" in second, second
    assert second_kwargs["target_type"] == "converted", second_kwargs


def test_trivy_repo_names_the_scan_in_the_operator_overflow_warning(
    tmp_path, monkeypatch
):
    for module in (scanner_plugin, trivy_repo_scanner):
        if hasattr(module, "find_executable"):
            monkeypatch.setattr(module, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "aaaa,bbbb,cccc,dddd"}
    scanner.dependencies_satisfied = True
    ashs_own = "--skip-dirs=out"
    one_entry = len("--skip-dirs=aaaa") + 1
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: [])
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    monkeypatch.setattr(
        trivy_base,
        "skip_args_budget",
        lambda environment: len(ashs_own) + 1 + 2 * one_entry + 3,
    )
    report = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": []}],
    }
    records: list[tuple[str, dict]] = []

    def _run(self, command, **kwargs):
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(TrivyRepoScanner, "_run_subprocess", autospec=True) as double,
        patch.object(
            scanner,
            "_plugin_log",
            side_effect=lambda m, **k: records.append((str(m), k)),
        ),
        patch.object(
            TrivyScannerBase, "_output_dir_skip_args", return_value=[ashs_own]
        ),
    ):
        double.side_effect = _run
        scanner.scan(target=Path(scanner.context.source_dir), target_type="converted")

    ((warning, kwargs),) = [(m, k) for m, k in records if "operator's skip" in m]
    assert "not apply to the converted scan" in warning, warning
    assert kwargs["target_type"] == "converted", kwargs


# --- the operator's entries are sized once for a scan target -----------------------


def _three_ignored_files(monkeypatch) -> None:
    monkeypatch.setattr(
        trivy_base, "trivy_skip_files", lambda *a, **k: _ignored_files(3)
    )
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])


def test_the_operators_config_lists_are_read_once_for_a_scan_target(
    tmp_path, monkeypatch
):
    """Sizing the entries and giving them back were two passes, each opening and
    parsing the operator's config file for both lists: four reads of the file, of
    a large generated list, for one target. The entries are sized once and the
    result is handed to the second step."""
    _operator_config_in_env(
        tmp_path, monkeypatch, "scan:\n  skip-files:\n    - secrets.txt\n"
    )
    _three_ignored_files(monkeypatch)
    scanner = _builtin_scanner(tmp_path)
    messages, logging_patch = _logged(scanner)

    with (
        logging_patch,
        patch.object(
            scanner, "_config_file_list", wraps=scanner._config_file_list
        ) as reads,
    ):
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    keys = [
        call.args[2]
        for call in reads.call_args_list
        if call.args[2] in ("skip-dirs", "skip-files")
    ]
    assert keys == ["skip-dirs", "skip-files"], keys
    assert "--skip-files=secrets.txt" in argv, argv
    assert len([a for a in argv if a.startswith("--skip-files=ignored/")]) == 3, argv


def test_an_operator_entry_equal_to_an_ignored_path_is_passed_once(
    tmp_path, monkeypatch
):
    """The entries are sized before the links are built, so a link token can equal
    one of them; the token is on the command line once."""
    _three_ignored_files(monkeypatch)
    scanner = _builtin_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_FILES": "ignored/000.txt,keep.txt"}

    argv, _, _ = scanner._execute_scan(Path(scanner.context.source_dir), "source", [])

    assert argv.count("--skip-files=ignored/000.txt") == 1, argv
    assert "--skip-files=keep.txt" in argv, argv


def test_control_a_line_break_entry_is_said_once_for_both_targets_of_a_scanner(
    tmp_path, monkeypatch
):
    _three_ignored_files(monkeypatch)
    _operator_config_in_env(
        tmp_path, monkeypatch, 'scan:\n  skip-dirs:\n    - "zz\\nzz"\n    - vendor\n'
    )
    scanner = _builtin_scanner(tmp_path)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        for target_type in ("source", "converted"):
            argv, _, _ = scanner._execute_scan(
                Path(scanner.context.source_dir), target_type, []
            )
            assert "--skip-dirs=vendor" in argv, argv

    (warning,) = [m for m in messages if "holds a line break" in m]
    assert "entry 1 of scan.skip-dirs" in warning, warning


def test_control_a_line_break_entry_is_not_said_when_ash_passes_no_skip_flag(
    tmp_path, monkeypatch
):
    """With no skip flag of ASH's, trivy reads the operator's list itself and
    nothing of it is left out, so there is nothing to report."""
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: [])
    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", lambda *a, **k: [])
    _operator_config_in_env(
        tmp_path, monkeypatch, 'scan:\n  skip-dirs:\n    - "zz\\nzz"\n    - vendor\n'
    )
    scanner = _builtin_scanner(tmp_path)
    messages, logging_patch = _logged(scanner)

    with logging_patch:
        argv, _, _ = scanner._execute_scan(
            Path(scanner.context.source_dir), "source", []
        )

    assert _skip_tokens(argv) == [], argv
    assert not [m for m in messages if "holds a line break" in m], messages


# --- the operator's entries on a Windows command line ------------------------------


def test_operator_entries_with_spaces_are_counted_as_the_windows_line_builds_them(
    tmp_path, monkeypatch
):
    """CreateProcess holds the whole command line to 32,767 UTF-16 units, and
    ``subprocess.list2cmdline`` wraps an argument that holds a space in quotes. The
    operator's tokens were counted by their bytes, without those quotes, so a long
    list of directories with a space in the name overflowed the budget on the line
    that was built and left no room for the rest of trivy's argv."""
    scanner = _repo_scanner(tmp_path)
    names = [f"dir {index:04d} with space" for index in range(2000)]
    scanner.extra_env = {"TRIVY_SKIP_DIRS": ",".join(names)}
    _platform(monkeypatch, "win32")
    ashs_own = "--skip-dirs=.ash/ash_output"

    with patch.object(scanner, "_plugin_log"):
        tokens = scanner._operator_skip_args([ashs_own])

    line = subprocess.list2cmdline([ashs_own, *tokens])
    assert 0 < len(tokens) < 2000
    assert len(line.encode("utf-16-le")) // 2 < trivy_base._WINDOWS_SKIP_ARGS_BUDGET


def test_control_operator_skip_entries_without_spaces_count_as_their_bytes(
    tmp_path, monkeypatch
):
    scanner = _repo_scanner(tmp_path)
    scanner.extra_env = {"TRIVY_SKIP_DIRS": "vendor,build"}
    _platform(monkeypatch, "win32")

    with patch.object(scanner, "_plugin_log"):
        tokens = scanner._operator_skip_args(["--skip-dirs=.ash/ash_output"])

    assert tokens == ["--skip-dirs=vendor", "--skip-dirs=build"]
