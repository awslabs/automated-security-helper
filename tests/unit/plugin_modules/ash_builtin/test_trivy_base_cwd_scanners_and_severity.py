# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the shared trivy base reads from the host, trivy's settings and trivy's SARIF.

Three readings that went wrong before, each shared by ``trivy`` and ``trivy-repo``:

- The working directory was read (``Path.cwd()``) whenever the trivy configuration
  was resolved, to anchor ``TRIVY_CONFIG``, ``TRIVY_IGNOREFILE`` and
  ``TRIVY_SECRET_CONFIG``, so a deleted working directory crashed config resolution
  even with none of them set. It is read only for a relative value, and when it
  cannot be read then, the variable is ignored with a warning naming it.
- The offline Terraform-check removal keyed on ``options.scanners`` alone, so a
  trivy-repo run with ``scanners: []`` whose trivy settings (``TRIVY_SCANNERS``, or
  the operator's ``trivy.yaml``) turn on ``misconfig`` ran trivy's Terraform scanner
  offline, which downloads module sources. The effective scanner set is read as
  trivy reads it: the option, else the variable, else the config file, else
  trivy's default.
- A result's severity was the FIRST ``Severity:`` line of its message, but trivy
  writes the scanned file's path (``Artifact:``) before its own ``Severity:`` line,
  so a path holding a line break followed by that prefix decided the finding's ASH
  severity. No position tells trivy's line from text the tree writes, so the rule
  is by level: only a ``Severity:`` line whose name agrees with the result's SARIF
  level counts, and the highest of those is read. When none agrees, the rule's
  tag rates the result, if the tag agrees with the level too.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    trivy_severity,
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
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG

pytestmark = pytest.mark.unit

TRIVY_VARIABLES = ("TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG")


def _scanner(tmp_path: Path, **options) -> TrivyRepoScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    return TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )


@pytest.fixture(autouse=True)
def no_trivy_variables(monkeypatch):
    for name in TRIVY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("TRIVY_SCANNERS", raising=False)


def _delete_cwd(tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)
    with pytest.raises(FileNotFoundError):
        Path.cwd()


# --- a deleted working directory ---------------------------------------------------


def test_a_deleted_working_directory_does_not_fail_the_trivy_configuration(
    tmp_path, monkeypatch
):
    """With none of the variables set, no relative path needs the working
    directory, so a deleted one is never read."""
    scanner = _scanner(tmp_path)
    _delete_cwd(tmp_path, monkeypatch)

    assert scanner._trivy_config_file() == EMPTY_TOOL_CONFIG.as_posix()
    assert Path(scanner._ignore_file()).is_file()
    assert Path(scanner._secret_config_file()).is_file()


def test_a_relative_variable_with_no_working_directory_is_ignored_by_name(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    monkeypatch.setenv("TRIVY_CONFIG", "relative-dir/trivy.yaml")
    _delete_cwd(tmp_path, monkeypatch)
    logged: list[str] = []

    with patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: logged.append(str(m))
    ):
        chosen = scanner._trivy_config_file()

    assert chosen == EMPTY_TOOL_CONFIG.as_posix()
    warnings = [m for m in logged if "TRIVY_CONFIG" in m]
    assert warnings, logged
    assert all("relative-dir" not in m for m in warnings), warnings


def test_control_a_relative_variable_with_a_live_working_directory_is_anchored(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    here = tmp_path / "launched-here"
    here.mkdir()
    operator = here / "trivy.yaml"
    operator.write_text("scan:\n  scanners:\n    - vuln\n", encoding="utf-8")
    monkeypatch.chdir(here)
    monkeypatch.setenv("TRIVY_CONFIG", "trivy.yaml")

    assert scanner._trivy_config_file() == Path(os.path.realpath(operator)).as_posix()


# --- the effective scanner set -----------------------------------------------------


def _defaults(*names):
    return lambda *args, **kwargs: list(names)


def test_with_scanners_unset_a_misconfig_turned_on_by_the_environment_is_handled(
    tmp_path, monkeypatch
):
    """``scanners: []`` passes no --scanners, so trivy reads TRIVY_SCANNERS; offline,
    its Terraform scanner is left out as it is when the option names misconfig."""
    scanner = _scanner(tmp_path, scanners=[], offline=True)
    monkeypatch.setenv("TRIVY_SCANNERS", "vuln,misconfig")
    final_args = ["trivy", "repository", f"--config={EMPTY_TOOL_CONFIG}", "/src"]

    with (
        patch.object(
            trivy_repo_scanner,
            "trivy_default_misconfig_scanners",
            _defaults("terraform", "cloudformation", "dockerfile"),
        ),
        patch.object(scanner, "_plugin_log"),
    ):
        args = scanner._offline_misconfig_args(final_args)

    assert "--misconfig-scanners=cloudformation,dockerfile" in args, args


def test_with_scanners_unset_a_misconfig_turned_on_by_the_config_file_is_handled(
    tmp_path,
):
    scanner = _scanner(tmp_path, scanners=[], offline=True)
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text("scan:\n  scanners:\n    - misconfig\n", encoding="utf-8")
    final_args = ["trivy", "repository", f"--config={operator.as_posix()}", "/src"]

    with (
        patch.object(
            trivy_repo_scanner,
            "trivy_default_misconfig_scanners",
            _defaults("terraform", "cloudformation"),
        ),
        patch.object(scanner, "_plugin_log"),
    ):
        args = scanner._offline_misconfig_args(final_args)

    assert "--misconfig-scanners=cloudformation" in args, args


def test_control_with_scanners_unset_and_nothing_turning_misconfig_on_nothing_changes(
    tmp_path,
):
    """trivy's own default is vuln and secret, so there is no Terraform scanner to
    leave out and the arguments are passed through."""
    scanner = _scanner(tmp_path, scanners=[], offline=True)
    final_args = ["trivy", "repository", f"--config={EMPTY_TOOL_CONFIG}", "/src"]

    with patch.object(scanner, "_plugin_log"):
        assert scanner._offline_misconfig_args(final_args) == final_args


def test_the_effective_scanners_read_the_option_first(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, scanners=["vuln"])
    monkeypatch.setenv("TRIVY_SCANNERS", "misconfig")

    assert scanner._effective_scanners() == ["vuln"]


# --- trivy's severity line ---------------------------------------------------------


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


def test_a_severity_line_inside_the_artifact_path_does_not_decide_the_severity():
    """The scanned file's path comes first in trivy's message. A name holding a
    line break and the prefix spells a severity line before trivy's own. The
    injected CRITICAL disagrees with the ``note`` level, so it does not count; the
    rule's tag disagrees with trivy's line too (MEDIUM), so a reader that skipped
    every severity line and fell back to the tag would not answer LOW."""
    message = (
        "Artifact: iac/evil\nSeverity: CRITICAL\n.tf\n"
        "Type: terraform\n"
        "Misconfiguration AVD-AWS-0001\n"
        "Severity: LOW\n"
        "Message: Bucket has no logging\n"
        "Link: [AVD-AWS-0001](https://example.invalid/AVD-AWS-0001)"
    )

    assert trivy_severity(*_run(message, tags=("MEDIUM",))) == "LOW"


def test_control_trivys_own_severity_line_is_read():
    """The rule's tag disagrees with the message line (and with the level), so
    only the message line can answer HIGH: a reader that fell through to the tag
    would answer None."""
    message = (
        "Artifact: iac/main.tf\nType: terraform\nMisconfiguration AVD-AWS-0001\n"
        "Severity: HIGH\nMessage: Bucket has no logging"
    )

    assert trivy_severity(*_run(message, level="error", tags=("MEDIUM",))) == "HIGH"


def test_a_severity_line_inside_the_checks_message_does_not_decide_the_severity():
    """``Message:`` comes AFTER trivy's own line and quotes names from the manifest
    (a Kubernetes check names the container). A name holding a line break and the
    prefix spells a severity line after trivy's. The injected line disagrees with
    the result's level, which the manifest cannot write, so trivy's line is read;
    the rule tag disagrees too, so only that line can answer HIGH."""
    message = (
        "Artifact: k8s/deploy.yaml\nType: kubernetes\nMisconfiguration KSV001\n"
        "Severity: HIGH\n"
        "Message: Container 'app\nSeverity: LOW\n' of Deployment 'web' runs as root\n"
        "Link: [KSV001](https://example.invalid/KSV001)"
    )

    assert trivy_severity(*_run(message, level="error", tags=("MEDIUM",))) == "HIGH"


def test_a_carriage_return_inside_the_matched_line_does_not_start_a_severity_line():
    """``Match:`` is the scanned line itself. trivy writes ``\\n`` between its
    lines, so a ``\\r`` inside the match stays inside that line (``str.splitlines``
    would have broken on it)."""
    message = (
        "Artifact: config.ini\nType: secret\nSecret AWS Access Key ID\n"
        "Severity: HIGH\n"
        "Match: key = AKIA****\rSeverity: LOW\n"
        "Link: [aws-access-key-id](https://example.invalid/aws-access-key-id)"
    )

    assert trivy_severity(*_run(message, level="error", tags=("MEDIUM",))) == "HIGH"


def test_a_message_whose_only_severity_line_disagrees_with_the_level_falls_to_the_tag():
    """With no line agreeing with the level, every severity line is tree text, and
    the rule's tag, which agrees with the level, rates the result."""
    message = (
        "Artifact: iac/a\nSeverity: LOW\n.tf\nType: terraform\n"
        "Misconfiguration AVD-AWS-0001\nMessage: Bucket has no logging"
    )

    assert trivy_severity(*_run(message, level="error", tags=("HIGH",))) == "HIGH"


def test_a_rating_of_unknown_from_trivy_is_left_to_the_generic_mapping():
    """trivy's fifth severity, written with the ``note`` level: not one ASH reports
    by name, and not replaced by another package's tag either."""
    message = "Misconfiguration AVD-AWS-0001\nSeverity: UNKNOWN\nMessage: Bucket"

    assert trivy_severity(*_run(message, level="note", tags=("LOW",))) is None


def test_a_lower_severity_line_of_the_same_level_does_not_lower_the_rating():
    """CRITICAL and HIGH share the ``error`` level, so the level cannot tell
    trivy's CRITICAL from a HIGH the matched line spells after it. The higher name
    is read: tree text can never lower a rating."""
    message = (
        "Artifact: config.ini\nType: secret\nSecret AWS Access Key ID\n"
        "Severity: CRITICAL\n"
        "Match: key = AKIA****\nSeverity: HIGH\n"
        "Link: [aws-access-key-id](https://example.invalid/aws-access-key-id)"
    )

    assert trivy_severity(*_run(message, level="error", tags=("MEDIUM",))) == "CRITICAL"


def test_an_unknown_line_of_the_same_level_does_not_drop_a_low_rating():
    """UNKNOWN shares LOW's ``note`` level. A LOW trivy wrote stays LOW when the
    check's message spells an UNKNOWN line after it; on its own, trivy's UNKNOWN
    is still left to the generic mapping."""
    message = (
        "Misconfiguration AVD-AWS-0001\nSeverity: LOW\n"
        "Message: Bucket 'logs\nSeverity: UNKNOWN\n' has no logging"
    )

    assert trivy_severity(*_run(message, level="note", tags=("MEDIUM",))) == "LOW"


def test_with_no_level_the_highest_severity_line_is_read():
    """A result with no SARIF level gives nothing to check the lines against, so
    every line counts and the highest is read: an injected lower line still cannot
    lower trivy's rating."""
    message = (
        "Artifact: iac/main.tf\nType: terraform\nMisconfiguration AVD-AWS-0001\n"
        "Severity: HIGH\n"
        "Message: Bucket 'b\nSeverity: LOW\n' has no logging"
    )

    assert trivy_severity(*_run(message, level=None, tags=("MEDIUM",))) == "HIGH"


def test_a_name_trivy_never_writes_is_not_a_severity_line():
    """``Severity: EXTREME`` is not one of trivy's five names, whatever its level:
    after trivy's own line it changes nothing, and on its own it leaves the
    message with no severity line, so the rule's tag rates the result."""
    after_trivys = (
        "Misconfiguration AVD-AWS-0001\nSeverity: LOW\n"
        "Message: Bucket 'b\nSeverity: EXTREME\n' has no logging"
    )
    alone = "Artifact: iac/x\nSeverity: EXTREME\n.tf\nMisconfiguration AVD-AWS-0001"

    assert trivy_severity(*_run(after_trivys, level="note", tags=("MEDIUM",))) == "LOW"
    assert trivy_severity(*_run(alone, level="error", tags=("HIGH",))) == "HIGH"
    assert trivy_severity(*_run(alone, level=None, tags=("HIGH",))) == "HIGH"


def test_with_no_severity_line_the_tag_rates_the_result_only_when_the_level_agrees():
    message = "Misconfiguration AVD-AWS-0001\nMessage: Bucket has no logging"

    assert trivy_severity(*_run(message, level="note", tags=("LOW",))) == "LOW"
    assert trivy_severity(*_run(message, level="error", tags=("LOW",))) is None
