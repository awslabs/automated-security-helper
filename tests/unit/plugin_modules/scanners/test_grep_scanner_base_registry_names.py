# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A registry ruleset name is never read as a local rules path, and a local rules
path is judged the way every tool path option is.

Offline, a local file or directory in ``options.config`` is the scan's rules. The
test for "local" was "the path exists in ASH's working directory", so a directory
there that happens to be named like a registry entry (``p/ci``) was read as the
operator's local rules, and the registry cache was skipped for it. Registry
spellings (``auto``, ``p/<ruleset>``, ``r/<rule-id>``, ``s/<snippet>``) are now
never local, and a local path goes through ``config/path_trust.honored_path``: it
is taken from the source directory, and one inside the scanned tree is refused, so
the scanned repository cannot ship the rules it is scanned with.

Building the scanners probes uv and opengrep; the unit conftest's tool guard answers
the probes as a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit

RULE = "rules:\n  - id: placeholder\n    languages: [python]\n    message: m\n    severity: INFO\n    pattern: $X == $X\n"


def _configs(scanner) -> list[str]:
    return [arg.value for arg in scanner.args.extra_args if arg.key == "--config"]


def _offline_scanner(test_plugin_context, config: str) -> SemgrepScanner:
    return SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=True, config=config)
        ),
    )


@pytest.mark.parametrize(
    "name",
    [
        "p/ci",
        "r/python.lang.security.audit",
        "s/some-snippet",
        "auto",
        "policy",
        "secrets",
    ],
)
def test_a_registry_name_is_not_local_rules_even_when_a_path_of_that_name_exists(
    test_plugin_context, tmp_path, monkeypatch, name
):
    """Fails at the base: the existing ``p/ci`` directory was read as local rules,
    so no cache reason was recorded and the directory became ``--config``.

    The directory exists both in ASH's working directory and in the source
    directory, the two places a relative path has been taken from, and neither
    copy is read: the name is the registry's, or one of the product names semgrep
    reserves (``policy``, ``secrets``), which the tool resolves before any path.
    """
    source_dir = Path(test_plugin_context.source_dir)
    for root in (tmp_path, source_dir):
        (root / name).mkdir(parents=True, exist_ok=True)
        (root / name / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    scanner = _offline_scanner(test_plugin_context, name)

    assert "SEMGREP_RULES_CACHE_DIR" in (scanner.dependency_unavailable_reason or "")
    # The two directories by resolved path, as the scanner emits them: a bare
    # substring test would read "auto" inside the bundled rules' own path
    # (automated_security_helper/...).
    planted = {
        Path(os.path.realpath(root / name)).as_posix()
        for root in (tmp_path, source_dir)
    }
    assert not planted.intersection(_configs(scanner)), _configs(scanner)


def test_a_local_path_outside_the_tree_is_local_rules(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: the same directory, outside the scanned tree and named by its
    path, is the operator's rules."""
    (tmp_path / "p" / "ci").mkdir(parents=True)
    (tmp_path / "p" / "ci" / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    scanner = _offline_scanner(test_plugin_context, str(tmp_path / "p" / "ci"))

    assert scanner.dependency_unavailable_reason is None
    assert any(value.endswith("/p/ci") for value in _configs(scanner)), _configs(
        scanner
    )


def test_a_local_path_inside_the_scanned_tree_is_refused(
    test_plugin_context, monkeypatch, caplog
):
    """Fails at the base: ``./p/ci`` was resolved against ASH's working directory
    and accepted wherever it sat. A rules directory the scanned repository ships is
    not passed to the tool, the scanner declines with a reason naming the option
    (it does not fall back to the cache: the operator asked for those rules), and
    the path-trust refusal is logged once with the option's key."""
    source_dir = Path(test_plugin_context.source_dir)
    (source_dir / "p" / "ci").mkdir(parents=True, exist_ok=True)
    (source_dir / "p" / "ci" / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(source_dir)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    with caplog.at_level("WARNING"):
        scanner = _offline_scanner(test_plugin_context, "./p/ci")

    reason = scanner.dependency_unavailable_reason or ""
    assert "scanners.semgrep.options.config" in reason, reason
    assert "SEMGREP_RULES_CACHE_DIR" not in reason, reason
    assert scanner.validate_plugin_dependencies() is False
    assert not any(value.endswith("/p/ci") for value in _configs(scanner)), _configs(
        scanner
    )
    assert (
        sum(
            "scanners.semgrep.options.config" in record.getMessage()
            for record in caplog.records
        )
        == 1
    ), [record.getMessage() for record in caplog.records]
