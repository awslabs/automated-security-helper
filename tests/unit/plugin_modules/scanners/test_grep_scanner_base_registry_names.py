# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A registry ruleset name is never read as a local rules path.

Offline, a local file or directory in ``options.config`` is the scan's rules. The
test for "local" was "the path exists", so a directory in ASH's working directory
that happens to be named like a registry entry (``p/ci``) was read as the operator's
local rules, and the registry cache was skipped for it. Registry spellings (``auto``,
``p/<ruleset>``, ``r/<rule-id>``) are now never local; a local path that shares the
name is spelled ``./p/ci`` or absolutely.

Building the scanners probes uv and opengrep; the unit conftest's tool guard answers
the probes as a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

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


@pytest.mark.parametrize("name", ["p/ci", "r/python.lang.security.audit", "auto"])
def test_a_registry_name_is_not_local_rules_even_when_a_path_of_that_name_exists(
    test_plugin_context, tmp_path, monkeypatch, name
):
    """Fails at the base: the existing ``p/ci`` directory was read as local rules,
    so no cache reason was recorded and the directory became ``--config``."""
    (tmp_path / name).mkdir(parents=True)
    (tmp_path / name / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=True, config=name)
        ),
    )

    assert "SEMGREP_RULES_CACHE_DIR" in (scanner.dependency_unavailable_reason or "")
    assert (tmp_path / name).as_posix() not in _configs(scanner)


def test_a_local_path_spelled_as_one_is_local_rules(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: the same directory named ``./p/ci`` is the operator's rules."""
    (tmp_path / "p" / "ci").mkdir(parents=True)
    (tmp_path / "p" / "ci" / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)

    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(
            options=SemgrepScannerConfigOptions(offline=True, config="./p/ci")
        ),
    )

    assert scanner.dependency_unavailable_reason is None
    assert any(value.endswith("/p/ci") for value in _configs(scanner)), _configs(
        scanner
    )
