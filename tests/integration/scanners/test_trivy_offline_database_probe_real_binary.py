# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The offline database check of trivy-repo, run against a real trivy binary.

The unit tests of the trivy base replace the probe (``content_db_staleness``) that
the offline check runs, so they read the same on every machine. This test runs it:
``trivy version`` against a cache directory with no database in it, and expects
the scanner to land as unavailable for want of a database. The probe's
``ContentDatabaseAbsent`` is a ``ValueError``, the arm the check reads as no
database, and a release of trivy that handled an empty ``--cache-dir`` another way
would show here and nowhere else. Skipped when no trivy executable is on PATH.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)

PluginContext.model_rebuild(_types_namespace={"AshConfig": AshConfig})

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("trivy") is None, reason="needs a trivy executable on PATH"
    ),
]


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    """The probe reads no cache, config or scanner set from the shell."""
    for name in ("TRIVY_CONFIG", "TRIVY_CACHE_DIR", "TRIVY_SCANNERS", "ASH_OFFLINE"):
        monkeypatch.delenv(name, raising=False)


def _scanner(tmp_path: Path) -> TrivyRepoScanner:
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
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(
                ignore_unfixed=False, scanners=[], offline=True
            )
        ),
    )


def test_the_real_probe_reads_an_empty_cache_as_a_missing_database(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    empty_cache = tmp_path / "cache" / "empty"
    empty_cache.mkdir(parents=True)
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: empty_cache)
    messages: list[str] = []

    with patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: messages.append(str(m))
    ):
        assert scanner._offline_database_available() is False

    assert "no vulnerability database" in scanner.dependency_unavailable_reason
    assert not [m for m in messages if "could not check" in m], messages
