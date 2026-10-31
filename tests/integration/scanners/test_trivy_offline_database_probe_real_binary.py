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
from automated_security_helper.utils.content_db_staleness import (
    ContentDatabaseAbsent,
    _built_from_trivy,
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


def _scanner_with_an_empty_cache(tmp_path, monkeypatch) -> TrivyRepoScanner:
    scanner = _scanner(tmp_path)
    empty_cache = tmp_path / "cache" / "empty"
    empty_cache.mkdir(parents=True)
    monkeypatch.setattr(TrivyRepoScanner, "_trivy_cache_dir", lambda self: empty_cache)
    return scanner


def test_the_real_probe_raises_the_missing_database_error_for_an_empty_cache(
    tmp_path, monkeypatch
):
    """Every ``ValueError`` the probe builds says ``no vulnerability database`` once
    the scanner wraps it, so the scanner-level test below cannot tell an empty cache
    from a changed ``trivy version`` layout or a missing executable. The probe's own
    ``ContentDatabaseAbsent`` can."""
    scanner = _scanner_with_an_empty_cache(tmp_path, monkeypatch)

    with pytest.raises(ContentDatabaseAbsent):
        _built_from_trivy(scanner.content_database_probe_context())


def test_the_real_probe_reads_an_empty_cache_as_a_missing_database(
    tmp_path, monkeypatch
):
    scanner = _scanner_with_an_empty_cache(tmp_path, monkeypatch)
    messages: list[str] = []

    with patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: messages.append(str(m))
    ):
        assert scanner._offline_database_available() is False

    assert "no vulnerability database" in scanner.dependency_unavailable_reason
    # The text only ContentDatabaseAbsent carries: the other ValueErrors of the
    # probe (nothing printed, invalid JSON, an unreadable metadata file) do not.
    assert "no trivy database was found" in scanner.dependency_unavailable_reason
    assert not [m for m in messages if "could not check" in m], messages
