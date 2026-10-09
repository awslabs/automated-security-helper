# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan, the update and the database probes agree on one cache, and the probes
read nothing from the scanned tree.

Two gaps, both waiting on the content-database probe helper in #792, and so both
marked xfail(strict=True): when the helper lands and the trivy scanners use it,
these pass, strict xfail turns that into a failure, and the marks come off.

* The scan is given ``--cache-dir`` from ``content_db_refresh.default_cache_dir``,
  which is ``TRIVY_CACHE_DIR`` or the platform default under ``$HOME``
  (``~/.cache/trivy``, ``~/Library/Caches/trivy`` on macOS) and leaves out
  ``XDG_CACHE_HOME``, which the sandbox does not pass. trivy outside a sandbox
  follows ``XDG_CACHE_HOME``, and the post-scan staleness probe runs ``trivy
  version`` with no ``--cache-dir``, so the probe can read a different cache from
  the one the scan read. Offline scans pass no ``--cache-dir`` at all.
* The offline dependency check (``TrivyScanner.validate_plugin_dependencies``)
  runs ``trivy version`` from ASH's working directory with no ``--config``. A
  ``trivy.yaml`` there is loaded, and its ``cache.dir`` decides which database the
  check sees (measured with trivy 0.75.0: a planted ``cache.dir`` with a
  ``metadata.json`` dated 2099 was reported as the database).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance

PluginContext.model_rebuild()

_PENDING = (
    "waits for the content-database probe helper in #792: the staleness probe run "
    "in isolation and given the scan's cache dir, and that cache dir used offline too"
)


def _scanner(tmp_path: Path, source: Path, **options) -> TrivyScanner:
    config = AshConfig()
    record_provenance(config, in_tree=[])
    return TrivyScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(**options)
        ),
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="trivy's XDG rule is Linux's"
)
@pytest.mark.xfail(strict=True, reason=_PENDING)
@pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
def test_the_scan_and_the_staleness_probe_read_one_cache(
    tmp_path, monkeypatch, offline
):
    monkeypatch.delenv("TRIVY_CACHE_DIR", raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    source = tmp_path / "repo"
    source.mkdir()
    monkeypatch.setattr(trivy_base, "prepare_content_db", lambda *a, **k: None)
    ran = []
    monkeypatch.setattr(
        trivy_base.ScannerPluginBase,
        "_run_subprocess",
        lambda self, command, *a, **k: ran.append(list(command)) or {},
    )
    scanner = _scanner(tmp_path, source, offline=offline)

    scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path / "r")

    (command,) = ran
    flags = [a.split("=", 1)[1] for a in command if a.startswith("--cache-dir=")]
    assert len(flags) == 1, command
    cache = Path(flags[0])
    # Where trivy itself keeps its cache with XDG_CACHE_HOME set.
    assert cache == (tmp_path / "xdg" / "trivy").absolute()
    probe = scanner.content_database_probe_context()
    assert probe.cache_dir is not None and Path(probe.cache_dir) == cache


_FAKE_TRIVY = """#!{python}
import json, os, sys
with open({record!r}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({{"cwd": os.getcwd(), "argv": sys.argv[1:]}}) + "\\n")
print(json.dumps({{"Version": "0.75.0",
                  "VulnerabilityDB": {{"UpdatedAt": "2026-10-09T00:00:00Z"}}}}))
"""


@pytest.mark.skipif(os.name == "nt", reason="the stand-in trivy is a POSIX script")
@pytest.mark.xfail(strict=True, reason=_PENDING)
def test_the_offline_database_check_reads_nothing_from_the_tree(tmp_path, monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    (source / "trivy.yaml").write_text("cache:\n  dir: sentinel-cache\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "calls.jsonl"
    fake = bin_dir / "trivy"
    fake.write_text(_FAKE_TRIVY.format(python=sys.executable, record=str(record)))
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    # ASH started from inside the repository it scans.
    monkeypatch.chdir(source)
    config = resolve_config(source_dir=source)
    scanner = TrivyScanner(
        context=PluginContext(
            source_dir=source, output_dir=tmp_path / "out", config=config
        ),
        config=TrivyScannerConfig(enabled=True, options=TrivyScannerConfigOptions()),
    )

    assert scanner.validate_plugin_dependencies(), scanner.dependency_unavailable_reason

    calls = [json.loads(line) for line in record.read_text().splitlines()]
    probes = [c for c in calls if c["argv"][:1] == ["version"]]
    assert probes, calls  # not vacuous: the check ran trivy
    for call in probes:
        assert not Path(call["cwd"]).resolve().is_relative_to(source.resolve())
        assert any(a == "--config" or a.startswith("--config=") for a in call["argv"])
