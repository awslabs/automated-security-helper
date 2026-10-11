# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan, the update and the database probes agree on one cache, and the probes
read nothing from the scanned tree.

One gap waits on the content-database probe helper in #792 and is marked
xfail(strict=True): when the helper lands and the trivy scanners use it, it
passes, strict xfail turns that into a failure, and the mark comes off.

* The scan is given ``--cache-dir`` from ``content_db_refresh.default_cache_dir``,
  which is ``TRIVY_CACHE_DIR`` or the platform default under ``$HOME``
  (``~/.cache/trivy``, ``~/Library/Caches/trivy`` on macOS) and leaves out
  ``XDG_CACHE_HOME``, which the sandbox does not pass. trivy outside a sandbox
  follows ``XDG_CACHE_HOME``, and the post-scan staleness probe runs ``trivy
  version`` with no ``--cache-dir``, so the probe can read a different cache from
  the one the scan read. Offline scans pass no ``--cache-dir`` at all.

The other is closed here. The offline dependency check
(``TrivyScanner.validate_plugin_dependencies``) and the post-scan staleness probe
both ran ``trivy version`` from ASH's working directory with no ``--config``. A
``trivy.yaml`` there was loaded, and its ``cache.dir`` decided which database they
measured (trivy 0.75.0: a planted ``cache.dir`` with a ``metadata.json`` dated 2099
was reported as the database; on 2026-10-11 a ``trivy.yaml`` in the working
directory naming an empty ``cache.dir`` made ``trivy version`` report no database
while ``--config`` with an empty file reported the real one). Both now run from an
empty directory with an explicit ``--config``: the file the scan passed trivy,
or an empty one.
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
    "waits for the content-database probe helper in #792: the staleness probe given "
    "the scan's cache dir, and that cache dir used offline too"
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
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=_PENDING)
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


def _fake_trivy(tmp_path: Path, monkeypatch) -> Path:
    from automated_security_helper.utils import subprocess_utils

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "calls.jsonl"
    fake = bin_dir / "trivy"
    fake.write_text(_FAKE_TRIVY.format(python=sys.executable, record=str(record)))
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    return record


def _config_flag(argv):
    for i, arg in enumerate(argv):
        if arg == "--config":
            return argv[i + 1]
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
    return None


@pytest.mark.skipif(os.name == "nt", reason="the stand-in trivy is a POSIX script")
def test_the_post_scan_probe_reads_nothing_from_the_working_directory(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils.content_db_staleness import (
        ProbeContext,
        _built_from_trivy,
    )

    record = _fake_trivy(tmp_path, monkeypatch)
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    (source / "trivy.yaml").write_text("cache:\n  dir: sentinel-cache\n")
    monkeypatch.chdir(source)

    _built_from_trivy(
        ProbeContext(env=dict(os.environ), executable=str(tmp_path / "bin" / "trivy"))
    )

    (call,) = [json.loads(line) for line in record.read_text().splitlines()]
    assert not Path(call["cwd"]).resolve().is_relative_to(source.resolve())
    config = _config_flag(call["argv"])
    assert config is not None, call
    assert not Path(config).resolve().is_relative_to(source.resolve())


@pytest.mark.skipif(os.name == "nt", reason="the stand-in trivy is a POSIX script")
def test_the_probe_reads_through_the_config_the_scan_passed(tmp_path, monkeypatch):
    """An operator's trivy.yaml can name the cache; the probe must read that one."""
    record = _fake_trivy(tmp_path, monkeypatch)
    source = tmp_path / "repo"
    source.mkdir()
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text("cache:\n  dir: /operator/cache\n")
    config = AshConfig()
    # The operator's own value: from --config-overrides, outside the tree.
    record_provenance(
        config,
        in_tree=[],
        config_overrides=[f"scanners.trivy.options.config_file={operator}"],
    )
    scanner = TrivyScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=TrivyScannerConfig(
            enabled=True,
            options=TrivyScannerConfigOptions(config_file=str(operator)),
        ),
    )
    scanner.results_dir = tmp_path / "results"
    scanner.results_dir.mkdir()
    argv, _, _ = scanner._execute_scan(source, "source", [])
    passed = [a.split("=", 1)[1] for a in argv if a.startswith("--config=")]

    probe = scanner.content_database_probe_context()

    assert passed == [operator.resolve().as_posix()]
    assert probe.config_file == passed[0]
    from automated_security_helper.utils.content_db_staleness import _built_from_trivy

    _built_from_trivy(probe)
    (call,) = [json.loads(line) for line in record.read_text().splitlines()]
    assert _config_flag(call["argv"]) == passed[0]


@pytest.mark.skipif(os.name == "nt", reason="the stand-in trivy is a POSIX script")
def test_a_probe_whose_temporary_directory_is_in_a_checkout_runs_from_the_root(
    tmp_path, monkeypatch
):
    """The probe's scratch directory is made in the temporary directory; when that is
    inside a checkout, trivy runs from the filesystem root instead."""
    import tempfile

    from automated_security_helper.utils.content_db_staleness import (
        ProbeContext,
        _built_from_trivy,
    )

    record = _fake_trivy(tmp_path, monkeypatch)
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "tmp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(checkout / "tmp"))

    _built_from_trivy(
        ProbeContext(env=dict(os.environ), executable=str(tmp_path / "bin" / "trivy"))
    )

    (call,) = [json.loads(line) for line in record.read_text().splitlines()]
    # Not vacuous: the probe's empty config was written inside the checkout.
    assert checkout.resolve() in Path(_config_flag(call["argv"])).resolve().parents
    cwd = Path(call["cwd"])
    assert not any((p / ".git").exists() for p in [cwd, *cwd.parents])
    assert cwd == Path(cwd.anchor)
