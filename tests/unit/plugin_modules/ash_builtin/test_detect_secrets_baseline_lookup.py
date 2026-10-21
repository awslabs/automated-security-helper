"""The detect-secrets baseline is looked up in the scanned tree, not the working directory.

The defect
----------
``DetectSecretsScanner._process_config_options`` tests each candidate baseline
(``baseline_file``, ``.ash/.secrets.baseline``, ``.secrets.baseline``) with
``Path(candidate).absolute().exists()``, which resolves a relative name against the
process working directory. So:

* ``ash scan --source-dir repo`` run from anywhere but ``repo`` ignores
  ``repo/.secrets.baseline``: its plugin list and filters are not applied, and the
  same tree reports different findings depending on where ASH was started.
* a ``.secrets.baseline`` in the working directory is applied to whatever tree is
  scanned, although it belongs to a different directory.
* a relative ``baseline_file`` is taken from the working directory, while the
  option's own description says "relative to current source directory".

The required behavior: the default names and a relative ``baseline_file`` are
resolved against the source directory, and a baseline in the working directory has
no effect on a scan of another tree.

How the tests observe it
------------------------
The baseline carries a ``should_exclude_file`` filter for ``skipme.py``. Two files in
the tree hold the same planted key id, ``skipme.py`` and ``keepme.py``. With the
baseline applied only ``keepme.py`` is reported; with it ignored both are. The kept
file is what shows the scan ran at all, so no case can pass by reporting nothing.
None of these baselines enables verification, so nothing here uses the network.
"""

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)
from automated_security_helper.utils.offline_tool_env import OFFLINE_TOOL_ENVIRONMENT
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholder.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
EXCLUDE_FILTER_PATH = "detect_secrets.filters.regex.should_exclude_file"


def _baseline_excluding(name: str) -> str:
    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [
                {
                    "path": EXCLUDE_FILTER_PATH,
                    "pattern": [rf"(^|[\\/]){re.escape(name)}$"],
                }
            ],
            "results": {},
            "generated_at": "2026-01-01T00:00:00Z",
        }
    )


def _plant(directory: Path, *names: str) -> None:
    for name in names:
        (directory / name).write_text(f"KEY_ID = '{PLANTED_KEY}'\n", encoding="utf-8")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """None of these baselines verifies; any request would reach only this.

    The in-process scan below also probes every scanner tool's version through
    ``uv tool run`` and the tool itself, online. uv revalidates its index and checkov
    asks PyPI for a newer release whenever their caches are cold, which depends on
    what ran earlier in the process. Those probes are kept off the network the way
    offline mode keeps them off, so a request here can only come from detect-secrets.
    """
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.setenv("UV_OFFLINE", "1")
    for name, value in OFFLINE_TOOL_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    yield proxy
    proxy.close()
    assert proxy.external_requests() == [], proxy.requests


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """A scanned tree, an output dir outside it, and an empty working directory."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = tmp_path / "repo"
    source.mkdir()
    _plant(source, "skipme.py", "keepme.py")
    output = tmp_path / "out"
    output.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    return source, output, cwd


def _scanner(source: Path, output: Path, **options) -> DetectSecretsScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    return DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(**options)
        ),
    )


def _reported_files(scanner: DetectSecretsScanner, source: Path) -> set:
    report = scanner.scan(target=source, target_type="source")
    assert report is not False, "the scan did not run"
    names = set()
    for result in report.runs[0].results:
        text = result.message.root.text
        for candidate in ("skipme.py", "keepme.py"):
            if candidate in text:
                names.add(candidate)
    return names


@pytest.mark.parametrize("name", [".secrets.baseline", ".ash/.secrets.baseline"])
def test_baseline_in_the_source_directory_applies_from_any_working_directory(
    layout, monkeypatch, name
):
    source, output, cwd = layout
    baseline = source / name
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(_baseline_excluding("skipme.py"), encoding="utf-8")
    monkeypatch.chdir(cwd)

    reported = _reported_files(_scanner(source, output), source)

    assert reported == {"keepme.py"}, (
        f"the tree's own {name} was not applied when ASH ran from another "
        f"directory: reported {sorted(reported)}"
    )


def test_relative_baseline_file_is_taken_from_the_source_directory(layout, monkeypatch):
    source, output, cwd = layout
    (source / "config").mkdir()
    (source / "config" / "team.baseline").write_text(
        _baseline_excluding("skipme.py"), encoding="utf-8"
    )
    monkeypatch.chdir(cwd)

    reported = _reported_files(
        _scanner(source, output, baseline_file="config/team.baseline"), source
    )

    assert reported == {"keepme.py"}, (
        "baseline_file='config/team.baseline' was not read from the source "
        f"directory: reported {sorted(reported)}"
    )


@pytest.mark.parametrize("name", [".secrets.baseline", ".ash/.secrets.baseline"])
def test_baseline_in_the_working_directory_does_not_apply_to_another_tree(
    layout, monkeypatch, name
):
    source, output, cwd = layout
    decoy = cwd / name
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_text(_baseline_excluding("keepme.py"), encoding="utf-8")
    monkeypatch.chdir(cwd)

    reported = _reported_files(_scanner(source, output), source)

    assert reported == {"skipme.py", "keepme.py"}, (
        f"the working directory's {name} was applied to a scan of {source}: "
        f"reported {sorted(reported)}"
    )


def test_control_baseline_applies_when_run_from_the_source_directory(
    layout, monkeypatch
):
    """Control: from inside the tree the baseline already applies."""
    source, output, _ = layout
    (source / ".secrets.baseline").write_text(
        _baseline_excluding("skipme.py"), encoding="utf-8"
    )
    monkeypatch.chdir(source)

    reported = _reported_files(_scanner(source, output), source)

    assert reported == {"keepme.py"}


def test_control_no_baseline_reports_both_files(layout, monkeypatch):
    """Control: without a baseline both planted keys are reported."""
    source, output, cwd = layout
    monkeypatch.chdir(cwd)

    assert _reported_files(_scanner(source, output), source) == {
        "skipme.py",
        "keepme.py",
    }


def test_cli_scan_from_another_directory_applies_the_trees_baseline(
    layout, monkeypatch
):
    """The same through ``run_ash_scan``, the function behind ``ash scan``."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source, output, cwd = layout
    (source / ".secrets.baseline").write_text(
        _baseline_excluding("skipme.py"), encoding="utf-8"
    )
    monkeypatch.chdir(cwd)

    try:
        run_ash_scan(
            source_dir=str(source),
            output_dir=str(output),
            scanners=["detect-secrets"],
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            show_summary=False,
            quiet=True,
            color=False,
        )
    except SystemExit:
        pass

    sarif = json.loads(
        (
            output / "scanners" / "detect-secrets" / "source" / "results_sarif.sarif"
        ).read_text(encoding="utf-8")
    )
    messages = " ".join(
        result["message"]["text"]
        for run in sarif.get("runs", [])
        for result in run.get("results", [])
    )
    assert "keepme.py" in messages, "the harness did not reach detect-secrets"
    assert "skipme.py" not in messages, (
        "ash scan --source-dir run from another directory ignored the tree's "
        ".secrets.baseline"
    )
