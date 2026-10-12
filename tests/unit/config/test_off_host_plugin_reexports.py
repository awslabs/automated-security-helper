# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin class from an off-host package, re-exported by another package, is the operator's.

``config/plugin_module_trust.py`` keeps a repository's or an MCP client's
``ash_plugin_modules`` from naming ``ash_snyk_plugins`` or ``ash_aws_plugins``,
keyed on the module name. Another installed ``*_ash_plugins`` package can list
``SnykCodeScanner`` or an AWS reporter in its own ``ASH_SCANNERS`` or
``ASH_REPORTERS``, and naming that package passes the name check. So the scan
also checks the classes it selects: a class defined in an off-host package is
dropped, with a warning, unless the trusted base or ``--ash-plugin-modules``
loads that package or a module that lists the class.

Registration lasts for the rest of the process, and the MCP server runs every
scan in the server's process, so a scan is also checked after an earlier scan
in that process loaded those classes. A class another package defines as a
subclass of one of them is checked the same way.

The re-exporting package is written outside the scanned tree and put on the
path of a subprocess, because importing a plugin package registers its plugins
for the rest of the process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

PACKAGE = "reexport_ash_plugins"
SNYK = "automated_security_helper.plugin_modules.ash_snyk_plugins"
AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"

_PACKAGE_SOURCE = f"""
from {SNYK}.snyk_code_scanner import SnykCodeScanner
from {AWS}.s3_reporter import S3Reporter

ASH_SCANNERS = [SnykCodeScanner]
ASH_REPORTERS = [S3Reporter]
"""

SUBCLASS_PACKAGE = "subclass_ash_plugins"

_SUBCLASS_SOURCE = f"""
from automated_security_helper.plugins.decorators import (
    ash_reporter_plugin,
    ash_scanner_plugin,
)
from {SNYK}.snyk_code_scanner import SnykCodeScanner
from {AWS}.s3_reporter import S3Reporter


@ash_scanner_plugin
class DerivedSnykScanner(SnykCodeScanner):
    pass


@ash_reporter_plugin
class DerivedS3Reporter(S3Reporter):
    pass


ASH_SCANNERS = [DerivedSnykScanner]
ASH_REPORTERS = [DerivedS3Reporter]
"""

#: The classes the two off-host packages define.
OFF_HOST_SCANNERS = ("SnykCodeScanner",)
OFF_HOST_REPORTERS = (
    "BedrockSummaryReporter",
    "CloudWatchLogsReporter",
    "S3Reporter",
    "SecurityHubReporter",
)

# One scan engine per entry of argv[1], built in this one process in order, over
# a config resolved the way the CLI resolves it, with the entry's "cli" as
# --ash-plugin-modules. Prints, for each, the classes it selected and the
# warnings it logged.
_ENGINE = """
import json, logging, sys
from pathlib import Path
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.utils.log import ASH_LOGGER

scans = json.loads(sys.argv[1])
warnings = []

class _Collect(logging.Handler):
    def emit(self, record):
        warnings.append(record.getMessage())

ASH_LOGGER.addHandler(_Collect(level=logging.WARNING))
ASH_LOGGER.setLevel(logging.DEBUG)
results = []
for spec in scans:
    warnings.clear()
    source = Path(spec["source"])
    config = resolve_config(source_dir=source, **spec.get("resolve", {}))
    engine = ScanExecutionEngine(
        context=PluginContext(source_dir=source, output_dir=source.parent / "out",
                              work_dir=source.parent / "work", config=config),
        show_progress=False,
        ash_plugin_modules=spec["cli"],
    )
    results.append({
        "scanners": sorted(c.__name__ for c in engine.plugins["scanner"]),
        "reporters": sorted(c.__name__ for c in engine.plugins["reporter"]),
        "warnings": list(warnings),
    })
print(json.dumps(results))
"""

#: Variables that would hand the subprocess a config or plugin list the test did
#: not write.
_AMBIENT = (
    "ASH_CONFIG",
    "ASH_PLUGIN_MODULES",
    "ASH_MCP_WORKSPACE_ROOT",
    "ASH_MCP_ALLOWED_ROOTS",
    "ASH_MCP_ALLOWED_CONFIG_ROOTS",
)


@pytest.fixture
def site(tmp_path: Path) -> Path:
    """Installed packages outside the scanned tree: one re-exports both classes,
    the other defines a subclass of each."""
    path = tmp_path / "site"
    for package, source in (
        (PACKAGE, _PACKAGE_SOURCE),
        (SUBCLASS_PACKAGE, _SUBCLASS_SOURCE),
    ):
        (path / package).mkdir(parents=True)
        (path / package / "__init__.py").write_text(source, encoding="utf-8")
    return path


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _tree(tmp_path: Path, modules: List[str]) -> Path:
    source = tmp_path / "repo"
    _write(
        source / ".ash" / ".ash.yaml",
        {"project_name": "scanned", "ash_plugin_modules": modules},
    )
    return source


def _scan(source: Path, cli: List[str] | None = None, **resolve: Any) -> Dict[str, Any]:
    return {"source": str(source), "cli": cli or [], "resolve": resolve}


def _engines(
    site: Path, scans: List[Dict[str, Any]], env: Dict[str, str] | None = None
) -> List[Dict[str, Any]]:
    """What each of ``scans`` selected, built one after another in one process."""
    environment = {k: v for k, v in os.environ.items() if k not in _AMBIENT}
    environment.update(env or {})
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(site), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    result = subprocess.run(
        [sys.executable, "-c", _ENGINE, json.dumps(scans)],
        cwd=site.parent,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def _engine(
    site: Path,
    source: Path,
    cli: List[str] | None = None,
    env: Dict[str, str] | None = None,
    **resolve: Any,
) -> Dict[str, Any]:
    [result] = _engines(site, [_scan(source, cli, **resolve)], env)
    return result


def _dropped(warnings: List[str], name: str) -> List[str]:
    return [w for w in warnings if name in w and "not selected" in w]


def test_a_repository_config_naming_the_package_does_not_select_them(tmp_path, site):
    result = _engine(site, _tree(tmp_path, [PACKAGE]))

    assert "SnykCodeScanner" not in result["scanners"], result
    assert "S3Reporter" not in result["reporters"], result
    [scanner] = _dropped(result["warnings"], "SnykCodeScanner")
    assert SNYK in scanner, scanner
    [reporter] = _dropped(result["warnings"], "S3Reporter")
    assert AWS in reporter, reporter


def test_the_command_line_naming_the_package_selects_them(tmp_path, site):
    result = _engine(site, _tree(tmp_path, [PACKAGE]), cli=[PACKAGE])

    assert "SnykCodeScanner" in result["scanners"], result
    assert "S3Reporter" in result["reporters"], result
    assert not _dropped(result["warnings"], "SnykCodeScanner"), result["warnings"]


def test_an_operator_config_naming_the_package_selects_them(tmp_path, site):
    """The operator's config replaces the tree's in workspace mode, and is trusted."""
    source = _tree(tmp_path, [PACKAGE])
    operator = _write(
        tmp_path / "operator" / "ash.yaml", {"ash_plugin_modules": [PACKAGE]}
    )

    result = _engine(
        site,
        source,
        config_path=str(source / ".ash" / ".ash.yaml"),
        trusted_config_path=str(operator),
    )

    assert "SnykCodeScanner" in result["scanners"], result
    assert "S3Reporter" in result["reporters"], result


def test_the_command_line_naming_the_off_host_package_itself_selects_its_class(
    tmp_path, site
):
    """Re-exported or not, the class is the operator's once the operator loads it."""
    result = _engine(site, _tree(tmp_path, [PACKAGE]), cli=[SNYK])

    assert "SnykCodeScanner" in result["scanners"], result
    assert "S3Reporter" not in result["reporters"], result
    assert _dropped(result["warnings"], "S3Reporter"), result["warnings"]


def test_a_delivered_config_naming_the_package_does_not_select_them(tmp_path, site):
    upload = _write(tmp_path / "upload" / "ash.yaml", {"ash_plugin_modules": [PACKAGE]})
    source = tmp_path / "repo"
    source.mkdir()

    result = _engine(site, source, config_path=str(upload), untrusted_config=True)

    assert "SnykCodeScanner" not in result["scanners"], result
    assert "S3Reporter" not in result["reporters"], result


def test_without_a_package_that_re_exports_nothing_is_dropped(tmp_path, site):
    """Positive control: a tree config naming no plugin module drops no class."""
    result = _engine(site, _tree(tmp_path, []))

    assert "BanditScanner" in result["scanners"], result
    assert not [w for w in result["warnings"] if "not selected" in w], result


def test_a_repository_config_naming_a_package_of_subclasses_does_not_select_them(
    tmp_path, site
):
    """A subclass defined in another package sends what its off-host base sends."""
    result = _engine(site, _tree(tmp_path, [SUBCLASS_PACKAGE]))

    assert "DerivedSnykScanner" not in result["scanners"], result
    assert "DerivedS3Reporter" not in result["reporters"], result
    [scanner] = _dropped(result["warnings"], "DerivedSnykScanner")
    assert SNYK in scanner, scanner
    [reporter] = _dropped(result["warnings"], "DerivedS3Reporter")
    assert AWS in reporter, reporter


def test_the_command_line_selects_a_subclass_by_loading_its_package_or_its_base(
    tmp_path, site
):
    """Naming the subclass's own package, or the off-host package its base is in."""
    source = _tree(tmp_path, [SUBCLASS_PACKAGE])

    own, base = _engines(
        site, [_scan(source, [SUBCLASS_PACKAGE]), _scan(source, [SNYK])]
    )

    assert "DerivedSnykScanner" in own["scanners"], own
    assert "DerivedS3Reporter" in own["reporters"], own
    assert "DerivedSnykScanner" in base["scanners"], base
    assert "DerivedS3Reporter" not in base["reporters"], base
    assert _dropped(base["warnings"], "DerivedS3Reporter"), base["warnings"]


@pytest.mark.parametrize("first", ["tree", "operator"])
def test_a_later_scan_in_the_same_process_selects_only_what_it_loads(
    tmp_path, site, first
):
    """Registration outlives a scan, so each scan checks the classes it selects.

    The first scan loads the re-exporting package, from a config inside its tree
    or from the operator's config, and importing it registers every class of both
    off-host packages. The next scan, in the same process, is of a tree with no
    config, and names neither package; the one after it names the Snyk package on
    the command line.
    """
    source = tmp_path / "repo"
    if first == "tree":
        earlier = _scan(_tree(tmp_path, [PACKAGE]))
    else:
        source.mkdir()
        operator = _write(
            tmp_path / "operator" / "ash.yaml", {"ash_plugin_modules": [PACKAGE]}
        )
        earlier = _scan(source, config_path=str(operator))
    plain = tmp_path / "plain"
    plain.mkdir()

    _, later, named = _engines(site, [earlier, _scan(plain), _scan(plain, [SNYK])])

    assert not set(later["scanners"]) & set(OFF_HOST_SCANNERS), later
    assert not set(later["reporters"]) & set(OFF_HOST_REPORTERS), later
    assert "BanditScanner" in later["scanners"], later
    [dropped] = [w for w in later["warnings"] if "not selected" in w]
    assert SNYK in dropped and AWS in dropped, dropped
    assert "SnykCodeScanner" in named["scanners"], named
    assert not set(named["reporters"]) & set(OFF_HOST_REPORTERS), named


def test_a_class_outside_the_off_host_packages_is_kept(tmp_path):
    """Only a class defined in an off-host package is checked."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        drop_untrusted_off_host_plugins,
    )

    class LocalScanner:
        pass

    LocalScanner.__module__ = "other_ash_plugins.scanner"
    config = AshConfig()
    config._trusted_plugin_modules = ()

    kept = drop_untrusted_off_host_plugins(config, {"scanner": [LocalScanner]}, [])

    assert kept == {"scanner": [LocalScanner]}


def test_a_subclass_is_checked_against_the_off_host_class_it_derives_from():
    """Kept when a trusted name covers its own module or its off-host base's."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        drop_untrusted_off_host_plugins,
    )

    class OffHostReporter:
        pass

    OffHostReporter.__module__ = f"{AWS}.s3_reporter"

    class DerivedReporter(OffHostReporter):
        pass

    DerivedReporter.__module__ = "other_ash_plugins.reporter"
    config = AshConfig()
    config._trusted_plugin_modules = ()
    plugins = {"reporter": [DerivedReporter]}

    assert drop_untrusted_off_host_plugins(config, plugins, []) == {"reporter": []}
    for names in (["other_ash_plugins"], [AWS], [f"{AWS}.s3_reporter"]):
        kept = drop_untrusted_off_host_plugins(config, plugins, names)
        assert kept == plugins, names


def test_a_config_with_no_untrusted_file_selects_what_its_own_modules_load():
    """``resolve_config`` records the trusted list only when a file needs it.

    Without one, every file the config was built from is the operator's, so its
    own ``ash_plugin_modules`` are the trusted names. A class that something else
    in the process registered is not selected on that alone.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        drop_untrusted_off_host_plugins,
    )

    class ImportedScanner:
        pass

    ImportedScanner.__module__ = f"{SNYK}.snyk_code_scanner"
    plugins = {"scanner": [ImportedScanner]}
    named = AshConfig(ash_plugin_modules=[SNYK])

    assert drop_untrusted_off_host_plugins(AshConfig(), plugins, []) == {"scanner": []}
    assert drop_untrusted_off_host_plugins(named, plugins, []) == plugins
    assert drop_untrusted_off_host_plugins(AshConfig(), plugins, [SNYK]) == plugins


# ``ash report``: resolves --config, loads the config's plugin modules, and looks
# up the reporter --format names.
_REPORT = """
import json, os, sys

spec = json.loads(sys.argv[1])
os.chdir(spec["cwd"])

from typer.testing import CliRunner
from automated_security_helper.cli.main import app

result = CliRunner().invoke(app, spec["args"])
print(json.dumps({"exit": result.exit_code, "output": result.output}))
"""


@pytest.mark.parametrize("where", ["tree", "operator"])
def test_ash_report_runs_a_re_exported_reporter_only_from_the_operators_config(
    tmp_path, site, where
):
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    repo = tmp_path / "repo"
    document = {"ash_plugin_modules": [PACKAGE]}
    config = _write(
        repo / ".ash" / ".ash.yaml"
        if where == "tree"
        else tmp_path / "operator" / "ash.yaml",
        document,
    )
    output = repo / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults(ash_config=AshConfig()).model_dump_json(),
        encoding="utf-8",
    )
    args = ["report", "--format", "s3", "--config", str(config)]
    args += ["--output-dir", str(output)]
    environment = {k: v for k, v in os.environ.items() if k not in _AMBIENT}
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(site), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    spec = {"cwd": str(repo), "args": args}
    run = subprocess.run(
        [sys.executable, "-c", _REPORT, json.dumps(spec)],
        cwd=site.parent,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert run.returncode == 0, run.stderr[-4000:]
    result = json.loads(run.stdout.strip().splitlines()[-1])

    not_found = "Reporter plugin 's3' not found" in result["output"]
    assert not_found is (where == "tree"), result["output"]
