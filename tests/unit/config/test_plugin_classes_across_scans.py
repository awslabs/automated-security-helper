# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin class one scan loaded is not offered to the next scan unless that scan names it.

Plugin registration lasts for the rest of the process, and the MCP server and a
workspace run build several scans in one process. A config inside the scanned
tree, one an MCP client delivered, an operator's config or
``--ash-plugin-modules`` may name an installed plugin package in
``ash_plugin_modules``; importing it registers the package's classes. A later
scan in the same process that does not name that package must not select them:
a fresh process would not.

That holds whoever named the package first, the operator included: on the MCP
server each session's profile is the operator's config, and one session's
profile must not add plugins to another session's scans. A class embedding code
registers through the registry directly is used only by a scan that names its
module.

Each test builds its scans one after another in one subprocess, because
importing a plugin package registers its plugins for the rest of the process.
The packages are written outside the scanned trees and put on that
subprocess's path.
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

pytestmark = pytest.mark.integration

CARRY = "carry_ash_plugins"
KEPT = "kept_ash_plugins"
TRIVY = "automated_security_helper.plugin_modules.ash_trivy_plugins"
EMBEDDING = "embedding_host_ash_plugins"

_SCANNER = """
from typing import Annotated, Any, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class {cls}Config(ScannerPluginConfigBase):
    name: Literal["{name}"] = "{name}"
    enabled: bool = True
    options: Annotated[ScannerOptionsBase, Field(description="none")] = (
        ScannerOptionsBase()
    )


@ash_scanner_plugin{decorator_args}
class {cls}(ScannerPluginBase[{cls}Config]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = {cls}Config()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        raise NotImplementedError("scan() is overridden")

    def scan(self, target, target_type, config: Any = None, *args, **kwargs):
        return {{"findings": []}}
"""

_UNSUPPORTED_REPORTER = """
from typing import Annotated, Literal

from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class CarriedReporterConfig(ReporterPluginConfigBase):
    name: Literal["carried-report"] = "carried-report"
    extension: str = "carried.txt"
    enabled: bool = True
    options: Annotated[ReporterOptionsBase, Field(description="none")] = (
        ReporterOptionsBase()
    )


@ash_reporter_plugin
class CarriedReporter(ReporterPluginBase[CarriedReporterConfig]):
    workspace_behaviour = ReporterWorkspaceBehaviour.UNSUPPORTED

    def model_post_init(self, context):
        if self.config is None:
            self.config = CarriedReporterConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:
        return ""
"""


def _scanner(cls: str, name: str, decorator_args: str = "") -> str:
    return _SCANNER.format(cls=cls, name=name, decorator_args=decorator_args)


# Each entry of argv[1] is one step, run in this one process in order:
#   scan       a scan engine over a config resolved the way the CLI resolves it,
#              with "cli" as --ash-plugin-modules;
#   register   embedding code registering a class through the registry directly;
#   list       the scanner classes the MCP list_scanners tool loads;
#   workspace  a workspace run whose projects' scan engines are real.
# Prints, for each step, the classes each engine selected and the warnings logged.
_DRIVER = """
import importlib, json, logging, sys
from pathlib import Path
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.utils.log import ASH_LOGGER

steps = json.loads(sys.argv[1])
warnings = []

class _Collect(logging.Handler):
    def emit(self, record):
        warnings.append(record.getMessage())

ASH_LOGGER.addHandler(_Collect(level=logging.WARNING))


def selected(engine):
    return {
        "scanners": sorted(c.__name__ for c in engine.plugins["scanner"]),
        "reporters": sorted(c.__name__ for c in engine.plugins["reporter"]),
    }


def engine(source, output, config, cli):
    return ScanExecutionEngine(
        context=PluginContext(source_dir=source, output_dir=output,
                              work_dir=output / "work", config=config),
        show_progress=False,
        ash_plugin_modules=cli,
    )


def scan(step):
    source = Path(step["source"])
    config = resolve_config(source_dir=source, **step["resolve"])
    return selected(engine(source, source.parent / "out", config, step["cli"]))


def listed(step):
    from automated_security_helper.core.scanner_inventory import (
        _loaded_scanner_classes,
    )

    return {"listed": sorted(c.__name__ for c in _loaded_scanner_classes())}


def register(step):
    from automated_security_helper.plugins import ash_plugin_manager

    module = importlib.import_module(step["module"])
    ash_plugin_manager.register_plugin_module(
        plugin_type="scanner",
        plugin_module_class=getattr(module, step["class"]),
        plugin_module_path=module.__name__,
    )
    return {}


def workspace(step):
    from automated_security_helper.core.exceptions import WorkspaceDefinitionError
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        execute_workspace,
    )
    from automated_security_helper.workspace.resolver import resolve_workspace

    projects = {}

    class Orchestrator:
        def __init__(self, **kwargs):
            source = Path(kwargs["source_dir"])
            self.config = kwargs["resolved_config"]
            projects[source.name] = selected(engine(
                source, Path(kwargs["output_dir"]), self.config,
                kwargs["ash_plugin_modules"],
            ))

        @classmethod
        def create(cls, **kwargs):
            return cls(**kwargs)

        def execute_scan(self, phases=None):
            model = AshAggregatedResults()
            model.ash_config = self.config
            model.sarif = SarifReport.model_validate(
                {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ASH"}}}]}
            )
            model.scanner_results["bandit"] = ScannerTargetStatusInfo(
                status="PASSED", excluded=False, dependencies_satisfied=True
            )
            return model

    try:
        plan = resolve_workspace(Path(step["workspace"]))
        settings = ProjectScanSettings(
            output_dir=Path(step["output"]),
            phases=tuple(step["phases"]),
            ash_plugin_modules=tuple(step["cli"]),
            max_parallel_projects=2,
        )
        execute_workspace(plan, settings, orchestrator_factory=Orchestrator.create)
    except WorkspaceDefinitionError as exc:
        return {"projects": projects, "refused": str(exc)}
    return {"projects": projects, "refused": None}


results = []
for step in steps:
    warnings.clear()
    run = {"scan": scan, "register": register, "list": listed, "workspace": workspace}
    result = run[step["kind"]](step)
    result["warnings"] = list(warnings)
    results.append(result)
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
    """Installed packages outside every scanned tree.

    ``carry_ash_plugins`` defines a scanner and a reporter that refuses workspace
    mode, ``kept_ash_plugins`` a scanner, and ``embedding_host_ash_plugins`` a
    scanner that registers only when embedding code registers it.
    """
    path = tmp_path / "site"
    sources = {
        CARRY: _scanner("CarriedScanner", "carried")
        + _UNSUPPORTED_REPORTER
        + "\nASH_SCANNERS = [CarriedScanner]\nASH_REPORTERS = [CarriedReporter]\n",
        KEPT: _scanner("KeptScanner", "kept") + "\nASH_SCANNERS = [KeptScanner]\n",
        EMBEDDING: _scanner("EmbeddedScanner", "embedded", "(auto_register=False)"),
    }
    for package, source in sources.items():
        (path / package).mkdir(parents=True)
        (path / package / "__init__.py").write_text(source, encoding="utf-8")
    return path


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _tree(tmp_path: Path, name: str, modules: List[str] | None = None) -> Path:
    """A scanned tree, with a config of its own naming ``modules`` when given."""
    source = tmp_path / name
    source.mkdir(parents=True, exist_ok=True)
    if modules is not None:
        _write(
            source / ".ash" / ".ash.yaml",
            {"project_name": name, "ash_plugin_modules": modules},
        )
    return source


def _scan(source: Path, cli: List[str] | None = None, **resolve: Any) -> Dict[str, Any]:
    return {"kind": "scan", "source": str(source), "cli": cli or [], "resolve": resolve}


def _delivered(tmp_path: Path, name: str, modules: List[str]) -> Dict[str, Any]:
    """A scan of an empty tree with a config an MCP client delivered."""
    upload = _write(
        tmp_path / f"{name}-upload" / "ash.yaml", {"ash_plugin_modules": modules}
    )
    return _scan(_tree(tmp_path, name), config_path=str(upload), untrusted_config=True)


def _workspace(
    tmp_path: Path,
    name: str,
    projects: Dict[str, List[str] | None],
    phases: tuple = ("scan",),
) -> Dict[str, Any]:
    root = tmp_path / name
    for key, modules in projects.items():
        _tree(root, key, modules)
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": key} for key in projects]}),
        encoding="utf-8",
    )
    return {
        "kind": "workspace",
        "workspace": str(workspace_file),
        "output": str(tmp_path / f"{name}-out"),
        "phases": list(phases),
        "cli": [],
    }


def _run(site: Path, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What each of ``steps`` selected, run one after another in one process."""
    environment = {k: v for k, v in os.environ.items() if k not in _AMBIENT}
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(site), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    result = subprocess.run(
        [sys.executable, "-c", _DRIVER, json.dumps(steps)],
        cwd=site.parent,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize(
    "package,scanner", [(CARRY, "CarriedScanner"), (TRIVY, "TrivyRepoScanner")]
)
@pytest.mark.parametrize("untrusted", ["tree", "delivered"])
def test_a_later_scan_does_not_select_what_an_earlier_untrusted_config_loaded(
    tmp_path, site, package, scanner, untrusted
):
    """A third-party package, or ASH's own trivy package, named by the first scan."""
    first = (
        _scan(_tree(tmp_path, "repo", [package]))
        if untrusted == "tree"
        else _delivered(tmp_path, "repo", [package])
    )

    loaded, later = _run(site, [first, _scan(_tree(tmp_path, "plain"))])

    assert scanner in loaded["scanners"], loaded
    assert scanner not in later["scanners"], later
    assert "BanditScanner" in later["scanners"], later
    if package == CARRY:
        assert "CarriedReporter" in loaded["reporters"], loaded
        assert "CarriedReporter" not in later["reporters"], later


def test_a_later_scan_whose_own_config_names_the_package_selects_it(tmp_path, site):
    """Left out of the scan that does not load it, and offered again to one that does."""
    first, plain, again = _run(
        site,
        [
            _scan(_tree(tmp_path, "one", [CARRY])),
            _scan(_tree(tmp_path, "plain")),
            _delivered(tmp_path, "two", [CARRY]),
        ],
    )

    assert "CarriedScanner" in first["scanners"], first
    assert "CarriedScanner" not in plain["scanners"], plain
    assert "CarriedScanner" in again["scanners"], again
    assert "CarriedReporter" in again["reporters"], again


@pytest.mark.parametrize("operator", ["command_line", "operator_config"])
def test_a_module_the_operator_loaded_takes_no_part_in_a_later_scan(
    tmp_path, site, operator
):
    """In the same first scan, the tree's config names both packages.

    The operator names ``kept_ash_plugins`` too, on the command line or in its
    config file outside the tree, and ``carry_ash_plugins`` only the tree names.
    The next scan names neither, so it selects neither, as a fresh process's scan
    would: an operator's module belongs to the scan the operator named it for.
    """
    source = _tree(tmp_path, "repo", [CARRY, KEPT])
    if operator == "command_line":
        first = _scan(source, cli=[KEPT])
    else:
        trusted = _write(
            tmp_path / "operator" / "ash.yaml", {"ash_plugin_modules": [KEPT]}
        )
        first = _scan(
            source,
            config_path=str(source / ".ash" / ".ash.yaml"),
            trusted_config_path=str(trusted),
        )

    loaded, later = _run(site, [first, _scan(_tree(tmp_path, "plain"))])

    assert {"CarriedScanner", "KeptScanner"} <= set(loaded["scanners"]), loaded
    assert "KeptScanner" not in later["scanners"], later
    assert "CarriedScanner" not in later["scanners"], later
    assert "BanditScanner" in later["scanners"], later


def test_each_scan_selects_the_package_only_while_it_names_it(tmp_path, site):
    """Which source loaded the package before does not decide what a scan gets.

    Loaded first for a tree's config, the package is left out of the next scan.
    A scan whose command line names it selects it, and the scan after that, which
    names it nowhere, leaves it out again.
    """
    plain = _tree(tmp_path, "plain")

    first, before, named, after = _run(
        site,
        [
            _scan(_tree(tmp_path, "repo", [CARRY])),
            _scan(plain),
            _scan(plain, cli=[CARRY]),
            _scan(plain),
        ],
    )

    assert "CarriedScanner" in first["scanners"], first
    assert "CarriedScanner" not in before["scanners"], before
    assert "CarriedScanner" in named["scanners"], named
    assert "CarriedScanner" not in after["scanners"], after


def test_a_class_registered_directly_is_used_only_by_a_scan_naming_its_module(
    tmp_path, site
):
    """Embedding code registers a class itself, from a plugin-namespace module.

    A scan that names another package, and one that names nothing, leave the
    class out; a scan that names its module selects it.
    """
    plain = _tree(tmp_path, "plain")
    registered, other, unnamed, named = _run(
        site,
        [
            {"kind": "register", "module": EMBEDDING, "class": "EmbeddedScanner"},
            _scan(_tree(tmp_path, "repo", [CARRY])),
            _scan(plain),
            _scan(plain, cli=[EMBEDDING]),
        ],
    )

    assert "CarriedScanner" in other["scanners"], other
    assert "EmbeddedScanner" not in other["scanners"], other
    assert "EmbeddedScanner" not in unnamed["scanners"], unnamed
    assert "CarriedScanner" not in unnamed["scanners"], unnamed
    assert "EmbeddedScanner" in named["scanners"], named


def test_listing_the_scanners_adds_none_to_a_later_scan(tmp_path, site):
    """The MCP list_scanners tool imports the scanner packages ASH ships.

    Their scanners are enabled by default, so a scan selecting them would run
    them. A fresh process's scan of the same tree does not, and one that names
    the package still does.
    """
    plain = _tree(tmp_path, "plain")

    listing, later, named = _run(
        site, [{"kind": "list"}, _scan(plain), _scan(plain, cli=[TRIVY])]
    )

    shipped = {"TrivyRepoScanner", "FerretScanScanner"}
    assert shipped <= set(listing["listed"]), listing
    assert not shipped & set(later["scanners"]), later
    assert "BanditScanner" in later["scanners"], later
    assert "TrivyRepoScanner" in named["scanners"], named
    assert "FerretScanScanner" not in named["scanners"], named


def test_a_workspace_run_selects_only_what_its_projects_load(tmp_path, site):
    """After a scan whose tree's config loaded the package, in the same process.

    A workspace whose projects name different module sets is refused before
    anything runs, as before, so the package cannot reach a project that does not
    name it from a sibling. The next workspace names nothing: neither project's
    scan selects the package's classes, and the workspace-level report step does
    not consider its reporter, which refuses workspace mode and would otherwise
    refuse the run. The last names the package in both projects, and both select
    it; a plain scan after that still does not.
    """
    first, mixed, none, both, later = _run(
        site,
        [
            _scan(_tree(tmp_path, "repo", [CARRY])),
            _workspace(tmp_path, "mixed", {"api": [CARRY], "web": None}),
            _workspace(
                tmp_path, "none", {"api": None, "web": None}, ("scan", "report")
            ),
            _workspace(tmp_path, "both", {"api": [CARRY], "web": [CARRY]}),
            _scan(_tree(tmp_path, "plain")),
        ],
    )

    assert "CarriedScanner" in first["scanners"], first
    assert mixed["refused"] and "ash_plugin_modules" in mixed["refused"], mixed
    assert none["refused"] is None, none
    assert set(none["projects"]) == {"api", "web"}, none
    for key, project in none["projects"].items():
        assert "CarriedScanner" not in project["scanners"], (key, project)
        assert "BanditScanner" in project["scanners"], (key, project)
    assert both["refused"] is None, both
    for key, project in both["projects"].items():
        assert "CarriedScanner" in project["scanners"], (key, project)
    assert "CarriedScanner" not in later["scanners"], later
