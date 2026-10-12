# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter's declared destination options are not chosen by the scanned tree's config.

A reporter loaded from a plugin module (``ash_plugin_modules``,
``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``) can send findings off the host,
and the options that say where are its own. It names them in
``ReporterPluginBase.destination_options``. Plugin modules are imported after the
config is resolved, so once the scan has loaded them those options are confined
the way ``config/reporter_trust.py`` confines the built-in AWS reporters': a file
inside the scanned tree, or one an MCP client delivered, does not set them, and
the trusted base (the defaults, an operator config outside the tree and
``--config-overrides``) does.

The stand-in reporter lives in a plugin package written outside the scanned tree
and is registered the way a third-party plugin is, by ``@ash_reporter_plugin``
when the scan imports the package. Each scan runs in a subprocess, because
importing a plugin package registers its plugins for the rest of the process.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Tuple

import pytest
import yaml
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER

PLUGIN = "standin_ash_plugins"
REPORTER = "endpoint-reporter"
KEY = f"reporters.{REPORTER}.options.endpoint"
DEFAULT_ENDPOINT = "https://default.invalid/"
REPO_ENDPOINT = "https://repo.invalid/"
OPERATOR_ENDPOINT = "https://operator.invalid/"
OVERRIDE_ENDPOINT = "https://override.invalid/"
CLIENT_ENDPOINT = "https://client.invalid/"
AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"

_PLUGIN_SOURCE = f'''
import json
from typing import Annotated, ClassVar, Literal, Tuple

from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class EndpointReporterOptions(ReporterOptionsBase):
    endpoint: str = "{DEFAULT_ENDPOINT}"
    title: str = "default title"


class EndpointReporterConfig(ReporterPluginConfigBase):
    name: Literal["{REPORTER}"] = "{REPORTER}"
    extension: str = "endpoint.json"
    enabled: bool = True
    options: Annotated[EndpointReporterOptions, Field()] = EndpointReporterOptions()


@ash_reporter_plugin
class EndpointReporter(ReporterPluginBase[EndpointReporterConfig]):
    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)

    def model_post_init(self, context):
        if self.config is None:
            self.config = EndpointReporterConfig()
        return super().model_post_init(context)

    def report(self, model):
        options = self.config.options
        return json.dumps({{"endpoint": options.endpoint, "title": options.title}})


ASH_REPORTERS = [EndpointReporter]
'''

# The scan path the CLI and the MCP tools take, up to and including the report
# phase: ASHScanOrchestrator resolves the config and builds the engine, which
# imports the plugin modules; ReportPhase then builds the stand-in from the
# engine's reporter classes and context, and runs it. What it would send is
# what it writes to reports/ash.endpoint.json.
_SCAN = """
import json, logging, sys
from pathlib import Path

spec = json.loads(sys.argv[1])

from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER

warnings = []

class _Collect(logging.Handler):
    def emit(self, record):
        warnings.append(record.getMessage())

ASH_LOGGER.addHandler(_Collect(level=logging.WARNING))
ASH_LOGGER.setLevel(logging.DEBUG)

scan = dict(spec["scan"])
if spec.get("mcp"):
    # What mcp_tools._run_scan_async passes for a config path the client named.
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )
    from automated_security_helper.cli.mcp_tools import _session_client_rules

    named = scan.get("config_path")
    scan["untrusted_config"] = named is not None and client_named_config_is_untrusted(
        named
    )
    scan["client_config_policy"] = _session_client_rules(None)
orchestrator = ASHScanOrchestrator.create(show_progress=False, **scan)
engine = orchestrator.execution_engine
reports = Path(scan["output_dir"]) / "reports"
ReportPhase(
    plugins=engine.plugins["reporter"],
    plugin_context=engine._context,
    progress_display=engine.progress_display,
    asharp_model=AshAggregatedResults(),
)._execute_phase(
    report_dir=reports,
    aggregated_results=AshAggregatedResults(),
    cli_output_formats=["endpoint-reporter"],
    python_based_plugins_only=False,
)
config = engine._context.config
options = {
    name: dict((config.get_plugin_config("reporter", name) or {}).get("options") or {})
    for name in ("s3", "aws-security-hub")
}
sent = reports / "ash.endpoint.json"
print(json.dumps({
    "sent": json.loads(sent.read_text()) if sent.exists() else None,
    "options": options,
    "warnings": warnings,
}))
"""

# ``ash report``: resolves --config, loads the config's plugin modules, and runs
# the reporter --format names, printing what it returns.
_REPORT = """
import json, os, sys

spec = json.loads(sys.argv[1])
os.chdir(spec["cwd"])

from typer.testing import CliRunner
from automated_security_helper.cli.main import app

result = CliRunner().invoke(app, spec["args"])
print(json.dumps({"exit": result.exit_code, "output": result.output}))
"""

#: Variables that would make the subprocess read a config or a plugin list the
#: test did not write.
_AMBIENT = (
    "ASH_CONFIG",
    "ASH_PLUGIN_MODULES",
    "ASH_MCP_WORKSPACE_ROOT",
    "ASH_MCP_ALLOWED_ROOTS",
    "ASH_MCP_ALLOWED_CONFIG_ROOTS",
)


@pytest.fixture
def site(tmp_path: Path) -> Path:
    """An installed plugin package, outside every scanned tree in these tests."""
    path = tmp_path / "site"
    (path / PLUGIN).mkdir(parents=True)
    (path / PLUGIN / "__init__.py").write_text(_PLUGIN_SOURCE, encoding="utf-8")
    return path


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _reporters(endpoint: str, **other: Dict[str, Any]) -> Dict[str, Any]:
    return {
        REPORTER: {"options": {"endpoint": endpoint, "title": "repo title"}},
        **other,
    }


def _run(script: str, spec: Dict[str, Any], site: Path, env: Dict[str, str]) -> Dict:
    environment = {k: v for k, v in os.environ.items() if k not in _AMBIENT}
    environment.update(env)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(site), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(spec)],
        cwd=site.parent,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def _scan(
    tmp_path: Path,
    site: Path,
    *,
    modules: Tuple[str, ...] = (PLUGIN,),
    env: Dict[str, str] | None = None,
    mcp: bool = False,
    **scan: Any,
) -> Dict:
    scan.setdefault("source_dir", str(tmp_path / "repo"))
    scan.setdefault("output_dir", str(tmp_path / "out"))
    scan["ash_plugin_modules"] = list(modules)
    return _run(_SCAN, {"scan": scan, "mcp": mcp}, site, env or {})


def _ignoring(warnings: List[str], key: str) -> List[str]:
    return [w for w in warnings if w.startswith("Ignoring ") and key in w]


# ---------------------------------------------------------------------------
# (a) A repository's own config
# ---------------------------------------------------------------------------


def test_an_in_tree_config_does_not_choose_a_declared_destination(tmp_path, site):
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"reporters": _reporters(REPO_ENDPOINT)},
    )

    result = _scan(tmp_path, site)

    assert result["sent"]["endpoint"] == DEFAULT_ENDPOINT, result
    # The reporter's other options still apply from the tree.
    assert result["sent"]["title"] == "repo title", result
    assert len(_ignoring(result["warnings"], KEY)) == 1, result["warnings"]


def test_the_warning_is_the_one_a_built_in_reporter_gets(tmp_path, site):
    """Same values and the same message as config/reporter_trust.py gives for S3."""
    s3_key = "reporters.s3.options.bucket_name"
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {
            "reporters": _reporters(
                REPO_ENDPOINT, s3={"options": {"bucket_name": "repo-bucket"}}
            )
        },
    )

    result = _scan(tmp_path, site)

    [declared] = _ignoring(result["warnings"], KEY)
    [built_in] = _ignoring(result["warnings"], s3_key)
    assert declared.replace(KEY, "<option>") == built_in.replace(s3_key, "<option>")
    assert "bucket_name" not in result["options"]["s3"]
    assert result["sent"]["endpoint"] == DEFAULT_ENDPOINT


def test_a_project_config_replacing_the_operators_keeps_the_operators_value(
    tmp_path, site
):
    """Workspace mode: the in-tree project config replaces the operator's default."""
    project = _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"reporters": _reporters(REPO_ENDPOINT)},
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {REPORTER: {"options": {"endpoint": OPERATOR_ENDPOINT}}}},
    )

    result = _scan(
        tmp_path,
        site,
        config_path=str(project),
        trusted_config_path=str(operator),
    )

    assert result["sent"]["endpoint"] == OPERATOR_ENDPOINT, result
    assert len(_ignoring(result["warnings"], KEY)) == 1, result["warnings"]


def test_a_project_config_without_the_section_keeps_the_operators_value(tmp_path, site):
    """The project config replaces the operator's, so leaving the section out
    would send to the default endpoint rather than the operator's."""
    project = _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml", {"project_name": "scanned"}
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {REPORTER: {"options": {"endpoint": OPERATOR_ENDPOINT}}}},
    )

    result = _scan(
        tmp_path,
        site,
        config_path=str(project),
        trusted_config_path=str(operator),
    )

    assert result["sent"]["endpoint"] == OPERATOR_ENDPOINT, result
    assert not _ignoring(result["warnings"], KEY), result["warnings"]


def test_a_base_the_tree_extends_does_not_choose_it_either(tmp_path, site):
    _write(
        tmp_path / "repo" / "shared" / "base.yaml",
        {"reporters": _reporters(REPO_ENDPOINT)},
    )
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"project_name": "scanned", "extends": "../shared/base.yaml"},
    )

    result = _scan(tmp_path, site)

    assert result["sent"]["endpoint"] == DEFAULT_ENDPOINT, result


def test_an_in_tree_config_that_loads_the_plugin_itself_does_not_choose_it(
    tmp_path, site
):
    """The tree may add an installed module outside it, and still not point it."""
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"ash_plugin_modules": [PLUGIN], "reporters": _reporters(REPO_ENDPOINT)},
    )

    result = _scan(tmp_path, site, modules=())

    assert result["sent"]["endpoint"] == DEFAULT_ENDPOINT, result


def test_a_project_config_does_not_turn_on_a_reporter_the_operator_turned_off(
    tmp_path, site
):
    """A reporter that declares a destination sends findings somewhere, so whether
    it runs is the operator's choice, as for the built-in AWS reporters."""
    project = _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"reporters": {REPORTER: {"enabled": True}}},
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {REPORTER: {"enabled": False}}},
    )

    result = _scan(
        tmp_path,
        site,
        config_path=str(project),
        trusted_config_path=str(operator),
    )

    assert result["sent"] is None, result
    enabled_key = f"reporters.{REPORTER}.enabled"
    assert len(_ignoring(result["warnings"], enabled_key)) == 1, result["warnings"]


@pytest.mark.parametrize("on", [False, True], ids=["operator-off", "operator-on"])
def test_a_null_section_in_a_project_config_reads_as_an_empty_one(tmp_path, site, on):
    """Left null, the section would build the reporter from its defaults: on, and
    sending to the default endpoint rather than the operator's."""
    project = _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml", {"reporters": {REPORTER: None}}
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {
            "reporters": {
                REPORTER: {"enabled": on, "options": {"endpoint": OPERATOR_ENDPOINT}}
            }
        },
    )

    result = _scan(
        tmp_path,
        site,
        config_path=str(project),
        trusted_config_path=str(operator),
    )

    if on:
        assert result["sent"]["endpoint"] == OPERATOR_ENDPOINT, result
    else:
        assert result["sent"] is None, result


# ---------------------------------------------------------------------------
# (b) --config-overrides and (c) an operator config outside the tree
# ---------------------------------------------------------------------------


def test_config_overrides_set_it(tmp_path, site):
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"reporters": _reporters(REPO_ENDPOINT)},
    )

    result = _scan(tmp_path, site, config_overrides=[f"{KEY}={OVERRIDE_ENDPOINT}"])

    assert result["sent"]["endpoint"] == OVERRIDE_ENDPOINT, result
    assert not _ignoring(result["warnings"], KEY), result["warnings"]


def test_an_operator_config_outside_the_tree_sets_it(tmp_path, site):
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {"reporters": _reporters(REPO_ENDPOINT)},
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {REPORTER: {"options": {"endpoint": OPERATOR_ENDPOINT}}}},
    )

    result = _scan(tmp_path, site, config_path=str(operator))

    assert result["sent"]["endpoint"] == OPERATOR_ENDPOINT, result
    assert not _ignoring(result["warnings"], KEY), result["warnings"]


# ---------------------------------------------------------------------------
# (d) A config an MCP client delivered
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_server(tmp_path: Path) -> Dict[str, Any]:
    """An MCP server's directories, and the operator's config it runs with."""
    root = tmp_path / "ash-mcp"
    (root / "session-a" / "config").mkdir(parents=True)
    target = tmp_path / "scan-root" / "target"
    target.mkdir(parents=True)
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {REPORTER: {"options": {"endpoint": OPERATOR_ENDPOINT}}}},
    )
    env = {
        "ASH_MCP_WORKSPACE_ROOT": str(root),
        "ASH_MCP_ALLOWED_ROOTS": str(target.parent),
        "ASH_CONFIG": str(operator),
    }
    return {"root": root, "target": target, "env": env}


@pytest.mark.parametrize("override", [False, True])
def test_an_mcp_clients_upload_does_not_choose_it(tmp_path, site, mcp_server, override):
    """The upload loads the installed plugin itself, as a client's config may.

    With ``override``, the client's own ``config_overrides`` set the option too.
    Under the MCP server those are the client's, held to the session's allowlist,
    and are not replayed onto the trusted base, as for the built-in reporters.
    """
    upload = _write(
        mcp_server["root"] / "session-a" / "upload-staging" / "ash.yaml",
        {"ash_plugin_modules": [PLUGIN], "reporters": _reporters(CLIENT_ENDPOINT)},
    )
    overrides = [f"{KEY}={CLIENT_ENDPOINT}"] if override else []

    result = _scan(
        tmp_path,
        site,
        modules=(),
        env=mcp_server["env"],
        mcp=True,
        source_dir=str(mcp_server["target"]),
        config_path=str(upload),
        config_overrides=overrides,
    )

    assert result["sent"]["endpoint"] == OPERATOR_ENDPOINT, result
    assert result["sent"]["title"] == "repo title", result
    assert len(_ignoring(result["warnings"], KEY)) == 1, result["warnings"]


def test_a_delivered_trees_own_config_does_not_choose_it(tmp_path, site, mcp_server):
    source = mcp_server["root"] / "session-a" / "source"
    _write(
        source / ".ash" / ".ash.yaml",
        {"ash_plugin_modules": [PLUGIN], "reporters": _reporters(CLIENT_ENDPOINT)},
    )

    result = _scan(
        tmp_path,
        site,
        modules=(),
        env=mcp_server["env"],
        mcp=True,
        source_dir=str(source),
    )

    assert result["sent"]["endpoint"] == OPERATOR_ENDPOINT, result


def test_an_operator_can_have_such_a_file_refused_with_denied_paths(tmp_path):
    """As the reporter guide says: the profile lists the option in denied_paths."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.client_config_policy import rules_from
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    profile = AshConfig.model_validate(
        {
            "global_settings": {
                "mcp": {
                    "runtime_overrides": {
                        "denied_paths": [f"/reporters/{REPORTER}/options/endpoint"]
                    }
                }
            }
        }
    )
    upload = _write(
        tmp_path / "upload" / "ash.yaml", {"reporters": _reporters(CLIENT_ENDPOINT)}
    )
    (tmp_path / "repo").mkdir()

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=upload,
            source_dir=tmp_path / "repo",
            untrusted_config=True,
            client_config_policy=rules_from(profile),
        )
    assert KEY in str(refused.value)


# ---------------------------------------------------------------------------
# ash report
# ---------------------------------------------------------------------------


def test_ash_report_does_not_take_it_from_an_in_tree_config(tmp_path, site):
    repo = tmp_path / "repo"
    config = _write(
        repo / ".ash" / ".ash.yaml",
        {"ash_plugin_modules": [PLUGIN], "reporters": _reporters(REPO_ENDPOINT)},
    )
    output = repo / ".ash" / "ash_output"
    output.mkdir(parents=True)
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults(ash_config=AshConfig()).model_dump_json(),
        encoding="utf-8",
    )
    args = ["report", "--format", REPORTER, "--config", str(config)]
    args += ["--output-dir", str(output)]

    result = _run(_REPORT, {"cwd": str(repo), "args": args}, site, {})

    assert result["exit"] == 0, result["output"]
    assert DEFAULT_ENDPOINT in result["output"], result["output"]
    assert REPO_ENDPOINT not in result["output"], result["output"]


# ---------------------------------------------------------------------------
# The built-in AWS reporters, loaded alongside
# ---------------------------------------------------------------------------


def test_the_built_in_reporters_are_confined_once_and_unchanged(tmp_path, site):
    _write(
        tmp_path / "repo" / ".ash" / ".ash.yaml",
        {
            "reporters": _reporters(
                REPO_ENDPOINT,
                s3={"options": {"bucket_name": "repo-bucket", "file_format": "yaml"}},
                **{"aws-security-hub": {"options": {"account_id": "000000000001"}}},
            )
        },
    )

    result = _scan(tmp_path, site, modules=(PLUGIN, AWS))

    assert result["options"]["s3"].get("bucket_name") != "repo-bucket"
    assert result["options"]["s3"]["file_format"] == "yaml"
    assert result["options"]["aws-security-hub"].get("account_id") != "000000000001"
    # One warning at resolution for the built-ins; loading their classes later
    # does not repeat it.
    built_in = _ignoring(result["warnings"], "reporters.s3.options.bucket_name")
    assert len(built_in) == 1, result["warnings"]
    assert "reporters.aws-security-hub.options.account_id" in built_in[0]
    assert result["sent"]["endpoint"] == DEFAULT_ENDPOINT


# ---------------------------------------------------------------------------
# The declaration itself
# ---------------------------------------------------------------------------


def test_a_reporter_declares_no_destination_options_by_default():
    assert ReporterPluginBase.destination_options == ()


class _AliasedOptions(ReporterOptionsBase):
    token: str = Field("", alias="apiToken")
    region: str = "default-region"


class _AliasedConfig(ReporterPluginConfigBase):
    name: Literal["aliased-reporter"] = "aliased-reporter"
    options: _AliasedOptions = _AliasedOptions()


class _AliasedReporter(ReporterPluginBase[_AliasedConfig]):
    destination_options: ClassVar[Tuple[str, ...]] = ("token", "region")

    def report(self, model):
        return None


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def test_an_aliased_option_is_covered_under_its_alias(tmp_path, ash_log):
    """The config writes an aliased field under its alias, so that is confined too."""
    from automated_security_helper.config.reporter_trust import (
        confine_declared_reporter_destinations,
    )

    source = tmp_path / "repo"
    _write(
        source / ".ash" / ".ash.yaml",
        {
            "reporters": {
                "aliased-reporter": {
                    "options": {"apiToken": "repo-token", "region": "repo-region"}
                }
            }
        },
    )
    config = resolve_config(source_dir=source)

    confine_declared_reporter_destinations(config, [_AliasedReporter])

    section = config.get_plugin_config("reporter", "aliased-reporter")
    assert "apiToken" not in section["options"], section
    assert "region" not in section["options"], section
    [warning] = [
        r.getMessage() for r in ash_log if "aliased-reporter" in r.getMessage()
    ]
    assert "reporters.aliased-reporter.options.apiToken" in warning
    assert "reporters.aliased-reporter.options.region" in warning


def test_nothing_is_confined_for_a_config_with_no_file_in_the_tree(tmp_path, ash_log):
    from automated_security_helper.config.reporter_trust import (
        confine_declared_reporter_destinations,
    )

    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {"aliased-reporter": {"options": {"region": "op-region"}}}},
    )
    (tmp_path / "repo").mkdir()
    config = resolve_config(config_path=operator, source_dir=tmp_path / "repo")

    confine_declared_reporter_destinations(config, [_AliasedReporter])

    section = config.get_plugin_config("reporter", "aliased-reporter")
    assert section["options"]["region"] == "op-region"
    assert not ash_log


class _LocalReporter(ReporterPluginBase[_AliasedConfig]):
    """Writes only a local file: it declares no destination options."""

    def report(self, model):
        return None


def _operator_turns_off(tmp_path: Path, project_section: Dict[str, Any] | None):
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {"aliased-reporter": {"enabled": False}}},
    )
    source = tmp_path / "repo"
    reporters: Dict[str, Any] = {"markdown": {"enabled": True}}
    if project_section is not None:
        reporters["aliased-reporter"] = project_section
    project = _write(source / ".ash" / ".ash.yaml", {"reporters": reporters})
    return resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )


def _enabled(config) -> Any:
    return (config.get_plugin_config("reporter", "aliased-reporter") or {}).get(
        "enabled"
    )


def test_a_declared_reporters_enabled_comes_from_the_trusted_base(tmp_path, ash_log):
    from automated_security_helper.config.reporter_trust import (
        confine_declared_reporter_destinations,
    )

    config = _operator_turns_off(tmp_path, {"enabled": True})

    confine_declared_reporter_destinations(config, [_AliasedReporter])

    assert _enabled(config) is False
    [warning] = [
        r.getMessage() for r in ash_log if "aliased-reporter" in r.getMessage()
    ]
    assert "reporters.aliased-reporter.enabled" in warning


def test_leaving_a_declared_reporter_out_keeps_the_operators_off(tmp_path, ash_log):
    """The project's config replaces the operator's, so leaving the section out
    would turn the reporter back on by its default."""
    from automated_security_helper.config.reporter_trust import (
        confine_declared_reporter_destinations,
    )

    config = _operator_turns_off(tmp_path, None)

    confine_declared_reporter_destinations(config, [_AliasedReporter])

    assert _enabled(config) is False
    assert not ash_log


def test_a_tree_may_turn_a_declared_reporter_off(tmp_path, ash_log):
    from automated_security_helper.config.reporter_trust import (
        confine_declared_reporter_destinations,
    )

    source = tmp_path / "repo"
    _write(
        source / ".ash" / ".ash.yaml",
        {"reporters": {"aliased-reporter": {"enabled": False}}},
    )
    config = resolve_config(source_dir=source)

    confine_declared_reporter_destinations(config, [_AliasedReporter])

    assert _enabled(config) is False
    assert not ash_log


def test_a_reporter_with_no_destination_keeps_its_enabled_from_the_tree(
    tmp_path, ash_log
):
    """It writes only local files, so whether it runs is the tree's to say."""
    from automated_security_helper.config.reporter_trust import (
        confine_declared_reporter_destinations,
    )

    config = _operator_turns_off(tmp_path, {"enabled": True})

    confine_declared_reporter_destinations(config, [_LocalReporter])

    assert _enabled(config) is True
    assert not ash_log
