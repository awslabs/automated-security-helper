# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config in the scanned tree cannot load ASH's plugin packages that send data off the host.

ASH's own plugin packages are installed code, so ``plugin_module_trust`` keeps an
in-tree config's entries that name them. The exception is a package that sends
findings or source to a remote service with the operator's credentials:
``ash_aws_plugins``, whose reporters send findings to AWS, and ``ash_snyk_plugins``,
whose scanner sends the scanned source to Snyk with the operator's Snyk token. Their
plugins are enabled by default, so naming the package was enough to send the data
off the host. Only the operator can add them now. See config/plugin_module_trust.py.
"""

import ast
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER

AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"
SNYK = "automated_security_helper.plugin_modules.ash_snyk_plugins"
OFF_HOST = [AWS, SNYK]
#: The community packages an in-tree config can still add.
COMMUNITY = [
    "automated_security_helper.plugin_modules.ash_trivy_plugins",
    "automated_security_helper.plugin_modules.ash_ferret_plugins",
]
BUILTIN = "automated_security_helper.plugin_modules.ash_builtin"
REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings(records: List[logging.LogRecord]) -> List[str]:
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


def _module_warnings(records: List[logging.LogRecord]) -> List[str]:
    return [w for w in _warnings(records) if "ash_plugin_modules" in w]


def _tree(tmp_path: Path, modules: List[str]) -> Path:
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"project_name": "scanned", "ash_plugin_modules": modules})
    )
    return source


@pytest.mark.parametrize(
    "entry, sends",
    [
        (AWS, "findings"),
        (f"{AWS}.s3_reporter", "findings"),
        (f"{AWS}.bedrock_summary_reporter", "findings"),
        (SNYK, "source"),
        (f"{SNYK}.snyk_code_scanner", "source"),
    ],
)
def test_an_in_tree_config_cannot_add_them(tmp_path, ash_log, entry, sends):
    source = _tree(tmp_path, [entry])

    config = resolve_config(source_dir=source)

    assert entry not in config.ash_plugin_modules
    warnings = _module_warnings(ash_log)
    assert len(warnings) == 1, _warnings(ash_log)
    # The entry, then what its package sends, in parentheses.
    reason = warnings[0].split(f"{entry!r} (", 1)[1].split(")", 1)[0]
    assert reason.endswith(f"{sends} off the host"), warnings[0]
    assert "--ash-plugin-modules" in warnings[0]


def test_the_other_entries_of_that_config_are_kept(tmp_path, ash_log):
    source = _tree(tmp_path, [AWS, SNYK, *COMMUNITY])

    config = resolve_config(source_dir=source)

    assert config.ash_plugin_modules == COMMUNITY
    warnings = _module_warnings(ash_log)
    assert len(warnings) == 1, _warnings(ash_log)
    assert repr(AWS) in warnings[0] and repr(SNYK) in warnings[0]


@pytest.mark.parametrize("package", OFF_HOST)
def test_an_uploaded_config_cannot_add_them(tmp_path, ash_log, package):
    upload = tmp_path / "upload" / "ash.yaml"
    upload.parent.mkdir()
    upload.write_text(yaml.safe_dump({"ash_plugin_modules": [package]}))
    source = tmp_path / "repo"
    source.mkdir()

    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(config_path=upload, source_dir=source, untrusted_config=True)
    assert repr(package) in str(refused.value)


@pytest.mark.parametrize("package", OFF_HOST)
@pytest.mark.parametrize("delivered", ["upload", "tree"])
def test_a_config_an_mcp_client_delivered_cannot_add_them(
    tmp_path, monkeypatch, ash_log, package, delivered
):
    """Resolved the way the MCP tools resolve a client's config.

    An upload named as ``config_path`` is resolved with ``untrusted_config`` when
    ``config_is_client_supplied`` says a client delivered it; a delivered tree's
    own ``.ash/.ash.yaml`` is found inside the scanned tree.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    root = tmp_path / "ash-mcp"
    source = root / "session-a" / "source"
    source.mkdir(parents=True)
    (root / "session-a" / "config").mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    document = yaml.safe_dump(
        {"project_name": "delivered", "ash_plugin_modules": [package, *COMMUNITY]}
    )
    if delivered == "upload":
        config_path = root / "session-a" / "upload-staging" / "ash.yaml"
    else:
        config_path = source / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(document)
    assert config_is_client_supplied(config_path)

    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    # Refused, naming the package, rather than resolved with it left out.
    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=config_path,
            source_dir=source,
            untrusted_config=config_is_client_supplied(config_path),
            fallback_to_default=True,
        )
    assert repr(package) in str(refused.value)
    assert not any(module in str(refused.value) for module in COMMUNITY)


@pytest.mark.parametrize("package", OFF_HOST)
def test_an_operator_config_outside_the_tree_can(tmp_path, ash_log, package):
    _tree(tmp_path, [])
    operator = tmp_path / "operator.yaml"
    operator.write_text(yaml.safe_dump({"ash_plugin_modules": [package]}))

    config = resolve_config(config_path=operator, source_dir=tmp_path / "repo")

    assert config.ash_plugin_modules == [package]
    assert not _warnings(ash_log)


@pytest.mark.parametrize("package", OFF_HOST)
def test_an_operator_default_config_replaced_by_the_tree_can(
    tmp_path, ash_log, package
):
    source = _tree(tmp_path, [package])
    operator = tmp_path / "operator.yaml"
    operator.write_text(yaml.safe_dump({"ash_plugin_modules": [package]}))

    config = resolve_config(
        config_path=source / ".ash" / ".ash.yaml",
        source_dir=source,
        trusted_config_path=operator,
    )

    assert config.ash_plugin_modules == [package]


@pytest.mark.parametrize("package", OFF_HOST)
@pytest.mark.parametrize("key", ["ash_plugin_modules", "ash-plugin-modules"])
def test_config_overrides_can(tmp_path, ash_log, key, package):
    source = _tree(tmp_path, [])

    config = resolve_config(
        source_dir=source, config_overrides=[f'{key}+=["{package}"]']
    )

    assert package in config.ash_plugin_modules


@pytest.mark.parametrize("package", OFF_HOST)
@pytest.mark.parametrize("how", ["option", "environment"])
def test_the_command_line_hands_them_to_the_scan(tmp_path, monkeypatch, how, package):
    """``--ash-plugin-modules`` and ``ASH_PLUGIN_MODULES`` reach the scan as given."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    source = _tree(tmp_path, [package])
    monkeypatch.chdir(source)
    args = ["scan", "--source-dir", str(source)]
    env = {"ASH_PLUGIN_MODULES": package} if how == "environment" else {}
    if how == "option":
        args += ["--ash-plugin-modules", package]

    with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
        result = CliRunner(env=env).invoke(app, args)

    assert result.exit_code == 0, result.output
    assert run.call_args.kwargs["ash_plugin_modules"] == [package]


# Run in a subprocess, because loading a plugin package registers its plugins for
# the rest of the process: the scan engine built over a config resolved from an
# in-tree file that lists argv[2], with argv[3:] as --ash-plugin-modules.
_ENGINE_LOADS = """
import json, sys
from pathlib import Path
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.plugins import ash_plugin_manager

source = Path(sys.argv[1])
config = resolve_config(source_dir=source)
ScanExecutionEngine(
    context=PluginContext(source_dir=source, output_dir=source.parent / "out",
                          work_dir=source.parent / "work", config=config),
    show_progress=False,
    ash_plugin_modules=sys.argv[3:],
)
print(json.dumps({
    "config": config.ash_plugin_modules,
    "loaded": sorted({c.__module__ for kind in ("scanner", "reporter")
                      for c in ash_plugin_manager.plugin_modules(kind)
                      if c.__module__.startswith(sys.argv[2] + ".")}),
}))
"""


@pytest.mark.parametrize(
    "package, plugin",
    [
        (AWS, f"{AWS}.s3_reporter"),
        (SNYK, f"{SNYK}.snyk_code_scanner"),
    ],
)
def test_the_scan_engine_loads_them_only_from_the_command_line(
    tmp_path, package, plugin
):
    source = _tree(tmp_path, [package])

    def engine(*cli_modules: str) -> Dict[str, List[str]]:
        result = subprocess.run(
            [sys.executable, "-c", _ENGINE_LOADS, str(source), package, *cli_modules],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
        return json.loads(result.stdout.strip().splitlines()[-1])

    from_the_tree = engine()
    from_the_command_line = engine(package)

    assert from_the_tree == {"config": [], "loaded": []}
    assert from_the_command_line["config"] == []
    assert plugin in from_the_command_line["loaded"]


def test_ash_community_plugins_file_keeps_its_modules(tmp_path, ash_log):
    """This repository's own CI scan loads these from a config inside its tree.

    snyk is not among them: the CI legs that use this file pass it with
    --ash-plugin-modules (.github/actions/run-scan-test/action.yml).
    """
    community = REPO / ".ash" / ".ash_community_plugins.yaml"
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    copied = source / ".ash" / ".ash_community_plugins.yaml"
    copied.write_text(community.read_text())

    config = resolve_config(config_path=copied, source_dir=source)

    assert config.ash_plugin_modules == COMMUNITY
    assert not _module_warnings(ash_log)


def test_the_ci_legs_using_that_file_pass_snyk_on_the_command_line():
    """Every scan the run-scan-test action starts with the community file names snyk."""
    action = (REPO / ".github" / "actions" / "run-scan-test" / "action.yml").read_text()
    scans = [
        line
        for line in action.splitlines()
        if ".ash_community_plugins.yaml" in line
        and line.lstrip().startswith(("ash ", "./ash ", "Invoke-ASH "))
        and " config validate " not in line
        and " dependencies install" not in line
    ]

    assert len(scans) == 5, scans
    for line in scans:
        assert f"--ash-plugin-modules {SNYK}" in line, line


_NETWORK_MODULES = {
    "_socket",
    "_ssl",
    "aiohttp",
    "azure",
    "boto3",
    "botocore",
    "ftplib",
    "github",
    "google.cloud",
    "grpc",
    "http.client",
    "httpx",
    "imaplib",
    "paramiko",
    "poplib",
    "requests",
    "slack_sdk",
    "smtplib",
    "socket",
    "telnetlib",
    "urllib.request",
    "urllib3",
    "websocket",
    "websockets",
    "xmlrpc",
}
#: Functions a network module above also holds that open no connection. An import
#: that takes only these from it is not network use; any other name from the same
#: module still is. url2pathname turns a file: URL into a local path:
#: utils/ash_install.py reads ASH's own install location from pip's
#: direct_url.json with it, and the gitlab-sast reporter and the suppression
#: expiration checker reach that module through utils/symbol_spans' install hint.
_CONNECTIONLESS_IMPORTS = {"urllib.request": {"url2pathname", "pathname2url"}}
_PROCESS_MODULES = {
    "_posixsubprocess",
    "_winapi",
    "nt",
    "posix",
    "asyncio.subprocess",
    "concurrent.futures.ProcessPoolExecutor",
    "concurrent.futures.process",
    "multiprocessing",
    "pty",
    "subprocess",
}
_OS_PROCESS_FUNCTIONS = {
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fork",
    "forkpty",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "system",
}
_PROCESS_CALLS = {
    f"{module}.{name}"
    for module in ("os", "posix", "nt")
    for name in _OS_PROCESS_FUNCTIONS
}
_PROCESS_MODULES |= {
    f"{module}.{name}"
    for module in ("os", "posix", "nt")
    for name in _OS_PROCESS_FUNCTIONS
}
_DYNAMIC_IMPORT_CALLS = {"importlib.import_module", "__import__"}
# Either can call connect() or system() without going through the modules above.
_NATIVE_MODULES = {"cffi", "ctypes"}
# Followed from a reporter or event handler module: ASH's plugin modules and its
# shared helpers, where a reporter's network or process use could live.
_FOLLOWED = (
    "automated_security_helper.plugin_modules.",
    "automated_security_helper.utils.",
)

#: Modules a reporter or event handler reaches that start processes, with what
#: they run. Each runs a local program. A new one fails the test below until it is
#: added here, or its package is added to OFF_HOST_PLUGIN_PACKAGES.
_REVIEWED_LOCAL_PROCESSES = {
    # Reached from the markdown, text and flat-json reporters through
    # utils.content_db_staleness, which runs grype's and trivy's database status
    # commands to read when their databases were built.
    "automated_security_helper.utils.subprocess_utils": "spawn_run, a local tool",
    "automated_security_helper.utils.sandbox.backends": (
        "probes for the local sandbox programs, reached through subprocess_utils"
    ),
    # Reached from the same reporters because utils.content_db_staleness imports
    # EMPTY_TOOL_CONFIG from it (the empty config file its status commands pass).
    # The reporters call none of its functions. Its own spawns, through
    # spawn_run, are grype db update and trivy's database downloads, run by the
    # scanners before an online scan; they send no scan data.
    "automated_security_helper.utils.content_db_refresh": (
        "spawn_run for grype and trivy database updates, a local tool; "
        "reporters import only EMPTY_TOOL_CONFIG"
    ),
}

#: Modules a reporter or event handler reaches that import a module chosen at run
#: time, with what they import.
_REVIEWED_DYNAMIC_IMPORTS = {
    "automated_security_helper.utils.symbol_spans": (
        "tree_sitter and its installed grammar packages, to parse source locally"
    ),
}


#: Scanners that ask the sandbox for a network (``sandbox_requirements.network`` or
#: ``network_requires_grant``), in the packages an in-tree config can add, with what
#: the network is for. A scanner reaches the network through the program it runs,
#: which the import walk below cannot see, so its declaration is read instead. A new
#: one fails the test below until it is added here, or its package is added to
#: OFF_HOST_PLUGIN_PACKAGES. A scanner that is also handed a credential
#: (``sandbox_requirements.env_names``) sends with the operator's identity, so it
#: cannot be listed here.
_REVIEWED_NETWORK_SCANNERS = {
    "trivy-repo": (
        "trivy, scanning against the databases ASH downloads before an online scan "
        "(utils/content_db_refresh.py); it is handed no credential"
    ),
}


def _module_file(name: str, repo: Path) -> Path:
    relative = Path(*name.split("."))
    package = repo / relative / "__init__.py"
    return package if package.is_file() else (repo / relative).with_suffix(".py")


def _imports_and_calls(path: Path, package: str) -> Tuple[Set[str], Set[str]]:
    """Absolute names ``path`` imports, relative imports resolved, and dotted calls."""
    names: Set[str] = set()
    calls: Set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                parent = ".".join(parts[: len(parts) - node.level + 1])
                base = f"{parent}.{base}" if base else parent
            members = {alias.name for alias in node.names}
            if members <= _CONNECTIONLESS_IMPORTS.get(base, set()):
                continue
            names.add(base)
            names.update(f"{base}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                calls.add(f"{node.func.value.id}.{node.func.attr}")
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    return names, calls


def _matches(name: str, roots: Set[str]) -> bool:
    return any(name == root or name.startswith(root + ".") for root in roots)


def _reached(module: str, repo: Path = REPO) -> Dict[str, Set[str]]:
    """What ``module`` and the modules it reaches use: ``network``, ``processes``
    and ``dynamic`` (an import chosen at run time, or ctypes/cffi).

    Each set holds the names of the modules that use it; ``modules`` holds every
    module of the package the walk opened.
    """
    found: Dict[str, Set[str]] = {
        "network": set(),
        "processes": set(),
        "dynamic": set(),
        "modules": set(),
    }
    seen: Set[str] = set()
    pending = [module]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        path = _module_file(name, repo)
        if not path.is_file():
            continue
        found["modules"].add(name)
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        imported, calls = _imports_and_calls(path, package)
        if any(_matches(i, _NETWORK_MODULES) for i in imported):
            found["network"].add(name)
        if any(_matches(i, _PROCESS_MODULES) for i in imported) or (
            calls & _PROCESS_CALLS
        ):
            found["processes"].add(name)
        if calls & _DYNAMIC_IMPORT_CALLS or any(
            _matches(i, _NATIVE_MODULES) for i in imported
        ):
            found["dynamic"].add(name)
        pending.extend(i for i in imported if i.startswith(_FOLLOWED))
    return found


def test_every_plugin_package_that_sends_data_off_the_host_is_listed(tmp_path):
    """Derived from the code: each package's ASH_REPORTERS, event handlers and ASH_SCANNERS.

    A reporter or event handler sends from the ASH process, so the modules it
    reaches are walked for network imports. A scanner sends through the program it
    runs, so its ``sandbox_requirements`` are read. ash_builtin's scanners are not
    checked: ``load_internal_plugins`` loads that package on every scan, so a config
    naming it adds nothing.

    Loaded in a subprocess, because loading a plugin package registers its
    plugins for the rest of the process.
    """
    code = (
        "import json, pkgutil\n"
        "import automated_security_helper.plugin_modules as pm\n"
        "import importlib\n"
        "from automated_security_helper.base.plugin_config import plugin_config_key\n"
        "from automated_security_helper.utils.sandbox.policy import SandboxRequirements\n"
        "out = {}\n"
        "for info in pkgutil.iter_modules(pm.__path__):\n"
        "    name = pm.__name__ + '.' + info.name\n"
        "    module = importlib.import_module(name)\n"
        "    handlers = getattr(module, 'ASH_EVENT_HANDLERS', {}) or {}\n"
        "    needs = {plugin_config_key(c): c.sandbox_requirements\n"
        "             for c in getattr(module, 'ASH_SCANNERS', [])}\n"
        # A scanner that decides per instance (a property) reads as None: networked
        # and not known to be without a credential.
        "    out[name] = {\n"
        "        'reporters': sorted(\n"
        "            {c.__module__ for c in getattr(module, 'ASH_REPORTERS', [])}\n"
        "            | {f.__module__ for fs in handlers.values() for f in fs}),\n"
        "        'network_scanners': {\n"
        "            key: bool(need.env_names)\n"
        "            if isinstance(need, SandboxRequirements) else None\n"
        "            for key, need in needs.items()\n"
        "            if not isinstance(need, SandboxRequirements)\n"
        "            or need.network or need.network_requires_grant}}\n"
        "print(json.dumps(out))\n"
    )
    from automated_security_helper.config.plugin_module_trust import (
        OFF_HOST_PLUGIN_PACKAGES,
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    in_process: Dict[str, Dict] = json.loads(result.stdout.strip().splitlines()[-1])

    reporting: Set[str] = set()
    scanning: Set[str] = set()
    reviewed: Dict[str, Optional[bool]] = {}
    unreviewed: Dict[str, Set[str]] = {}
    for package, found in in_process.items():
        for module in found["reporters"]:
            reached = _reached(module)
            if reached["network"]:
                reporting.add(package)
            launching = reached["processes"] - set(_REVIEWED_LOCAL_PROCESSES)
            dynamic = reached["dynamic"] - set(_REVIEWED_DYNAMIC_IMPORTS)
            if (launching or dynamic) and package not in OFF_HOST_PLUGIN_PACKAGES:
                unreviewed.setdefault(package, set()).update(launching | dynamic)
        if package == BUILTIN:
            continue
        for scanner, credential in found["network_scanners"].items():
            if scanner in _REVIEWED_NETWORK_SCANNERS:
                reviewed[scanner] = credential
            else:
                scanning.add(package)
    assert BUILTIN in in_process
    assert reporting | scanning == set(OFF_HOST_PLUGIN_PACKAGES)
    assert AWS in reporting
    assert SNYK in scanning
    assert not (reporting | scanning) & set(COMMUNITY)
    # Each reviewed scanner still asks for a network, and none is handed a credential.
    assert reviewed == dict.fromkeys(_REVIEWED_NETWORK_SCANNERS, False)
    assert not unreviewed


def test_the_walk_follows_shared_helpers_and_sees_processes(tmp_path):
    """A reporter reaching the network or a process through utils is seen."""
    root = tmp_path / "repo"
    plugin = root / "automated_security_helper" / "plugin_modules" / "probe"
    utils = root / "automated_security_helper" / "utils"
    plugin.mkdir(parents=True)
    utils.mkdir(parents=True)
    (plugin / "__init__.py").write_text("")
    (plugin / "reporter.py").write_text(
        "from automated_security_helper.utils import sender, runner\n"
    )
    (utils / "sender.py").write_text("import requests\n")
    (utils / "runner.py").write_text("from os import system\nsystem('true')\n")
    (utils / "loader.py").write_text(
        "import importlib\nimportlib.import_module('requests')\n"
    )
    (plugin / "other.py").write_text(
        "from automated_security_helper.utils import loader\n"
        "from concurrent.futures import ProcessPoolExecutor\n"
    )
    (plugin / "low.py").write_text("from _socket import gethostbyname\nimport posix\n")
    (plugin / "native.py").write_text("import ctypes\n")
    (plugin / "paths.py").write_text("from urllib.request import url2pathname\n")
    (plugin / "fetch.py").write_text(
        "from urllib.request import url2pathname, urlopen\n"
    )

    reached = _reached("automated_security_helper.plugin_modules.probe.reporter", root)

    assert reached["network"] == {"automated_security_helper.utils.sender"}
    assert reached["processes"] == {"automated_security_helper.utils.runner"}
    other = _reached("automated_security_helper.plugin_modules.probe.other", root)
    assert other["dynamic"] == {"automated_security_helper.utils.loader"}
    assert other["processes"] == {
        "automated_security_helper.plugin_modules.probe.other"
    }
    low = _reached("automated_security_helper.plugin_modules.probe.low", root)
    assert low["network"] == {"automated_security_helper.plugin_modules.probe.low"}
    assert low["processes"] == {"automated_security_helper.plugin_modules.probe.low"}
    native = _reached("automated_security_helper.plugin_modules.probe.native", root)
    assert native["dynamic"] == {
        "automated_security_helper.plugin_modules.probe.native"
    }
    # A path conversion taken alone from a network module is not network use;
    # any other name from that module still is.
    paths = _reached("automated_security_helper.plugin_modules.probe.paths", root)
    assert paths["network"] == set()
    fetch = _reached("automated_security_helper.plugin_modules.probe.fetch", root)
    assert fetch["network"] == {"automated_security_helper.plugin_modules.probe.fetch"}


def test_the_staleness_probes_share_the_refreshs_paths_without_reaching_it():
    """The reporters reach utils/content_db_staleness, which shares the empty tool
    config with utils/content_db_refresh through utils/content_db_shared. That
    module imports the standard library only, so the walk from the probes reaches
    it and finds nothing to review there, and never reaches the database updates."""
    shared = "automated_security_helper.utils.content_db_shared"
    imported, calls = _imports_and_calls(
        _module_file(shared, REPO), "automated_security_helper.utils"
    )
    assert not {
        name for name in imported if name.startswith("automated_security_helper")
    }

    assert _reached(shared) == {
        "network": set(),
        "processes": set(),
        "dynamic": set(),
        "modules": {shared},
    }
    probes = _reached("automated_security_helper.utils.content_db_staleness")
    assert shared in probes["modules"]
    assert "automated_security_helper.utils.content_db_refresh" not in probes["modules"]


# Run in a subprocess: the report() of every built-in reporter outside
# OFF_HOST_PLUGIN_PACKAGES on the fixture scan the snapshot tests use, with
# creating a non-Unix socket, resolving a name and starting a process replaced by
# a recorder that raises. The static walk above reads imports; this catches what
# it cannot see, such as a module imported by name or a library that connects.
_RUN_REPORTERS_GUARDED = """
import json, os, socket, subprocess, sys

# The recorders go in before anything else is imported, so a module that binds
# `from socket import gethostbyname` or `from os import system` at import gets the
# recorder. They pass calls through until armed, which is only while a reporter's
# report() or the control runs.
armed = [False]
attempts = {"network": [], "processes": []}

def refuse(kind, what):
    attempts[kind].append(what)
    raise OSError("refused by the test")

def guard(kind, what, original):
    def guarded(*args, **kwargs):
        if armed[0]:
            refuse(kind, what)
        return original(*args, **kwargs)
    return guarded

# Any socket that is not a Unix socket, so TCP, UDP and raw sockets alike, and
# every name lookup.
original_socket_init = socket.socket.__init__
def guarded_socket_init(self, family=-1, type=-1, proto=-1, fileno=None):
    if armed[0] and fileno is None and family != socket.AF_UNIX:
        refuse("network", f"socket family {family}")
    original_socket_init(self, family, type, proto, fileno)
socket.socket.__init__ = guarded_socket_init
import _socket
for module in (socket, _socket):
    for name in ("create_connection", "getaddrinfo", "gethostbyname",
                 "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        if hasattr(module, name):
            setattr(module, name, guard("network", name, getattr(module, name)))

original_popen_init = subprocess.Popen.__init__
def guarded_popen_init(self, args, *rest, **kwargs):
    if armed[0]:
        argv = args if isinstance(args, (list, tuple)) else [args]
        refuse("processes", os.path.basename(str(argv[0])))
    original_popen_init(self, args, *rest, **kwargs)
subprocess.Popen.__init__ = guarded_popen_init
import importlib
for module in (os, importlib.import_module(os.name)):  # os.name is posix or nt
    for name in dir(module):
        if name in ("system", "popen", "fork", "forkpty") or name.startswith(
            ("exec", "spawn", "posix_spawn")):
            setattr(module, name, guard("processes", "os." + name,
                                        getattr(module, name)))
try:
    import _posixsubprocess
    _posixsubprocess.fork_exec = guard(
        "processes", "fork_exec", _posixsubprocess.fork_exec)
except ImportError:
    pass

# Bound the way a module would bind them at import, before arming.
from socket import gethostbyname as early_bound_lookup
from os import system as early_bound_system
from _socket import gethostbyname as low_level_lookup
low_level_system = importlib.import_module(os.name).system

import pkgutil, tempfile
from pathlib import Path

out = {}

def record(key, run):
    attempts["network"].clear()
    attempts["processes"].clear()
    armed[0] = True
    try:
        result = run()
        error = None
    except Exception as e:
        result, error = None, type(e).__name__
    finally:
        armed[0] = False
    out[key] = {"network": list(attempts["network"]),
                "processes": sorted(attempts["processes"]), "error": error,
                "length": len(result) if isinstance(result, str) else 0}

# Importing the plugin packages outside OFF_HOST_PLUGIN_PACKAGES (argv[2]), armed
# and before anything else of ASH is imported, so their import-time code runs here.
plugin_dir = Path(sys.argv[1]) / "automated_security_helper" / "plugin_modules"
prefix = "automated_security_helper.plugin_modules."
local_packages = [prefix + i.name for i in pkgutil.iter_modules([str(plugin_dir)])
                  if i.ispkg and prefix + i.name not in sys.argv[2].split(",")]
preloaded = [name for name in sys.modules if name.startswith("automated_security_helper")]
record("imports", lambda: str([importlib.import_module(n) for n in local_packages]))
out["imports"]["packages"] = local_packages
out["imports"]["preloaded"] = preloaded

sys.path.insert(0, sys.argv[1])
from tests.snapshot.support.fixture_model import build_fixture_model
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_module_trust import off_host_package
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    load_additional_plugin_modules, load_internal_plugins)
import automated_security_helper.plugin_modules as pm

packages = [pm.__name__ + "." + i.name for i in pkgutil.iter_modules(pm.__path__)]

def control():
    for attempt in (
        lambda: socket.create_connection(("example.invalid", 443)),
        lambda: socket.gethostbyname("localhost"),
        lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
        lambda: early_bound_lookup("localhost"),
        lambda: subprocess.run(["true"]),
        lambda: os.system("true"),
        lambda: early_bound_system("true"),
        lambda: low_level_lookup("localhost"),
        lambda: low_level_system("true"),
    ):
        try:
            attempt()
        except OSError:
            pass
    socket.socketpair()  # a Unix socket pair is local, and allowed
    return "done"

record("control", control)
load_internal_plugins()
load_additional_plugin_modules(packages)
model = build_fixture_model(Path(tempfile.mkdtemp()))
for cls in sorted(ash_plugin_manager.plugin_modules("reporter"), key=plugin_config_key):
    if off_host_package(cls.__module__) is not None:
        continue
    with tempfile.TemporaryDirectory() as tmp:
        context = PluginContext(source_dir=Path(tmp) / "src",
                                output_dir=Path(tmp) / "out", config=AshConfig())
        record(plugin_config_key(cls), lambda: cls(context=context).report(model))
        out[plugin_config_key(cls)]["module"] = cls.__module__
print(json.dumps(out))
"""


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the recorders use POSIX process functions and a Unix socket pair",
)
def test_no_reporter_outside_those_packages_connects_or_starts_a_process(tmp_path):
    from automated_security_helper.config.plugin_module_trust import (
        OFF_HOST_PLUGIN_PACKAGES,
        off_host_package,
    )

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _RUN_REPORTERS_GUARDED,
            str(REPO),
            ",".join(OFF_HOST_PLUGIN_PACKAGES),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=600,
    )
    runs = json.loads(result.stdout.strip().splitlines()[-1])

    control = runs.pop("control")
    imports = runs.pop("imports")
    # ASH itself was not imported yet, so every package's import ran armed.
    assert imports["preloaded"] == []
    assert f"{AWS.rpartition('.')[0]}.ash_builtin" in imports["packages"]
    assert not set(imports["packages"]) & set(OFF_HOST_PLUGIN_PACKAGES)
    assert (imports["error"], imports["network"], imports["processes"]) == (
        None,
        [],
        [],
    )
    assert control["error"] is None
    assert len(control["network"]) == 5, control
    assert control["processes"] == ["os.system"] * 3 + ["true"], control
    local = {k: v for k, v in runs.items() if off_host_package(v["module"]) is None}
    assert local == runs
    assert len(local) >= 15, sorted(local)
    assert {k: v["error"] for k, v in local.items() if v["error"]} == {}
    # Each produced its report, so none returned before reaching its own code.
    assert sorted(k for k, v in local.items() if not v["length"]) == []
    assert {
        k: (v["network"], v["processes"])
        for k, v in local.items()
        if v["network"] or v["processes"]
    } == {}
