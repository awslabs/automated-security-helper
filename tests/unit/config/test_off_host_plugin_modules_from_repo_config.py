# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config in the scanned tree cannot load ASH's plugin packages that send findings off the host.

ASH's own plugin packages are installed code, so ``plugin_module_trust`` keeps an
in-tree config's entries that name them. The exception is a package whose
reporters send findings to a remote service with the operator's credentials
(``ash_aws_plugins``). Every one of its reporters is enabled by default, so naming
the package was enough to send the findings off the host. Only the operator can
add it now. See config/plugin_module_trust.py.
"""

import ast
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER

AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"
COMMUNITY = [
    "automated_security_helper.plugin_modules.ash_snyk_plugins",
    "automated_security_helper.plugin_modules.ash_trivy_plugins",
    "automated_security_helper.plugin_modules.ash_ferret_plugins",
]
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


def _tree(tmp_path: Path, modules: List[str]) -> Path:
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"project_name": "scanned", "ash_plugin_modules": modules})
    )
    return source


@pytest.mark.parametrize(
    "entry", [AWS, f"{AWS}.s3_reporter", f"{AWS}.bedrock_summary_reporter"]
)
def test_an_in_tree_config_cannot_add_the_aws_reporters(tmp_path, ash_log, entry):
    source = _tree(tmp_path, [entry])

    config = resolve_config(source_dir=source)

    assert entry not in config.ash_plugin_modules
    warnings = [w for w in _warnings(ash_log) if "ash_plugin_modules" in w]
    assert len(warnings) == 1, _warnings(ash_log)
    assert entry in warnings[0]


def test_the_other_entries_of_that_config_are_kept(tmp_path, ash_log):
    source = _tree(tmp_path, [AWS, *COMMUNITY])

    config = resolve_config(source_dir=source)

    assert config.ash_plugin_modules == COMMUNITY


def test_an_uploaded_config_cannot_add_them(tmp_path, ash_log):
    upload = tmp_path / "upload" / "ash.yaml"
    upload.parent.mkdir()
    upload.write_text(yaml.safe_dump({"ash_plugin_modules": [AWS]}))
    source = tmp_path / "repo"
    source.mkdir()

    config = resolve_config(
        config_path=upload, source_dir=source, untrusted_config=True
    )

    assert AWS not in config.ash_plugin_modules


def test_an_operator_config_outside_the_tree_can(tmp_path, ash_log):
    _tree(tmp_path, [])
    operator = tmp_path / "operator.yaml"
    operator.write_text(yaml.safe_dump({"ash_plugin_modules": [AWS]}))

    config = resolve_config(config_path=operator, source_dir=tmp_path / "repo")

    assert config.ash_plugin_modules == [AWS]
    assert not _warnings(ash_log)


def test_an_operator_default_config_replaced_by_the_tree_can(tmp_path, ash_log):
    source = _tree(tmp_path, [AWS])
    operator = tmp_path / "operator.yaml"
    operator.write_text(yaml.safe_dump({"ash_plugin_modules": [AWS]}))

    config = resolve_config(
        config_path=source / ".ash" / ".ash.yaml",
        source_dir=source,
        trusted_config_path=operator,
    )

    assert config.ash_plugin_modules == [AWS]


@pytest.mark.parametrize("key", ["ash_plugin_modules", "ash-plugin-modules"])
def test_config_overrides_can(tmp_path, ash_log, key):
    source = _tree(tmp_path, [])

    config = resolve_config(source_dir=source, config_overrides=[f'{key}+=["{AWS}"]'])

    assert AWS in config.ash_plugin_modules


def test_ash_community_plugins_file_keeps_all_three_modules(tmp_path, ash_log):
    """This repository's own CI scan loads these from a config inside its tree."""
    community = REPO / ".ash" / ".ash_community_plugins.yaml"
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    copied = source / ".ash" / ".ash_community_plugins.yaml"
    copied.write_text(community.read_text())

    config = resolve_config(config_path=copied, source_dir=source)

    assert config.ash_plugin_modules == COMMUNITY
    assert not [w for w in _warnings(ash_log) if "ash_plugin_modules" in w]


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
}

#: Modules a reporter or event handler reaches that import a module chosen at run
#: time, with what they import.
_REVIEWED_DYNAMIC_IMPORTS = {
    "automated_security_helper.utils.symbol_spans": (
        "tree_sitter and its installed grammar packages, to parse source locally"
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

    Each set holds the names of the modules that use it.
    """
    found: Dict[str, Set[str]] = {
        "network": set(),
        "processes": set(),
        "dynamic": set(),
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


def test_every_plugin_package_whose_reporters_reach_the_network_is_listed(tmp_path):
    """Derived from the code: each package's ASH_REPORTERS and event handlers.

    Loaded in a subprocess, because loading a plugin package registers its
    plugins for the rest of the process.
    """
    code = (
        "import json, pkgutil\n"
        "import automated_security_helper.plugin_modules as pm\n"
        "import importlib\n"
        "out = {}\n"
        "for info in pkgutil.iter_modules(pm.__path__):\n"
        "    name = pm.__name__ + '.' + info.name\n"
        "    module = importlib.import_module(name)\n"
        "    handlers = getattr(module, 'ASH_EVENT_HANDLERS', {}) or {}\n"
        "    out[name] = sorted(\n"
        "        {c.__module__ for c in getattr(module, 'ASH_REPORTERS', [])}\n"
        "        | {f.__module__ for fs in handlers.values() for f in fs})\n"
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
    in_process: Dict[str, List[str]] = json.loads(
        result.stdout.strip().splitlines()[-1]
    )

    reaching: Set[str] = set()
    unreviewed: Dict[str, Set[str]] = {}
    for package, modules in in_process.items():
        for module in modules:
            reached = _reached(module)
            if reached["network"]:
                reaching.add(package)
            launching = reached["processes"] - set(_REVIEWED_LOCAL_PROCESSES)
            dynamic = reached["dynamic"] - set(_REVIEWED_DYNAMIC_IMPORTS)
            if (launching or dynamic) and package not in OFF_HOST_PLUGIN_PACKAGES:
                unreviewed.setdefault(package, set()).update(launching | dynamic)
    assert reaching == set(OFF_HOST_PLUGIN_PACKAGES)
    assert AWS in reaching
    assert not reaching & set(COMMUNITY)
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
