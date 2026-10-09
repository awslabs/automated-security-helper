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
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set

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
    "boto3",
    "botocore",
    "requests",
    "httpx",
    "urllib3",
    "urllib.request",
    "http.client",
    "aiohttp",
    "socket",
}


def _module_file(name: str) -> Path:
    relative = Path(*name.split("."))
    package = REPO / relative / "__init__.py"
    return package if package.is_file() else (REPO / relative).with_suffix(".py")


def _imports(path: Path, package: str) -> Set[str]:
    """Absolute names ``path`` imports, with relative imports resolved."""
    names: Set[str] = set()
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
    return names


def _reaches_the_network(module: str) -> bool:
    """Whether ``module``, or a plugin module it imports, imports a network client."""
    seen: Set[str] = set()
    pending = [module]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        path = _module_file(name)
        if not path.is_file():
            continue
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        for imported in _imports(path, package):
            if any(
                imported == net or imported.startswith(net + ".")
                for net in _NETWORK_MODULES
            ):
                return True
            if imported.startswith("automated_security_helper.plugin_modules."):
                pending.append(imported)
    return False


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
    import json

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

    reaching = {
        package
        for package, modules in in_process.items()
        if any(_reaches_the_network(module) for module in modules)
    }
    assert reaching == set(OFF_HOST_PLUGIN_PACKAGES)
    assert AWS in reaching
    assert not reaching & set(COMMUNITY)
