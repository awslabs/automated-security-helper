# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every ASH_* variable the package reads is in the container's exclusion set.

A config file that reads an environment variable gets the value passed into
the container, except for the names in ``CONTAINER_ENV_NOT_PASSED``: ASH sets
those in the container or reads them as its own settings, so a passed value
would be read by ASH itself, not by the configuration, and the scan refuses
with exit 3 instead. The set is an explicit catalog, so a new ``os.environ``
read of an ``ASH_*`` name added anywhere in the package has to join it; this
cell derives the read names from the sources (every literal ``os.environ``
subscript, ``.get`` and ``os.getenv``) and fails naming the strays, which is
how the catalog is kept from drifting without runtime prefix guessing.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from automated_security_helper.interactions import run_ash_container

_ASH_NAME = re.compile(r"ASH_[A-Z0-9_]+\Z")


def _is_environ(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr == "environ"
    return isinstance(node, ast.Name) and node.id == "environ"


def _literal(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _module_constants(tree: ast.Module) -> dict:
    """Module-level ``NAME = "literal"`` assignments, by name."""
    constants: dict = {}
    for node in tree.body:
        targets: list = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        literal = _literal(value) if value is not None else None
        if literal is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = literal
    return constants


def _environment_reads(package: Path) -> tuple:
    """Every environment name the package reads, and the unresolved key sites.

    A key is read as its string literal, through the module's own string
    constant when the expression is a plain name, or through the one
    module-level string constant of that name anywhere in the package (how an
    imported constant key resolves; a name two modules bind to different
    strings resolves through neither). ``envvar=`` keywords are reads too: the
    CLI package reads those names through its option declarations, as a string
    or as a list of them. A key that resolves no other way lands in the second
    element as ``<file> [<shape>] :: <key expression>``, so the caller judges
    it against the catalog of known relay sites instead of assuming the
    literal set is exhaustive.
    """
    parsed = []
    package_constants: dict = {}
    colliding: set = set()
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        constants = _module_constants(tree)
        parsed.append((path.relative_to(package), tree, constants))
        for name, value in constants.items():
            if name in package_constants and package_constants[name] != value:
                colliding.add(name)
            package_constants[name] = value
    for name in colliding:
        del package_constants[name]

    names = set()
    unresolved = []
    for rel, tree, constants in parsed:

        def resolved(node: ast.expr) -> str | None:
            literal = _literal(node)
            if literal is not None:
                return literal
            if isinstance(node, ast.Name):
                return constants.get(node.id) or package_constants.get(node.id)
            return None

        def record(node: ast.expr, shape: str) -> None:
            name = resolved(node)
            if name is not None:
                names.add(name)
            else:
                unresolved.append(f"{rel.as_posix()} [{shape}] :: {ast.unparse(node)}")

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                getenv = (
                    func.attr == "getenv"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "os"
                )
                environ_get = func.attr == "get" and _is_environ(func.value)
                if (getenv or environ_get) and node.args:
                    record(node.args[0], func.attr)
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg != "envvar":
                        continue
                    value = keyword.value
                    if isinstance(value, (ast.List, ast.Tuple)):
                        for element in value.elts:
                            record(element, "envvar-list")
                    else:
                        record(value, "envvar")
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Load)
                and _is_environ(node.value)
            ):
                record(node.slice, "subscript")
            if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.In, ast.NotIn)) for op in node.ops
            ):
                if any(_is_environ(cmp) for cmp in node.comparators):
                    record(node.left, "in-environ")
    return names, unresolved


#: The reads whose key is a value a CALLER supplies (a relay helper reading a
#: name passed in, a loop over a collection of names, a regex group from a
#: ``${VAR}`` interpolation, a per-scanner accessor). The name such a site
#: reads arrives from its call sites, whose literals this sweep collects where
#: they name one, so the relay itself adds no name the catalog could hold. The
#: list is exact, with multiplicity, so a NEW dynamic read anywhere in the
#: package fails the cell naming its site, and a removed one fails it as
#: stale. Line numbers are left out so the pin survives unrelated edits.
_KNOWN_DYNAMIC_READS = sorted(
    [
        "cli/mcp/scan_target.py [get] :: var",
        "config/ash_config.py [get] :: var_name",
        "config/ash_config.py [get] :: name",
        "config/config_validator.py [get] :: reference.group(1)",
        "config/environment_record.py [get] :: name",
        "core/constants.py [get] :: variable",
        "core/constants.py [get] :: variable",
        "core/constants.py [get] :: variable",
        "interactions/run_ash_container.py [get] :: name",
        "interactions/run_ash_container.py [get] :: name",
        "interactions/run_ash_container.py [get] :: name",
        "interactions/run_ash_container.py [get] :: name",
        "interactions/run_ash_container.py [in-environ] :: name",
        "interactions/run_ash_container.py [subscript] :: name",
        "interactions/run_ash_scan.py [get] :: name",
        "plugin_modules/ash_aws_plugins/bedrock_summary_reporter.py [get] :: name",
        "plugin_modules/ash_builtin/scanners/_grep_scanner_base.py [get] :: cache_env",
        "plugin_modules/ash_builtin/scanners/_grep_scanner_base.py [get] :: self.cache_dir_env_var()",
        "plugin_modules/ash_builtin/scanners/grype_scanner.py [in-environ] :: name",
        "plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py [get] :: env",
        "utils/command_safe_stream.py [get] :: name",
        "utils/console.py [get] :: name",
        "utils/log.py [in-environ] :: name",
        "utils/log.py [in-environ] :: name",
        "utils/log.py [in-environ] :: name",
        "utils/process_env.py [get] :: key",
        "utils/uv_tool_runner.py [get] :: variable",
    ]
)


def test_every_ash_variable_the_package_reads_is_in_the_exclusion_set():
    package = Path(run_ash_container.__file__).resolve().parents[1]
    collected, unresolved = _environment_reads(package)
    reads = {name for name in collected if _ASH_NAME.fullmatch(name)}
    # The sweep's own denominator: a sweep that collects nothing proves
    # nothing, and ASH_CONFIG is read for certain, as is the CLI's own
    # declared environment option name.
    assert "ASH_CONFIG" in reads
    assert len(reads) >= 15, sorted(reads)
    missing = sorted(reads - run_ash_container.CONTAINER_ENV_NOT_PASSED)
    assert missing == [], missing
    # A key the resolution cannot read could be an uncatalogued name, so every
    # unresolved site must be one of the known relays: a new dynamic read
    # fails here naming its site, and a removed one fails as a stale entry.
    assert sorted(unresolved) == _KNOWN_DYNAMIC_READS, sorted(unresolved)
