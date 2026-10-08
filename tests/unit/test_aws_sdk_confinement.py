# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The AWS SDK is confined to the opt-in ash_aws_plugins module.

Why this exists: the EKS operator stack ships its scan ServiceAccount with no AWS
permissions, and deploy/cdk/lib/ash-eks-operator-stack.ts justifies that by a
measurement: every boto3/botocore user in ASH lives under
plugin_modules/ash_aws_plugins/, nothing loads that module unless a scan names it
in ash_plugin_modules, and pyproject.toml declares no entry points through which
it could be registered automatically. That measurement was made once, by hand.
A scanner or core module that later imported boto3 would make the default install
need AWS credentials with nothing failing, so this test re-takes it on every run.

What it checks, all statically (no import of the package under test):

- No module outside ash_aws_plugins imports boto3 or botocore, by `import`,
  `from ... import`, `importlib.import_module("...")` or `__import__("...")` with a
  literal name. Imports inside functions count, because a lazy import is still an
  import once the function runs.
- No module outside ash_aws_plugins imports ash_aws_plugins, which would load it
  without the adopter opting in.
- The installed distribution declares no entry points other than its console
  scripts. Read from installed metadata rather than parsed from pyproject.toml,
  which covers what is actually installed and needs no TOML parser (tomllib is
  stdlib only from 3.11, and this repository supports 3.10).

Known limits: an import whose module name is computed at run time is not
detected. The check covers the installed package (automated_security_helper/),
not tests or deploy tooling, which do not ship in the wheel's default path.
"""

from __future__ import annotations

import ast
from importlib.metadata import EntryPoint, distribution
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "automated_security_helper"
AWS_PLUGINS_DIR = Path("automated_security_helper/plugin_modules/ash_aws_plugins")
AWS_PLUGINS_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"
SDK_ROOTS = ("boto3", "botocore")


def _names_sdk(module: str | None) -> bool:
    if not module:
        return False
    return any(module == root or module.startswith(root + ".") for root in SDK_ROOTS)


def _names_aws_plugins(module: str | None) -> bool:
    if not module:
        return False
    return module == AWS_PLUGINS_MODULE or module.startswith(AWS_PLUGINS_MODULE + ".")


def _imported_modules(tree: ast.AST) -> list[tuple[int, str]]:
    """Every module name the source imports, with its line number."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Relative imports (level > 0) stay inside the package by definition,
            # and resolving them is not needed: a relative import cannot reach
            # boto3, and one reaching ash_aws_plugins is caught below by path.
            if node.level == 0 and node.module:
                found.append((node.lineno, node.module))
                # `from automated_security_helper.plugin_modules import ash_aws_plugins`
                found.extend(
                    (node.lineno, f"{node.module}.{alias.name}") for alias in node.names
                )
        elif isinstance(node, ast.Call):
            func = node.func
            is_import_call = (
                isinstance(func, ast.Attribute)
                and func.attr == "import_module"
                and isinstance(func.value, ast.Name)
                and func.value.id == "importlib"
            ) or (
                isinstance(func, ast.Name)
                and func.id in {"__import__", "import_module"}
            )
            if (
                is_import_call
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                found.append((node.lineno, node.args[0].value))
    return found


def find_violations(package_root: Path, repo_root: Path) -> list[str]:
    """Imports of the AWS SDK or of ash_aws_plugins from outside ash_aws_plugins."""
    violations: list[str] = []
    seen: set[tuple[str, int]] = set()
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(repo_root)
        if relative.is_relative_to(AWS_PLUGINS_DIR):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for lineno, module in _imported_modules(tree):
            # One report per import statement: `from botocore.exceptions import X`
            # yields both the module and the module-qualified name.
            if (relative.as_posix(), lineno) in seen:
                continue
            if _names_sdk(module) or _names_aws_plugins(module):
                seen.add((relative.as_posix(), lineno))
            if _names_sdk(module):
                violations.append(f"{relative.as_posix()}:{lineno} imports {module}")
            elif _names_aws_plugins(module):
                violations.append(
                    f"{relative.as_posix()}:{lineno} imports {module}, which loads the "
                    "AWS plugins without the scan opting in"
                )
    return violations


def registering_entry_points(entry_points: list[EntryPoint]) -> list[str]:
    """Entry points through which a plugin could be loaded without an import.

    Console scripts are how the CLI is installed and load nothing on their own.
    Any other group is a registration path a source scan cannot see.
    """
    return sorted(
        f"{ep.group}: {ep.name} = {ep.value}"
        for ep in entry_points
        if ep.group != "console_scripts"
    )


def test_the_scan_covers_the_package_and_finds_the_sdk_users() -> None:
    # Non-vacuity. If the package moved or the walk broke, an empty scan would
    # report no violations for the wrong reason. The AWS plugins themselves must be
    # seen to import boto3, through the same detector, or the detector is blind.
    files = list(PACKAGE.rglob("*.py"))
    assert len(files) > 100, f"only {len(files)} files under {PACKAGE}"
    aws_files = [
        p for p in files if p.relative_to(REPO_ROOT).is_relative_to(AWS_PLUGINS_DIR)
    ]
    sdk_users = [
        p.name
        for p in aws_files
        if any(
            _names_sdk(m) for _, m in _imported_modules(ast.parse(p.read_text("utf-8")))
        )
    ]
    assert len(sdk_users) >= 4, (
        f"expected the AWS reporters to import the SDK, saw {sdk_users}"
    )


def test_no_module_outside_ash_aws_plugins_uses_the_aws_sdk() -> None:
    assert find_violations(PACKAGE, REPO_ROOT) == []


def test_the_distribution_registers_no_plugin_entry_points() -> None:
    # Entry points are the one registration path a source scan cannot see: a
    # plugin listed there could be loaded with no import anywhere in the tree.
    installed = list(distribution("automated-security-helper").entry_points)
    # Non-vacuity: the console scripts must be visible, or the metadata read found
    # some other distribution or none, and an empty list would pass below.
    assert any(ep.group == "console_scripts" for ep in installed), installed
    assert registering_entry_points(installed) == []


@pytest.mark.parametrize(
    "planted",
    [
        "import boto3\n",
        "import botocore.exceptions\n",
        "from botocore.exceptions import ClientError\n",
        "def lazy():\n    import boto3\n    return boto3\n",
        "import importlib\nclient = importlib.import_module('boto3')\n",
        "sdk = __import__('botocore.session')\n",
        "from automated_security_helper.plugin_modules import ash_aws_plugins\n",
        "import automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter\n",
    ],
)
def test_a_planted_import_is_reported(tmp_path: Path, planted: str) -> None:
    # The negative control: the same detector over a copy of the layout with one
    # scanner that imports the SDK must report it.
    package = tmp_path / "automated_security_helper"
    scanner = package / "plugin_modules" / "ash_builtin" / "scanners" / "planted.py"
    scanner.parent.mkdir(parents=True)
    scanner.write_text(planted, encoding="utf-8")
    allowed = package / "plugin_modules" / "ash_aws_plugins" / "s3_reporter.py"
    allowed.parent.mkdir(parents=True)
    allowed.write_text("import boto3\n", encoding="utf-8")

    violations = find_violations(package, tmp_path)

    assert len(violations) == 1, violations
    assert violations[0].startswith(
        "automated_security_helper/plugin_modules/ash_builtin/scanners/planted.py:"
    )


def test_a_planted_entry_point_is_reported() -> None:
    planted = [
        EntryPoint(
            "ashx", "automated_security_helper.cli.entrypoint:main", "console_scripts"
        ),
        EntryPoint("aws", AWS_PLUGINS_MODULE, "ash.plugins"),
    ]
    assert registering_entry_points(planted) == [
        f"ash.plugins: aws = {AWS_PLUGINS_MODULE}"
    ]
