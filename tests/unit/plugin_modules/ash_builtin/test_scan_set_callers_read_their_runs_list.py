# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each plugin that reads the scan set reads back the list its run wrote.

The orchestrator writes the scan set under the run's ID before any plugin runs,
and a plugin that calls ``scan_set`` with ``run_id=context.run_id`` reads that list
back instead of walking the tree again (``get_scan_set``). Six places call it for
the plugins: the archive and Jupyter converters, detect-secrets, npm-audit,
snyk-code's copy of the tree, and ``utils/cfn_template_model``, which picks the
candidate templates for cdk-nag and cfn-nag.

What pinned those calls was an AST test that each passes a ``run_id=`` keyword,
which a call passing ``getattr(self.context, "runid", None)`` satisfies, and which
does not see a call through ``scan_set as _files_to_scan`` or
``getattr(<module>, "scan_set")``. The Jupyter kwargs test compared the keyword
with ``context.run_id``, which its fixture left None, so ``run_id=None`` passed it.

Here each plugin's file-list step runs with a run ID on its context, after
``scan_set`` wrote that run's list, and with the walk patched to raise. The step
must read the list back, under that ID, and not walk. A stricter AST check
resolves import aliases, refuses a ``getattr`` that fetches ``scan_set``, and
refuses a ``run_id`` that is a literal None or names no run ID.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Callable
from unittest.mock import patch

import pytest

import automated_security_helper
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import scan_set

AshConfig.model_rebuild()
PluginContext.model_rebuild()

RUN = "e" * 32
GET_SCAN_SET = "automated_security_helper.utils.get_scan_set"


@pytest.fixture(autouse=True)
def _no_uv_probe(monkeypatch):
    """No uv probe and no tool update check, as tests/snapshot/conftest.py pins."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    monkeypatch.setattr(
        UVToolRunner,
        "get_tool_version",
        lambda self, tool_name, package_name=None, *args, **kwargs: "0.0.0",
    )


def _archive(context: PluginContext) -> Callable[[], object]:
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        ArchiveConverter,
        ArchiveConverterConfig,
    )

    converter = ArchiveConverter(context=context, config=ArchiveConverterConfig())
    return converter.convert


def _jupyter(context: PluginContext) -> Callable[[], object]:
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    converter = JupyterConverter(context=context, config=JupyterConverterConfig())
    return converter._notebooks_in_scan_set


def _scanner_step(scanner_class, config_class, context: PluginContext):
    """Run *scanner_class*'s scan of the source with its tool taken as present."""
    scanner = scanner_class(context=context, config=config_class())
    scanner.dependencies_satisfied = True

    def _scan():
        with patch.object(scanner_class, "_pre_scan", return_value=True):
            return scanner.scan(target=context.source_dir, target_type="source")

    return _scan


def _cdk_nag(context: PluginContext) -> Callable[[], object]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
        CdkNagScanner,
        CdkNagScannerConfig,
    )

    return _scanner_step(CdkNagScanner, CdkNagScannerConfig, context)


def _cfn_nag(context: PluginContext) -> Callable[[], object]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
        CfnNagScannerConfig,
    )

    return _scanner_step(CfnNagScanner, CfnNagScannerConfig, context)


def _detect_secrets(context: PluginContext) -> Callable[[], object]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    return _scanner_step(DetectSecretsScanner, DetectSecretsScannerConfig, context)


def _npm_audit(context: PluginContext) -> Callable[[], object]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
        NpmAuditScannerConfig,
    )

    return _scanner_step(NpmAuditScanner, NpmAuditScannerConfig, context)


def _snyk_code(context: PluginContext) -> Callable[[], object]:
    """snyk-code's copy of the scan set; nothing here starts snyk."""
    import contextlib

    from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
        SnykCodeScanner,
        SnykCodeScannerConfig,
    )

    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())

    def _stage():
        with contextlib.ExitStack() as cleanup:
            return scanner._stage_source(context.source_dir, [], cleanup)

    return _stage


#: Each place that calls scan_set for a plugin, by the module the call is in,
#: relative to the package, with the plugin steps that reach it.
CALL_SITES = {
    "plugin_modules/ash_builtin/converters/archive_converter.py": (_archive,),
    "plugin_modules/ash_builtin/converters/jupyter_converter.py": (_jupyter,),
    "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py": (_detect_secrets,),
    "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py": (_npm_audit,),
    "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py": (_snyk_code,),
    "utils/cfn_template_model.py": (_cdk_nag, _cfn_nag),
}

#: The callers that are not a plugin's: the definition and its command line, the
#: orchestrator that writes the run's list, and the helper a scanner's exclusions
#: are worked out with.
NOT_PLUGIN_CALLERS = {
    "utils/get_scan_set.py",
    "core/orchestrator.py",
    "utils/scan_output_dirs.py",
}

STEPS = [
    pytest.param(step, id=f"{module}::{step.__name__.lstrip('_')}")
    for module, steps in sorted(CALL_SITES.items())
    for step in steps
]


@pytest.mark.parametrize("make_step", STEPS)
def test_the_plugin_reads_back_the_list_its_run_wrote(tmp_path, make_step):
    source = tmp_path / "src"
    source.mkdir()
    for name in ("app.py", "other.py"):
        (source / name).write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    written = scan_set(source=str(source), output=str(output), run_id=RUN)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
        run_id=RUN,
    )
    step = make_step(context)
    call_site = make_step.__name__

    read_back = []
    real_read_back = gss._lists_this_run_wrote

    def _recording_read_back(output_path, run_id, *inputs):
        lists = real_read_back(output_path, run_id, *inputs)
        read_back.append((run_id, lists))
        return lists

    with (
        patch.object(
            gss,
            "_collect_ignorefiles_and_all_files",
            side_effect=AssertionError("walked the tree"),
        ) as walk,
        patch.object(gss, "_lists_this_run_wrote", side_effect=_recording_read_back),
    ):
        step()

    assert walk.call_count == 0, f"{call_site} walked the tree instead of reading back"
    assert read_back, f"{call_site} did not read back its run's list"
    for run_id, lists in read_back:
        assert run_id == RUN
        assert lists is not None and [item.strip() for item in lists[1]] == written


def test_every_call_site_is_covered_above():
    """The parametrized test above names each module that calls scan_set for a
    plugin: every caller in the package but the ones that are not a plugin's."""
    package = Path(automated_security_helper.__file__).parent
    calling = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if _scan_set_calls(path)
    }
    assert calling - NOT_PLUGIN_CALLERS == set(CALL_SITES)
    assert NOT_PLUGIN_CALLERS <= calling


def _scan_set_names(tree: ast.Module) -> set[str]:
    """The names a module binds to get_scan_set.scan_set, aliases included."""
    names = {"scan_set"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == GET_SCAN_SET:
            for alias in node.names:
                if alias.name == "scan_set":
                    names.add(alias.asname or alias.name)
    return names


def _scan_set_calls(path: Path) -> list[ast.Call]:
    """Calls of scan_set by any name it is imported as, as a module attribute, or
    fetched with ``getattr``; the last is returned as the ``getattr`` call."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = _scan_set_names(tree)
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in names:
            calls.append(node)
        elif isinstance(func, ast.Attribute) and func.attr == "scan_set":
            calls.append(node)
        elif (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "scan_set"
        ):
            calls.append(node)
    return calls


def _names_a_run_id(value: ast.expr) -> bool:
    """Whether *value* reads a run ID: an attribute ``run_id`` or ``_run_id``, or a
    ``getattr`` of ``"run_id"``. A literal None or a misspelled name does not."""
    for node in ast.walk(value):
        if isinstance(node, ast.Attribute) and node.attr in ("run_id", "_run_id"):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "run_id"
        ):
            return True
    return False


def test_every_scan_set_call_passes_a_run_id_it_reads_from_the_run():
    """A call through an alias counts, a ``getattr`` that fetches ``scan_set`` is
    refused (nothing can tell what it passes), and the ``run_id`` keyword has to
    read a run ID rather than be None or a misspelled attribute."""
    package = Path(automated_security_helper.__file__).parent
    problems = []
    for path in sorted(package.rglob("*.py")):
        if path.name == "get_scan_set.py":
            continue
        for call in _scan_set_calls(path):
            where = f"{path.relative_to(package)}:{call.lineno}"
            if isinstance(call.func, ast.Name) and call.func.id == "getattr":
                problems.append(f"{where}: scan_set fetched with getattr")
                continue
            run_id = next((k.value for k in call.keywords if k.arg == "run_id"), None)
            if run_id is None:
                problems.append(f"{where}: no run_id")
            elif not _names_a_run_id(run_id):
                problems.append(f"{where}: run_id={ast.unparse(run_id)}")
    assert not problems, problems
