"""A plugin field that can be unset is refused, by name, where a method reads it.

A plugin can be built on its own and a context without validation, so a plugin's
context, configuration, configuration name, work directory and results directory
can each be None when a method reads them. Each such read raises an error that
names the plugin and the missing piece, rather than an AttributeError or a
TypeError on None further down.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
from rich.console import Console

from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.vocab import TargetType

pytestmark = pytest.mark.unit


def _context(tmp_path: Path, *, with_config: bool = True) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    if not with_config:
        # The default None is not validated, so the context keeps it.
        return PluginContext(source_dir=source, output_dir=output)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="unset-fields"),
    )


def _scanner_class() -> type:
    class _Scanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    return _Scanner


def test_a_scanner_whose_configuration_has_no_name_is_refused(tmp_path):
    # The results directory is named for the configuration.
    scanner_class = _scanner_class()
    with pytest.raises(ScannerError, match="Its configuration has no name"):
        scanner_class(config=ScannerPluginConfigBase(), context=_context(tmp_path))


def test_a_scanner_without_a_configuration_is_refused_by_its_config_swap(tmp_path):
    scanner_class = _scanner_class()
    scanner = scanner_class(
        config=ScannerPluginConfigBase(name="stub"), context=_context(tmp_path)
    )
    scanner.config = None
    with pytest.raises(ScannerError, match="_Scanner has no configuration"):
        scanner._pre_scan(tmp_path, TargetType.SOURCE, config={"name": "stub"})


def test_a_scanner_whose_context_has_no_work_directory_is_refused(tmp_path):
    scanner_class = _scanner_class()
    scanner = scanner_class(
        config=ScannerPluginConfigBase(name="stub"), context=_context(tmp_path)
    )
    # A plugin's construction derives the work directory when the context has
    # none, so it is taken away afterwards. The context warns of the repoint.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        scanner.context.work_dir = None
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(ScannerError, match="_Scanner has no work directory"):
        scanner._pre_scan(target, TargetType.SOURCE)


def test_a_converter_whose_context_has_no_configuration_is_refused(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.converters.mcp_config_converter import (
        McpConfigConverter,
        McpConfigConverterConfig,
    )

    context = _context(tmp_path, with_config=False)
    assert context.config is None
    converter = McpConfigConverter(context=context, config=McpConfigConverterConfig())
    with pytest.raises(ValueError, match="McpConfigConverter has no ASH configuration"):
        converter._skipped(str(context.source_dir / ".mcp.json"))


def test_a_converter_without_a_context_is_refused_before_it_records_anything(
    tmp_path,
):
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        ArchiveConverter,
        ArchiveConverterConfig,
    )

    converter = ArchiveConverter(
        context=_context(tmp_path), config=ArchiveConverterConfig()
    )
    # Construction refuses a converter without a context, so it is taken away
    # afterwards.
    converter.context = None
    with pytest.raises(ScannerError, match="No context provided for ArchiveConverter"):
        converter.convert()


def test_a_converter_whose_results_directory_is_unset_is_refused(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.converters.sdist_lock_harvester import (
        SdistLockHarvester,
    )

    harvester = SdistLockHarvester(context=_context(tmp_path))
    harvester.results_dir = None
    package = SimpleNamespace(name="pkg", version="1.0")
    with pytest.raises(
        ScannerError, match="SdistLockHarvester has no results directory"
    ):
        harvester._materialize(package, tmp_path, [], {})


def test_the_jupyter_converter_refuses_options_the_generic_configuration_lacks(
    tmp_path,
):
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
    )

    converter = JupyterConverter(context=_context(tmp_path))
    # Construction reads a generic configuration into the converter's own model,
    # so the generic one is put in afterwards, as the field admits.
    converter.config = ConverterPluginConfigBase(name="jupyter")
    with pytest.raises(TypeError, match="runs on the generic converter configuration"):
        converter._get_tool_version_constraint()


def test_a_reporter_without_a_configuration_is_refused_by_name(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
        MarkdownReporter,
    )

    reporter = MarkdownReporter(context=_context(tmp_path))
    reporter.config = None
    with pytest.raises(ScannerError, match="MarkdownReporter has no configuration"):
        reporter.report(None)


def test_trivy_refuses_an_operator_path_lookup_for_a_configuration_without_a_name(
    tmp_path,
):
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )

    scanner = TrivyRepoScanner(context=_context(tmp_path))
    # The operator's write of an option is looked up under the section the name
    # gives; without one there is no section to look under.
    scanner.config = scanner.config.model_copy(update={"name": None})
    with pytest.raises(ScannerError, match="configuration has no name"):
        scanner._operator_path(
            "module_dir", tmp_path / "modules", "trivy uses its own."
        )


def test_scan_targets_refuses_a_context_without_a_work_directory(tmp_path):
    from automated_security_helper.utils.scan_targets import scan_targets

    with pytest.raises(ValueError, match="The scan's context has no work directory"):
        scan_targets(SimpleNamespace(source_dir=tmp_path, work_dir=None))


def test_the_suppression_pass_refuses_a_context_without_a_configuration(tmp_path):
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

    report = SarifReport(version="2.1.0", runs=[])
    with pytest.raises(ValueError, match="The suppression pass has no configuration"):
        apply_suppressions_to_sarif(report, _context(tmp_path, with_config=False))


def test_the_suppression_scope_check_refuses_an_engine_without_a_configuration():
    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    engine = SimpleNamespace(_context=SimpleNamespace(config=None), plugins={})
    with pytest.raises(
        ValueError, match="no configuration to check suppression scopes against"
    ):
        ScanExecutionEngine._check_suppression_scope_engines(engine)


def test_the_plugin_listing_refuses_a_table_key_that_is_not_a_plugin_section(
    tmp_path,
):
    from automated_security_helper.cli.plugin import (
        _print_tables,
        _reachable_label,
        _version_label,
    )

    class _Listed:
        pass

    context = _context(tmp_path)
    console = Console(record=True, width=400)
    _print_tables(
        console,
        {"widgets": [_Listed]},
        context,
        context.config,
        False,
        False,
        {},
        _version_label,
        _reachable_label,
    )
    assert "'widgets' is not a plugin section" in console.export_text()
