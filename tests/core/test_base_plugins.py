"""Tests for base plugin classes."""

from typing import List, Literal
import pytest
from pathlib import Path
from datetime import datetime
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
    ScannerError,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolArgs,
    ToolExtraArg,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.models.asharp_model import ASHARPModel


class TestConverterPlugin:
    """Test cases for ConverterPluginBase."""

    class DummyConfig(ConverterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    class DummyConverter(ConverterPluginBase):
        """Dummy converter for testing."""

        def validate(self) -> bool:
            return True

        def convert(self) -> list[Path]:
            return [Path("test.txt")]

    def test_setup_paths_default(self, test_plugin_context):
        """Test setup_paths with default values."""
        converter = self.DummyConverter(context=test_plugin_context)
        assert converter.context.source_dir == test_plugin_context.source_dir
        assert converter.context.output_dir == test_plugin_context.output_dir
        assert converter.context.work_dir == test_plugin_context.work_dir

    def test_setup_paths_custom(self, test_plugin_context):
        """Test setup_paths with custom values."""
        source = Path("/custom/source")
        output = Path("/custom/output")
        # Create a custom context with the specified paths
        custom_context = PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output.joinpath(ASH_WORK_DIR_NAME),
            config=test_plugin_context.config,
        )
        converter = self.DummyConverter(context=custom_context)
        assert converter.context.source_dir == source
        assert converter.context.output_dir == output
        assert converter.context.work_dir == output.joinpath(ASH_WORK_DIR_NAME)

    def test_setup_paths_string_conversion(self, test_plugin_context):
        """Test setup_paths converts string paths to Path objects."""
        # Create a custom context with string paths
        custom_context = PluginContext(
            source_dir="/test/source",
            output_dir="/test/output",
            config=test_plugin_context.config,
        )
        converter = self.DummyConverter(context=custom_context)
        assert isinstance(converter.context.source_dir, Path)
        assert isinstance(converter.context.output_dir, Path)
        assert isinstance(converter.context.work_dir, Path)

    def test_configure_with_config(self, test_plugin_context):
        """Test configure method with config."""
        converter = self.DummyConverter(context=test_plugin_context)
        config = self.DummyConfig()
        converter.configure(config)
        assert converter.config == config

    def test_configure_without_config(self, test_plugin_context):
        """Test configure method without config."""
        converter = self.DummyConverter(context=test_plugin_context)
        original_config = converter.config
        converter.configure(None)
        assert converter.config == original_config

    def test_validate_implementation(self, test_plugin_context):
        """Test validate method implementation."""
        converter = self.DummyConverter(context=test_plugin_context)
        assert converter.validate() is True

    def test_convert_implementation(self, test_plugin_context):
        """Test convert method implementation."""
        converter = self.DummyConverter(context=test_plugin_context)
        result = converter.convert()
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)

    def test_abstract_methods_not_implemented(self):
        """Test that abstract methods raise NotImplementedError when not implemented."""

        class AbstractConverter(ConverterPluginBase):
            pass

        with pytest.raises(
            TypeError,
            match="Can't instantiate abstract class AbstractConverter",
        ):
            AbstractConverter()


class TestReporterPlugin:
    """Test cases for ReporterPluginBase."""

    class DummyConfig(ReporterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"
        extension: str = ".txt"

    class DummyReporter(ReporterPluginBase):
        """Dummy reporter for testing."""

        def validate(self) -> bool:
            return True

        def report(self, model: ASHARPModel) -> str:
            return '{"report": "complete"}'

    def test_setup_paths_default(self, test_plugin_context):
        """Test setup_paths with default values."""
        reporter = self.DummyReporter(context=test_plugin_context)
        assert reporter.context.source_dir == test_plugin_context.source_dir
        assert reporter.context.output_dir == test_plugin_context.output_dir

    def test_setup_paths_custom(self, test_plugin_context):
        """Test setup_paths with custom values."""
        source = Path("/custom/source")
        output = Path("/custom/output")
        custom_context = PluginContext(
            source_dir=source, output_dir=output, config=test_plugin_context.config
        )
        reporter = self.DummyReporter(context=custom_context)
        assert reporter.context.source_dir == source
        assert reporter.context.output_dir == output

    def test_configure_with_config(self, test_plugin_context):
        """Test configure method with config."""
        reporter = self.DummyReporter(context=test_plugin_context)
        config = self.DummyConfig()
        reporter.configure(config)
        assert reporter._config == config

    def test_validate_implementation(self, test_plugin_context):
        """Test validate method implementation."""
        reporter = self.DummyReporter(context=test_plugin_context)
        assert reporter.validate() is True

    def test_pre_report(self, test_plugin_context):
        """Test _pre_report sets start time."""
        reporter = self.DummyReporter(context=test_plugin_context)
        reporter._pre_report()
        assert reporter.start_time is not None
        assert isinstance(reporter.start_time, datetime)

    def test_post_report(self, test_plugin_context):
        """Test _post_report sets end time."""
        reporter = self.DummyReporter(context=test_plugin_context)
        reporter._post_report()
        assert reporter.end_time is not None
        assert isinstance(reporter.end_time, datetime)

    def test_report_with_model(self, test_plugin_context):
        """Test report method with ASHARPModel."""
        reporter = self.DummyReporter(context=test_plugin_context)
        model = ASHARPModel(findings=[], metadata={})
        result = reporter.report(model)
        assert result == '{"report": "complete"}'

    def test_report_end_to_end(self, test_plugin_context):
        """Test report method end to end with ASHARPModel."""
        reporter = self.DummyReporter(context=test_plugin_context)
        model = ASHARPModel(findings=[], metadata={})

        reporter._pre_report()
        result = reporter.report(model)
        reporter._post_report()

        assert reporter.start_time is not None
        assert reporter.end_time is not None
        assert result == '{"report": "complete"}'

    def test_abstract_methods_not_implemented(self):
        """Test that abstract methods raise NotImplementedError when not implemented."""

        class AbstractReporter(ReporterPluginBase):
            pass

        with pytest.raises(
            TypeError,
            match="Can't instantiate abstract class AbstractReporter",
        ):
            AbstractReporter()


class TestScannerPlugin:
    """Test cases for ScannerPluginBase."""

    class DummyConfig(ScannerPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    class DummyScanner(ScannerPluginBase):
        """Dummy scanner for testing."""

        def validate(self) -> bool:
            return True

        def scan(
            self,
            target: Path,
            target_type: Literal["source", "converted"],
            global_ignore_paths: List[IgnorePathWithReason] = [],
            config=None,
            *args,
            **kwargs,
        ):
            self.output.append("hello world")
            return SarifReport(runs=[])

    def test_model_post_init_no_config(self, test_plugin_context):
        """Test model_post_init with no config raises error."""
        with pytest.raises(ScannerError):
            self.DummyScanner(context=test_plugin_context)

    def test_model_post_init_with_config(self, tmp_path, test_plugin_context):
        """Test model_post_init with config."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config, context=test_plugin_context)
        assert scanner.context.source_dir == test_plugin_context.source_dir
        assert scanner.context.output_dir == test_plugin_context.output_dir
        assert scanner.context.work_dir == test_plugin_context.work_dir
        assert scanner.results_dir == scanner.context.output_dir.joinpath(
            "scanners"
        ).joinpath(config.name)

    def test_process_config_options(self, test_plugin_context):
        """Test _process_config_options does nothing by default."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config, context=test_plugin_context)
        scanner._process_config_options()  # Should not raise any error

    def test_resolve_arguments_basic(self, test_plugin_context):
        """Test _resolve_arguments with basic configuration."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            config=config, context=test_plugin_context, command="dummy-scan"
        )
        args = scanner._resolve_arguments("test.txt")
        assert args[0] == "dummy-scan"  # Command
        assert "test.txt" in args  # Target path

    def test_resolve_arguments_with_extra_args(self, test_plugin_context):
        """Test _resolve_arguments with extra arguments."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            config=config,
            context=test_plugin_context,
            command="dummy-scan",
            args=ToolArgs(extra_args=[ToolExtraArg(key="--debug", value="true")]),
        )
        args = scanner._resolve_arguments("test.txt")
        assert "--debug" in args
        assert "true" in args

    def test_pre_scan_invalid_target(self, test_plugin_context):
        """Test _pre_scan with invalid target."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(context=test_plugin_context, config=config)
        with pytest.raises(ScannerError):
            scanner._pre_scan(Path("nonexistent.txt"), target_type="converted")

    def test_pre_scan_creates_dirs(self, tmp_path, test_plugin_context):
        """Test _pre_scan creates necessary directories."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            context=test_plugin_context,
            config=config,
        )
        test_file = tmp_path.joinpath("test.txt")
        test_file.touch()
        scanner._pre_scan(test_file, target_type="converted")
        assert scanner.context.work_dir.exists()
        assert scanner.results_dir.exists()

    def test_post_scan_sets_end_time(self, tmp_path, test_plugin_context):
        """Test _post_scan sets end_time."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            context=test_plugin_context,
            config=config,
        )
        test_file = tmp_path.joinpath("test.txt")
        test_file.touch()
        scanner._pre_scan(
            test_file,
            target_type="source",
            config=config,
        )
        scanner.scan(test_file, target_type="source")
        scanner._post_scan(
            test_file,
            target_type="source",
        )
        assert scanner.end_time is not None

    def test_run_subprocess_success(self, test_source_dir, test_plugin_context):
        """Test _run_subprocess with successful command."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            context=test_plugin_context,
            config=config,
            command="echo",
            args=ToolArgs(extra_args=[ToolExtraArg(key="hello", value="world")]),
        )
        scanner.scan(test_source_dir, target_type="source")
        assert scanner.exit_code == 0
        assert len(scanner.output) > 0

    def test_run_subprocess_failure(self, test_source_dir, test_plugin_context):
        """Test _run_subprocess with failing command."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            context=test_plugin_context,
            config=config,
            command="nonexistent-command",
        )
        final_args = scanner._resolve_arguments(test_source_dir)
        scanner._run_subprocess(final_args)
        assert scanner.exit_code == 1
        assert len(scanner.errors) > 0

    def test_run_subprocess_with_stdout_stderr(self, tmp_path, test_plugin_context):
        """Test _run_subprocess with stdout and stderr output."""
        # Skip this test for now as it's failing consistently
        # import pytest
        # pytest.skip("Skipping test_run_subprocess_with_stdout_stderr due to consistent failures")

        config = self.DummyConfig()
        scanner = self.DummyScanner(
            context=test_plugin_context,
            config=config,
            command="python",
            args=ToolArgs(
                extra_args=[
                    ToolExtraArg(
                        key="-c",
                        value="import sys; print('hello'); print('error', file=sys.stderr)",
                    )
                ]
            ),
        )
        scanner.results_dir = tmp_path
        scanner._run_subprocess(
            [
                "python",
                "-c",
                "import sys; print('hello'); print('error', file=sys.stderr)",
            ],
            tmp_path,
            cwd=tmp_path,  # Use tmp_path as the working directory to avoid directory not found errors
            stderr_preference="both",
            stdout_preference="both",
        )
        assert len(scanner.output) > 0
        assert len(scanner.errors) > 0
        assert (
            Path(tmp_path).joinpath(f"{scanner.__class__.__name__}.stdout.log").exists()
        )
        assert (
            Path(tmp_path).joinpath(f"{scanner.__class__.__name__}.stderr.log").exists()
        )

    def test_run_subprocess_binary_not_found(self, test_plugin_context):
        """Test _run_subprocess when binary is not found."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            context=test_plugin_context,
            config=config,
            command="nonexistent-binary",
        )
        scanner._run_subprocess(["nonexistent-binary"])
        assert scanner.exit_code == 1
        assert len(scanner.errors) > 0

    def test_abstract_methods_not_implemented(self):
        """Test that abstract methods raise NotImplementedError when not implemented."""

        class AbstractScanner(ScannerPluginBase):
            pass

        with pytest.raises(
            TypeError,
            match="Can't instantiate abstract class AbstractScanner",
        ):
            AbstractScanner()
