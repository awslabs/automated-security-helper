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

        def convert(self, target: Path | str) -> list[Path]:
            return [Path("test.txt")]

    def test_setup_paths_default(self):
        """Test setup_paths with default values."""
        converter = self.DummyConverter()
        assert converter.source_dir == Path(".")
        assert converter.output_dir == Path("ash_output")
        assert converter.work_dir == Path("ash_output/work")

    def test_setup_paths_custom(self):
        """Test setup_paths with custom values."""
        source = Path("/custom/source")
        output = Path("/custom/output")
        converter = self.DummyConverter(source_dir=source, output_dir=output)
        assert converter.source_dir == source
        assert converter.output_dir == output
        assert converter.work_dir == output.joinpath("temp")

    def test_setup_paths_string_conversion(self):
        """Test setup_paths converts string paths to Path objects."""
        converter = self.DummyConverter(
            source_dir="/test/source", output_dir="/test/output"
        )
        assert isinstance(converter.source_dir, Path)
        assert isinstance(converter.output_dir, Path)
        assert isinstance(converter.work_dir, Path)

    def test_configure_with_config(self):
        """Test configure method with config."""
        converter = self.DummyConverter()
        config = self.DummyConfig()
        converter.configure(config)
        assert converter.config == config

    def test_configure_without_config(self):
        """Test configure method without config."""
        converter = self.DummyConverter()
        original_config = converter.config
        converter.configure(None)
        assert converter.config == original_config

    def test_validate_implementation(self):
        """Test validate method implementation."""
        converter = self.DummyConverter()
        assert converter.validate() is True

    def test_convert_implementation(self):
        """Test convert method implementation."""
        converter = self.DummyConverter()
        result = converter.convert("test.txt")
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)

    def test_abstract_methods_not_implemented(self):
        """Test that abstract methods raise NotImplementedError when not implemented."""

        class AbstractConverter(ConverterPluginBase):
            pass

        with pytest.raises(
            TypeError,
            match="Can't instantiate abstract class AbstractConverter without an implementation for abstract method",
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

    def test_setup_paths_default(self):
        """Test setup_paths with default values."""
        reporter = self.DummyReporter()
        assert reporter.source_dir == Path(".")
        assert reporter.output_dir == Path("ash_output")

    def test_setup_paths_custom(self):
        """Test setup_paths with custom values."""
        source = Path("/custom/source")
        output = Path("/custom/output")
        reporter = self.DummyReporter(source_dir=source, output_dir=output)
        assert reporter.source_dir == source
        assert reporter.output_dir == output

    def test_configure_with_config(self):
        """Test configure method with config."""
        reporter = self.DummyReporter()
        config = self.DummyConfig()
        reporter.configure(config)
        assert reporter._config == config

    def test_validate_implementation(self):
        """Test validate method implementation."""
        reporter = self.DummyReporter()
        assert reporter.validate() is True

    def test_pre_report(self):
        """Test _pre_report sets start time."""
        reporter = self.DummyReporter()
        reporter._pre_report()
        assert reporter.start_time is not None
        assert isinstance(reporter.start_time, datetime)

    def test_post_report(self):
        """Test _post_report sets end time."""
        reporter = self.DummyReporter()
        reporter._post_report()
        assert reporter.end_time is not None
        assert isinstance(reporter.end_time, datetime)

    def test_report_with_model(self):
        """Test report method with ASHARPModel."""
        reporter = self.DummyReporter()
        model = ASHARPModel(findings=[], metadata={})
        result = reporter.report(model)
        assert result == '{"report": "complete"}'

    def test_report_end_to_end(self):
        """Test report method end to end with ASHARPModel."""
        reporter = self.DummyReporter()
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
            match="Can't instantiate abstract class AbstractReporter without an implementation for abstract method",
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
            target_type: Literal["source", "temp"],
            global_ignore_paths: List[IgnorePathWithReason] = [],
            config=None,
            *args,
            **kwargs,
        ):
            self.output.append("hello world")
            return SarifReport(runs=[])

    def test_model_post_init_no_config(self):
        """Test model_post_init with no config raises error."""
        with pytest.raises(ScannerError):
            self.DummyScanner()

    def test_model_post_init_with_config(self, tmp_path):
        """Test model_post_init with config."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config, source_dir=tmp_path)
        assert scanner.source_dir == tmp_path
        assert scanner.output_dir == tmp_path.joinpath("ash_output")
        assert scanner.work_dir == scanner.output_dir.joinpath("temp")
        assert scanner.results_dir == scanner.output_dir.joinpath("scanners").joinpath(
            config.name
        )

    def test_process_config_options(self):
        """Test _process_config_options does nothing by default."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config)
        scanner._process_config_options()  # Should not raise any error

    def test_resolve_arguments_basic(self):
        """Test _resolve_arguments with basic configuration."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config, command="dummy-scan")
        args = scanner._resolve_arguments("test.txt")
        assert args[0] == "dummy-scan"  # Command
        assert "test.txt" in args  # Target path

    def test_resolve_arguments_with_extra_args(self):
        """Test _resolve_arguments with extra arguments."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            config=config,
            command="dummy-scan",
            args=ToolArgs(extra_args=[{"key": "--debug", "value": "true"}]),
        )
        args = scanner._resolve_arguments("test.txt")
        assert "--debug" in args
        assert "true" in args

    def test_pre_scan_invalid_target(self):
        """Test _pre_scan with invalid target."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config)
        with pytest.raises(ScannerError):
            scanner._pre_scan(Path("nonexistent.txt"), target_type="temp")

    def test_pre_scan_creates_dirs(self, tmp_path):
        """Test _pre_scan creates necessary directories."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            config=config, source_dir=tmp_path, output_dir=tmp_path.joinpath("output")
        )
        test_file = tmp_path.joinpath("test.txt")
        test_file.touch()
        scanner._pre_scan(test_file, target_type="temp")
        assert scanner.work_dir.exists()
        assert scanner.results_dir.exists()

    def test_post_scan_sets_end_time(self, tmp_path):
        """Test _post_scan sets end_time."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config)
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

    def test_run_subprocess_success(self, test_source_dir):
        """Test _run_subprocess with successful command."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
            config=config,
            command="echo",
            args=ToolArgs(extra_args=[ToolExtraArg(key="hello", value="world")]),
        )
        scanner.scan(test_source_dir, target_type="source")
        assert scanner.exit_code == 0
        assert len(scanner.output) > 0

    def test_run_subprocess_failure(self, test_source_dir):
        """Test _run_subprocess with failing command."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config, command="nonexistent-command")
        final_args = scanner._resolve_arguments(test_source_dir)
        scanner._run_subprocess(final_args)
        assert scanner.exit_code == 1
        assert len(scanner.errors) > 0

    def test_run_subprocess_with_stdout_stderr(self, tmp_path):
        """Test _run_subprocess with stdout and stderr output."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(
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
        )
        assert len(scanner.output) > 0
        assert len(scanner.errors) > 0
        assert (
            Path(tmp_path).joinpath(f"{scanner.__class__.__name__}.stdout.log").exists()
        )
        assert (
            Path(tmp_path).joinpath(f"{scanner.__class__.__name__}.stderr.log").exists()
        )

    def test_run_subprocess_binary_not_found(self, test_source_dir):
        """Test _run_subprocess when binary is not found."""
        config = self.DummyConfig()
        scanner = self.DummyScanner(config=config, command="nonexistent-binary")
        scanner._run_subprocess(["nonexistent-binary"])
        assert scanner.exit_code == 1
        assert len(scanner.errors) > 0

    def test_abstract_methods_not_implemented(self):
        """Test that abstract methods raise NotImplementedError when not implemented."""

        class AbstractScanner(ScannerPluginBase):
            pass

        with pytest.raises(
            TypeError,
            match="Can't instantiate abstract class AbstractScanner without an implementation for abstract method",
        ):
            AbstractScanner()
