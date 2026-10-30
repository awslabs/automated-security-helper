"""Tests for Bandit scanner."""

import logging

import pytest
from pathlib import Path
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.models.core import IgnorePathWithReason

pytestmark = pytest.mark.integration


@pytest.fixture
def test_bandit_scanner(test_plugin_context):
    """Create a test Bandit scanner."""
    return BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(),
    )


def test_bandit_scanner_init(test_plugin_context):
    """Test BanditScanner initialization."""
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(),
    )
    assert scanner.config.name == "bandit"
    assert scanner.command == "bandit"
    assert scanner.args.format_arg == "--format"
    assert scanner.args.format_arg_value == "sarif"


def test_bandit_scanner_configure(test_plugin_context, test_source_dir):
    """Test BanditScanner configuration."""
    test_config_file = test_source_dir.joinpath(".bandit")
    test_config_file.touch()
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                config_file=test_config_file,
                excluded_paths=[
                    IgnorePathWithReason(path="tests/*", reason="Test files")
                ],
            )
        ),
    )
    assert scanner.config.options.config_file.name == ".bandit"
    assert len(scanner.config.options.excluded_paths) == 1
    assert scanner.config.options.excluded_paths[0].path == "tests/*"


def test_bandit_scanner_validate(test_bandit_scanner):
    """Test BanditScanner validation."""
    assert test_bandit_scanner.validate_plugin_dependencies() is True


@pytest.mark.parametrize(
    "config_file,config_arg",
    [
        (".bandit", "--ini"),
        ("bandit.yaml", "--configfile"),
        ("bandit.toml", "--configfile"),
    ],
)
def test_process_config_options_with_config_files(
    config_file, config_arg, test_source_dir, test_plugin_context
):
    """Test processing of different config file types."""
    config_path = test_source_dir.joinpath(config_file)
    config_path.touch()

    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                config_file=config_path,
            )
        ),
    )
    # Construction has already processed the options (ScannerPluginBase). A
    # second call rebuilds the option flags from the base arguments, so it
    # would count one --ini too (the behavior tests pin that); none is needed.

    config_args_keys = [arg.key for arg in scanner.args.extra_args]
    if config_arg == "--ini":
        # A scan always passes one --ini (BanditScanner._process_config_options):
        # the operator's .bandit here, so the empty file ASH writes otherwise is
        # not added beside it. The file is recorded on the scanner as well.
        assert scanner._ini_file is not None
        assert Path(scanner._ini_file).resolve() == config_path.resolve()
        ini_values = [
            arg.value for arg in scanner.args.extra_args if arg.key == "--ini"
        ]
        assert len(ini_values) == 1, config_args_keys
        assert Path(ini_values[0]).resolve() == config_path.resolve()
    else:
        assert any(arg.startswith(config_arg) for arg in config_args_keys)


def test_process_config_options_exclusions(test_plugin_context):
    """Test processing of exclusion paths."""
    scanner = BanditScanner(
        context=test_plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[
                    IgnorePathWithReason(path="tests/*", reason="Test files"),
                    IgnorePathWithReason(path="examples/*", reason="Example files"),
                ]
            )
        ),
    )
    scanner._process_config_options()

    # Check that exclusion arguments were added
    exclusion_args = [arg.key for arg in scanner.args.extra_args]
    # The exclusion args are in the format '--exclude=tests/*' (no embedded
    # quotes — quoting values here would pass '"' as part of the argv since
    # ASH invokes scanners via subprocess without a shell).
    assert any("--exclude=" in arg and "tests/*" in arg for arg in exclusion_args)


def test_bandit_scanner_scan(test_bandit_scanner, test_source_dir, monkeypatch):
    """Test BanditScanner scan method."""
    # Create a test Python file with a known vulnerability
    test_file = test_source_dir.joinpath("test_file.py")
    test_file.write_text("import pickle\npickle.loads(b'test')")  # Known security issue

    # Import json here for use in the mock function
    import json
    from pathlib import Path

    # Create a mock function that properly handles the self parameter
    def mock_run_subprocess(*args, **kwargs):
        # Extract the results_dir from kwargs
        results_dir = kwargs.get("results_dir")
        if not results_dir:
            # If not in kwargs, try to get it from args (position 2)
            if len(args) > 2:
                results_dir = args[2]

        # Create the results directory
        Path(results_dir).mkdir(parents=True, exist_ok=True)

        # Create a minimal valid SARIF file
        sarif_file = Path(results_dir).joinpath("bandit.sarif")
        minimal_sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "Bandit", "rules": []}}, "results": []}
            ],
        }

        with open(sarif_file, "w") as f:
            json.dump(minimal_sarif, f)

        return {"returncode": 0, "stdout": "", "stderr": ""}

    # Apply the monkeypatch
    monkeypatch.setattr(test_bandit_scanner, "_run_subprocess", mock_run_subprocess)

    # Run the scan
    results = test_bandit_scanner.scan(test_source_dir, target_type="source")

    # Check that results were returned
    assert results is not None


def test_bandit_scanner_scan_nonexistent_path(test_bandit_scanner):
    """Test BanditScanner scan method with error."""
    # Try to scan a non-existent directory
    resp = test_bandit_scanner.scan(Path("nonexistent"), target_type="source")
    assert resp is not None
    assert resp is True
    assert (
        "(bandit) Target directory nonexistent is empty or doesn't exist. Skipping scan."
        in test_bandit_scanner.errors
    )


def test_bandit_scanner_additional_formats(test_plugin_context, caplog):
    """additional_formats adds no ``--format`` to the extra arguments, and the
    operator is told the formats are not produced.

    bandit takes one ``--format`` (argparse ``store``, last one wins). A second
    one after the base class's ``--format sarif`` made bandit write that format
    into bandit.sarif, and the scan failed reading it as SARIF. The one format in
    argv stays the base class's SARIF; without the warning ``html`` would just
    never appear.
    """
    with caplog.at_level(logging.WARNING):
        scanner = BanditScanner(
            context=test_plugin_context,
            config=BanditScannerConfig(
                options=BanditScannerConfigOptions(
                    additional_formats=["sarif", "html"],
                )
            ),
        )
        scanner._process_config_options()

    format_args = [arg.key for arg in scanner.args.extra_args]
    assert "--format" not in format_args
    assert scanner.args.format_arg == "--format"
    assert scanner.args.format_arg_value == "sarif"
    told = [
        record.getMessage()
        for record in caplog.records
        if "additional_formats" in record.getMessage()
    ]
    assert any("html" in message and "not produced" in message for message in told), [
        record.getMessage() for record in caplog.records
    ]
