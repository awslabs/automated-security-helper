import pytest
from datetime import date, timedelta
from automated_security_helper.models.core import (
    ToolExtraArg,
    ScanStatistics,
    IgnorePathWithReason,
    ToolArgs,
    Suppression,
)


def test_tool_extra_arg_model():
    """Test the ToolExtraArg model."""
    # Test with string value
    arg = ToolExtraArg(key="format", value="sarif")
    assert arg.key == "format"
    assert arg.value == "sarif"

    # Test with integer value
    arg = ToolExtraArg(key="timeout", value=30)
    assert arg.key == "timeout"
    assert arg.value == 30

    # Test with boolean value
    arg = ToolExtraArg(key="verbose", value=True)
    assert arg.key == "verbose"
    assert arg.value is True

    # Test with None value
    arg = ToolExtraArg(key="config")
    assert arg.key == "config"
    assert arg.value is None


def test_scan_statistics_model():
    """Test the ScanStatistics model."""
    stats = ScanStatistics(
        files_scanned=100,
        lines_of_code=5000,
        total_findings=10,
        findings_by_type={"critical": 2, "high": 3, "medium": 5},
        scan_duration_seconds=15.5,
    )

    assert stats.files_scanned == 100
    assert stats.lines_of_code == 5000
    assert stats.total_findings == 10
    assert stats.findings_by_type == {"critical": 2, "high": 3, "medium": 5}
    assert stats.scan_duration_seconds == 15.5


def test_ignore_path_with_reason_model():
    """Test the IgnorePathWithReason model."""
    ignore = IgnorePathWithReason(
        path="tests/*", reason="Test files should not be scanned"
    )

    assert ignore.path == "tests/*"
    assert ignore.reason == "Test files should not be scanned"


def test_tool_args_model():
    """Test the ToolArgs model."""
    args = ToolArgs(
        output_arg="--output",
        scan_path_arg="--path",
        format_arg="--format",
        format_arg_value="sarif",
        extra_args=[
            ToolExtraArg(key="verbose", value=True),
            ToolExtraArg(key="timeout", value=30),
        ],
    )

    assert args.output_arg == "--output"
    assert args.scan_path_arg == "--path"
    assert args.format_arg == "--format"
    assert args.format_arg_value == "sarif"
    assert len(args.extra_args) == 2
    assert args.extra_args[0].key == "verbose"
    assert args.extra_args[0].value is True
    assert args.extra_args[1].key == "timeout"
    assert args.extra_args[1].value == 30


def test_tool_args_with_extra_fields():
    """Test the ToolArgs model with extra fields."""
    args = ToolArgs(
        output_arg="--output", custom_field="custom_value", another_field=123
    )

    assert args.output_arg == "--output"
    assert args.custom_field == "custom_value"
    assert args.another_field == 123


def test_suppression_model_minimal():
    """Test the Suppression model with minimal fields."""
    suppression = Suppression(
        reason="Test suppression", rule_id="TEST001", path="src/main.py"
    )

    assert suppression.rule_id == "TEST001"
    assert suppression.path == "src/main.py"
    assert suppression.line_start is None
    assert suppression.line_end is None
    assert suppression.reason == "Test suppression"
    assert suppression.expiration is None


def test_suppression_model_with_line_range():
    """Test the Suppression model with line range."""
    suppression = Suppression(
        rule_id="TEST001",
        path="src/main.py",
        line_start=10,
        line_end=20,
        reason="False positive",
    )

    assert suppression.rule_id == "TEST001"
    assert suppression.path == "src/main.py"
    assert suppression.line_start == 10
    assert suppression.line_end == 20
    assert suppression.reason == "False positive"


def test_suppression_model_with_future_expiration():
    """Test the Suppression model with a future expiration date."""
    # Create a date 30 days in the future
    future_date = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")

    suppression = Suppression(
        reason="Test suppression",
        rule_id="TEST001",
        path="src/main.py",
        expiration=future_date,
    )

    assert suppression.rule_id == "TEST001"
    assert suppression.path == "src/main.py"
    assert suppression.expiration == future_date


def test_suppression_model_invalid_line_range():
    """Test the Suppression model with an invalid line range."""
    with pytest.raises(ValueError) as excinfo:
        Suppression(
            reason="Test suppression",
            rule_id="TEST001",
            path="src/main.py",
            line_start=20,
            line_end=10,  # End line before start line
        )

    assert "line_end must be greater than or equal to line_start" in str(excinfo.value)


def test_suppression_model_invalid_expiration_format():
    """Test the Suppression model with an invalid expiration date format."""
    with pytest.raises(ValueError) as excinfo:
        Suppression(
            reason="Test suppression",
            rule_id="TEST001",
            path="src/main.py",
            expiration="01/01/2025",  # Wrong format
        )

    assert "Invalid expiration date format" in str(excinfo.value)


def test_suppression_model_past_expiration():
    """Test the Suppression model with a past expiration date."""
    # Create a date in the past
    past_date = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")

    with pytest.raises(ValueError) as excinfo:
        Suppression(
            reason="Test suppression",
            rule_id="TEST001",
            path="src/main.py",
            expiration=past_date,
        )

    assert "expiration date must be in the future" in str(excinfo.value)
