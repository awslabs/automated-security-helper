import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from automated_security_helper.core.enums import RunMode, Phases
from automated_security_helper.interactions.run_ash_scan import (
    run_ash_scan,
    format_duration,
)


@pytest.fixture
def mock_logger():
    with patch("automated_security_helper.utils.log.get_logger") as mock:
        mock_logger_instance = MagicMock()
        mock.return_value = mock_logger_instance
        yield mock_logger_instance


@pytest.fixture
def mock_orchestrator():
    with patch(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator"
    ) as mock:
        mock_instance = MagicMock()
        mock_instance.execute_scan.return_value = MagicMock()
        mock_instance.execute_scan.return_value.metadata.summary_stats.actionable = 0
        mock_instance.config.fail_on_findings = True
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_container():
    with patch(
        "automated_security_helper.interactions.run_ash_container.run_ash_container"
    ) as mock:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock.return_value = mock_result
        yield mock


def test_format_duration():
    """Test the format_duration function."""
    assert format_duration(30) == "30s"
    assert format_duration(90) == "1m 30s"
    assert format_duration(3700) == "1h 1m 40s"


def test_run_ash_scan_local_mode(mock_logger, mock_orchestrator, tmp_path):
    """Test run_ash_scan in local mode."""
    source_dir = tmp_path / "source"
    output_dir = tmp_path / "output"
    source_dir.mkdir()
    output_dir.mkdir()

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.exists",
            return_value=False,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.cwd",
            return_value=Path("/fake/cwd"),
        ),
        patch("automated_security_helper.interactions.run_ash_scan.os.chdir"),
        patch("builtins.open", mock_open()),
        patch(
            "automated_security_helper.models.asharp_model.AshAggregatedResults"
        ) as mock_results,
    ):
        mock_results.model_dump_json.return_value = "{}"

        result = run_ash_scan(
            source_dir=str(source_dir),
            output_dir=str(output_dir),
            mode=RunMode.local,
            show_summary=True,
        )

        mock_orchestrator.execute_scan.assert_called_once()
        assert result is not None


@pytest.mark.skip(reason="Need to fix mocks")
def test_run_ash_scan_container_mode(mock_logger, mock_container, tmp_path):
    """Test run_ash_scan in container mode."""
    source_dir = tmp_path / "source"
    output_dir = tmp_path / "output"
    source_dir.mkdir()
    output_dir.mkdir()

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.cwd",
            return_value=Path("/fake/cwd"),
        ),
        patch("automated_security_helper.interactions.run_ash_scan.os.chdir"),
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.exists",
            return_value=True,
        ),
        patch("builtins.open", mock_open(read_data="{}")),
        patch(
            "automated_security_helper.interactions.run_ash_scan.AshAggregatedResults"
        ) as mock_results,
    ):
        mock_results.model_validate_json.return_value = MagicMock()
        mock_results.model_validate_json.return_value.metadata.summary_stats.actionable = 0

        result = run_ash_scan(
            source_dir=str(source_dir),
            output_dir=str(output_dir),
            mode=RunMode.container,
            debug=True,
        )

        mock_container.assert_called_once()
        assert result is not None


def test_run_ash_scan_with_actionable_findings(
    mock_logger, mock_orchestrator, test_source_dir, test_output_dir
):
    """Test run_ash_scan with actionable findings."""
    source_dir = test_source_dir
    output_dir = test_output_dir
    Path(source_dir).mkdir(parents=True, exist_ok=True)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.exists",
            return_value=False,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.cwd",
            return_value=Path("/fake/cwd"),
        ),
        patch("automated_security_helper.interactions.run_ash_scan.os.chdir"),
        patch("builtins.open", mock_open()),
        patch(
            "automated_security_helper.interactions.run_ash_scan.AshAggregatedResults"
        ) as mock_results,
        patch(
            "automated_security_helper.interactions.run_ash_scan.sys.exit"
        ) as mock_exit,
    ):
        mock_results.model_dump_json.return_value = "{}"
        mock_orchestrator.execute_scan.return_value.metadata.summary_stats.actionable = 5

        run_ash_scan(
            source_dir=str(source_dir),
            output_dir=str(output_dir),
            mode=RunMode.local,
            show_summary=True,
            fail_on_findings=True,
        )

        mock_exit.assert_called_once_with(2)


def test_run_ash_scan_with_custom_phases(mock_logger, mock_orchestrator, tmp_path):
    """Test run_ash_scan with custom phases."""
    source_dir = tmp_path / "source"
    output_dir = tmp_path / "output"
    source_dir.mkdir()
    output_dir.mkdir()

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.exists",
            return_value=False,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.Path.cwd",
            return_value=Path("/fake/cwd"),
        ),
        patch("automated_security_helper.interactions.run_ash_scan.os.chdir"),
        patch("builtins.open", mock_open()),
        patch(
            "automated_security_helper.interactions.run_ash_scan.AshAggregatedResults"
        ) as mock_results,
    ):
        mock_results.model_dump_json.return_value = "{}"

        run_ash_scan(
            source_dir=str(source_dir),
            output_dir=str(output_dir),
            mode=RunMode.local,
            phases=[Phases.convert, Phases.report],
            inspect=True,
        )

        mock_orchestrator.execute_scan.assert_called_once()
        # Check that the phases were correctly processed
        args, kwargs = mock_orchestrator.execute_scan.call_args
        assert kwargs.get("phases") == ["convert", "report", "inspect"] or (
            args
            and "convert" in args[0]
            and "report" in args[0]
            and "inspect" in args[0]
        )
