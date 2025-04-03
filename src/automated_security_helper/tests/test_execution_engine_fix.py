from automated_security_helper.execution_engine import ScanExecutionEngine
from automated_security_helper.models.config import ASHConfig
from automated_security_helper.models.scanner_types import BanditScannerConfig


def test_execution_engine_initialization():
    engine = ScanExecutionEngine()
    assert engine._scanners is not None
    assert "bandit" in engine._scanners
    assert "cdknag" in engine._scanners


def test_execute_with_default_config():
    engine = ScanExecutionEngine()
    results = engine.execute(None)
    assert isinstance(results, dict)
    assert "scanners" in results


def test_execute_with_custom_config():
    engine = ScanExecutionEngine()
    config = ASHConfig(
        project_name="test", sast={"scanners": [BanditScannerConfig(enabled=True)]}
    )
    results = engine.execute(config)
    assert isinstance(results, dict)
    assert "scanners" in results
    assert "bandit" in results["scanners"]
