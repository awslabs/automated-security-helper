"""The scan method reads the results model class from the module, not a local."""

import pytest

from automated_security_helper.core.orchestrator import ASHScanOrchestrator

pytestmark = pytest.mark.unit


def test_execute_scan_does_not_rebind_the_results_model_name():
    """A function-local import of the results model class made the name a local
    for the whole method, so reads after the existing-results branch raised
    UnboundLocalError on every completed scan. The module-level import serves.
    """
    local_names = ASHScanOrchestrator._execute_scan.__code__.co_varnames

    assert "AshAggregatedResults" not in local_names
