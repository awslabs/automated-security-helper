"""The SARIF flag is the container's counter rule plus the stop causes.

``ScanResultsContainer.scan_succeeded`` reads the counters the saved results model
holds. ``ScannerPluginBase._sarif_execution_successful`` reads the same counters and
then the live plugin's recorded stop causes and exit code, which the model does not
carry. So the flag can be False where the container is True (a run stopped before it
counted a target), and never True where the container is False.
"""

from types import SimpleNamespace

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)


def _sarif_flag(attempted, failed, kept_flag=None, post_run_error=None) -> bool:
    scanner = SimpleNamespace(
        targets_attempted=attempted,
        targets_failed=failed,
        scan_kept_flag=kept_flag,
        scan_post_run_error=post_run_error,
        exit_code=None,
        _sarif_exit_code_accepted=lambda: True,
    )
    return ScannerPluginBase._sarif_execution_successful(scanner)


def _container_verdict(attempted, failed) -> bool:
    return ScanResultsContainer(
        scanner_name="probe-scanner",
        targets_attempted=attempted,
        targets_failed=failed,
    ).scan_succeeded


COUNTERS = [
    (None, 0),
    (0, 0),
    (1, 0),
    (3, 0),
    (-1, 0),
    (None, 1),
    (0, 2),
    (3, 1),
    (3, 3),
]


@pytest.mark.parametrize("attempted,failed", COUNTERS)
def test_the_flag_is_never_true_where_the_container_is_false(attempted, failed):
    if not _container_verdict(attempted, failed):
        assert _sarif_flag(attempted, failed) is False


@pytest.mark.parametrize("attempted,failed", COUNTERS)
def test_with_no_stop_cause_the_flag_follows_the_counters(attempted, failed):
    assert _sarif_flag(attempted, failed) is _container_verdict(attempted, failed)


@pytest.mark.parametrize("attempted", [None, 0])
def test_a_run_stopped_before_it_counted_a_target_is_false_only_in_the_flag(attempted):
    assert _container_verdict(attempted, 0) is True
    assert _sarif_flag(attempted, 0, kept_flag=("timed_out", "the run timed out")) is (
        False
    )
    assert _sarif_flag(attempted, 0, post_run_error="output was not recorded") is False
