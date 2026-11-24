import pytest

from tests.unit.plugin_modules.ash_aws_plugins.security_hub_reporter_doubles import (
    archive_run,
    built_finding,
    isolated_aws_environment as isolated_aws_environment,
    make_model,
    make_reporter,
    make_result,
    no_retry_sleep as no_retry_sleep,
    stored_finding,
)

pytestmark = pytest.mark.unit


def test_baseline_results_send_no_archive_record(tmp_path):
    model = make_model([make_result()], completed=("bandit",))
    model.metadata.baseline = {
        "sha256": "abc",
        "matched": 1,
        "matched_without_lines": 0,
    }
    stale = stored_finding(
        built_finding(make_reporter(tmp_path), make_result(rule_id="B105", line=5))
    )
    document, imports, _ = archive_run(tmp_path, model, [stale], expected_sent=1)
    assert document["archived"] == 0
    assert (
        document["archive_skipped"]
        == "the results leave out findings already in a baseline"
    )
    assert len(imports.findings) == 1
