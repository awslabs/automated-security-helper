# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for .github/actions/validate-container/assert_detection.py.

That script is the verdict of the validate-container detection leg: the built
image scans a fixture with a shell=True call and a key-shaped credential planted
in it, and the leg passes only if bandit reports B602 and detect-secrets reports a
SECRET-* rule. It replaced a check that required at least one actionable finding
per scanner, which stayed green with shell=True removed from the fixture because
bandit still reported B404, B105 and B603. The case that pins that regression is
`test_bandit_without_b602_fails`, built from the rule ids a real scan of the
fixture without shell=True produced.

The script is loaded by path, as tests/unit/test_scanner_error_counter_gate.py
loads count_scanner_errors.py, because `.github/actions/` is not a package.

What this does not cover: the payloads here are synthetic. They follow the shape
of `ash_aggregated_results.json` (`sarif.runs[].results[]` with `ruleId`,
`properties.scanner_name` and `suppressions`) as a real local scan of the fixture
wrote it, but nothing here runs a scan. The validate-container leg is what runs
the real image.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = (
    REPO_ROOT / ".github" / "actions" / "validate-container" / "assert_detection.py"
)


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "ash_validate_container_assert_detection", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_script()


def _result(rule_id, scanner, suppressed=False):
    return {
        "ruleId": rule_id,
        "suppressions": [{"kind": "external"}] if suppressed else None,
        "properties": {"scanner_name": scanner},
    }


# The rule ids a local scan of the fixture produced, with and without shell=True.
PLANTED = [
    _result("SECRET-AWS-ACCESS-KEY", "detect-secrets"),
    _result("SECRET-SECRET-KEYWORD", "detect-secrets"),
    _result("SECRET-BASE64-HIGH-ENTROPY-STRING", "detect-secrets"),
    _result("B404", "bandit"),
    _result("B105", "bandit"),
    _result("B602", "bandit"),
]
NO_SHELL_TRUE = [r for r in PLANTED if r["ruleId"] != "B602"] + [
    _result("B603", "bandit")
]


def _report(results):
    return {"scanner_results": {}, "sarif": {"runs": [{"results": results}]}}


def _run(tmp_path, capsys, payload):
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(
        payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
    )
    code = gate.main([str(path)])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_planted_fixture_passes(tmp_path, capsys):
    code, out, err = _run(tmp_path, capsys, _report(PLANTED))
    assert code == 0, err
    assert "PASS" in out


def test_bandit_without_b602_fails(tmp_path, capsys):
    """The reviewer's case: three bandit findings, none of them the plant."""
    code, _, err = _run(tmp_path, capsys, _report(NO_SHELL_TRUE))
    assert code == 1
    assert "bandit did not report B602" in err
    assert "B603" in err


def test_detect_secrets_without_a_secret_rule_fails(tmp_path, capsys):
    results = [
        r for r in PLANTED if r["properties"]["scanner_name"] != "detect-secrets"
    ]
    code, _, err = _run(tmp_path, capsys, _report(results))
    assert code == 1
    assert "detect-secrets did not report a SECRET-* rule" in err


def test_a_non_secret_rule_from_detect_secrets_does_not_count(tmp_path, capsys):
    results = [r for r in PLANTED if r["properties"]["scanner_name"] == "bandit"]
    results.append(_result("KEYWORD", "detect-secrets"))
    code, _, err = _run(tmp_path, capsys, _report(results))
    assert code == 1
    assert "detect-secrets" in err


def test_b602_from_another_scanner_does_not_count(tmp_path, capsys):
    results = list(NO_SHELL_TRUE) + [_result("B602", "semgrep")]
    code, _, err = _run(tmp_path, capsys, _report(results))
    assert code == 1
    assert "bandit did not report B602" in err


@pytest.mark.parametrize("rule_id", ["B602", "SECRET-AWS-ACCESS-KEY"])
def test_a_suppressed_plant_does_not_count(tmp_path, capsys, rule_id):
    results = []
    for r in PLANTED:
        if r["properties"]["scanner_name"] == (
            "bandit" if rule_id == "B602" else "detect-secrets"
        ):
            r = _result(r["ruleId"], r["properties"]["scanner_name"], suppressed=True)
        results.append(r)
    code, _, err = _run(tmp_path, capsys, _report(results))
    assert code == 1
    assert "did not report" in err


def test_both_scanners_missing_names_both(tmp_path, capsys):
    code, _, err = _run(tmp_path, capsys, _report([]))
    assert code == 1
    assert "bandit" in err and "detect-secrets" in err


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "{}",
        json.dumps({"sarif": None}),
        json.dumps({"sarif": {"runs": {}}}),
        json.dumps({"sarif": {"runs": [{"results": [{"ruleId": "B602"}]}]}}),
    ],
    ids=["empty-file", "no-sarif", "null-sarif", "runs-not-a-list", "no-scanner-name"],
)
def test_an_unreadable_or_reshaped_report_fails(tmp_path, capsys, payload):
    code, _, err = _run(tmp_path, capsys, payload)
    assert code == 1
    assert "FAIL" in err


def test_a_missing_report_fails(tmp_path, capsys):
    code = gate.main([str(tmp_path / "absent" / "ash_aggregated_results.json")])
    assert code == 1
    assert "no usable results" in capsys.readouterr().err


def test_usage_error_without_a_path(capsys):
    assert gate.main([]) == 2


def test_the_action_passes_the_script_path_through_env():
    """The assert step reads the script path from env, not an inline `${{ }}`.

    An expression in `run:` is pasted into the shell script before bash parses
    it. github.action_path is runner-controlled, so this is hygiene rather than
    an injection fix, but it keeps the step in the same shape as the rest of
    the repository's actions.
    """
    action = yaml.safe_load(
        (SCRIPT_PATH.parent / "action.yml").read_text(encoding="utf-8")
    )
    steps = [
        s
        for s in action["runs"]["steps"]
        if "assert_detection.py" in s.get("run", "")
        or "assert_detection.py" in str(s.get("env", {}))
    ]
    assert len(steps) == 1, steps
    step = steps[0]
    assert "${{" not in step["run"], step["run"]
    env = step.get("env", {})
    assert env.get("ASSERT_DETECTION") == (
        "${{ github.action_path }}/assert_detection.py"
    ), env
    assert '"${ASSERT_DETECTION}"' in step["run"], step["run"]
