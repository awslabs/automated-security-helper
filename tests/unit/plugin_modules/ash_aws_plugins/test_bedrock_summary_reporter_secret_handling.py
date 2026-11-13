# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What the Bedrock summary reporter sends and writes when findings involve secrets.

Two requirements, both checked against the converse() payloads a stand-in
bedrock-runtime client records, so nothing is sent anywhere:

* No secret value is sent to Bedrock or written to the reporter's local markdown
  (its "Raw JSON" blocks and code snippets). The reporter receives results the
  engine has already masked, so these tests hand it the results a real scan saved
  (``tests/utils/secret_bearing_scan.py``).
* A finding from a secrets scanner is counted, not sent. Which scanner reported a
  finding decides it: the scanner's tool type looked up from its name, or a
  ``tool_type::`` tag in either of the spellings scanners write. No scanner writes
  a ``scanner_type`` property, which is the only thing the reporter used to read,
  so its exclusion never matched. ``SECRET`` and ``SECRETS`` in
  ``exclude_scanner_types`` both match. A finding whose scanner type cannot be
  determined is still sent, but without its snippet.
* With ``include_code_snippets`` off, the local summary holds no code: its
  "Raw JSON" blocks used to carry every finding's snippets regardless.

The findings that are not from a real scan are built the way the engine builds
them: the scanner's own result, passed through ``attach_scanner_details`` and
merged as ``ScanResultProcessor`` merges it.
"""

import importlib
import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    MODULE,
    make_reporter,
    plugin_context_in,
)
from tests.utils.secret_bearing_scan import (
    RUN_LINE,
    SECRETS,
    isolate_from_aws,
    load_results,
    run_secret_bearing_scan,
    scanner_shaped_report,
)

# Every detect-secrets message starts with this (detect_secrets_scanner.py).
DETECTOR_MESSAGE_START = "Secret of type "

# Bandit's B105, B106 and B107 messages start with this; the value that follows
# is masked.
HARDCODED_VALUE_MESSAGE = "Possible hardcoded " + "pass" + "word: '"


class RuntimeDouble:
    """Stands in for a bedrock-runtime client and records every converse() call."""

    def __init__(self):
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": f"stub reply {len(self.calls)}"}],
                }
            }
        }

    def sent(self):
        """Everything the reporter sent, as one string."""
        return json.dumps(self.calls)


@pytest.fixture(autouse=True)
def _no_aws(monkeypatch, tmp_path):
    """No test here may reach AWS; see ``isolate_from_aws``."""
    isolate_from_aws(monkeypatch, tmp_path)


@pytest.fixture
def runtime(monkeypatch):
    runtime = RuntimeDouble()

    class SessionDouble:
        def __init__(self, **kwargs):
            pass

        def client(self, service, **kwargs):
            assert service == "bedrock-runtime", service
            return runtime

    monkeypatch.setattr(f"{MODULE}.boto3.Session", SessionDouble)
    return runtime


@pytest.fixture(scope="module")
def scan_output(tmp_path_factory):
    return run_secret_bearing_scan(tmp_path_factory.mktemp("bedrock-secret-scan"))


def _result(rule_id, message, uri="src/app.py", line=4, snippet_text=None, tags=None):
    """One SARIF result as a scanner writes it."""
    region = {"startLine": line, "endLine": line}
    if snippet_text is not None:
        region["snippet"] = {"text": snippet_text}
    result = {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
        ],
    }
    if tags is not None:
        result["properties"] = {"tags": tags}
    return result


def model_of(*reports):
    model = AshAggregatedResults()
    for report in reports:
        model.sarif.merge_sarif_report(report)
    return model


#: A bandit finding with no secret in it; it is sent, snippet and all.
BANDIT_MESSAGE = "subprocess call with shell=True identified, security issue."
BANDIT_SNIPPET = "    return subprocess.call(cmd, shell=True)\n"


def bandit_report():
    # Registered in every scan; imported here so a lookup by name finds it even
    # when this test runs in a process that has not scanned yet.
    importlib.import_module(
        "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner"
    )
    return scanner_shaped_report(
        "bandit",
        [_result("B602", BANDIT_MESSAGE, line=7, snippet_text=BANDIT_SNIPPET)],
    )


def _detect_secrets_count(model):
    return sum(
        1
        for result in model.sarif.get_all_results()
        if result.properties is not None
        and getattr(result.properties, "scanner_name", None) == "detect-secrets"
    )


@pytest.mark.integration
class TestNoSecretValueLeavesTheReporter:
    """Results a real scan saved, reported with every option that adds content."""

    CONTENT_OPTIONS = {
        "include_code_snippets": True,
        "actionable_only": False,
        "max_findings_to_analyze": 50,
        "output_markdown": True,
    }

    @pytest.mark.parametrize(
        "add_section_headers", [True, False], ids=["structured", "simple"]
    )
    def test_prompts_hold_no_secret_value(
        self, scan_output, runtime, tmp_path, add_section_headers
    ):
        reporter = make_reporter(
            plugin_context_in(tmp_path),
            add_section_headers=add_section_headers,
            **self.CONTENT_OPTIONS,
        )

        reporter.report(load_results(scan_output))

        sent = runtime.sent()
        assert HARDCODED_VALUE_MESSAGE in sent, "no B105-B107 finding was sent"
        assert SECRETS.found_in(sent) == []

    def test_local_markdown_holds_no_secret_value(self, scan_output, runtime, tmp_path):
        reporter = make_reporter(plugin_context_in(tmp_path), **self.CONTENT_OPTIONS)

        reporter.report(load_results(scan_output))

        written = sorted((tmp_path / "reports").glob("*.md"))
        summary = tmp_path / "reports" / "ash.bedrock.summary.md"
        assert HARDCODED_VALUE_MESSAGE in summary.read_text(encoding="utf-8")
        leaks = {
            path.name: SECRETS.found_in(path.read_text(encoding="utf-8"))
            for path in written
            if SECRETS.found_in(path.read_text(encoding="utf-8"))
        }
        assert leaks == {}

    def test_snippet_of_a_finding_with_no_secret_is_still_sent(
        self, scan_output, runtime, tmp_path
    ):
        """Control: masking and the secret exclusion leave other snippets alone."""
        reporter = make_reporter(plugin_context_in(tmp_path), **self.CONTENT_OPTIONS)

        reporter.report(load_results(scan_output))

        assert RUN_LINE.strip() in runtime.sent()


class TestSecretScannerFindingsAreCountedNotSent:
    @pytest.mark.parametrize(
        "exclude", [None, ["SECRET"], ["SECRETS"]], ids=["default", "SECRET", "SECRETS"]
    )
    @pytest.mark.parametrize(
        "add_section_headers", [True, False], ids=["structured", "simple"]
    )
    @pytest.mark.integration
    def test_detect_secrets_findings_are_counted_and_not_sent(
        self, scan_output, runtime, tmp_path, add_section_headers, exclude
    ):
        # Above the scan's finding count, so the cap on findings per prompt is not
        # what keeps a detect-secrets message out.
        options = {
            "add_section_headers": add_section_headers,
            "max_findings_to_analyze": 50,
        }
        if exclude is not None:
            options["exclude_scanner_types"] = exclude
        model = load_results(scan_output)
        count = _detect_secrets_count(model)
        assert count >= 3, "the scan's detect-secrets findings are missing"
        reporter = make_reporter(plugin_context_in(tmp_path), **options)

        reporter.report(model)

        sent = runtime.sent()
        assert DETECTOR_MESSAGE_START not in sent
        assert f"Secret findings: {count}" in sent

    @pytest.mark.integration
    def test_findings_of_other_scanners_are_still_sent(
        self, scan_output, runtime, tmp_path
    ):
        """Control: the exclusion only removes secrets-scanner findings."""
        reporter = make_reporter(plugin_context_in(tmp_path))

        reporter.report(load_results(scan_output))

        assert BANDIT_MESSAGE in runtime.sent()

    @pytest.mark.unit
    def test_finding_from_another_secrets_scanner_is_counted_and_not_sent(
        self, runtime, tmp_path
    ):
        # Registers ferret-scan, whose tool type is SECRETS, as loading the
        # plugin package does in a scan that enables it.
        importlib.import_module(
            "automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner"
        )

        marker = "ferret fixture finding in deploy config"
        ferret = scanner_shaped_report(
            "ferret-scan", [_result("SECRETS", marker, uri="deploy/config.yaml")]
        )
        reporter = make_reporter(plugin_context_in(tmp_path))

        reporter.report(model_of(bandit_report(), ferret))

        sent = runtime.sent()
        assert marker not in sent
        assert "Secret findings: 1" in sent
        assert BANDIT_MESSAGE in sent

    @pytest.mark.parametrize(
        "tool_type_tag", ["tool_type::SECRETS", "tool_type::ScannerToolType.SECRETS"]
    )
    @pytest.mark.unit
    def test_finding_tagged_with_the_secrets_tool_type_is_counted_and_not_sent(
        self, runtime, tmp_path, tool_type_tag
    ):
        marker = "acme secret scanner fixture finding"
        acme = scanner_shaped_report(
            "acme-secret-scanner",
            [_result("ACME-KEY", marker, tags=["acme-secret-scanner", tool_type_tag])],
        )
        reporter = make_reporter(plugin_context_in(tmp_path))

        reporter.report(model_of(bandit_report(), acme))

        sent = runtime.sent()
        assert marker not in sent
        assert "Secret findings: 1" in sent

    @pytest.mark.unit
    def test_finding_whose_scanner_type_is_unknown_is_sent_without_its_snippet(
        self, runtime, tmp_path
    ):
        unknown_snippet = "acme_unknown_scanner_marker = compute()\n"
        # A suggested fix carries code too, in its replacement's insertedContent.
        unknown_fix = "acme_unknown_fix_marker = compute_safely()\n"
        result = _result(
            "ACME-001",
            "acme linter fixture finding",
            line=9,
            snippet_text=unknown_snippet,
            tags=["acme-linter"],
        )
        result["fixes"] = [
            {
                "description": {"text": "acme fix"},
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": "src/app.py"},
                        "replacements": [
                            {
                                "deletedRegion": {"startLine": 9},
                                "insertedContent": {"text": unknown_fix},
                            }
                        ],
                    }
                ],
            }
        ]
        unknown = scanner_shaped_report("acme-linter", [result])
        reporter = make_reporter(
            plugin_context_in(tmp_path),
            include_code_snippets=True,
            actionable_only=False,
            output_markdown=True,
        )

        reporter.report(model_of(bandit_report(), unknown))

        sent = runtime.sent()
        # The local summary's Raw JSON is the whole finding, fixes included.
        summary = (tmp_path / "reports" / "ash.bedrock.summary.md").read_text(
            encoding="utf-8"
        )
        assert unknown_snippet.strip() not in sent
        assert unknown_fix.strip() not in sent
        assert unknown_fix.strip() not in summary
        # The finding itself is still sent and written, so the checks are not vacuous.
        assert "acme linter fixture finding" in sent
        assert "acme linter fixture finding" in summary
        # The known scanner's snippet still goes, so the rule is not "no snippets".
        assert BANDIT_SNIPPET.strip() in sent


@pytest.mark.integration
class TestLocalSummaryFollowsIncludeCodeSnippets:
    """``include_code_snippets`` decides whether the local summary holds code at all.

    The summary's "Raw JSON" block is the whole SARIF result, snippets included,
    so with the option off the summary still carried every finding's code.
    """

    OPTIONS = {
        "actionable_only": False,
        "max_findings_to_analyze": 50,
        "output_markdown": True,
    }

    def _summary(self, tmp_path):
        return (tmp_path / "reports" / "ash.bedrock.summary.md").read_text(
            encoding="utf-8"
        )

    def test_summary_holds_no_snippet_when_snippets_are_off(
        self, scan_output, runtime, tmp_path
    ):
        reporter = make_reporter(
            plugin_context_in(tmp_path), include_code_snippets=False, **self.OPTIONS
        )

        reporter.report(load_results(scan_output))

        summary = self._summary(tmp_path)
        assert HARDCODED_VALUE_MESSAGE in summary, "the summary lists no finding"
        assert RUN_LINE.strip() not in summary
        assert SECRETS.found_in(summary) == []

    def test_summary_shows_snippets_when_snippets_are_on(
        self, scan_output, runtime, tmp_path
    ):
        """Control: with the option on, a snippet with no secret in it is shown."""
        reporter = make_reporter(
            plugin_context_in(tmp_path), include_code_snippets=True, **self.OPTIONS
        )

        reporter.report(load_results(scan_output))

        assert RUN_LINE.strip() in self._summary(tmp_path)


@pytest.mark.unit
class TestSastSecretFindingsAreCountedNotSent:
    """A semgrep or opengrep secret finding is a secret finding to Bedrock too.

    The scanner is SAST, so its tool type does not name it; its rule does
    (``generic.secrets.*``, tagged CWE-798). The fixture is the SARIF opengrep
    writes for two p/ci AWS rules (``secret_bearing_scan.opengrep_secret_sarif``).
    """

    @pytest.mark.parametrize("scanner_name", ["opengrep", "semgrep"])
    def test_grep_secret_findings_are_counted_and_not_sent(
        self, runtime, tmp_path, scanner_name
    ):
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.utils.sarif_utils import (
            attach_scanner_details,
        )
        from tests.utils.secret_bearing_scan import opengrep_secret_sarif

        grep = attach_scanner_details(
            SarifReport.model_validate(opengrep_secret_sarif()),
            scanner_name=scanner_name,
            scanner_version="1.0.0",
        )
        reporter = make_reporter(plugin_context_in(tmp_path))

        reporter.report(model_of(bandit_report(), grep))

        sent = runtime.sent()
        assert "AWS Secret Access Key detected" not in sent
        assert "AWS Access Key ID Value detected" not in sent
        assert "Secret findings: 2" in sent
        assert BANDIT_MESSAGE in sent


@pytest.mark.integration
class TestHardCodedPasswordFindingsAreSentMasked:
    """Bandit's B105-B107 are sent, with the value their message quotes masked.

    They are SAST findings about a name, not detections of a credential, so the
    secret exclusion leaves them in (``is_secret_detection``); the engine has
    already masked the value in their messages and snippets
    (``utils/secret_masking.py``).
    """

    OPTIONS = {
        "include_code_snippets": True,
        "actionable_only": False,
        "max_findings_to_analyze": 50,
        "output_markdown": True,
    }

    @pytest.mark.parametrize(
        "name", ["keyword_value", "long_key", "default_arg_value", "call_arg_value"]
    )
    def test_masked_message_is_sent_and_written_without_the_value(
        self, scan_output, runtime, tmp_path, name
    ):
        from automated_security_helper.utils.secret_masking import _mask_secret_value

        value = getattr(SECRETS, name)
        masked_message = HARDCODED_VALUE_MESSAGE + _mask_secret_value(value) + "'"
        reporter = make_reporter(plugin_context_in(tmp_path), **self.OPTIONS)

        reporter.report(load_results(scan_output))

        sent = runtime.sent()
        summary = (tmp_path / "reports" / "ash.bedrock.summary.md").read_text(
            encoding="utf-8"
        )
        assert masked_message in sent
        assert masked_message in summary
        assert value not in sent
        assert value not in summary
