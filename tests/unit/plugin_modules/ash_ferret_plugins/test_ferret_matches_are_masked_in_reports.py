# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A value ferret-scan matched reaches no report.

With ``show_match`` on -- the scanner option, or one of the six bundled profiles
that set it (comprehensive, json-api, debug, person-name, enhanced-metadata,
social-media) -- ferret-scan puts the matched text in the result's message
(``Matched text: '<value>'``), in ``region.snippet`` and in
``contextRegion.snippet``. Every report ASH writes carries one of those, including
the ones built from messages alone (HTML, OCSF, JUnit, GHAS SARIF, the markdown
summary).

The ferret-scan tool is not needed: its dependency check and subprocess call are
replaced, and the subprocess writes the SARIF ferret-scan 2.5.3 produced for this
file with ``--format sarif --show-match`` (rebuilt from the file text). The
plugin's own result handling, ``ScanResultProcessor`` and the report phase run
unmodified, through ``run_ash_scan`` with the plugin loaded the way an operator
loads it.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
)
from tests.utils.secret_bearing_scan import find_result, isolate_from_aws, sarif_results

pytestmark = pytest.mark.unit

FERRET_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_ferret_plugins"

# A card-network test number, assembled here so this source holds no match.
CARD_NUMBER = "4111" + " 1111" * 3
CARD_LINE = "card: " + CARD_NUMBER
SAMPLE_TEXT = 'customer = "Ada"\n' + CARD_LINE + "\nok = 1\n"
MESSAGE_START = "Credit Card Number Detected in sample.txt at line 2"

OPERATOR_CONFIG = """
global_settings:
  severity_threshold: LOW
reporters:
  yaml:
    enabled: true
scanners:
  ferret-scan:
    enabled: true
    options:
      show_match: true
"""


def ferret_sarif(source_dir: Path) -> dict:
    """What ferret-scan 2.5.3 writes for ``sample.txt`` with ``--show-match``."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Ferret Scan",
                        "version": "v2.5.3",
                        "semanticVersion": "v2.5.3",
                        "informationUri": "https://github.com/awslabs/ferret-scan",
                        "rules": [
                            {
                                "id": "VISA",
                                "shortDescription": {
                                    "text": "Credit Card Number Detected"
                                },
                            }
                        ],
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": source_dir.as_uri() + "/"}},
                "results": [
                    {
                        "ruleId": "VISA",
                        "level": "error",
                        "message": {
                            "text": MESSAGE_START
                            + " (confidence: 15.0% - LOW). Matched text: '"
                            + CARD_NUMBER
                            + "'"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "sample.txt",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {
                                        "startLine": 2,
                                        "startColumn": 7,
                                        "endColumn": 26,
                                        "snippet": {"text": CARD_LINE},
                                    },
                                    "contextRegion": {
                                        "startLine": 2,
                                        "snippet": {"text": "card: \n" + CARD_LINE},
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "confidence": 15,
                            "confidenceLevel": "LOW",
                            "validator": "creditcard",
                        },
                        "rank": 57.5,
                    }
                ],
            }
        ],
    }


@pytest.fixture(scope="module")
def ferret_scan_output(tmp_path_factory):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    root = tmp_path_factory.mktemp("ferret-show-match")
    source_dir = root / "src"
    source_dir.mkdir()
    (source_dir / "sample.txt").write_text(SAMPLE_TEXT, encoding="utf-8")
    config_path = root / "ash-config.yaml"
    config_path.write_text(OPERATOR_CONFIG, encoding="utf-8")
    output_dir = root / "out"

    def _dependencies_present(self) -> bool:
        self.dependencies_satisfied = True
        return True

    def _run_canned_ferret(self, command, results_dir, *args, **kwargs):
        results_dir = Path(results_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "ferret-scan.sarif").write_text(
            json.dumps(ferret_sarif(source_dir)), encoding="utf-8"
        )
        self.exit_code = 0
        return {"returncode": 0}

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            FerretScanScanner, "validate_plugin_dependencies", _dependencies_present
        )
        monkeypatch.setattr(FerretScanScanner, "_run_subprocess", _run_canned_ferret)
        isolate_from_aws(monkeypatch, root)
        run_ash_scan(
            source_dir=str(source_dir),
            output_dir=str(output_dir),
            config=str(config_path),
            scanners=["ferret-scan"],
            ash_plugin_modules=[FERRET_PLUGIN_MODULE],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
        )
    return output_dir


def _read(output_dir, relative):
    return (output_dir / relative).read_text(encoding="utf-8")


class TestFerretMatchesAreMasked:
    @pytest.mark.parametrize(
        "relative",
        [
            "ash_aggregated_results.json",
            "reports/ash.sarif",
            "reports/ash.flat.json",
            "reports/ash.csv",
            "reports/ash.gl-sast-report.json",
            "reports/ash.yaml",
            "reports/ash.html",
            "reports/ash.ocsf.json",
            "reports/ash.junit.xml",
            "reports/ash.ghas.sarif",
            "reports/ash.summary.md",
        ],
    )
    def test_report_holds_no_ferret_match(self, ferret_scan_output, relative):
        text = _read(ferret_scan_output, relative)

        assert "VISA" in text, (
            f"{relative} lists no ferret finding; this checks nothing"
        )
        assert CARD_NUMBER not in text, f"{relative} holds the matched value"

    def test_ferret_finding_keeps_the_rest_of_its_message(self, ferret_scan_output):
        """Control: masking takes out the match, not the finding's description."""
        results = sarif_results(
            json.loads(_read(ferret_scan_output, "reports/ash.sarif"))
        )

        finding = find_result(results, "VISA", "sample.txt", 2)

        assert finding["message"]["text"].startswith(MESSAGE_START)
