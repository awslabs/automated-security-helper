# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Parser for SARIF formatted outputs.

Example from Bandit:

{
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Bandit",
          "organization": "PyCQA",
          "rules": [
            {
              "id": "B101",
              "name": "assert_used",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-703"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.7.8/plugins/b101_assert_used.html"
            }
          ],
          "version": "1.7.8",
          "semanticVersion": "1.7.8"
        }
      },
      "invocations": [
        {
          "executionSuccessful": true,
          "endTimeUtc": "2024-03-05T03:28:48Z"
        }
      ],
      "properties": {
        "metrics": {
          "_totals": {
            "loc": 1,
            "nosec": 0,
            "skipped_tests": 0,
            "SEVERITY.UNDEFINED": 0,
            "CONFIDENCE.UNDEFINED": 0,
            "SEVERITY.LOW": 1,
            "CONFIDENCE.LOW": 0,
            "SEVERITY.MEDIUM": 0,
            "CONFIDENCE.MEDIUM": 0,
            "SEVERITY.HIGH": 0,
            "CONFIDENCE.HIGH": 1
          },
          "./examples/assert.py": {
            "loc": 1,
            "nosec": 0,
            "skipped_tests": 0,
            "SEVERITY.UNDEFINED": 0,
            "SEVERITY.LOW": 1,
            "SEVERITY.MEDIUM": 0,
            "SEVERITY.HIGH": 0,
            "CONFIDENCE.UNDEFINED": 0,
            "CONFIDENCE.LOW": 0,
            "CONFIDENCE.MEDIUM": 0,
            "CONFIDENCE.HIGH": 1
          }
        }
      },
      "results": [
        {
          "message": {
            "text": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code."
          },
          "level": "note",
          "locations": [
            {
              "physicalLocation": {
                "region": {
                  "snippet": {
                    "text": "assert True\n"
                  },
                  "endColumn": 11,
                  "endLine": 1,
                  "startColumn": 0,
                  "startLine": 1
                },
                "artifactLocation": {
                  "uri": "examples/assert.py"
                },
                "contextRegion": {
                  "snippet": {
                    "text": "assert True\n"
                  },
                  "endLine": 1,
                  "startLine": 1
                }
              }
            }
          ],
          "properties": {
            "issue_confidence": "HIGH",
            "issue_severity": "LOW"
          },
          "ruleId": "B101",
          "ruleIndex": 0
        }
      ]
    }
  ],
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json"
}
"""

from typing import Annotated, Any, Dict, List, Literal
from pydantic import Field
from automated_security_helper.base.options import BaseParserOptions
from automated_security_helper.base.scanner import ParserConfig
from automated_security_helper.models.core import (
    Location,
    ParserBaseConfig,
)
from automated_security_helper.schemas.data_interchange import SecurityReport
from automated_security_helper.models.parser_plugin import ParserPlugin


class SarifParserConfigOptions(BaseParserOptions):
    pass


class SarifParserConfig(ParserBaseConfig):
    """SARIF parser configuration."""

    name: Literal["sarif"] = "sarif"
    enabled: bool = True
    options: Annotated[
        SarifParserConfigOptions, Field(description="Configure SARIF parser")
    ] = SarifParserConfigOptions()
    config = ParserConfig(
        name="sarif",
        enabled=True,
    )


class SarifParser(ParserPlugin, SarifParserConfig):
    """Parser for SARIF formatted outputs."""

    def parse(self, raw_results: List[Dict[str, Any]]) -> SecurityReport:
        """Parse raw scanner results into a standardized format."""
        pass

    def get_finding_locations(self, finding: Dict[str, Any]) -> List[Location]:
        """Extract location information from a finding."""
        pass
