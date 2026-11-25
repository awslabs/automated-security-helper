# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A local stand-in for the Snyk Agent Scan analysis endpoint (test tooling only).

``snyk-agent-scan scan`` posts the skill files it collected to a remote analysis
service and prints that service's answer. ASH tests must never send anything to
that service, so the committed captures were made against this stub: it binds
127.0.0.1, reads the posted request, and answers with a fixed set of risk
entries when a skill file holds the documented marker string, and with no risk
otherwise. The JSON envelope the tool printed is the real one the pinned tool
writes; the risk values in it are this stub's, not an analysis result.

Usage (see ``README.md``): ``python3 -I stub_analysis_server.py <port>``.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List

MARKER = "ASH-FIXTURE-MARKER-agent-scan-mild"

#: One entry per score band of the pinned tool (0-299, 300-599, 600-999, 1000).
MARKED_RISKS: Dict[str, Dict[str, Any]] = {
    "third_party_content_exposure": {
        "score": 250,
        "evidence": "Stub entry, lowest band: the skill carries the documented marker.",
    },
    "secret_detection": {
        "score": 450,
        "evidence": "Stub entry, second band: the skill carries the documented marker.",
    },
    "suspicious_download_url": {
        "score": 800,
        "evidence": "Stub entry, third band: the skill names a placeholder URL.",
        "malicious_urls": ["https://example.invalid/payload"],
    },
    "unverifiable_dependencies": {
        "score": 150,
        "evidence": "Stub entry, lowest band: the skill names a placeholder dependency.",
        "unverifiable_urls": ["https://example.invalid/dependency"],
    },
}


def _risks_for(skill: Dict[str, Any]) -> Dict[str, Any]:
    indexes: Dict[str, Any] = {}
    for file in skill.get("files", []):
        for number, text in enumerate(file["content"].splitlines(), start=1):
            if MARKER not in text:
                continue
            indexes["prompt_injection_skill_instructions"] = {
                "score": 650,
                "evidence": "Stub entry, third band: the skill carries the documented marker.",
                "locations": [
                    {
                        "start": {"path": file["path"], "line": number, "offset": 0},
                        "end": {
                            "path": file["path"],
                            "line": number,
                            "offset": len(text),
                        },
                    }
                ],
            }
            indexes["malicious_code"] = {
                "score": 1000,
                "evidence": "Stub entry, top band: the skill carries the documented marker.",
                "locations": [
                    {"start": {"path": file["path"], "line": number, "offset": 0}}
                ],
            }
            indexes.update(MARKED_RISKS)
    return indexes


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        responses: List[Dict[str, Any]] = []
        for path in request.get("scan_path_requests", []):
            skill_risks = []
            for skill in path.get("skills", []):
                files = [
                    {
                        "name": f["path"],
                        "type": "instruction"
                        if f["path"].endswith(".md")
                        else "script",
                    }
                    for f in skill.get("files", [])
                ]
                skill_risks.append(
                    {
                        "name": skill["name"],
                        "files": files,
                        "risk_indexes": _risks_for(skill),
                    }
                )
            responses.append(
                {
                    "client": path.get("client"),
                    "path": path["path"],
                    "server_risks": [],
                    "skill_risks": skill_risks,
                }
            )
        body = json.dumps({"scan_path_responses": responses}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("stub: " + (format % args) + "\n")


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
