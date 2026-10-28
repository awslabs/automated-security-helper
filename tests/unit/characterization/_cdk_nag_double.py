# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The cdk-nag worker double, and the route and scan the cdk-nag scenarios build on it.

``test_cdk_nag`` pins how ASH launches the cdk-nag worker; the explicit-executor cells
run the same worker against other executors. Both build on what is here: the one
template the scenarios scan, the worker double that answers each template the way
the child would, the scanner's config, the route that puts ``node`` and the worker on
PATH, and the scan itself. This module imports nothing from a test file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import yaml

from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
    CdkNagScannerConfigOptions,
)
from automated_security_helper.utils import cdk_nag_worker
from tests.unit.characterization._harness import (
    FIXTURES_DIR,
    Exit,
    Hang,
    Outcome,
    ToolCall,
    ToolDouble,
)

TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
)

SOURCE = {"template.yaml": TEMPLATE}

#: The protocol the worker double speaks. Written out rather than read from the
#: product, so a protocol change shows in the double as well as in the request.
PROTOCOL = 2

REQUEST_KEYS = ["cwd", "log_level", "options", "protocol", "templates"]


def _finding(uri: str) -> Dict[str, Any]:
    finding = json.loads((FIXTURES_DIR / "cdk-nag" / "finding.json").read_text("utf-8"))
    finding["analysisTarget"]["uri"] = uri
    finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
    return finding


class WorkerDouble(ToolDouble):
    """``python -c <cdk_nag_worker bootstrap> REQUEST RESPONSE``.

    Answers each requested template the way the child would: a symlink is refused,
    text no YAML parser loads raises a YAML error, a document with a ``Resources``
    mapping gets the fixture finding, and anything else is not CloudFormation.
    Each launch takes the next entry of ``launches`` (default: answer everything and
    exit 0); an entry may stop after ``answer`` templates, set ``failure`` on every
    response, write another protocol header, or replace the outcome. A ``Hang``
    outcome hangs before answering anything, unless ``answer`` says how many
    templates it answers first. The request and every template are confined to the
    test's tree before they are read or even tested.
    """

    def __init__(self, *launches: Dict[str, Any]) -> None:
        self.launches = list(launches)

    def run(self, call: ToolCall) -> Outcome:
        if len(call.args) != 4 or call.args[0] != "-c":
            raise call.reject("expected -c BOOTSTRAP REQUEST RESPONSE")
        if call.args[1] != cdk_nag_worker._CHILD_BOOTSTRAP:
            raise call.reject("not the cdk-nag worker bootstrap")
        request_path = call.confined(call.args[2])
        response_path = call.confined(call.args[3])
        request = json.loads(call.read(request_path).decode("utf-8"))
        if sorted(request) != REQUEST_KEYS or request["protocol"] != PROTOCOL:
            raise call.reject(
                f"request {sorted(request)} protocol {request.get('protocol')}"
            )
        if call.cwd is None or Path(call.cwd) != request_path.parent:
            raise call.reject("the child runs in its own work directory")
        launch = self.launches.pop(0) if self.launches else {}
        if isinstance(launch.get("outcome"), Hang) and "answer" not in launch:
            return launch["outcome"]
        templates: List[str] = request["templates"]
        limit = launch.get("answer", len(templates))
        lines = [json.dumps({"protocol": launch.get("protocol", PROTOCOL)})]
        for template in templates[:limit]:
            answer = self._answer(call, Path(template), Path(request["cwd"]))
            if answer["status"] == "response" and "failure" in launch:
                answer.update(failure=launch["failure"], results={})
            lines.append(json.dumps(answer))
        call.write(response_path, ("\n".join(lines) + "\n").encode("utf-8"))
        return launch.get("outcome", Exit(0))

    @staticmethod
    def name_for(template: str, cwd: Path, exists: Callable[[Path], bool]) -> str:
        """The name the child gives ``template`` against the parent's ``cwd``.

        Written out rather than read from the product, the way the child's
        ``get_shortest_name`` computes it: relative to ``cwd`` when the template
        exists below it, and the path as given otherwise. A child never names a
        template with ``..``; a name that climbs out of ``cwd`` would hide a parent
        that renames the wrong way. ``exists`` is the double's own confined check.
        """
        if template == ".":
            return template
        given = Path(template)
        probe = given if given.is_absolute() else cwd / given
        if not exists(probe):
            return template
        probe_posix = probe.absolute().as_posix()
        cwd_posix = cwd.absolute().as_posix()
        if probe_posix.startswith(cwd_posix) and probe_posix != cwd_posix:
            return probe.absolute().relative_to(cwd).as_posix()
        return given.as_posix()

    @staticmethod
    def _answer(call: ToolCall, template: Path, cwd: Path) -> Dict[str, Any]:
        call.confined(template)
        if template.is_symlink():
            return {
                "status": "raised",
                "kind": "refused",
                "type": "TreeInputRefused",
                "message": f"{template}: it is a symbolic link",
                "path": str(template),
                "reason": "it is a symbolic link",
                "logs": [],
            }
        try:
            document = yaml.safe_load(call.read(template).decode("utf-8"))
        except yaml.YAMLError as error:
            return {
                "status": "raised",
                "kind": "yaml",
                "type": type(error).__name__,
                "message": "while parsing a flow sequence",
                "logs": [],
            }
        if not isinstance(document, dict) or not isinstance(
            document.get("Resources"), dict
        ):
            return {"status": "not-cloudformation", "logs": []}
        uri = WorkerDouble.name_for(
            str(template), cwd, lambda path: call.confined(path).exists()
        )
        return {
            "status": "response",
            "failure": None,
            "outdir": None,
            "results": {"AwsSolutionsChecks": [_finding(uri)]},
            "logs": [
                {
                    "level": logging.WARNING,
                    "message": f"replayed from the child for {uri}",
                    "pathname": "cdk_nag_wrapper.py",
                    "lineno": 1,
                    "funcName": "run_cdk_nag_against_cfn_template",
                }
            ],
        }


def _config(**options) -> CdkNagScannerConfig:
    return CdkNagScannerConfig(options=CdkNagScannerConfigOptions(**options))


def _route(char, worker: Optional[WorkerDouble] = None) -> None:
    """node on PATH, found and never started; the worker is the one launch."""
    char.tool("node")
    char.tool("python", worker or WorkerDouble(), on=None)


def _scan(
    char,
    config: Optional[CdkNagScannerConfig] = None,
    *,
    handler_levels: Sequence[int] = (logging.INFO,),
    **kwargs,
):
    """Run the scanner with ASH_LOGGER holding one handler per ``handler_levels``.

    The child's ``log_level`` comes from those handlers' levels, so they are fixed
    here rather than left to whoever configured logging: pytest's logging plugin
    adds handlers at level 0 to ASH's non-propagating logger, and a run without that
    plugin has none of them. The default is ASH's console handler at INFO.
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    char.fix_clock()
    saved = ASH_LOGGER.handlers
    ASH_LOGGER.handlers = [_handler(level) for level in handler_levels]
    try:
        return char.run_scanner(CdkNagScanner, config or _config(), **kwargs)
    finally:
        ASH_LOGGER.handlers = saved


def _handler(level: int) -> logging.Handler:
    handler = logging.NullHandler()
    handler.setLevel(level)
    return handler
