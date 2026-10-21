#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform CodeCommit gate scans with the operator's configuration and credentials-free.

Why this file exists
--------------------
The gate clones a pull request and runs ``ash scan`` over it. ASH reads its config from
``--config``, else from ``ASH_CONFIG`` (the option's envvar, cli/scan.py), else from a
file it discovers inside the scanned tree (``_discovered_config_path``,
interactions/run_ash_scan.py). The Terraform image's entrypoint sets ``ASH_CONFIG`` only
when a base config was supplied, so the handler always passes ``--config`` naming a file
outside the clone. A pull request whose own ``.ash/.ash.yaml`` adds
``global_settings.ignore_paths`` over a failing file still gets the failing verdict,
whether or not a base config was supplied.

The scan runs without the function's AWS credentials. The execution role comments on
and votes on pull requests, and the scan needs no AWS call.

The example module and the module README pass no narrowing options. The handler
refuses ``--changed-files-only`` and ``--base-ref`` (GATE_OWNED_SCAN_OPTIONS, pinned in
test_codecommit_gate_fails_closed.py), and ``origin/main`` does not resolve in the
gate's single-branch clone.

The gate is loaded by path, as test_codecommit_gate_fails_closed.py explains.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
TERRAFORM = REPO_ROOT / "deploy" / "terraform"
GATE_MODULE = TERRAFORM / "modules" / "codecommit-gate"
GATE_PATH = GATE_MODULE / "files" / "ash_pr_gate.py"
EXAMPLE = GATE_MODULE / "examples" / "basic" / "main.tf"

#: Stand-ins for what the Lambda runtime puts in a function's environment for its
#: execution role. Built from the names, so nothing here looks like a credential to a
#: secret scanner.
FUNCTION_CREDENTIALS = {
    name: "function-role-" + name.lower().replace("_", "-")
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
}

#: Every variable through which a child process could pick up AWS credentials.
CREDENTIAL_VARIABLES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_PROFILE",
)

PULL_REQUEST_CONFIG = (
    "project_name: pull-request-chose-this-config\n"
    "fail_on_findings: false\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    '    - path: "**"\n'
    '      reason: "the pull request does not want to be scanned"\n'
)


def _load_gate() -> ModuleType:
    assert GATE_PATH.is_file(), f"gate not found at {GATE_PATH}"
    spec = importlib.util.spec_from_file_location(
        "_ash_pr_gate_config_trust", GATE_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def gate(monkeypatch, tmp_path) -> ModuleType:
    module = _load_gate()
    monkeypatch.setattr(module, "WORK_ROOT", tmp_path / "ash-gate")
    # Nothing from the developer's shell may decide these tests; the image's own
    # variables in particular are set per test where a test is about them.
    for name in (
        "ASH_CONFIG",
        "ASH_SCAN_EXTRA_ARGS",
        "ASH_OFFLINE",
        "ASH_IMAGE_PATH",
        "ASH_BAKED_UV_TOOL_DIR",
        *CREDENTIAL_VARIABLES,
    ):
        monkeypatch.delenv(name, raising=False)
    return module


def _pull_request_tree(tmp_path: pathlib.Path) -> pathlib.Path:
    """A cloned pull request carrying its own config, in both discovered spellings."""
    source = tmp_path / "ash-gate" / "src"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(PULL_REQUEST_CONFIG, encoding="utf-8")
    (source / ".ash.yaml").write_text(PULL_REQUEST_CONFIG, encoding="utf-8")
    (source / "app.py").write_text('print("scanned")\n', encoding="utf-8")
    return source


class _ScanCapture:
    """Stands in for the subprocess runner and records the ``ash scan`` call.

    The config file is read at the moment of the call, because that is when ASH would
    read it; a file the gate deletes afterwards is still a file ASH saw.
    """

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, argv, cwd=None, env=None):
        argv = list(argv)
        if argv == ["ash", "scan", "--help"]:
            # The gate's probe of the image's options; answered as an ASH that has
            # --fail-on-incomplete-scanners, and not a scan.
            return SimpleNamespace(
                returncode=0, stdout="  --fail-on-incomplete-scanners\n", stderr=""
            )
        if argv[:2] == ["ash", "scan"]:
            effective = _effective_config(argv, env or {})
            content: Optional[str] = None
            if effective and pathlib.Path(effective).is_file():
                content = pathlib.Path(effective).read_text(encoding="utf-8")
            self.calls.append(
                {
                    "argv": argv,
                    "env": dict(env or {}),
                    "config": effective,
                    "content": content,
                }
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _effective_config(argv: List[str], env: Dict[str, str]) -> Optional[str]:
    """The config file ASH would read for this argv and environment.

    ``--config`` is resolved through the real CLI, so every spelling click accepts
    counts. The option's envvar is hidden from that parse, because click would read it
    from this test process rather than from the scan's environment; the fallback to
    ``ASH_CONFIG`` is then taken from the environment the scan is launched with.
    """
    import os

    import typer.main

    from automated_security_helper.cli.main import app

    scan_command = typer.main.get_command(app).commands["scan"]
    hidden = os.environ.pop("ASH_CONFIG", None)
    try:
        params = scan_command.make_context(
            "scan", argv[2:], resilient_parsing=False
        ).params
    finally:
        if hidden is not None:
            os.environ["ASH_CONFIG"] = hidden
    explicit = params.get("config")
    if explicit:
        return str(explicit)
    return env.get("ASH_CONFIG") or None


def _is_inside(child: str, parent: pathlib.Path) -> bool:
    try:
        pathlib.Path(child).resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Controls: these pass on the unmodified base
# ---------------------------------------------------------------------------


def test_without_an_operator_config_ash_reads_the_pull_requests_own_file(tmp_path):
    """What is at stake: ASH's own discovery picks the config the pull request commits."""
    from automated_security_helper.interactions.run_ash_scan import (
        _discovered_config_path,
    )

    source = _pull_request_tree(tmp_path)
    discovered = _discovered_config_path(source)

    assert discovered is not None and _is_inside(discovered, source), discovered


def test_a_materialized_base_config_is_what_the_scan_reads(gate, monkeypatch, tmp_path):
    """ash-container-init writes the base config and exports ASH_CONFIG; the scan uses it."""
    source = _pull_request_tree(tmp_path)
    base = tmp_path / "ash-config" / ".ash" / ".ash.yaml"
    base.parent.mkdir(parents=True)
    base.write_text("project_name: operator-base-config\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(base))
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    gate.run_scan(source, "low", True)

    assert [call["content"] for call in capture.calls] == [
        "project_name: operator-base-config\n"
    ]


# ---------------------------------------------------------------------------
# The operator decides the configuration
# ---------------------------------------------------------------------------


def test_without_a_base_config_the_scan_names_an_operator_config_outside_the_clone(
    gate, monkeypatch, tmp_path
):
    source = _pull_request_tree(tmp_path)
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    gate.run_scan(source, "low", True)

    assert len(capture.calls) == 1, capture.calls
    call = capture.calls[0]
    assert call["config"] is not None and call["content"] is not None, (
        "ash was given no config file it could read, so it discovers the pull "
        f"request's own .ash/.ash.yaml. argv={call['argv']}"
    )
    assert not _is_inside(call["config"], source), (
        f"the config ash reads, {call['config']}, is inside the cloned pull request"
    )
    assert "pull-request-chose-this-config" not in call["content"]

    # And it is a config ASH accepts. An empty or comment-only file is not one
    # (AshConfig rejects both), so a placeholder would turn every scan into exit 3.
    from automated_security_helper.config.ash_config import AshConfig

    loaded = tmp_path / "operator-config-as-seen.yaml"
    loaded.write_text(call["content"], encoding="utf-8")
    AshConfig.from_file(str(loaded))


def test_the_scan_runs_without_the_function_role_credentials(
    gate, monkeypatch, tmp_path
):
    source = _pull_request_tree(tmp_path)
    for name, value in FUNCTION_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    gate.run_scan(source, "low", True)

    assert len(capture.calls) == 1, capture.calls
    scan_env = capture.calls[0]["env"]
    leaked = sorted(
        name
        for name in CREDENTIAL_VARIABLES
        if scan_env.get(name) and scan_env[name] in FUNCTION_CREDENTIALS.values()
    )
    assert leaked == [], (
        f"the scanners would run with the role that can approve pull requests: {leaked}"
    )


# ---------------------------------------------------------------------------
# The example and the docs recommend only what the gate accepts
# ---------------------------------------------------------------------------

_EXTRA_ARGS_ASSIGNMENT = re.compile(r'ash_scan_extra_args\s*=\s*"([^"]*)"')


def test_the_assignment_parser_finds_an_assignment():
    """Positive control on the parser the two tests below depend on."""
    sample = (
        'module "x" {\n  ash_scan_extra_args = "--offline --output-formats html"\n}\n'
    )
    assert _EXTRA_ARGS_ASSIGNMENT.findall(sample) == ["--offline --output-formats html"]


def test_the_example_module_passes_only_extra_args_the_gate_accepts(gate):
    values = _EXTRA_ARGS_ASSIGNMENT.findall(EXAMPLE.read_text(encoding="utf-8"))
    refused = []
    for value in values:
        try:
            gate._reject_gate_owned_options(value.split())
        except RuntimeError:
            refused.append(value)
    assert refused == [], (
        "the example sets ash_scan_extra_args the handler refuses, so every pull "
        f"request it gates ends in outcome 'error': {refused}"
    )


#: Words that mark a sentence as saying an option is refused rather than recommending it.
_REFUSAL_WORDS = re.compile(
    r"refus|reserv|reject|not accept|owned by the gate", re.IGNORECASE
)


def _terraform_docs() -> List[pathlib.Path]:
    files = [
        path
        for pattern in ("*.md", "*.tf")
        for path in TERRAFORM.rglob(pattern)
        if ".terraform" not in path.parts
    ]
    assert files, "found no Terraform docs or modules to check"
    return sorted(files)


def test_no_terraform_doc_recommends_an_option_the_gate_refuses(gate):
    """Every line naming --changed-files-only or --base-ref says it is refused.

    These two were the documented recommendation for ash_scan_extra_args. The gate
    reserves them (GATE_OWNED_SCAN_OPTIONS), so the only true thing an operator doc
    can say about them is that they are refused there.
    """
    assert {"--changed-files-only", "--base-ref"} <= gate.GATE_OWNED_SCAN_OPTIONS
    offending = []
    for path in _terraform_docs():
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if ("--changed-files-only" in line or "--base-ref" in line) and not (
                _REFUSAL_WORDS.search(line)
            ):
                offending.append(
                    f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}"
                )
    assert offending == [], "\n".join(offending)


# ---------------------------------------------------------------------------
# A base config the gate cannot use refuses the scan
# ---------------------------------------------------------------------------


def test_a_base_config_that_names_no_file_refuses_the_scan(gate, monkeypatch, tmp_path):
    """Fail closed: ASH_CONFIG set by the image but naming nothing is not "no config"."""
    source = _pull_request_tree(tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "ash-config" / "missing.yaml"))
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    with pytest.raises(RuntimeError, match="not a file"):
        gate.run_scan(source, "low", True)
    assert capture.calls == []


def test_a_base_config_inside_the_clone_refuses_the_scan(gate, monkeypatch, tmp_path):
    """An ASH_CONFIG that resolves into the pull request is the pull request's file."""
    source = _pull_request_tree(tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(source / ".ash" / ".ash.yaml"))
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    with pytest.raises(RuntimeError, match="inside the cloned pull request"):
        gate.run_scan(source, "low", True)
    assert capture.calls == []


def test_the_operator_config_is_also_what_ash_config_names(gate, monkeypatch, tmp_path):
    """ASH reads ASH_CONFIG in places --config does not reach; both name one file."""
    source = _pull_request_tree(tmp_path)
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    gate.run_scan(source, "low", True)

    [call] = capture.calls
    assert call["env"]["ASH_CONFIG"] == call["config"]


# ---------------------------------------------------------------------------
# The base config is read on every invocation, not trusted from disk
# ---------------------------------------------------------------------------


class _FakeSsm:
    """Answers get_parameter with whatever ``value`` holds when it is called."""

    def __init__(self, value: Optional[str]) -> None:
        self.value = value
        self.calls: List[Dict[str, Any]] = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        if self.value is None:
            raise RuntimeError("ParameterNotFound")
        return {"Parameter": {"Name": kwargs.get("Name"), "Value": self.value}}


def _with_base_config_parameter(gate, monkeypatch, value: Optional[str]) -> _FakeSsm:
    ssm = _FakeSsm(value)
    monkeypatch.setenv("ASH_BASE_CONFIG_SSM_PARAMETER", "/ash/base-config")
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: (
            ssm if service == "ssm" else pytest.fail(f"unexpected client {service}")
        ),
    )
    return ssm


def test_a_base_config_rewritten_on_disk_does_not_reach_the_next_scan(
    gate, monkeypatch, tmp_path
):
    """ash-container-init writes the base config once per sandbox, where the scan's
    own user can rewrite it. The gate reads the parameter again for every scan."""
    source = _pull_request_tree(tmp_path)
    on_disk = tmp_path / "ash-config" / ".ash" / ".ash.yaml"
    on_disk.parent.mkdir(parents=True)
    on_disk.write_text("project_name: rewritten-by-an-earlier-scan\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(on_disk))
    ssm = _with_base_config_parameter(
        gate, monkeypatch, "project_name: operator-base-config\n"
    )
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    gate.run_scan(source, "low", True)

    [call] = capture.calls
    assert call["content"] == "project_name: operator-base-config\n"
    assert not _is_inside(call["config"], source)
    assert [c["Name"] for c in ssm.calls] == ["/ash/base-config"]


def test_an_edit_to_the_parameter_reaches_the_next_scan(gate, monkeypatch, tmp_path):
    source = _pull_request_tree(tmp_path)
    ssm = _with_base_config_parameter(gate, monkeypatch, "project_name: first\n")
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    gate.run_scan(source, "low", True)
    ssm.value = "project_name: second\n"
    gate.run_scan(source, "low", True)

    assert [c["content"] for c in capture.calls] == [
        "project_name: first\n",
        "project_name: second\n",
    ]


def test_a_base_config_parameter_that_cannot_be_read_refuses_the_scan(
    gate, monkeypatch, tmp_path
):
    source = _pull_request_tree(tmp_path)
    _with_base_config_parameter(gate, monkeypatch, None)
    capture = _ScanCapture()
    monkeypatch.setattr(gate, "_run", capture)

    with pytest.raises(RuntimeError, match="/ash/base-config"):
        gate.run_scan(source, "low", True)
    assert capture.calls == []
