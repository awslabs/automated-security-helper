# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config validate`, `lint`, `get` and `validate-plugin-dependencies` give
the verdict a scan gives.

Each case puts one config file where a scan of the project directory discovers
it (or names it with --config, the same way for every command), then runs these
on it from that directory:

- the real `ash scan` CLI, in-process, with the scanners replaced: the
  orchestrator's ``execute_scan`` records that it was reached and stops the
  run, so everything up to and including config resolution is the real code;
- `ash config validate`, `lint`, `get` and `validate-plugin-dependencies`.

A scan refuses an invalid config with exit 3 before any scanner runs. The
assertion is that validate, get and validate-plugin-dependencies exit 3 exactly
when the scan does (and 0 when the scan accepts the file), and that lint exits 3
exactly when the scan does and otherwise ends without an exception. Each case
also pins which verdict it expects, so a case cannot pass because both sides
failed the same way for an unrelated reason.

The rows started as a measured divergence matrix: validate called wrong-typed
values valid (exit 0, scan exit 3) and refused files the scan accepts (unknown
top-level key, missing project_name, the internal fields `config update`
writes).
"""

from __future__ import annotations

import json
import os as _os
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp_tools import mcp_validate_config
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

INVALID_CONFIG_EXIT = 3
# What validate prints above its warnings. Asserting on the word "warning"
# alone would also match a path that validate prints.
WARNINGS_HEADER = "warning(s); a scan accepts these"


@dataclass(frozen=True)
class Case:
    id: str
    text: str
    scan_accepts: bool
    # Text validate must print. For a refused config these name the fields.
    validate_mentions: List[str] = field(default_factory=list)
    file_name: str = ".ash/.ash.yaml"
    overrides: List[str] = field(default_factory=list)
    # Other files the case needs, by path relative to the project.
    extra_files: Dict[str, str] = field(default_factory=dict)
    # Name the file with --config instead of letting discovery find it.
    config_option: bool = False
    # Text validate must not print (a wrong claim about what a scan does).
    validate_absent: List[str] = field(default_factory=list)
    # lint's own verdict, where it differs from the scan's: lint checks the
    # file as written, so an override is not part of what it judges. None keeps
    # the default expectation below.
    lint_refuses: Optional[bool] = None


def _dedent(text: str) -> str:
    return textwrap.dedent(text).lstrip()


CASES = [
    Case(
        id="module-list-emptied-by-override",
        # wsgiref is importable and outside the plugin namespace: without the
        # override the scan refuses it, and with the override there is nothing
        # left to refuse, so a check reading the pre-override list shows.
        text=_dedent(
            """
            project_name: demo
            ash_plugin_modules:
              - wsgiref
            """
        ),
        overrides=["ash_plugin_modules=[]"],
        scan_accepts=True,
        validate_absent=["wsgiref"],
        # lint checks the file as written, and a scan of the file without the
        # override refuses wsgiref, so lint's exit 3 is its own honest verdict.
        lint_refuses=True,
    ),
    Case(
        id="module-only-by-override",
        text=_dedent(
            """
            project_name: demo
            """
        ),
        overrides=['ash_plugin_modules=["wsgiref"]'],
        scan_accepts=False,
        validate_mentions=["wsgiref"],
    ),
    Case(
        id="schema-invalid-values",
        text=_dedent(
            """
            project_name: demo
            fail_on_findings: banana
            global_settings:
              severity_threshold: BOGUS
            scanners:
              bandit:
                enabled: maybe
            """
        ),
        scan_accepts=False,
        validate_mentions=[
            "fail_on_findings",
            "global_settings.severity_threshold",
            "scanners.bandit.enabled",
        ],
    ),
    Case(
        id="unknown-nested-key",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              severity_treshold: LOW
            """
        ),
        scan_accepts=False,
        validate_mentions=["global_settings.severity_treshold"],
    ),
    Case(
        id="suppression-without-reason",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              suppressions:
                - rule_id: B101
                  path: tests/**
            """
        ),
        scan_accepts=False,
        validate_mentions=["global_settings.suppressions[0].reason"],
    ),
    Case(
        id="unquoted-date-expiration",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              suppressions:
                - rule_id: B101
                  path: tests/**
                  reason: asserts in tests
                  expiration: 2099-01-31
            """
        ),
        scan_accepts=False,
        validate_mentions=[
            "global_settings.suppressions[0].expiration",
            "put it in quotes",
        ],
    ),
    Case(
        id="expiration-not-a-date",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              suppressions:
                - rule_id: B101
                  path: tests/**
                  reason: asserts in tests
                  expiration: "2099-13-45"
            """
        ),
        scan_accepts=False,
        validate_mentions=["global_settings.suppressions[0].expiration"],
    ),
    Case(
        id="ignore-path-unquoted-date-expiration",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              ignore_paths:
                - path: vendor/**
                  reason: third-party code
                  expiration: 2099-01-31
            """
        ),
        scan_accepts=False,
        validate_mentions=[
            "global_settings.ignore_paths[0].expiration",
            "put it in quotes",
        ],
    ),
    Case(
        id="ignore-path-expiration-not-a-date",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              ignore_paths:
                - path: vendor/**
                  reason: third-party code
                  expiration: "31/01/2099"
            """
        ),
        scan_accepts=False,
        validate_mentions=["global_settings.ignore_paths[0].expiration"],
    ),
    Case(
        id="symbol-not-a-qualified-name",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              suppressions:
                - rule_id: B101
                  path: app.py
                  reason: asserts in a handler
                  symbol: "handler(request)"
            """
        ),
        scan_accepts=False,
        validate_mentions=["global_settings.suppressions[0].symbol"],
    ),
    Case(
        id="invalid-build-section",
        text=_dedent(
            """
            project_name: demo
            build:
              build_mode: SOMETIMES
            """
        ),
        scan_accepts=False,
        validate_mentions=["build"],
    ),
    Case(
        id="extends-missing-base",
        text=_dedent(
            """
            extends: ../no-such-base.yaml
            project_name: demo
            """
        ),
        scan_accepts=False,
        validate_mentions=["no-such-base.yaml"],
    ),
    Case(
        id="pyproject-wrong-type",
        text=_dedent(
            """
            [tool.ash]
            project_name = "demo"
            fail_on_findings = "sometimes"
            """
        ),
        scan_accepts=False,
        validate_mentions=["fail_on_findings"],
        file_name="pyproject.toml",
    ),
    Case(
        id="override-makes-it-invalid",
        text="project_name: demo\n",
        scan_accepts=False,
        validate_mentions=["fail_on_findings"],
        overrides=["fail_on_findings=maybe"],
    ),
    Case(
        id="empty-file",
        text="",
        scan_accepts=False,
        validate_mentions=["Invalid value at '(top level)'"],
    ),
    Case(
        id="not-a-mapping",
        text="- just\n- a list\n",
        scan_accepts=False,
        validate_mentions=["Invalid value at '(top level)'"],
    ),
    Case(
        # Strict types: a scan refuses the string "true" for a boolean, where a
        # lax validation would accept it.
        id="strict-boolean",
        text='project_name: demo\nfail_on_findings: "true"\n',
        scan_accepts=False,
        validate_mentions=["fail_on_findings"],
    ),
    Case(
        # Discovery itself fails: pyproject.toml declares [tool.ash] but is not TOML.
        id="broken-pyproject-tool-ash",
        text='[tool.ash]\nproject_name = "demo\n',
        scan_accepts=False,
        validate_mentions=["pyproject.toml"],
        file_name="pyproject.toml",
    ),
    Case(
        # A --config file in a subdirectory whose base is elsewhere in the
        # repository: the scan confines bases to its source directory.
        id="config-option-extends-across-the-repository",
        text="extends: ../shared/base.yaml\nfail_on_findings: false\n",
        scan_accepts=True,
        file_name="configs/ash.yaml",
        extra_files={"shared/base.yaml": "project_name: demo\n"},
        config_option=True,
    ),
    Case(
        id="config-option-extends-out-of-the-repository",
        text="extends: ../../outside.yaml\nproject_name: demo\n",
        scan_accepts=False,
        validate_mentions=["outside.yaml"],
        file_name="configs/ash.yaml",
        config_option=True,
    ),
    Case(
        id="valid-minimal",
        text="project_name: demo\n",
        scan_accepts=True,
    ),
    Case(
        id="unknown-top-level-key",
        text="project_name: demo\nfoo_unknown: 1\n",
        scan_accepts=True,
        validate_mentions=["foo_unknown"],
    ),
    Case(
        id="missing-project-name",
        text="global_settings:\n  severity_threshold: LOW\n",
        scan_accepts=True,
        validate_mentions=["project_name"],
    ),
    Case(
        id="internal-plugin-fields",
        text=_dedent(
            """
            project_name: demo
            scanners:
              bandit:
                name: bandit
                enabled: true
            reporters:
              html:
                name: html
                extension: html
            """
        ),
        scan_accepts=True,
        validate_mentions=["'name'", "'extension'"],
    ),
    Case(
        # Internal-only fields a built-in section does not declare: a scan
        # refuses them at the section level.
        id="internal-plugin-fields-a-scan-refuses",
        text=_dedent(
            """
            project_name: demo
            scanners:
              bandit:
                tool_version: "1.7.5"
            converters:
              archive:
                install_timeout: 10
            """
        ),
        scan_accepts=False,
        validate_mentions=[
            # The model's refusal, the text the scan prints.
            (
                "Invalid value at 'scanners.bandit': Value error, Scanner 'bandit' "
                "contains internal-only field 'tool_version'"
            ),
            (
                "Invalid value at 'converters.archive': Value error, Converter "
                "'archive' contains internal-only field 'install_timeout'"
            ),
            # The fix is the point: the config does not load until they go.
            "'ash config lint --fix' removes internal-only fields",
        ],
        # Each is one error: not a warning as well, and not the model's
        # "move ... under options", which is wrong advice for a leaked field.
        validate_absent=[WARNINGS_HEADER, "move tool_version under options"],
    ),
    Case(
        id="build-section",
        text="project_name: demo\nbuild:\n  build_mode: ONLINE\n",
        scan_accepts=True,
        validate_mentions=["build"],
    ),
    Case(
        id="duplicate-top-level-key",
        text="project_name: demo\nfail_on_findings: true\nfail_on_findings: false\n",
        scan_accepts=True,
        validate_mentions=["fail_on_findings"],
    ),
    Case(
        id="env-reference",
        text=_dedent(
            """
            project_name: !ENV ${ASH_TEST_VALIDATE_PROJECT:demo}
            global_settings:
              severity_threshold: LOW
            """
        ),
        scan_accepts=True,
    ),
    Case(
        # The operator's documented key: nothing suggests removing it.
        id="documented-mcp-resource-management",
        text="project_name: demo\nmcp-resource-management:\n  max_concurrent_scans: 2\n",
        scan_accepts=True,
        validate_absent=["mcp-resource-management", WARNINGS_HEADER],
    ),
    Case(
        # The model's field name for a key documented by its alias: a scan
        # reads it as mcp-resource-management.
        id="snake-case-alias",
        text="project_name: demo\nmcp_resource_management:\n  max_concurrent_scans: 2\n",
        scan_accepts=True,
        validate_absent=["Unknown top-level field", "a scan ignores"],
    ),
    Case(
        id="both-alias-spellings",
        text=_dedent(
            """
            project_name: demo
            mcp_resource_management:
              max_concurrent_scans: 2
            mcp-resource-management:
              max_concurrent_scans: 3
            """
        ),
        scan_accepts=True,
        validate_mentions=["mcp_resource_management", "mcp-resource-management"],
    ),
    Case(
        id="both-plugin-spellings",
        text=_dedent(
            """
            project_name: demo
            scanners:
              cdk_nag:
                enabled: false
              cdk-nag:
                enabled: true
            """
        ),
        scan_accepts=True,
    ),
    Case(
        id="directory-ignore-path-without-glob",
        text=_dedent(
            """
            project_name: demo
            global_settings:
              ignore_paths:
                - path: vendor
                  reason: third-party code
            """
        ),
        scan_accepts=True,
        validate_mentions=["Use 'vendor/'"],
        extra_files={"vendor/lib.py": ""},
    ),
    Case(
        # YAML reads an unquoted off as false, which the configuration accepts
        # as the sandbox mode "off".
        id="unquoted-sandbox-off",
        text="project_name: demo\nsandbox:\n  mode: off\n",
        scan_accepts=True,
        validate_mentions=["Configuration is valid"],
        validate_absent=["sandbox.mode"],
    ),
    Case(
        id="valid-override",
        text="project_name: demo\n",
        scan_accepts=True,
        overrides=["global_settings.severity_threshold=LOW"],
    ),
]


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "demo"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_TEST_VALIDATE_PROJECT", raising=False)
    return root


def _write_case(root: Path, case: Case) -> Path:
    for name, text in case.extra_files.items():
        extra = root / name
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text(text, encoding="utf-8")
    # One level up, outside the project, for the case that escapes it.
    (root.parent / "outside.yaml").write_text("project_name: x\n", encoding="utf-8")
    path = root / case.file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(case.text, encoding="utf-8")
    return path


def _config_args(case: Case) -> List[str]:
    return ["--config", case.file_name] if case.config_option else []


def _override_args(overrides: List[str]) -> List[str]:
    args: List[str] = []
    for override in overrides:
        args += ["--config-overrides", override]
    return args


def _scan_verdict(
    root: Path, overrides: List[str], monkeypatch, config_args: List[str] = ()
) -> bool:
    """True when `ash scan` accepts the config, False when it exits 3."""
    return _scan(root, overrides, monkeypatch, config_args)[0]


def _scan(
    root: Path, overrides: List[str], monkeypatch, config_args: List[str] = ()
) -> Tuple[bool, object]:
    """Run `ash scan`: whether it accepted the config, and the CliRunner result."""

    reached: List[bool] = []

    def _stop(*_args, **_kwargs):
        # Past config resolution: the scan accepted the config. Exit here so no
        # scanner runs.
        reached.append(True)
        raise SystemExit(0)

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        _stop,
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--source-dir",
            str(root),
            "--output-dir",
            str(root.parent / "scan-output"),
            *config_args,
            *_override_args(overrides),
        ],
    )
    assert reached or result.exit_code == INVALID_CONFIG_EXIT, (
        "the scan neither reached execution nor refused the config with exit 3; "
        f"exit {result.exit_code}, exception {result.exception!r}\n{result.output}"
    )
    return bool(reached), result


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_validate_and_lint_agree_with_the_scan(case: Case, project: Path, monkeypatch):
    _write_case(project, case)

    config_args = _config_args(case)
    scan_accepts = _scan_verdict(project, case.overrides, monkeypatch, config_args)
    assert scan_accepts is case.scan_accepts, (
        "the scan's verdict on this case changed; update the case before "
        "trusting the comparison below"
    )
    expected = 0 if scan_accepts else INVALID_CONFIG_EXIT

    runner = CliRunner()
    validate = runner.invoke(
        app, ["config", "validate", *config_args, *_override_args(case.overrides)]
    )
    assert validate.exit_code == expected, validate.output
    for text in case.validate_mentions:
        assert text in validate.output, (text, validate.output)
    for text in case.validate_absent:
        assert text not in validate.output, (text, validate.output)

    for command in ("get", "validate-plugin-dependencies"):
        loaded = runner.invoke(
            app, ["config", command, *config_args, *_override_args(case.overrides)]
        )
        assert _no_exception(loaded), (command, loaded.exception)
        assert loaded.exit_code == expected, (command, loaded.output)

    lint = runner.invoke(app, ["config", "lint", *config_args])
    assert _no_exception(lint), lint.exception
    if case.lint_refuses is not None:
        # The case pins lint's own verdict on the file as written, where the
        # overrides make the scan's differ.
        assert (lint.exit_code == INVALID_CONFIG_EXIT) is case.lint_refuses, lint.output
    elif case.overrides:
        # lint checks the file as written; an override is not part of it.
        assert lint.exit_code != INVALID_CONFIG_EXIT, lint.output
    elif scan_accepts:
        # What a scan accepts is a warning at most: no exit 1 either.
        assert lint.exit_code == 0, lint.output
        assert "❌" not in lint.output, lint.output
    else:
        assert lint.exit_code == INVALID_CONFIG_EXIT, lint.output

    # The MCP validate_config tool gives the same verdict. It has no source
    # directory and no overrides, so the cases that need one are left out. The
    # file is the operator's own, so the operator's config roots name its
    # directory: a config_path outside them is judged a client's and held to
    # the runtime-override policy (cli/mcp/sandbox.client_named_config_is_untrusted),
    # which is a different question from the one a scan of this directory asks.
    if not case.overrides and "extends" not in case.text:
        monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(project.parent))
        mcp = mcp_validate_config(config_path=str(project / case.file_name))
        assert mcp["valid"] is scan_accepts, mcp


def _no_exception(result) -> bool:
    return result.exception is None or isinstance(result.exception, SystemExit)


def _flat(text: str) -> str:
    """``text`` with every run of whitespace one space: the scan's console wraps lines."""
    return " ".join(text.split())


def _squeezed(text: str) -> str:
    """``text`` without whitespace: the console also breaks a word too long for a line."""
    return "".join(text.split())


# Where one model message ends in the scan's refusal: the next one starts, or
# the refusal does.
_NEXT_MODEL_MESSAGE = re.compile(r"; (?=Invalid value at ')")
_OVERRIDE_SUFFIX = " (after --config-overrides)"


def _scan_refusal(output: str) -> Tuple[List[str], str]:
    """The model messages of the scan's refusal, and the refusal's whole text.

    The refusal is ``Configuration validation failed for '<file>': <messages>.
    Run: ash config lint ...`` for a file the model refuses, ``Configuration is
    invalid after applying the requested overrides for '<key>', ...:
    <messages>`` for one an override makes invalid, and another reason (a chain
    that does not resolve, a file that does not parse) with no model messages.
    """
    flat = _flat(output)
    marker = "ERROR (3) Invalid configuration: "
    assert marker in flat, flat
    refusal = flat.split(marker, 1)[1].split(" Run: ash config lint", 1)[0]
    if refusal.startswith("Configuration validation failed for '"):
        messages = refusal.split("': ", 1)[1]
        # The period the refusal puts before "Run:".
        messages = messages.removesuffix(".")
    elif refusal.startswith("Configuration is invalid after applying"):
        # The overrides are named by their keys, and no key holds ": ".
        messages = refusal.split(": ", 1)[1]
    else:
        return [], refusal
    return _NEXT_MODEL_MESSAGE.split(messages), refusal


def _validate_model_messages(output: str) -> List[str]:
    """The model messages in validate's numbered list of errors."""
    found = []
    for line in output.splitlines():
        match = re.match(r"\s*\d+\. (Invalid value at '.*)$", line)
        if match:
            found.append(match.group(1).removesuffix(_OVERRIDE_SUFFIX))
    return found


# Every case a scan refuses, including a pyproject.toml that is not TOML, which
# discovery refuses before any file is loaded: the scan prints that refusal under
# its own label, and validate prints it in the same words.
LOADER_REFUSALS = [case for case in CASES if not case.scan_accepts]


@pytest.mark.parametrize("case", LOADER_REFUSALS, ids=lambda c: c.id)
def test_validate_prints_the_refusal_the_scan_prints(
    case: Case, project: Path, monkeypatch
):
    """Each field the model refuses is named by both, in the same words.

    So validate tells the operator exactly what the scan will say, and a message
    the model gives cannot be swapped for another in only one of the two. A
    refusal that is not the model's, an ``extends`` chain that does not resolve,
    is printed by validate in the scan's words too — up to the plugin-module
    refusal's closing sentences, which each surface words for itself (the
    scan's name scan options; a check's fit a check).
    """
    _write_case(project, case)
    config_args = _config_args(case)
    accepted, scan = _scan(project, case.overrides, monkeypatch, config_args)
    assert not accepted
    validate = CliRunner().invoke(
        app, ["config", "validate", *config_args, *_override_args(case.overrides)]
    )

    scan_messages, refusal = _scan_refusal(scan.output)
    if scan_messages:
        # A message's own closing period merges into the one before "Run:".
        def same(message: str) -> str:
            return _squeezed(message).rstrip(".")

        assert sorted(map(same, _validate_model_messages(validate.output))) == (
            sorted(map(same, scan_messages))
        ), (scan_messages, validate.output)
    else:
        # The plugin-module refusal closes in each surface's own words, so the
        # agreement there is on the naming, everything before the closing; any
        # other refusal has no closing and the split leaves it whole.
        naming = refusal.split(" Nothing was imported", 1)[0]
        assert _squeezed(naming) in _squeezed(validate.output), (
            refusal,
            validate.output,
        )

    # Lint prints each of them too, in the same words: it replaced the model's
    # message about an expiration or a symbol with one of its own. An internal
    # field is the exception: lint reports it as one its --fix removes.
    if case.overrides:
        return  # lint checks the file as written; an override is not part of it.
    lint = CliRunner().invoke(app, ["config", "lint", *config_args])
    for message in scan_messages:
        if "internal-only field" in message:
            continue
        assert _squeezed(message) in _squeezed(lint.output), (message, lint.output)


def test_a_refusal_ending_in_a_period_reads_as_one_sentence_before_the_hint(
    project: Path, monkeypatch
):
    """A model message that ends with a period is not followed by a second one."""
    (project / ".ash").mkdir()
    (project / ".ash" / ".ash.yaml").write_text(
        "project_name: demo\nscanners:\n  bandit:\n    severity_threshold: HIGH\n",
        encoding="utf-8",
    )

    accepted, scan = _scan(project, [], monkeypatch)

    assert not accepted
    flat = _flat(scan.output)
    assert "move severity_threshold under options. Run: ash config lint" in flat, flat
    assert ".. Run:" not in flat, flat


@pytest.mark.parametrize("where", ["discovered", "ash-config-beside-named"])
@pytest.mark.parametrize("step", ["loader", "chain", "model"])
def test_a_refusal_in_the_shared_loader_reaches_every_command(
    step, where, project: Path, monkeypatch
):
    """The scan and the config commands load a config file through one function.

    A refusal added to it reaches all of them, for a file with no ``extends``
    too, which has no chain to resolve: `ash config validate` read such a file
    itself, so a rule the loader applied to every file a scan reads did not
    reach it. ``loader`` refuses in load_config_file itself, ``chain`` where
    the file and its bases are read, ``model`` where the AshConfig model is
    built from them.

    The refused file is the one discovery finds, or the one ASH_CONFIG names
    while --config names a valid file. A scan loads the ASH_CONFIG file as the
    configuration it starts from (get_default_config), so the refusal stops it
    as well, and the checks report it.
    """
    refused_name = "refused.yaml"
    if where == "discovered":
        (project / ".ash").mkdir()
        refused = project / ".ash" / ".ash.yaml"
        refused_name = refused.name
        config_args: List[str] = []
    else:
        refused = project.parent / refused_name
        named = project / "ash.yaml"
        named.write_text("project_name: demo\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(refused))
        config_args = ["--config", str(named)]
    # The model step tells the refused file by its contents, the only thing
    # build_config sees.
    refused.write_text("project_name: refused-by-the-loader\n", encoding="utf-8")
    import automated_security_helper.config.resolve_config as loader

    if step in ("loader", "chain"):
        expected = "the loader refuses this file (injected)"
        real = getattr(
            loader,
            "load_config_file" if step == "loader" else "resolve_config_document",
        )

        def refuse(config_path, *args, **kwargs):
            if Path(config_path).name == refused_name:
                raise ASHConfigSourceError(expected)
            return real(config_path, *args, **kwargs)

        monkeypatch.setattr(
            loader,
            "load_config_file" if step == "loader" else "resolve_config_document",
            refuse,
        )
    else:
        expected = "Invalid value at 'fail_on_findings'"
        build_config = loader.build_config

        def refuse(data, config_overrides=None):
            if isinstance(data, dict) and data.get("project_name") == (
                "refused-by-the-loader"
            ):
                data = {**data, "fail_on_findings": "maybe"}
            return build_config(data, config_overrides)

        monkeypatch.setattr(loader, "build_config", refuse)

    accepted, scan = _scan(project, [], monkeypatch, config_args)
    assert not accepted
    assert expected in _flat(scan.output), scan.output
    for command in ("validate", "lint", "get", "validate-plugin-dependencies"):
        result = CliRunner().invoke(app, ["config", command, *config_args])
        assert result.exit_code == INVALID_CONFIG_EXIT, (command, result.output)
        assert expected in _flat(result.output), (command, result.output)


# A value only the environment holds: it must never be printed.
ENV_CANARY = "canary-value-7f3a9e"


@pytest.mark.parametrize("value_from", ["the-file", "the-environment"])
@pytest.mark.parametrize("named_in", ["the-project", "elsewhere"])
@pytest.mark.parametrize(
    "command", ["validate", "lint", "get", "validate-plugin-dependencies", "mcp"]
)
def test_the_file_ash_config_names_is_checked_beside_the_named_one(
    command, named_in, value_from, project: Path, monkeypatch
):
    """A scan loads the file ASH_CONFIG names as the configuration it starts from.

    It does so with --config naming another file too, and refuses the run when
    the ASH_CONFIG file is refused. So validate, lint and the MCP validate_config
    tool check that file as well, and `config get` and
    `validate-plugin-dependencies`, which report what a scan would use, load
    it. Each reports its refusal in the scan's words, with the scan's exit
    code, and does not call the named file valid. The named file is in the
    project or outside it: a scan loads the ASH_CONFIG file either way.

    The refused value may be one the file reads from the environment; then no
    output, the MCP result included, holds it.
    """
    if named_in == "the-project":
        named = project / "ash.yaml"
    else:
        (project.parent / "configs").mkdir()
        named = project.parent / "configs" / "ash.yaml"
    named.write_text("project_name: demo\n", encoding="utf-8")
    other = project.parent / "ash-config.yaml"
    if value_from == "the-file":
        value = "banana"
    else:
        monkeypatch.setenv("ASH_TEST_CANARY", ENV_CANARY)
        value = "${ASH_TEST_CANARY:None}"
    other.write_text(
        f"project_name: demo\nfail_on_findings: {value}\n", encoding="utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(other))

    accepted, scan = _scan(project, [], monkeypatch, ["--config", str(named)])
    assert not accepted, "the scan refuses the run for the ASH_CONFIG file"
    scan_messages, _ = _scan_refusal(scan.output)
    assert scan_messages, scan.output

    if command == "mcp":
        result = mcp_validate_config(config_path=str(named))
        assert result["valid"] is False, result
        printed = " ".join(error["message"] for error in result["errors"])
        everything = json.dumps(result, default=str)
    else:
        invoked = CliRunner().invoke(app, ["config", command, "--config", str(named)])
        assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
        printed = invoked.output
        everything = printed + (invoked.stderr or "")
    assert other.name in _squeezed(printed), printed
    for message in scan_messages:
        assert _squeezed(message) in _squeezed(printed), (message, printed)
    assert ENV_CANARY not in everything, everything


def test_ash_config_naming_the_checked_file_reports_it_once(project: Path, monkeypatch):
    """When ASH_CONFIG names the file being checked, there is no second file to load."""
    named = project / "ash.yaml"
    named.write_text("project_name: demo\nfail_on_findings: banana\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))

    invoked = CliRunner().invoke(app, ["config", "validate", "--config", str(named)])

    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    assert _validate_model_messages(invoked.output) == [
        "Invalid value at 'fail_on_findings': Input should be a valid boolean"
    ], invoked.output


# Files a scan refuses when ASH_CONFIG names them: one that does not parse, and
# one the model refuses.
ASH_CONFIG_REFUSALS = {
    "unparsable": "project_name: demo\nscanners: [bandit\n",
    "invalid-value": "project_name: demo\nfail_on_findings: banana\n",
}


def _refused_ash_config(project: Path, broken: str, monkeypatch) -> Tuple[Path, str]:
    """A valid project file, and ASH_CONFIG naming a file a scan refuses.

    Returns the valid file and the scan's refusal for that invocation, which
    names the ASH_CONFIG file.
    """
    named = project / "ash.yaml"
    named.write_text("project_name: demo\n", encoding="utf-8")
    other = project.parent / "environment-config.yaml"
    other.write_text(ASH_CONFIG_REFUSALS[broken], encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(other))
    accepted, scan = _scan(project, [], monkeypatch, ["--config", str(named)])
    assert not accepted, "the scan refuses the run for the ASH_CONFIG file"
    _, refusal = _scan_refusal(scan.output)
    assert other.name in refusal, refusal
    return named, refusal


@pytest.mark.parametrize("broken", sorted(ASH_CONFIG_REFUSALS))
@pytest.mark.parametrize("command", ["get", "validate-plugin-dependencies"])
def test_the_ash_config_refusal_is_not_printed_as_the_named_files(
    command, broken, project: Path, monkeypatch
):
    """`get` and `validate-plugin-dependencies` print the ASH_CONFIG file's
    refusal under no file's name, and `validate-plugin-dependencies` names that
    file in its verdict. Under "Invalid configuration in <named file>:", or
    after "Config file '<named file>' is not valid.", it blamed the valid file
    --config names."""
    named, refusal = _refused_ash_config(project, broken, monkeypatch)
    other = Path(_os.environ["ASH_CONFIG"])

    invoked = CliRunner().invoke(app, ["config", command, "--config", str(named)])

    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    printed = _squeezed(invoked.output)
    assert _squeezed(f"Invalid configuration in {named}:") not in printed, (
        invoked.output
    )
    assert _squeezed(refusal) in printed, (refusal, invoked.output)
    if command == "validate-plugin-dependencies":
        assert _squeezed(f"Config file '{named.as_posix()}'") not in printed, (
            invoked.output
        )
        assert _squeezed(f"ASH_CONFIG names ('{other.as_posix()}')") in printed, (
            invoked.output
        )


def test_an_unreadable_ash_config_file_is_named_by_validate_plugin_dependencies(
    project: Path, monkeypatch
):
    """An ASH_CONFIG file that cannot be read is reported as that file, not as
    the valid one --config names."""
    if _os.name == "nt" or (hasattr(_os, "geteuid") and _os.geteuid() == 0):
        pytest.skip("root (and Windows, with no mode bits) reads a mode-0 file")
    named = project / "ash.yaml"
    named.write_text("project_name: demo\n", encoding="utf-8")
    other = project.parent / "environment-config.yaml"
    other.write_text("project_name: demo\n", encoding="utf-8")
    other.chmod(0)
    try:
        with pytest.raises(PermissionError):
            other.open(encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(other))

        invoked = CliRunner().invoke(
            app, ["config", "validate-plugin-dependencies", "--config", str(named)]
        )
    finally:
        other.chmod(0o644)

    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    printed = _squeezed(invoked.output)
    assert _squeezed(f"Config file '{named.as_posix()}'") not in printed, invoked.output
    # The label attributes the refusal to the file ASH_CONFIG names, and the
    # refusal itself is get_default_config's read wrap, the one
    # every caller now shows, instead of a sentence of this surface's own.
    assert _squeezed(f"ASH_CONFIG names ('{other.as_posix()}')") in printed, (
        invoked.output
    )
    assert _squeezed(f"could not read {other.as_posix()}") in printed, invoked.output


def test_a_directory_ash_config_names_is_reported_as_that_path(
    project: Path, monkeypatch
):
    """ASH_CONFIG naming a directory is refused as that path, which is not a
    file: under the --config file's name, the valid file was blamed."""
    named = project / "ash.yaml"
    named.write_text("project_name: demo\n", encoding="utf-8")
    other = project.parent / "environment-config"
    other.mkdir()
    monkeypatch.setenv("ASH_CONFIG", str(other))

    invoked = CliRunner().invoke(
        app, ["config", "validate-plugin-dependencies", "--config", str(named)]
    )

    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    printed = _squeezed(invoked.output)
    assert _squeezed(f"Config file '{named.as_posix()}'") not in printed, invoked.output
    assert _squeezed(f"ASH_CONFIG names ('{other.as_posix()}')") in printed, (
        invoked.output
    )


def test_a_pyproject_ash_config_names_is_named_by_its_table(project: Path, monkeypatch):
    """The label names a pyproject.toml as every other message does, with its
    [tool.ash] table and line."""
    named = project / "ash.yaml"
    named.write_text("project_name: demo\n", encoding="utf-8")
    other = project.parent / "environment" / "pyproject.toml"
    other.parent.mkdir()
    other.write_text(
        '[tool.ash]\nproject_name = "demo"\nfail_on_findings = "banana"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(other))

    invoked = CliRunner().invoke(
        app, ["config", "validate-plugin-dependencies", "--config", str(named)]
    )

    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    assert _squeezed(
        f"ASH_CONFIG names ('{other.as_posix()} [tool.ash] (line 1)')"
    ) in _squeezed(invoked.output), invoked.output


def test_the_label_is_decided_from_the_refusal_without_a_second_load(
    project: Path, monkeypatch
):
    """Which file a refusal is about is read from the refusal: loading the
    ASH_CONFIG file again to find out read it, and logged it, once more."""
    from automated_security_helper.cli import config as cli_config
    from automated_security_helper.config import default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    named, _ = _refused_ash_config(project, "invalid-value", monkeypatch)
    other = Path(_os.environ["ASH_CONFIG"])

    def loaded_again(*_args, **_kwargs):
        pytest.fail("the label loaded the ASH_CONFIG file again")

    monkeypatch.setattr(default_config, "get_default_config", loaded_again)
    label = f"Config file '{named.as_posix()}'"
    theirs = ASHConfigValidationError("refused")
    theirs.ash_config_file = other

    assert cli_config._refused_file_label(label, named, theirs) == (
        f"The file ASH_CONFIG names ('{other.as_posix()}')"
    )
    # A refusal of the named file itself keeps the named file's label.
    assert (
        cli_config._refused_file_label(label, named, ASHConfigValidationError("x"))
        == label
    )
    unreadable = PermissionError(13, "Permission denied", str(other))
    assert cli_config._refused_file_label(label, named, unreadable) == (
        f"The file ASH_CONFIG names ('{other.as_posix()}')"
    )


@pytest.mark.parametrize("broken", sorted(ASH_CONFIG_REFUSALS))
def test_validate_plugin_dependencies_loads_a_refused_ash_config_once(
    broken, project: Path, monkeypatch
):
    """resolve_config refuses the run for the ASH_CONFIG file. The report of that
    refusal checks --config's file again, and its check of the ASH_CONFIG file
    loaded that file a second time, logging it again, for a message the report
    then left out."""
    from automated_security_helper.config import default_config, resolve_config

    named, _ = _refused_ash_config(project, broken, monkeypatch)
    real = default_config.get_default_config
    calls: List[int] = []

    def counted(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(default_config, "get_default_config", counted)
    monkeypatch.setattr(resolve_config, "get_default_config", counted)

    invoked = CliRunner().invoke(
        app, ["config", "validate-plugin-dependencies", "--config", str(named)]
    )

    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    assert "The file ASH_CONFIG names" in invoked.output, invoked.output
    assert len(calls) == 1, f"the ASH_CONFIG file was loaded {len(calls)} times"


@pytest.mark.parametrize("unusable", ["directory", "unparsable", "invalid-value"])
@pytest.mark.parametrize("command", ["get", "validate-plugin-dependencies"])
def test_an_unusable_ash_config_file_is_refused_wherever_the_named_file_is(
    command, unusable, project: Path, monkeypatch
):
    """A scan starts from the ASH_CONFIG file wherever --config's file is; with
    that file outside the source directory, these commands called it valid."""
    outside = project.parent / "elsewhere" / "ash.yaml"
    outside.parent.mkdir()
    outside.write_text("project_name: demo\n", encoding="utf-8")
    other = project.parent / "environment-config.yaml"
    if unusable == "directory":
        other.mkdir()
    else:
        other.write_text(ASH_CONFIG_REFUSALS[unusable], encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(other))
    accepted, _ = _scan(project, [], monkeypatch, ["--config", str(outside)])

    invoked = CliRunner().invoke(app, ["config", command, "--config", str(outside)])

    assert not accepted, "the scan should refuse the run for the ASH_CONFIG file"
    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output


@pytest.mark.parametrize("broken", sorted(ASH_CONFIG_REFUSALS))
@pytest.mark.parametrize("command", ["plugin list", "dependencies install"])
def test_commands_that_load_plugins_refuse_the_ash_config_file_a_scan_refuses(
    command, broken, project: Path, tmp_path: Path, monkeypatch
):
    """`plugin list` and `dependencies install` load the plugins of the
    configuration a scan would use, which starts from the file ASH_CONFIG names.
    With --config naming a valid file and ASH_CONFIG one a scan refuses, each
    exits 3 with the scan's refusal, before any plugin is loaded. `plugin list`
    exited 1 ("Error: ..."), and `dependencies install` raised the error."""
    named, refusal = _refused_ash_config(project, broken, monkeypatch)
    loaded: List[bool] = []

    def _stop(*_args, **_kwargs):
        loaded.append(True)
        raise RuntimeError("stopped at loading plugins")

    module = command.split()[0]
    monkeypatch.setattr(f"automated_security_helper.cli.{module}.load_plugins", _stop)
    argv = [*command.split(), "--config", str(named)]
    if command == "dependencies install":
        # The command exports ASH_BIN_PATH; set here so it is put back.
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        argv += ["--bin-path", str(tmp_path / "bin")]

    invoked = CliRunner().invoke(app, argv)

    assert _no_exception(invoked), repr(invoked.exception)
    assert invoked.exit_code == INVALID_CONFIG_EXIT, invoked.output
    assert not loaded, "plugins were loaded for a configuration a scan refuses"
    assert _squeezed(refusal) in _squeezed(invoked.output), (refusal, invoked.output)


@pytest.mark.parametrize("broken", sorted(ASH_CONFIG_REFUSALS))
@pytest.mark.parametrize("asked_for", ["named", "discovered", "none-found"])
def test_mcp_get_config_refuses_the_ash_config_file_a_scan_refuses(
    asked_for, broken, project: Path, monkeypatch
):
    """The MCP get_config tool answers with the configuration a scan would use,
    whose base is the file ASH_CONFIG names. When a scan refuses that file, the
    tool returns an error result with the scan's refusal, for a named file, a
    discovered one, and none, where it returns the base alone. The error
    escaped the tool instead."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    named, refusal = _refused_ash_config(project, broken, monkeypatch)
    if asked_for == "named":
        result = mcp_get_config(config_path=str(named))
    else:
        if asked_for == "none-found":
            named.unlink()
        else:
            named.rename(project / ".ash.yaml")
        result = mcp_get_config(search_dir=str(project))

    assert result.get("success") is False, result
    assert _words(refusal) in _words(result["error"]), (refusal, result)


def _words(text: str) -> str:
    """``text``'s words, as an MCP tool's error and the scan's console both hold
    them. The tool's error is one line, each control as its escape, the YAML
    error's newlines included (raw_controls_on_one_line); the refusal read from
    the console has its line breaks as spaces (_flat). So both go through that
    function, the escapes of tab, newline and carriage return are read as the
    whitespace they stand for, and the whitespace is squeezed: every other
    escape, and every word, is compared."""
    from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

    shown = raw_controls_on_one_line(text)
    return _squeezed(re.sub(r"\\x(?:09|0a|0d)", " ", shown))


def test_config_init_output_validates_and_scans(project: Path, monkeypatch):
    runner = CliRunner()
    init = runner.invoke(app, ["config", "init"])
    assert init.exit_code == 0, init.output

    assert _scan_verdict(project, [], monkeypatch) is True
    validate = runner.invoke(app, ["config", "validate"])
    assert validate.exit_code == 0, validate.output
    assert WARNINGS_HEADER not in validate.output, validate.output
    lint = runner.invoke(app, ["config", "lint"])
    assert lint.exit_code == 0, lint.output
    assert "No issues found" in lint.output, lint.output


@pytest.mark.parametrize(
    "setting", ["global_settings.severity_threshold=LOW", "project_name=foo"]
)
def test_config_update_output_validates_and_scans(
    project: Path, monkeypatch, setting: str
):
    """The divergence row "init output after `config update --set`".

    `config update` writes no internal plugin field back, so lint reports no
    internal-only-field error on a file ASH wrote.
    """
    runner = CliRunner()
    assert runner.invoke(app, ["config", "init"]).exit_code == 0
    update = runner.invoke(app, ["config", "update", "--set", setting])
    assert update.exit_code == 0, update.output

    assert _scan_verdict(project, [], monkeypatch) is True
    validate = runner.invoke(app, ["config", "validate"])
    assert validate.exit_code == 0, validate.output
    assert WARNINGS_HEADER not in validate.output, validate.output
    lint = runner.invoke(app, ["config", "lint"])
    assert lint.exit_code == 0, lint.output
    assert "No issues found" in lint.output, lint.output


@pytest.mark.parametrize(
    "content, where",
    [
        pytest.param(
            b"project_name: demo\nglobal_settings: [unclosed\n", "line 3", id="yaml"
        ),
        pytest.param(
            b"project_name: caf\xe9\n", "not UTF-8 at byte offset", id="not-utf-8"
        ),
    ],
)
def test_unparseable_file_is_invalid(
    project: Path, monkeypatch, content: bytes, where: str
):
    """A file that does not parse is invalid: exit 3, as `config get` exits, and
    as a scan refuses it. The messages say the scan refuses the file."""
    (project / ".ash").mkdir()
    (project / ".ash" / ".ash.yaml").write_bytes(content)
    assert _scan_verdict(project, [], monkeypatch) is False
    runner = CliRunner()

    validate = runner.invoke(app, ["config", "validate"])
    assert validate.exit_code == INVALID_CONFIG_EXIT, validate.output
    # Where the file stops parsing.
    assert where in validate.output, validate.output
    assert "A scan refuses this file too" in validate.output, validate.output
    assert "default configuration" not in validate.output, validate.output
    lint = runner.invoke(app, ["config", "lint"])
    assert lint.exit_code == INVALID_CONFIG_EXIT, lint.output
    assert "A scan refuses this file too" in lint.output, lint.output
    assert "default configuration" not in lint.output, lint.output


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["update", "--set", "fail_on_findings=false"], id="update"),
        pytest.param(["wizard"], id="wizard"),
    ],
)
def test_a_source_discovery_cannot_read_is_invalid_for_the_writers(
    project: Path, monkeypatch, args: List[str]
):
    """The commands that rewrite the discovered config exit 3 too, as the scan does."""
    (project / "pyproject.toml").write_text(
        '[tool.ash]\nproject_name = "demo\n', encoding="utf-8"
    )
    assert _scan_verdict(project, [], monkeypatch) is False

    result = CliRunner().invoke(app, ["config", *args], input="\n" * 20)

    assert _no_exception(result), result.exception
    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "pyproject.toml" in result.output, result.output


@pytest.mark.parametrize(
    "command, where",
    [
        pytest.param(
            ["scan", "--mode", "local", "--no-progress"],
            "config-option",
            id="scan-config",
        ),
        pytest.param(
            ["scan", "--mode", "local", "--no-progress"],
            "source-dir",
            id="scan-source-dir",
        ),
        pytest.param(["plugin", "list"], "config-option", id="plugin-list-config"),
        pytest.param(
            ["scan", "--mode", "local", "--no-progress"],
            "source-dir-elsewhere",
            id="scan-source-dir-elsewhere",
        ),
    ],
)
def test_a_refusal_names_a_command_that_explains_it(
    project: Path, monkeypatch, command: List[str], where: str
):
    """A refused config points at `ash config lint`; that command must explain it.

    A bare "Run 'ash config lint'" would lint the config of the current
    directory: for `--config configs/bad.yaml`, or a scan of another directory,
    that is a different file, or none. So the refusal names the file, and the
    command it names reports the same field.
    """
    import shlex

    bad = "project_name: demo\nfail_on_findings: sometimes\n"
    if where == "config-option":
        (project / "configs").mkdir()
        (project / "configs" / "bad.yaml").write_text(bad, encoding="utf-8")
        args = [*command, "--config", "configs/bad.yaml"]
    elif where == "source-dir":
        (project / "other" / ".ash").mkdir(parents=True)
        (project / "other" / ".ash" / ".ash.yaml").write_text(bad, encoding="utf-8")
        args = [*command, "--source-dir", "other", "--output-dir", "out"]
    else:
        # A repository outside the working directory, whose config extends a
        # base elsewhere in it: linting the file without the scan's source
        # directory confines the base to the config's own directory and
        # reports that instead of the field the scan refused.
        repo = project.parent / "repo"
        (repo / "configs").mkdir(parents=True)
        (repo / "shared").mkdir()
        (repo / "shared" / "base.yaml").write_text(
            "project_name: demo\n", encoding="utf-8"
        )
        (repo / "configs" / "ash.yaml").write_text(
            "extends: ../shared/base.yaml\nfail_on_findings: sometimes\n",
            encoding="utf-8",
        )
        args = [
            *command,
            "--source-dir",
            str(repo),
            "--config",
            str(repo / "configs" / "ash.yaml"),
            "--output-dir",
            "out",
        ]
    # This directory's own config is valid: linting it would explain nothing.
    (project / ".ashrc.yaml").write_text("project_name: demo\n", encoding="utf-8")
    runner = CliRunner()
    # A scan the refusal does not stop is stopped here, before any scanner runs.
    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        lambda *_a, **_k: (_ for _ in ()).throw(SystemExit(0)),
    )
    # The refusal as raised, before the console wraps a long path in it. (A
    # wide COLUMNS for the run instead left a console of that width behind,
    # which later snapshot tests in the same worker then printed with.)
    import automated_security_helper.config.resolve_config as resolve_module

    raised: List[str] = []
    real_resolve = resolve_module._resolve_config

    def recording_resolve(*args, **kwargs):
        try:
            return real_resolve(*args, **kwargs)
        except Exception as e:
            raised.append(str(e))
            raise

    monkeypatch.setattr(resolve_module, "_resolve_config", recording_resolve)

    refused = runner.invoke(app, args)

    assert refused.exit_code != 0, refused.output
    assert raised, refused.output
    from automated_security_helper.config.resolve_config import pasteable_path

    if "<the file named above>" in raised[-1]:
        # The command points at the file instead of naming it only when the
        # temporary directory's path holds a character lint_hint does not
        # print (a `~`, a space); test_lint_hint_* covers that form.
        assert not pasteable_path(project.parent), raised[-1]
        pytest.skip("the temporary directory's path is not one lint_hint prints")
    # The command comes last, on its own, not inside quotes of the message, so
    # it can be pasted as it is; the console prints it.
    match = re.search(r"Run: (ash config lint --config [^<>]+)$", raised[-1])
    assert match, raised[-1]
    flat = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", refused.output).split())
    assert "Run: ash config lint --config" in flat, flat
    named = shlex.split(match.group(1))
    lint = runner.invoke(app, named[1:])
    assert lint.exit_code == INVALID_CONFIG_EXIT, (named, lint.output)
    assert "Invalid value at 'fail_on_findings'" in lint.output, lint.output
    assert "[blocks the scan]" in lint.output, lint.output


@pytest.mark.parametrize(
    "path, source_dir, expected",
    [
        pytest.param(
            "configs/ash.yaml",
            None,
            "Run: ash config lint --config configs/ash.yaml",
            id="plain",
        ),
        pytest.param(
            "/srv/repo/.ash/.ash.yaml",
            "/srv/repo",
            "Run: ash config lint --config /srv/repo/.ash/.ash.yaml --source-dir /srv/repo",
            id="source-dir",
        ),
        pytest.param(
            "/srv/my repo/.ash/.ash.yaml",
            None,
            "Run: ash config lint --config <the file named above>",
            id="space",
        ),
        pytest.param(
            "/srv/x & calc & y/.ash/.ash.yaml",
            "/srv/x & calc & y",
            "Run: ash config lint --config <the file named above> "
            "--source-dir <the directory the scan scanned>",
            id="cmd-metacharacters",
        ),
        pytest.param(
            "/srv/x;rm -rf ~/.ashrc.yaml",
            None,
            "Run: ash config lint --config <the file named above>",
            id="posix-metacharacters",
        ),
        # Only the config path needs the placeholder. Printing the source dir
        # after it left `... <the file named above> --source-dir /srv/repo`,
        # which a POSIX shell runs (input from ./the, output to ./--source-dir).
        pytest.param(
            "/srv/repo/configs/my config.yaml",
            "/srv/repo",
            "Run: ash config lint --config <the file named above> "
            "--source-dir <the directory the scan scanned>",
            id="config-path-only",
        ),
        pytest.param(
            "/srv/repo/configs/ash.yaml",
            "/srv/my repo",
            "Run: ash config lint --config <the file named above> "
            "--source-dir <the directory the scan scanned>",
            id="source-dir-only",
        ),
    ],
)
def test_lint_hint_prints_only_paths_safe_to_paste(path, source_dir, expected):
    """A path is inlined only when it holds nothing but ASCII letters, digits and
    `_ . / : -`; otherwise the message points at it, and at the other path too,
    so the line ends in `>`, which no shell accepts as a complete command."""
    from automated_security_helper.config.resolve_config import lint_hint

    assert lint_hint(path, source_dir) == expected


def test_lint_hint_leaves_out_the_working_directory(project: Path):
    from automated_security_helper.config.resolve_config import lint_hint

    assert lint_hint("ash.yaml", project) == "Run: ash config lint --config ash.yaml"
    assert lint_hint("ash.yaml", ".") == "Run: ash config lint --config ash.yaml"


@pytest.mark.parametrize("given_as", ["option", "env"])
@pytest.mark.parametrize(
    "command", ["validate", "lint", "get", "validate-plugin-dependencies"]
)
def test_source_dir_selects_the_config_each_command_checks(
    project: Path, monkeypatch, command: str, given_as: str
):
    """`--source-dir other` (or ASH_SOURCE_DIR) checks other's config, as a scan
    of other does, and not the working directory's valid one."""
    (project / "other" / ".ash").mkdir(parents=True)
    (project / "other" / ".ash" / ".ash.yaml").write_text(
        "project_name: demo\nfail_on_findings: sometimes\n", encoding="utf-8"
    )
    (project / ".ashrc.yaml").write_text("project_name: demo\n", encoding="utf-8")
    args = ["config", command]
    if given_as == "option":
        args += ["--source-dir", "other"]
    else:
        monkeypatch.setenv("ASH_SOURCE_DIR", "other")

    result = CliRunner().invoke(app, args)

    assert _no_exception(result), result.exception
    assert result.exit_code == INVALID_CONFIG_EXIT, result.output
    assert "fail_on_findings" in result.output, result.output


def test_validate_plugin_dependencies_says_an_empty_project_name_names_no_project(
    project: Path,
):
    """A scan and validate accept `project_name: ""`; vpd checks that the config
    names a project, so it fails, but not as an invalid configuration."""
    (project / ".ashrc.yaml").write_text('project_name: ""\n', encoding="utf-8")
    runner = CliRunner()

    validate = runner.invoke(app, ["config", "validate"])
    vpd = runner.invoke(app, ["config", "validate-plugin-dependencies"])

    assert validate.exit_code == 0, validate.output
    assert vpd.exit_code == 1, vpd.output
    assert "does not name a project" in vpd.output, vpd.output


def test_an_out_of_namespace_plugin_module_is_invalid_for_validate_too(
    project: Path, monkeypatch
):
    """The operator's --config names a module outside the plugin namespace: a
    scan refuses it with exit 3 before importing anything
    (plugins/loader.refuse_plugin_modules_outside_namespace), so validate and
    the MCP tool call the file invalid, naming the entry. The file sits outside
    the scanned tree; an in-tree file is the next test's case."""
    config = project.parent / "operator.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - outside_module\n",
        encoding="utf-8",
    )
    config_args = ["--config", str(config)]

    scan_accepts, _ = _scan(project, [], monkeypatch, config_args)
    assert scan_accepts is False

    validate = CliRunner().invoke(app, ["config", "validate", *config_args])
    assert validate.exit_code == INVALID_CONFIG_EXIT, validate.output
    assert "outside_module" in validate.output, validate.output
    assert "is not a plugin module ASH imports" in _flat(validate.output), (
        validate.output
    )

    mcp = mcp_validate_config(config_path=str(config))
    assert mcp["valid"] is False, mcp


def test_a_not_installed_in_namespace_module_is_invalid_for_validate_too(
    project: Path, monkeypatch
):
    """The scan refuses a configured module that fails to import with exit 3;
    a name inside the plugin namespace that no installed package provides is
    the locatable half of that class, found without importing anything, so
    every check surface refuses it in the import refusal's words. (A module
    that is installed but breaks while importing can only be caught by
    importing it, which no check may do; that half stays the scan's.)"""
    config = project.parent / "operator.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - missing_ash_plugins\n",
        encoding="utf-8",
    )
    config_args = ["--config", str(config)]

    scan_accepts, _ = _scan(project, [], monkeypatch, config_args)
    assert scan_accepts is False

    validate = _every_surface_agrees(config_args, scan_accepts=False)
    assert "missing_ash_plugins" in validate.output, validate.output
    assert "failed to import" in _flat(validate.output), validate.output

    mcp = mcp_validate_config(config_path=str(config))
    assert mcp["valid"] is False, mcp
    messages = " ".join(error["message"] for error in mcp["errors"])
    assert "missing_ash_plugins" in messages, mcp


def test_an_in_tree_entry_the_scan_drops_is_not_an_error_for_validate(
    project: Path, monkeypatch
):
    """The same entry in a file inside the scanned tree: the trust layer drops
    it before the loader sees it (plugin_module_trust.confine_plugin_modules,
    it is not installed), so the scan accepts the file with a warning, and
    validate agrees with exit 0. The name is inside the plugin namespace: a
    name outside it is kept for the scan's exit-3 namespace refusal wherever
    the file sits (the previous test's case)."""
    config = project / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - missing_ash_plugins\n",
        encoding="utf-8",
    )

    scan_accepts, _ = _scan(project, [], monkeypatch)
    assert scan_accepts is True

    validate = CliRunner().invoke(app, ["config", "validate"])
    assert validate.exit_code == 0, validate.output


def _every_surface_agrees(
    config_args: List[str],
    scan_accepts: bool,
    lint_refuses: Optional[bool] = None,
):
    """validate, get, validate-plugin-dependencies and lint all give the scan's
    verdict for ``config_args`` (the config-reading check surfaces); returns the
    validate result for message assertions. ``lint_refuses`` overrides lint's
    expectation where its as-written verdict differs from the scan's."""
    expected = 0 if scan_accepts else INVALID_CONFIG_EXIT
    runner = CliRunner()
    validate = runner.invoke(app, ["config", "validate", *config_args])
    assert validate.exit_code == expected, validate.output
    for command in ("get", "validate-plugin-dependencies"):
        loaded = runner.invoke(app, ["config", command, *config_args])
        assert _no_exception(loaded), (command, loaded.exception)
        assert loaded.exit_code == expected, (command, loaded.output)
    lint = runner.invoke(app, ["config", "lint", *config_args])
    assert _no_exception(lint), lint.exception
    refuses = (not scan_accepts) if lint_refuses is None else lint_refuses
    assert (lint.exit_code == INVALID_CONFIG_EXIT) is refuses, lint.output
    return validate


def test_a_module_the_ash_config_base_trusts_is_invalid_for_validate_too(
    project: Path, monkeypatch
):
    """ASH_CONFIG names an operator file outside the tree that lists the same
    not-installed module the named in-tree file lists. The scan's trusted base
    is that operator file, so the in-tree entry is kept and refused with
    exit 3; a check judging trust against the bare defaults drops it and calls
    the file valid. The in-tree file is named with --config: without it both
    the scan and the checks read the ASH_CONFIG file itself, and the base's
    part in the judgment goes unexercised."""
    operator = project.parent / "operator-base.yaml"
    operator.write_text(
        "project_name: op\nash_plugin_modules:\n  - outside_module\n",
        encoding="utf-8",
    )
    config = project / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - outside_module\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    config_args = ["--config", str(config)]

    scan_accepts, _ = _scan(project, [], monkeypatch, config_args)
    assert scan_accepts is False

    validate = _every_surface_agrees(config_args, scan_accepts=False)
    assert "outside_module" in validate.output, validate.output

    mcp = mcp_validate_config(config_path=str(config))
    assert mcp["valid"] is False, mcp
    # The verdict with its reason, not the verdict alone: the module refusal.
    messages = " ".join(error["message"] for error in mcp["errors"])
    assert "outside_module" in messages, mcp
    assert "is not a plugin module ASH imports" in messages, mcp


def test_an_in_tree_symlinked_extends_base_keeps_the_scans_trust_judgment(
    project: Path, monkeypatch
):
    """An outside config extends an in-tree symlink whose target sits outside
    the tree. The scan judges the base by the name that reached it, so the
    chain counts as repository-written: the not-installed entry is dropped and
    the scan accepts. A check judging only the resolved paths treats the chain
    as the operator's and refuses what the scan never loads. The entry is an
    in-namespace name no package provides; a name outside the namespace is
    refused with exit 3 wherever it sits."""
    target = project.parent / "base-target.yaml"
    target.write_text(
        "ash_plugin_modules:\n  - missing_ash_plugins\n",
        encoding="utf-8",
    )
    link = project / ".ash-base.yaml"
    link.symlink_to(target)
    operator = project.parent / "operator.yaml"
    operator.write_text(
        f"project_name: demo\nextends:\n  - {link}\n",
        encoding="utf-8",
    )
    config_args = ["--config", str(operator)]

    scan_accepts, _ = _scan(project, [], monkeypatch, config_args)
    assert scan_accepts is True

    _every_surface_agrees(config_args, scan_accepts=True)

    # The operator's file, named by the operator: set its directory aside, or
    # the tool judges the path a client's (see the first test's MCP step).
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(project.parent))
    mcp = mcp_validate_config(config_path=str(operator))
    assert mcp["valid"] is True, mcp


def test_mcp_validate_config_judges_a_client_supplied_path_as_untrusted(
    project: Path, tmp_path: Path, monkeypatch
):
    """A config_path under the MCP shared workspace root got there through a
    client, so it is judged as the scan judges it (untrusted): the
    not-installed entry is dropped and the file is valid. A session's own
    ``config/`` directory is the exception -- only the server writes it -- so
    the same text there keeps the operator's trust and is refused."""
    workspace = tmp_path / "mcp-workspaces"
    source = workspace / "sess1" / "src"
    source.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    text = "project_name: demo\nash_plugin_modules:\n  - outside_module\n"
    delivered = source / "cfg.yaml"
    delivered.write_text(text, encoding="utf-8")

    result = mcp_validate_config(config_path=str(delivered), session_id="sess1")
    assert result["valid"] is True, result

    server_dir = workspace / "sess1" / "config"
    server_dir.mkdir()
    materialized = server_dir / "cfg.yaml"
    materialized.write_text(text, encoding="utf-8")

    control = mcp_validate_config(config_path=str(materialized), session_id="sess1")
    assert control["valid"] is False, control
    # The refusal itself, not only the verdict: the kept entry's module refusal.
    messages = " ".join(error["message"] for error in control["errors"])
    assert "outside_module" in messages, control
    assert "is not a plugin module ASH imports" in messages, control


def test_mcp_validate_config_drops_a_client_contents_not_installed_module(
    project: Path,
):
    """A config a client sends is untrusted: a scan under it drops a
    not-installed ash_plugin_modules entry (resolve_config's untrusted path
    treats the whole chain as in-tree), so the MCP tool calls it valid rather
    than refusing a module the scan never loads."""
    result = mcp_validate_config(
        config_content="project_name: demo\nash_plugin_modules:\n  - outside_module\n"
    )

    assert result["valid"] is True, result


def test_validates_module_refusal_names_an_env_read_entry_masked(
    project: Path, monkeypatch
):
    """An entry the config read from the environment is named `<value>` in
    validate's refusal, as the loader's names it, never by the variable's
    value."""
    monkeypatch.setenv("ASH_V_PLUGIN", "env_named_module")
    config = project.parent / "operator.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - !ENV ${ASH_V_PLUGIN}\n",
        encoding="utf-8",
    )

    validate = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])
    assert validate.exit_code == INVALID_CONFIG_EXIT, validate.output
    assert "env_named_module" not in validate.output, validate.output
    assert "<value>" in validate.output, validate.output
